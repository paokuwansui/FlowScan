# FlowScan Agent 改进方案（参照 CyberStrikeAI agent 模式）

> 目标：参照 `/home/clay64/Public/CyberStrikeAI` 的 agent 架构（基于字节 eino 框架），对 FlowScan 当前自建 ReAct 循环做针对性增强。先设计、后动代码。

---

## 一、现状回顾（FlowScan 当前 agent）

位置：`web_app/__init__.py` 的 `_run_agent_loop` / `_call_llm_with_tools` / `_dispatch_agent_tool`，工具执行器在 `flowscan/agent_tools.py`。

现有能力：
- 单层 ReAct 循环（function calling），`for iteration in range(max_iterations)`（默认 20）。
- 终止条件：LLM 无 `tool_calls` 直接回答，或撞到 `max_iterations`。
- 工具集 13 个：list_events / get_children / scan_status / inject / remove_event / blacklist_add / http_request / run_python / run_shell / log / c2_beacons / c2_exec / c2_result / webshell_*（含 webshell_connections/exec/fileop）。
- 危险工具全自动执行 + 事后人工审计（`fs3:agent:audit`）+ AI 自动审计（审计摘要注入每轮 system）。
- inject 后 `sleep(agent_scan_gap_seconds)` 拉增量事件摘要喂回。

当前明显的薄弱点（与 CyberStrikeAI 对照）：
1. **无终结判定**——LLM 说"完成"就直接 done，不验证是否有 pending 工具、是否真产出了证据。
2. **工具错误处理粗放**——`json.loads` 失败直接 `args={}` 静默吞掉；工具执行错误原样 append，没有引导 LLM 自纠正。
3. **无上下文预算**——`messages` 无 token 计数，长工具输出会撑爆上下文，且无溢出恢复。
4. **无瞬时重试**——LLM API 429/5xx/网络抖动直接 `status=error` 终止。
5. **`max_iterations=20` 太小**——复杂扫描任务不够用。
6. **无 Plan-Execute**——复杂任务没有"先规划再执行"。
7. **无推理链记录**——前端看不到模型每一步的 reasoning。

---

## 二、CyberStrikeAI agent 模式的核心设计（可借鉴点）

| 模块 | 文件 | 核心思想 |
|---|---|---|
| 终结判定 | `internal/agentfinalizer/decision.go` | agent 文本只是"候选答案"，必须过 `Decision` 判定才 `Finalizable`。判定链：HITL 等待 → 空响应 → 状态异常 → pending 工具 → 证据缺失 → 通过 |
| 软错误恢复 | `internal/multiagent/tool_error_middleware.go` | 工具错误（JSON 解析/超时/工具未找到/权限）一律转成 LLM 可读的 soft error 返回，让模型自纠正；只有 `context.Canceled`（用户取消）才硬终止。默认 soft（黑名单制） |
| 上下文预算 | `internal/multiagent/context_budget.go` | 多级压缩：工具输出按字节截断（留头尾 + marker + spillRef）→ 按 token 预算截整轮 → 丢弃旧轮次 → 激进压缩（70% 预算）。带 API 溢出错误检测 |
| 瞬时重试 | `internal/multiagent/eino_transient_retry.go` | 网络瞬时错误自动重试，避免昂贵的中断重放 |
| Plan-Execute | `internal/multiagent/plan_execute_executor.go` | 两阶段：Planner 产出步骤计划 → Executor 逐步执行，会话里维护 Plan/ExecutedSteps |
| 迭代上限 | `internal/multiagent/max_iterations.go` | 默认 3000，config + 子代理 front matter 可覆盖；靠终结判定而非硬上限兜底 |
| HITL | `internal/multiagent/hitl_middleware.go` | 关键操作暂停等人工批准 |
| 推理追踪 | `internal/multiagent/reasoning_trace.go` | 记录推理链，可回溯 |

---

## 三、改进建议（按优先级）

### P0-1 终结判定（Finalizer / Decision）—— 最高优先级

**问题**：当前 LLM 无 `tool_calls` 就 `status=done`，可能"假完成"——比如它本应调用 `scan_status` 确认扫描结束，却提前输出一句"分析完成"。

**CyberStrikeAI 做法**：`Decision` 对象是终结的唯一契约，判定链：
1. HITL 等待 → `awaiting_hitl`
2. 空响应 → `blocked`（empty_response）
3. 状态异常（in_progress/blocked/failed/cancelled）→ 不终结
4. 有 pending 工具执行 → `in_progress`（pending_tool_executions）
5. 需要证据但无完成证据 → `blocked`（missing_execution_evidence）
6. 否则 → `finalizable`/`completed`

**FlowScan 方案**：
- 新增 `_finalize_agent_turn(redis, session_id, answer, tool_calls)`，在 LLM 无 tool_calls 时做判定：
  - `answer` 为空/占位 → 追加一句 system 提示"请给出结论"，继续一轮（而非 done）。
  - 本轮之前有 `tool_calls` 但对应工具结果为空/失败 → 引导 LLM 重试或换工具。
  - 关键任务（如 inject 了但尚未拉增量、blacklist 但未确认）→ 检查证据后决定。
- 把 `status` 从二值（running/done/error）扩展为 `running/done/blocked/awaiting_hitl/error`，前端轨迹能区分。
- 涉及文件：`web_app/__init__.py`（`_run_agent_loop` 终止分支）、`web_app/templates/ai_analysis.html`（轨迹状态展示）。

**收益**：杜绝"假完成"，复杂任务真正跑完才停。

---

### P0-2 软错误恢复（soft error recovery）

**问题**：现在工具调用 `json.loads` 失败直接 `args={}` 静默吞掉，LLM 不知道自己的参数坏了，会在错误前提下继续，浪费轮次甚至得出错结论。

**CyberStrikeAI 做法**：`isSoftRecoverableToolError` 默认 soft（黑名单制）——几乎所有工具错误都转成 `[Tool Error] ... 请检查参数后重试` 消息返回给 LLM，让它在同一轮自纠正；只有用户取消才硬终止。

**FlowScan 方案**：
- 改 `_run_agent_loop` 的工具分发段：
  - `json.loads(fn["arguments"])` 失败 → 不静默，append 一条 tool 结果：`[参数错误] 工具 {name} 的参数不是合法 JSON: {原文}，请修正后重试`。
  - 工具执行返回 `{"ok": false, "error": ...}` → 已有错误信息，确保格式引导 LLM（"请换工具或调整参数"）。
  - LLM 调用 `resp.ok=False` 且是瞬时错误 → 走 P1-3 重试；否则才 error 终止。
- 涉及文件：`web_app/__init__.py`（`_run_agent_loop` 1621-1630 段）。

**收益**：模型能自纠正参数/换工具，减少无效轮次和静默失败。

---

### P0-3 上下文预算与压缩

**问题**：`messages` 无 token 上限，`get_children`/`run_shell` 输出大时直接撑爆上下文，LLM 报错后 `status=error` 全盘终止。

**CyberStrikeAI 做法**：`context_budget.go` 三级压缩：
1. 工具输出按字节截断（`truncateBytesWithMarker`：留头 1/2 + 尾 1/2 + marker + spillRef 引用完整内容）。
2. 按 token 预算截整轮（`truncateRoundMessagesToTokenBudget`）。
3. 丢弃旧轮次（`compactMessagesByDroppingRounds`），激进模式只留最新轮 + 70% 预算。
4. 检测 API 溢出错误（`isEinoContextOverflowError`），触发时自动激进压缩重试。

**FlowScan 方案**（先做轻量版，不引入 token 计数器）：
- 给 `_run_agent_loop` 加 `context_max_chars`（如 60000 字符）预算：
  - 每次 append 前估算 `messages` 总字符数，超预算时：先截断最旧的工具消息（头尾 + `...[已截断]...`），再丢弃最旧的非 system/user 轮次。
  - 工具结果统一经 `_truncate_for_context(result, max=4000)`：留头尾 + marker。
- LLM 返回溢出类错误（匹配 `context length`/`maximum context`/`too many tokens` 等关键字）时，不终止，而是压缩 messages 后重试一次。
- 涉及文件：`web_app/__init__.py`（`_run_agent_loop` + 新增 `_compact_agent_messages`）、`flowscan/agent_tools.py`（截断策略统一）。

**收益**：长任务不再因上下文溢出崩溃，能持续跑完整轮数。

---

### P1-4 瞬时错误重试

**问题**：`_call_llm_with_tools` 的 `except urllib.error.HTTPError` 直接返回 `ok=False`，一次 429/5xx/网络抖动就整轮 error 终止。

**CyberStrikeAI 做法**：`eino_transient_retry.go` 对瞬时错误（429、5xx、超时、连接重置）指数退避重试，区分可重试 vs 不可重试。

**FlowScan 方案**：
- `_call_llm_with_tools` 加 `retries`（如 3 次，指数退避 2s/4s/8s）：
  - 429 / 5xx / `timeout` / `ConnectionResetError` → 重试。
  - 401/403/400（鉴权/参数错）→ 不重试，直接报错。
- 涉及文件：`web_app/__init__.py`（`_call_llm_with_tools`）。

**收益**：提升稳定性，减少因抖动导致的中断。

---

### P1-5 Plan-Execute 两阶段（可选模式）

**问题**：复杂任务（如"对整个资产做一轮完整侦察→指纹→漏洞→报告"）单层 ReAct 容易迷失、遗漏步骤。

**CyberStrikeAI 做法**：`planexecute` 先让 Planner 产出结构化步骤计划（存会话 `Plan`），Executor 逐步执行并维护 `ExecutedSteps`，每步完成后回写进度。

**FlowScan 方案**（做成可选的"计划模式"开关，非默认）：
- 用户输入里带"计划"/"plan"关键词，或前端勾选"计划模式"时：
  1. 第一轮让 LLM 产出 JSON 计划（`{"steps": ["...", ...]}`），存 `fs3:agent:session:{id}:plan`。
  2. 后续每轮在 system 里注入"当前计划 + 已完成步骤 + 下一步"，引导 LLM 按计划推进。
  3. 计划全部完成后正常终结。
- 涉及文件：`web_app/__init__.py`（`_run_agent_loop` 加 plan 分支）、`config.yaml`（`agent_plan_mode`）。

**收益**：复杂任务结构化、可追踪、不易漏步骤。轻量实现（不引框架）即可。

---

### P1-6 迭代上限调整

**问题**：`agent_max_iterations=20` 对复杂扫描偏小，且撞上限后只是"达到轮数上限"。

**CyberStrikeAI 做法**：默认 3000，靠终结判定兜底（不会真跑满），config + 子代理可覆盖。

**FlowScan 方案**：
- 把默认提到 50~100（有 P0-1 终结判定后不会空转）。
- 撞上限时不再写死"达到轮数上限"，而是走终结判定：若有产出就正常 done，否则 `blocked`。
- 支持前端每会话覆盖上限。
- 涉及文件：`config.yaml` / `config.yaml.example`、`web_app/__init__.py`（`_ai_config`）。

---

### P2-7 工具输出溢出保护（spillRef）

**问题**：`agent_tools.py` 截断 2000/4000 字符后，完整内容就丢了，模型无法再取回。

**CyberStrikeAI 做法**：截断 marker 带 `spillRef`（完整内容持久化到 reduction cache，需要时按引用取回）。

**FlowScan 方案**：
- 大工具输出截断后，把完整内容存 Redis `fs3:agent:spill:{session_id}:{ts}`，marker 里写"完整内容见 spill:xxx，需要时用 get_spill 取回"。
- 给 agent 加一个 `get_spill` 工具按引用取回完整内容。
- 涉及文件：`flowscan/agent_tools.py`、`web_app/__init__.py`（AGENT_TOOLS + dispatch）。

---

### P2-8 推理链记录（reasoning trace）

**问题**：前端只有 assistant 文本 + tool 结果，看不到模型"为什么这么想"。

**CyberStrikeAI 做法**：`reasoning_trace.go` 记录推理链。

**FlowScan 方案**：
- 若模型返回 `reasoning_content`（DeepSeek reasoner 等支持），把它作为 `reasoning` 字段存进消息帧，前端轨迹里用折叠区展示。
- 涉及文件：`web_app/__init__.py`（`_call_llm_with_tools` 保留 reasoning 字段）、`web_app/templates/ai_analysis.html`（轨迹渲染）。

---

### P2-9 HITL 强化（危险操作人工闸）

**问题**：危险工具（remove_event / blacklist / c2_exec / webshell_exec 等）当前全自动 + 事后审计，没有事前闸。

**CyberStrikeAI 做法**：`hitl_middleware.go` 关键操作暂停等人工批准。

**FlowScan 方案**（渐进，不推翻现有"全自动+审计"设计）：
- 给危险工具加"分级"：一级（可逆，如 blacklist_add）全自动；二级（不可逆，如 remove_event、c2_exec 高危命令）若总开关关闭时，转 `awaiting_hitl` 状态，前端弹"批准/拒绝"。
- 复用现有 `fs3:agent:audit` + 新增 `fs3:agent:pending` 待批准队列。
- 涉及文件：`web_app/__init__.py`（`_dispatch_agent_tool` + 状态机）、`web_app/templates/ai_analysis.html`（批准 UI）、`config.yaml`（`agent_require_approval` 分级）。

---

### P3-10 多 agent 编排（远期）

**问题**：单 agent 串行处理侦察/漏洞/利用，慢且上下文混杂。

**CyberStrikeAI 做法**：`markdown_orchestrator.go` + `sub_agent_context.go` 多代理编排，子代理各自独立上下文。

**FlowScan 方案（远期，仅记录）**：
- 若未来需要，可拆"侦察子代理 / 分析子代理"，用主 agent 派发。当前不建议——单 agent + Plan-Execute 已覆盖多数场景，多 agent 复杂度和 token 成本高。

---

## 四、实施顺序建议

| 批次 | 内容 | 工作量 | 依赖 |
|---|---|---|---|
| 第一批 | P0-1 终结判定 + P0-2 软错误恢复 | 小 | 无 |
| 第二批 | P1-3 瞬时重试 + P1-6 迭代上限 | 小 | 无 |
| 第三批 | P0-3 上下文预算（轻量版） | 中 | P1-3 |
| 第四批 | P1-5 Plan-Execute + P2-8 推理链 | 中 | P0-1 |
| 第五批 | P2-7 spillRef + P2-9 HITL 分级 | 中 | P0-1 |

建议按批次推进，每批独立可验证（沿用现有 ad-hoc 验证脚本模式：`/tmp/hermes-verify-*.py`，跑完清理）。

---

## 五、原则约束（保持 FlowScan 既有风格）

- 不引入 eino 等重型框架——上述改进都用纯 Python stdlib + 现有 Flask/Redis 实现，保持 FlowScan"轻、可读、单容器"的既有风格。
- 配置项统一进 `config.yaml` 的 `ai_analysis` 段，不新增顶层死配置。
- 每个 P0/P1 项落地后补 ad-hoc 验证脚本并清理。
- 危险工具审计机制（`_AGENT_DANGEROUS` + `_audit_agent_action`）保持不变，新增的分级/HITL 是增强而非替换。
