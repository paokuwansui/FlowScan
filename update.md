# FlowScan Web UI 优化建议书

> 编写日期:2026-08-16
> 范围:`web_app/templates/`(18 个模板)+ `web_app/static/style.css`(1842 行)
> 目标:在不破坏现有深色科技风设计系统(v3 设计令牌)的前提下,提升可用性、可访问性、信息密度与实时性

---

## 一、现状概述

- **设计系统已成型**:CSS 变量令牌(`--surface/--accent/--border/--radius` 等)统一,卡片/表格/徽章/按钮/统计卡/滑块/分段选择器组件齐全,深空蓝青主题观感统一,无需推倒重来。
- **页面结构**:18 个模板,一级导航 6 项(仪表盘 / 事件中心▾ / 资产情报▾ / AI 分析 / 命令&控制 / 调试工具▾)。
- **主要短板**:静态渲染无实时刷新、大列表无分页、时间戳原始 epoch 浮点、若干 a11y label 缺失、导航下拉仅 hover(触屏/键盘不可达)、内联样式泛滥难维护。
- 以下建议按 **P0(体验硬伤,改动小收益大)/ P1(交互效率)/ P2(增强项)** 分级,每项给出问题、建议与涉及文件。

---

## 二、P0 — 体验硬伤(建议优先做)

### P0-1 时间戳全部 humanize(当前到处是 epoch 浮点)
**现状**:多个页面直接把 `%.2f` 格式化的 Unix 浮点时间戳展示给用户,极不可读:
- `event_query.html` L141 路径时间线:`时间: {{ "%.2f"|format(node.timestamp|float) }}`
- `logs.html` L31 执行日志:`{{ "%.2f"|format(log.ts) }}`
- `nodes.html` L39 节点启动时间:`{{ "%.2f"|format(node.started_at|float) }}`
- 事件日记 AI 日志页已有 `created_at_iso`(可读),风格不一致。

**建议**:统一改为 `YYYY-MM-DD HH:MM:SS`(或相对时间)。最省事的方式是后端加一个公共 jinja filter 或在 `_helpers.py` 提供 `fmt_ts(ts)`(秒/毫秒/浮点自动识别),渲染处逐个替换;日志量大时用前端 JS 转换避免模板开销。**涉及**:`dashboard.py / events.py / ai_logs.py` 渲染上下文 + 3 个模板。

### P0-2 a11y 表单 label 关联补全(Chrome DevTools Issues 必报项)
**现状**:以下表单字段没有 label 关联(placeholder 不算 label,Chrome Issues 面板会报 "No label associated with a form field",14 页逐一查会暴露):
- `events.html`:
  - L49 文件恢复 `<input type="file" name="state_file">` 无 label
  - L75 搜索框 `search_val` 无 label
  - L108 批量移除 textarea `fingerprints` 无 label
  - L176-190 实时测试区:可见 `<label>事件类型</label>`/`<label>测试值</label>` 存在但**没有 for 属性**且未包裹 input(等于无关联)
- `event_query.html` L11 搜索框 `.eq-search-input` 无 label
- `event_tree.html` L13 `#graph-search-input` 无 label
- `template_lab.html` L45 `filename`、L47 `yaml_text`、L55 `event_type`、L59 `target`、L63 `timeout`、L67 `install_step`:label 无 for 或无 label
- `redis_cmd.html` L14 `#command` 无 label(只有 `redis>` 视觉提示符)
- `c2.html`:L89 `#c2-cmd`、L100 `#py-snippets`、L110 `#py-code`、L128 `#mod-search` 均无 label/aria-label(部分早期字段已修,新加字段漏了)
- `logs.html` L14 limit select 已由 label 包裹 → 合规,无需改。

**建议**:按既定三选一原则补齐——已有可见 label 的补 `for="字段id"`;无可见 label 的加 `aria-label`。改完用 test_client 渲染 + Chrome DevTools Issues 复核。**涉及**:上述 6 个模板。

### P0-3 导航下拉菜单 hover-only,触屏/键盘不可达
**现状**:`.nav-dropdown-menu` 仅靠 `.nav-dropdown:hover` 展开(base.html + style.css L186-217),Windows 触屏设备、键盘 Tab 导航完全无法进入子菜单;移动端(≤900px)只是横向滚动,子菜单依然 hover 展开。
**建议**(两选一,推荐 A):
- A:加 `:focus-within` 支持(最小改动,键盘可达,触屏点按一级项可聚焦展开),`<a href="#" onclick="return false;">` 保持;
- B:改成点击切换(JS toggle + 点击外部关闭),与页面内 tab 交互一致。

同时建议 900px 断点加汉堡菜单(见 P1-5)。**涉及**:`base.html` + style.css。

### P0-4 空状态组件不统一
**现状**:事件查询页已做 `.eq-empty` 卡片化空态(虚线边框 + SVG 图标 + CTA),但其他页仍用旧 `.empty-state`(仅居中文字,无图标无引导)甚至裸 `empty` 类:logs/nodes/events/event_logs/ai_analysis 等。
**建议**:把 `.eq-empty` 模式抽成通用组件类(如 `.empty-card`,或直接复用 `.eq-empty`),全站统一;空态文案带下一步引导(如"去事件管理注入")。**涉及**:style.css + 6 个模板。

---

## 三、P1 — 交互效率

### P1-1 关键页实时刷新(编排工具最需要的"活"感)
**现状**:仪表盘、执行日志、节点&工具、事件查询全部是服务端静态渲染,数据变了必须手动 F5;xray 报告页有"刷新状态"按钮但也是手点。
**建议**:
- 仪表盘:新增轻量 `GET /api/dashboard/stats`(redis_ok/event_count/node_count/tool_count + 各队列 pending 数),前端 5-10s 轮询,仅更新数值;pending>0 的队列行高亮/加"积压"徽章。
- 执行日志/节点页:同样 5s 轮询或加"自动刷新"开关(C2 页已有 `toggleAutoRefresh` 模式可复用)。
- 遵循既有教训:fetch 一律 try/catch + 失败提示;轮询失败静默重试,不打断页面。

### P1-2 事件查询:类型计数 + 分页 + 防抖搜索
**现状**:
- 左侧类型列表无计数徽章(不知道哪类最多);
- 搜索结果明确写"仅最近 1000 条内搜索",无分页/加载更多;
- 搜索需回车提交,无防抖自动搜索。
**建议**:
- 侧栏类型项加计数徽章(可复用 `.tab .cnt` 样式);
- 结果区加分页或"加载更多"(游标翻页,后端加 `offset/limit` 参数);
- 搜索框 debounce 300ms 自动提交(GET 表单 + `history.replaceState` 保留浏览器行为,遵循渐进增强)。

### P1-3 事件管理:批量注入/移除即时校验预览
**现状**:`events_batch` / `fingerprints` 都是裸 textarea,格式错误([事件类型]拼错、大小写、非 64hex)提交后才知道结果。
**建议**:前端逐行解析预览——每行渲染成 badge(类型着色)+ 值,非法行标红并说明原因(纯前端规则与后端 `_parse_event_line` 对齐);不阻断提交,只是提交前可视化。**涉及**:`events.html` JS + 少量 CSS。

### P1-4 事件日记 iframe 嵌入改组件化
**现状**:AI 分析页第 3 个 tab(`?tab=logs`)用 `<iframe src="/event-logs?embed=1">` 嵌入事件日记,存在双重滚动条、iframe 高度固定(内部内容超高时外层又滚)、焦点/键盘事件隔离等问题。
**建议**:若只是布局复用,建议把事件日记 3 个子 tab 内容抽成 Jinja 宏/独立模板片段直接 include,去掉 iframe(路由保留);若保留 iframe,则高度自适应(`postMessage` 或 ResizeObserver 同步内容高度)。**涉及**:`ai_analysis.html` + `event_logs.html` 拆分。

### P1-5 移动端/窄屏体验
**现状**:≤900px 时导航仅 `overflow-x:auto`(无汉堡菜单),下拉子菜单 hover 失效;表格(事件管理、节点、执行日志)无横向滚动容器,窄屏直接溢出。
**建议**:
- 900px 断点加汉堡按钮 + 抽屉式导航(纯 CSS + 少量 JS),子菜单改点击展开;
- 表格统一包 `<div class="table-scroll" style="overflow-x:auto;">` 或全局 `.table { min-width: 720px }` + 容器滚动;
- `.form-row` 内联 flex 换行已有,窄屏下按钮与输入同行的区域(批量移除、黑名单测试)确认换行后不挤。

### P1-6 内联样式收敛(渐进,不动视觉)
**现状**:模板里大量 `style="..."` 内联(事件管理、xray、screenshots、ai_analysis 均不少),设计令牌形同虚设,改主题时要逐个翻。
**建议**:把高频内联组合抽成语义类(如 `.btn-row`、`.cell-ellipsis`、`.pad-x`),新页面直接引用;**不强制一次性重构**(注意浏览器 CSS 缓存坑:新组件关键样式仍内联双保险,见历史教训)。可先列内联样式清单,挑 Top10 高频的抽。

---

## 四、P2 — 增强项(按需排期)

### P2-1 仪表盘升级
- 事件类型生产/消费 Top N 迷你条(bar),一眼看出链路活跃度;
- pending 积压告警条:任一队列 pending > 阈值(如 50)时顶部红色横幅;
- 最近事件流(右侧 10 条最新事件,点击跳事件查询)。
数据全部来自现有 Redis 结构(`fs3:stats:event_type` / `fs3:event:all` 时间索引),无存储改动。

### P2-2 全局搜索 / 快捷键
- 导航栏右侧加全局搜索框(事件值模糊搜索,跳事件查询结果页);
- `Ctrl/Cmd+K` 聚焦搜索;页面内 `?` 弹快捷键说明。局域网工具,纯加分项。

### P2-3 C2 工作台打磨
- 终端输出行内语法高亮(命令/参数/路径分色,复用现有 `tok/terr/tinfo` 体系扩展);
- Beacon 卡片加在线/离线状态点(现仅 `selected` 高亮),心跳超时标灰;
- Python 编辑器加行号(轻量,不用引 CodeMirror 大库,可用 contenteditable 行号列或纯 CSS counter)。

### P2-4 Xray 报告页
- findings 列表加 severity 过滤 + 关键字搜索(前端过滤即可,数据量级不大);
- iframe 加载指示器(报告大时白屏等待无反馈)。

### P2-5 全局反馈体系
- 引入统一 toast(右上角自动消失)替代 `alert()`/页面内零散提示;现有 flash 消息保留用于整页刷新场景;
- 骨架屏:数据密集页(事件查询、C2)首载用 `.loading` 或骨架块占位,避免白屏。

### P2-6 细节一致化
- `base.html` footer 全大写英文 + 页面 sub 中英混排,统一为中文为主;
- 事件图谱/执行流程两个 vis-network 页:加缩放百分比指示、全屏按钮、节点数统计;
- 表格列宽统一:时间列/类型列固定宽,值列自适应 ellipsis(已有 `.value-cell`/`.fp-cell`,补齐应用)。

---

## 五、待确认项

1. P0-1 时间戳格式:固定 `YYYY-MM-DD HH:MM:SS`(推荐)还是"相对时间(5 分钟前)"?全站统一用后端 filter 还是前端 JS?
2. P0-3 导航下拉:方案 A `:focus-within` 最小改动,还是方案 B 点击切换?
3. P0-4 空状态:抽新类 `.empty-card` 还是直接全站复用 `.eq-empty`?
4. P1-1 自动刷新:仪表盘 + 执行日志 + 节点页都做,还是只做仪表盘?(C2 页已有开关可参考)
5. P1-2 事件查询分页:后端游标分页(推荐,事件可能 10 万+)还是前端"加载更多"攒一次性数据?
6. P1-4 事件日记 iframe:改为直接 include 组件化(推荐),还是保留 iframe 只做高度自适应?
7. P1-5 移动端:本次是否做汉堡菜单,还是仅保证表格横向滚动 + 下拉键盘可达?
8. P2 各项(仪表盘升级/全局搜索/C2 高亮/Xray 过滤/toast):哪些进入下一轮排期?

> 回复方式:直接回复编号即可,如"1A 2A 3B 4 只仪表盘 5 后端分页 6 include 7 仅滚动 8 全部"。
