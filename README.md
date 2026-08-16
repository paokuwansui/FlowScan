# FlowScan3

基于 Redis 事件总线的安全扫描编排框架。工具以 YAML 模块描述，事件经 Redis 流转，自动串联成「资产发现 → 端口扫描 → 服务指纹 → 漏洞探测」完整扫描链。内置 Web 控制面板（仪表盘 / 事件中心 / AI 分析 / Agent / C2 / WebShell）、LLM 自动分析、xray 被动代理与截图/图标采集。

## 核心特性

- **事件驱动编排**：所有工具通过 Redis 交换事件（Lua 原子入队/认领），多 Worker 节点并行消费，自动形成扫描链
- **28 个扫描模块**：子域枚举（subfinder/amass/ksubdomain/crtsh/wayback）、DNS/反查/ASN、端口扫描（naabu）、HTTP 探活指纹（httpx）、目录爆破（feroxbuster/arjun）、爬虫（katana）、漏洞扫描（nuclei/afrog/medusa）、CMS 指纹（whatweb）、FOFA 资产测绘、截图/图标采集、403 绕过等
- **失败重试与看门狗**：命令失败事件不标记完成，本节点指数退避后重试，其他节点可随时抢占；锁靠心跳看门狗释放，节点宕机 120s 后自动接管
- **双轨黑名单 + 白名单**：文件规则（`black_list.cfg`）+ Redis 动态规则，4 种匹配模式（正则/后缀/前缀/IP 范围），入队即拦截；白名单非空时仅放行命中事件
- **AI 分析**：LLM 对事件日志自动分析（新增/删除/拉黑/记录动作），支持 dry-run 预览、定时任务调度、思考强度（reasoning_effort）配置
- **Agent 模式**：内置 ReAct 循环 + 30 个工具（事件操作 / C2 / WebShell / HTTP / 沙箱命令 / MCP / 技能库），危险操作按 auto / AI 审批 / 人工审批三档管控，全程审计
- **MCP 接入**：SSE / HTTP / stdio 三种传输，工具列表缓存与 schema 精简，Agent 可直接调用外部 MCP 工具
- **技能库（Skills）**：AI 面板可视化配置，全文加载 / 渐进式索引两种模式，Agent 可按需 load_skill / search_skills
- **命令 & 控制**：内嵌 pyexec-c2 服务端（Beacon 管理、模块下发、伪终端、审计、部署向导）+ WebShell 连接管理（执行/文件操作/GBK 解码）
- **xray 被动代理**：内嵌在容器内，报告自动接入 Web 面板（`/xray-report`）
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

事件生命周期：`push_event`（黑名单/白名单拦截 → 指纹去重 → 落库 + 时间索引 + 血缘 → 消费工具入队）→ worker `claim_task`（Lua 原子锁）→ `pipeline.process`（transform 参数化 → 执行命令 → 解析输出 → 发布子事件）→ 失败不标记完成，指数退避重试。

## 快速开始（Docker）

### 依赖

- Docker 20.10+，compose v2 插件
- 可访问 Docker Hub（拉取 `kalilinux/kali-rolling` 基础镜像）

### 启动主节点（单容器：redis + web + xray）

```bash
cd FlowScan
docker compose up -d --build
```

- Web 控制面板：http://127.0.0.1:8082 （登录账号密码见下方说明）
- 容器内嵌 redis（6379）、xray 被动代理（7777），宿主映射：`8082`（web）/ `6380`（redis，可选）/ `7777`（xray）
- 每次容器启动会**自动随机化** `config.yaml` 中的 redis 密码 / web 登录密码 / secret_key，最新密码可在容器日志首部或 `config.yaml` 中查看
- 日志：`docker compose logs -f main`

> 端口说明：宿主 8080 常被其他服务占用，默认走 8082。若需改回 8081 等，编辑 `docker-compose.yml` 的 ports 映射即可。

### 启动 Worker 节点

```bash
# 同机部署（复用主节点创建的 fs3net 网络，worker 经网络别名 redis 直连主节点内嵌 redis）
docker compose -f docker-compose.worker.yml up -d --build

# 跨机部署：把 worker 节点挂载的 config.yaml 中 redis.redis_host 改为主节点 IP
#   redis:
#     redis_host: 192.168.1.10
```

- worker 容器**不装 redis**，连接信息统一从挂载的 `config.yaml` 读取（不再用环境变量）
- worker 镜像内置全部 28 个模块工具链，启动时按 `install/*.sh` 幂等补装
- 日志：`docker compose -f docker-compose.worker.yml logs -f worker`

### 镜像构建

| 镜像 | 文件 | 内容 | 用途 |
|---|---|---|---|
| `flowscan:main` | `Dockerfile` | Kali + web 依赖 + chromium（Agent 浏览器）+ xray | 主节点（redis+web+xray 内嵌） |
| `flowscan:worker` | `Dockerfile.worker` | Kali + 28 模块工具链全量 | worker 扫描节点 |

两个镜像共用 `kalilinux/kali-rolling` 基础镜像。构建细节：

- **apt 源**：Dockerfile 第 0 层统一替换为清华镜像（官方 http.kali.org 302 会落到不可达镜像导致构建失败）
- **pip**：清华镜像 + `--break-system-packages`；worker 镜像系统 python 已装全量依赖（模块命令用系统 `python`）
- **release 下载**：afrog/katana/fofax/ksubdomain/dnsx/cdncheck 走 GitHub release，三镜像链回退（gh-proxy.com → ghproxy.net → 直连），600s 超时 + 3 次重试
- **katana**：构建时预下载 go-rod Chromium，避免运行时下载日志污染扫描结果
- 一键构建 + 验证：`sudo bash docker/verify_docker.sh`

### 本机开发（非容器）

```bash
# 需要本机有 redis（密码与 config.yaml 一致），改临时配置后直接跑
python3 -m venv .venv && . .venv/bin/activate
pip install PyYAML redis flask tldextract httpx beautifulsoup4 browser-use
cp config.yaml /tmp/config-web.yaml   # 按需修改 redis 地址/端口
python3 main.py web --config /tmp/config-web.yaml --host 0.0.0.0 --port 8081
```

## 配置（config.yaml）

| 段 | 说明 |
|---|---|
| `redis` | `redis_host` / `redis_port` / `password` / `db`。worker 与 web 统一从这里读连接信息 |
| `web_config` | web 面板监听地址/端口、登录用户名/密码、session 密钥与有效期 |
| `worker` | 扫描批大小、本地最大并发、心跳间隔、锁失联阈值（`lock_stale_seconds`）、失败重试退避（`retry_base_seconds` / `retry_cap_seconds`） |
| `xray_listen_http_proxy` / `xray_remote_http_proxy` | xray 被动代理监听地址与上游代理 |
| `fofa` | FOFA API key 与 base_url |
| `ai_analysis` | LLM 配置（base_url/api_key/model/timeout/max_events/log_api_key）+ 定时任务参数 + Agent 参数（迭代上限/扫描间隔/审批模式/上下文预算/思考强度 reasoning_effort） |
| `c2` | 内嵌 C2 服务开关与项目根目录（`c2_server`） |
| `mcp` | MCP server 列表（name/type/url/command/enabled） |
| `skills` | 技能库启用开关与目录列表（指向分类级目录，如 `~/.hermes/skills/hack-skills`） |

## Web 控制面板

导航结构：

- **仪表盘**：事件统计、节点/工具状态、队列积压预警（8s 自动刷新）
- **事件中心**
  - 事件查询：按类型/时间分页浏览、搜索（未选类型搜最近 1000 条，选中类型搜该类型最近 5000 条）、事件路径与递归子事件
  - 事件图谱：事件血缘树可视化，点击展开、搜索、查看递归后代
  - 事件管理：批量注入（`[类型]值` 或纯值）、删除（支持纯值全类型匹配）、清空、全量状态导出/恢复 JSON、文件/Redis 黑名单管理 + 白名单管理（实时测试）
- **资产情报**
  - 资产截图：chromium 对 URL 截图（SCREENSHOT 事件），图标采集（ICON 事件）分栏展示
  - Xray 报告：被动代理发现列表（severity 分级），iframe 嵌入原始 HTML 报告
- **AI 分析**（4 个 tab）
  - Agent 实时交互：自建 ReAct 循环，30 个工具，会话历史 + 实时轨迹，危险操作审批（auto/AI/人工），注入后自动拉取新事件喂回
  - 定时任务模式：按分钟周期对指定事件类型自动分析，动作开关控制自动执行范围，任务/运行历史管理
  - 事件日记：AI 分析日志 + 扫描事件总览 + API 调用示例
  - AI 配置：LLM 参数（含思考强度）、MCP 服务器管理（添加/验证/删除）、技能库滑块配置
- **命令 & 控制**
  - C2 管理：内嵌 pyexec-c2 服务端——Beacon 列表、伪终端（`use <id>` 切换）、模块管理/下发、通道配置、审计日志、部署向导、批量命令
  - WebShell 管理：连接 CRUD（密码脱敏）、执行命令（auto/UTF-8/GBK 解码）、文件操作（读/写/删/重命名/建目录）、命令历史
- **调试工具**
  - 执行流程：vis.js 事件流向图（工具×事件，含未消费事件告警）
  - 模板测试：模块 YAML 在线编辑与六步测试（校验/安装/transform/命令渲染/执行/解析）
  - 执行日志 / 节点&工具 / Redis 命令

## 事件类型

| 类型 | 含义 |
|---|---|
| `INPUT` | 任意输入文本（URL/域名/IP 混合），由 input 模块解析 |
| `DNS_NAME` | 域名（含子域名） |
| `IP_ADDRESS` / `IP_RANGE` | IPv4 地址 / CIDR 网段 |
| `URL` / `URL_UNVERIFIED` | 已验证/未验证存活的 URL |
| `ICON_PATH` | favicon 图标 URL |
| `HOST_TCP_PORT_OPEN` | `ip -> [port,...]` 端口扫描结果 |
| `OPEN_TCP_PORT` | `ip:port` 单个端口 |
| `FINDING` / `TECHNOLOGY` / `WAF` / `VULNERABILITY` / `SERVICE` | 指纹与漏洞发现 |
| `SCREENSHOT` / `ICON` | 截图/图标资产（value 为 JSON，含 url/path） |
| `403_URL` | 目录爆破产出的 403 路径（供 403 绕过模块消费） |

## 模块清单（28 个）

按流水线分层：

| 层 | 模块 | 输入 → 输出 |
|---|---|---|
| L0 输入 | `input` | INPUT → DNS_NAME/IP_ADDRESS/IP_RANGE/URL/URL_UNVERIFIED/ICON_PATH |
| L1 资产扩展 | `subfinder` / `amass` / `ksubdomain` | DNS_NAME → DNS_NAME（子域枚举） |
| | `crtsh` | DNS_NAME → DNS_NAME（证书透明度） |
| | `wayback` | DNS_NAME → URL（历史 URL） |
| | `whois` / `reverse_whois` | DNS_NAME → 注册信息 / 反查 |
| | `permute` | DNS_NAME → DNS_NAME（子域排列） |
| | `asn` | DNS_NAME → IP_RANGE（ASN 归属） |
| | `fofa` | DNS_NAME/URL/IP/ICON_PATH → 资产测绘（fofax） |
| L2 解析 | `ip_resolve` | DNS_NAME → IP_ADDRESS（dnsx + cdncheck 去 CDN） |
| | `ptr` | IP_ADDRESS → DNS_NAME（反查） |
| | `ip_range_split` | IP_RANGE → IP_ADDRESS（CIDR 展开） |
| L3 存活 | `naabu` | IP_ADDRESS/IP_RANGE → HOST_TCP_PORT_OPEN（端口扫描） |
| | `ip_port_split` | HOST_TCP_PORT_OPEN → OPEN_TCP_PORT（拆单端口） |
| L4 指纹 | `httpx` | URL/OPEN_TCP_PORT → 探活/指纹/ICON_PATH |
| | `whatweb` | URL → TECHNOLOGY（CMS 指纹） |
| | `nmap` | HOST_TCP_PORT_OPEN → FINDING（服务/OS 深度指纹） |
| | `icon` | ICON_PATH → ICON（favicon 下载） |
| L5 深挖 | `feroxbuster` | URL → URL/403_URL（目录爆破） |
| | `katana` | URL → FINDING（爬虫，JS 渲染） |
| | `screenshot` | URL → SCREENSHOT（chromium 截图） |
| | `403bypass` | 403_URL → URL/FINDING（绕过尝试） |
| | `arjun` | URL → FINDING（HTTP 参数发现） |
| L6 漏洞 | `nuclei` / `afrog` | URL → VULNERABILITY |
| | `medusa` | OPEN_TCP_PORT → FINDING（弱口令爆破） |

典型链路：`INPUT → input → DNS_NAME → subfinder/ip_resolve → IP_ADDRESS → naabu → HOST_TCP_PORT_OPEN → ip_port_split → OPEN_TCP_PORT → httpx → URL → nuclei/afrog/feroxbuster/katana → VULNERABILITY/FINDING`

## 扩展新模块

三步即可接入流水线：

1. **写脚本** `bin/<tool>.py`（可选）：优先纯标准库；stdout 每行一个 JSON `{事件类型: 值}`；进度写 stderr
2. **写定义** `modules/<name>.yaml`（无 check/install 块，工具由镜像安装）：

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

3. **写安装脚本** `install/<name>.sh`（与 YAML 同名，幂等，镜像构建与 worker 启动时复用；优先 apt，GitHub release 走三镜像链）

> 约定：transform/parse 代码运行在受限沙箱（仅白名单 import，无 Exception 类，`except` 用裸 `except:`）；命令模板中的用户输入必须 `shlex.quote()` 转义；消费新事件类型前先确认已有产出者（避免造重复类型）。

## 目录结构

```
FlowScan/
├── main.py                    # 入口（worker / status / web 三模式）
├── config.yaml                # 主配置（挂载给容器）
├── black_list.cfg             # 文件黑名单
├── docker-compose.yml         # 主节点编排（单容器 redis+web+xray）
├── docker-compose.worker.yml  # worker 节点编排
├── Dockerfile / Dockerfile.worker
├── docker/                    # entrypoint.sh（密钥随机化/内嵌 redis+xray）、redis 辅助脚本
├── modules/                   # 28 个工具 YAML 定义（无 check/install 块）
├── install/                   # 工具安装脚本（与模块同名，幂等）
├── flowscan/                 # 核心引擎
│   ├── worker.py              # Worker 主循环 + 线程池 + 失败退避 + 看门狗
│   ├── pipeline.py            # transform → exec → parse → publish
│   ├── redis_store.py         # Redis 数据层（Lua 原子 claim/push、索引、血缘）
│   ├── filter.py              # 黑名单/白名单引擎（文件 + Redis 双轨）
│   ├── llm.py                 # 统一 LLM 调用核心（重试/思考强度/溢出检测）
│   ├── code_runner.py         # 受限沙箱 exec
│   ├── tool_module.py         # YAML → ToolModule
│   ├── config.py / utils.py
│   ├── mcp_client.py / mcp_verify.py   # MCP 客户端与配置验证
│   ├── c2_bridge.py           # pyexec-c2 桥接
│   └── webshell.py            # WebShell 代理
├── web_app/                   # Web 控制面板（Flask 应用工厂 + 11 个功能子模块）
├── c2_server/                 # 内嵌 pyexec-c2 服务端
├── bin/                       # 配套脚本（input/httpx/fofa/permute 等 + xray 配置）
├── prompts/                   # AI system prompt
├── tools/                     # randomize_secrets.py 等辅助脚本
├── wordlists/                 # 字典
└── reports/                   # xray 报告、截图、图标（挂载持久化）
```

## 故障排查

- **注入事件后无产出**：`docker exec flowscan-main redis-cli -a <密码> hlen fs3:tools` —— 注册表为空则重启 worker（心跳每 10s 幂等自愈重建）；再查 `zcard fs3:pending:<tool>` 与 `docker logs flowscan-worker | grep exit=`
- **worker 日志 exit=127**：容器缺命令/解释器，检查工具是否装入（`docker exec flowscan-worker command -v <tool>`）
- **xray 报告空白**：被动模式需 HTTPS CONNECT 隧道流量（`curl -k -x http://127.0.0.1:7777 https://靶场`）；报告文件权限 root:0640 时 web 读不了（start_xray.sh 内已自动轮询 chmod）；报告不覆盖已存在文件（脚本已 rm -f 预清理）
- **改代码后 worker 不生效**：worker 容器只挂载 config.yaml，代码在镜像内——修改后需 `docker cp` 进容器（`flowscan/` 整目录 + `main.py`）或重建镜像
- **容器重启丢失数据**：内嵌 redis 为纯内存（无持久化），重启后事件库清空；需要持久化时开启 AOF 并挂载 data 卷
- **docker restart 丢端口映射**：用 `docker stop` + `docker start` 代替 restart
- **构建失败**：apt 源已固定清华；GitHub release 慢可重试（多镜像自动回退）；docker 命令在非交互环境注意 `docker` 可能是 `sudo` 别名
- **容器内时区为 UTC**：日志时间比宿主晚 8 小时

## 安全注意事项

- **授权范围**：仅扫描有明确授权的目标，遵守当地法律法规
- **命令注入面**：模块 transform 必须 `shlex.quote()` 转义用户输入；沙箱 import 白名单受限
- **凭据**：容器每次启动随机化 redis/web 密码；config.yaml 含 API key 时注意文件权限与镜像构建上下文（`.dockerignore` 已排除）
- **ksubdomain**：无状态发包需要 `NET_RAW` 能力（compose 已配置）；nmap -O 需 root（容器默认 root）
- **C2 / WebShell**：高危操作在面板内有二次确认，Agent 调用受审批模式管控并全量审计

## 免责声明

本工具仅供授权的安全评估、渗透测试与防御研究使用。使用者须确保拥有目标系统的合法授权，并自行承担扫描产生的网络流量、系统负载与法律后果。作者不对任何未经授权的使用或滥用承担责任。
