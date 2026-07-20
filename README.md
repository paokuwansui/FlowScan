# FlowScan3

基于 Redis 的事件驱动安全扫描编排框架。通过 YAML 模块化配置串联多个安全工具，自动形成从资产发现到漏洞利用的完整扫描链路。

## 核心功能

- **事件驱动架构**：所有工具通过 Redis 交换事件，自动串联扫描链
- **10 个扫描模块**：资产输入解析、FOFA 搜索引擎、DNS 解析、RustScan 全端口扫描、Fscan 服务/漏洞探测、httpx HTTP 探活、Katana 爬虫、BBOT 全量扫描、Nmap 深度扫描、Xray 被动代理
- **黑名单过滤**：文件默认规则（`black_list.cfg`）+ Redis 动态规则双重体系。4 种匹配模式：后缀/前缀/正则/IP 范围。忽略大小写，任一命中即在入队阶段拦截
- **多节点并行**：多个 Worker 节点通过 Redis Lua 原子锁协调任务分配
- **Web 控制面板**：仪表盘、事件管理/注入/删除/搜索、事件图谱、执行流图、黑名单管理、AI 分析（含黑名单自动化 + 定时调度）、模板实验室、事件日记（AI 日志 + 扫描事件总览 + API 示例）、Redis 命令执行器
- **状态快照**：全量 Redis 状态导出/恢复 JSON

## 事件类型

### 资产发现

| 类型 | 格式 | 示例 |
|------|------|------|
| `INPUT` | 任意文本（JSON/URL/域名混合） | `{"url":"https://..."}` |
| `DNS_NAME` | 域名（含子域名） | `api.example.com` |
| `IP_ADDRESS` | IPv4 地址 | `104.20.23.154` |
| `IP_RANGE` | CIDR 网段 | `10.0.0.0/24` |
| `URL` | 完整 URL | `https://example.com/admin` |
| `URL_UNVERIFIED` | 未验证存活的 URL | `https://example.com` |
| `ICON_PATH` | favicon 图标 URL | `https://example.com/favicon.ico` |

### 端口与服务

| 类型 | 格式 | 示例 |
|------|------|------|
| `HOST_TCP_PORT_OPEN` | `ip -> [port1,...]` | `1.2.3.4 -> [22,80,443]` |
| `OPEN_TCP_PORT` | `ip:port` | `1.2.3.4:443` |

### 指纹与漏洞

| 类型 | 格式 |
|------|------|
| `TECHNOLOGY` | `host:port\|名称/版本\|原始JSON` |
| `FINDING` | 分析发现（nmap/BBOT 综合指纹漏洞输出） |
| `WAF` | WAF 名称 @ URL |
| `WEBSCREENSHOT` | 网页截图 |

## 扫描模块

| 模块 | 输入 | 输出 | 工具 |
|------|------|------|------|
| `input_module` | INPUT | DNS_NAME, URL_UNVERIFIED, ICON_PATH, IP_ADDRESS, IP_RANGE | `./bin/input.py` |
| `fofa_module` | DNS_NAME, URL, URL_UNVERIFIED, IP_RANGE, ICON_PATH, IP_ADDRESS | DNS_NAME, IP_ADDRESS, URL_UNVERIFIED | `./bin/fofa.py` |
| `dns_name_resolve_module` | DNS_NAME | IP_ADDRESS | dnsx + cdncheck |
| `rustscan_module` | IP_ADDRESS, IP_RANGE | HOST_TCP_PORT_OPEN | rustscan (1-65535 SYN) |
| `fscan_module` | HOST_TCP_PORT_OPEN | URL, VULNERABILITY, TECHNOLOGY, OPEN_TCP_PORT, FINDING | fscan |
| `nmap_module` | HOST_TCP_PORT_OPEN | FINDING | nmap -sV -O -A --script=vuln |
| `httpx_module` | URL, URL_UNVERIFIED, OPEN_TCP_PORT | DNS_NAME, URL, ICON_PATH | httpx + `./bin/httpx.py` |
| `katana_module` | FINDING | URL | katana + `./bin/katana.py`（智能过滤静态资源/噪音参数） |
| `bbot_module` | DNS_NAME（仅主域名） | 30+ 种事件（子域名/端口/HTTP/漏洞全链） | bbot + `./bin/is_root_domain.py` |

### BBOT 扫描预设

BBOT 模块仅对**主域名**（非子域名）触发，通过 `is_root_domain.py` 前置检查。使用预设组合：

```
subdomain-enum cloud-enum code-enum email-enum spider web
paramminer waf-bypass wayback nuclei-budget tech-detect
virtualhost-heavy webbrute-heavy lightfuzz-heavy portscan
```

涵盖子域名枚举、云资源发现、代码仓库、邮箱、爬虫、参数挖掘、WAF 绕过、历史 URL、nuclei 漏洞扫描、技术指纹、虚拟主机爆破、目录爆破、端口扫描。

## 扫描链路

```
INPUT → input_module → DNS_NAME / URL / IP_ADDRESS / IP_RANGE / ICON_PATH

DNS_NAME → ip_resolve → IP_ADDRESS (过滤 CDN)
DNS_NAME → bbot_module（仅主域名）→ 30+ 种事件
DNS_NAME → fofa → DNS_NAME / IP_ADDRESS / URL

IP_ADDRESS → rustscan → HOST_TCP_PORT_OPEN
  ├──→ fscan → URL / VULNERABILITY / TECHNOLOGY / OPEN_TCP_PORT / FINDING
  └──→ nmap → FINDING

URL → httpx → DNS_NAME / URL / ICON_PATH
FINDING → katana → URL（智能过滤后）

HOST_TCP_PORT_OPEN 同时触发 fscan 和 nmap，互补扫描
```

### 工具链职责分工

- **rustscan**：全端口快速发现 → `HOST_TCP_PORT_OPEN`
- **fscan**：服务识别 + 弱口令/未授权漏洞 → `VULNERABILITY` / `TECHNOLOGY` / `FINDING`
- **nmap**：深度版本识别 + OS 检测 + vuln 脚本 → `FINDING`（带 CVE 编号）
- **katana**：消费 `FINDING` 中发现的 URL 进行爬取，智能过滤静态资源和噪音参数

## 黑名单系统

### 文件默认规则（`black_list.cfg`）

系统默认黑名单，格式：`事件类型:匹配模式:匹配值`。

```
# 后缀匹配
DNS_NAME:suffix:cloudflare.com

# 正则包含
*:contains:awsdns-

# IP 范围
IP_ADDRESS:ip_range:104.16.0.0/12
```

四种匹配模式：`suffix`（后缀）、`prefix`（前缀）、`contains`（正则）、`ip_range`（IP 范围）。忽略大小写。

### Redis 动态规则

通过 Web 面板（事件管理 → 黑名单管理 tab）动态增删，立即生效。支持实时测试预览。AI 分析也可通过 `blacklist_add`/`blacklist_del` 动作自动管理。

### 检查流程

事件入队 `push_event()` 时依次检查：文件规则 → Redis 规则 → 任一命中即丢弃。

## 部署

### 依赖
- Python 3.10+
- Redis
- Go（编译 ProjectDiscovery 工具）
- BBOT（Python venv）

### 一键安装

```bash
cd FlowScan3
bash main_node_setup.sh    # 主节点（安装 Redis + 配置）
bash worker_node_setup.sh  # Worker 节点（安装工具 + 清 Go 缓存）
```

### 配置文件

`config.yaml` 关键配置项：

```yaml
redis:
  listen_host: 0.0.0.0    # Redis 监听地址
  remote_host: 127.0.0.1  # Worker 连接地址（Web 面板也读此字段）
  port: 6379

web_config:
  host: 0.0.0.0
  port: 8080

worker:
  idle_sleep_seconds: 1.0
  scan_batch_size: 200
  max_local_pending: 40

fofa:
  api_key: YOUR_FOFA_API_KEY

bbot:
  securitytrails_api_key: YOUR_KEY
  virustotal_api_key: YOUR_KEY
  github_workflows_api_key: YOUR_KEY

xray_listen_http_proxy: 0.0.0.0:7777
xray_remote_http_proxy: http://127.0.0.1:7777

ai_analysis:
  base_url: https://api.openai.com/v1
  api_key: YOUR_API_KEY
  model: gpt-4o-mini
  max_events: 5000            # 单次分析上限
  log_api_key: YOUR_LOG_KEY   # 事件日记 API 访问密钥
```

## 使用

### 启动 Worker

```bash
# 先初始化工具（不需要 Redis）
python3 main.py init

# 启动 Worker
python3 main.py worker --pool-size 20
```

### 注入事件

```bash
python3 main.py inject --event-type DNS_NAME --value example.com
# Web UI: http://127.0.0.1:8080 → 事件管理 → 批量添加
```

### Web 控制面板

```bash
python3 main.py web --port 8080
```

功能页面：
- **仪表盘**：Redis 状态、事件/节点/工具数量、队列统计
- **事件管理**：批量注入/删除/清空/搜索、JSON 状态导出/恢复。**黑名单管理 tab**：文件规则只读、Redis 规则 CRUD、实时测试
- **事件图谱**：可视化事件树，点击展开，搜索链路
- **AI 分析**：LLM 分析 + 自动执行 5 种动作（add/del/blacklist_add/blacklist_del/log），6 个 toggle 开关，定时调度
- **事件日记**：3 tab（AI 分析日志 / 扫描事件总览 / API 调用示例）。API 示例支持一键复制全部用法给 Agent
- **执行流程**：vis.js 可视化工具间事件流向
- **模板实验室**：YAML 在线编辑 → 六步测试

### 查看状态

```bash
python3 main.py status
```

### 启动 Xray 被动代理

```bash
bash start_xray.sh
```

## AI 分析动作类型

执行顺序固定：删除事件 → 删除黑名单 → 增加黑名单 → 增加事件 → 存储日志。

| 动作 | 说明 | 约束 |
|------|------|------|
| `add` | 注入新事件到扫描队列 | - |
| `del` | 移除无效/误报事件 | - |
| `blacklist_add` | 添加 Redis 动态黑名单 | 用户明确要求或 ≥5 条独立证据 |
| `blacklist_del` | 删除 Redis 动态黑名单 | 用户明确要求或确认规则不再适用 |
| `log` | 记录分析日志 | 上下文含最近日志，如无必要不重复 |

## 事件日记 API

可通过 HTTP API 访问事件数据，支持 API Key 认证（配置 `ai_analysis.log_api_key`）。

| 接口 | 说明 |
|------|------|
| `GET /event-logs?api_key=KEY` | 获取 AI 分析日志 |
| `GET /event-logs?api_key=KEY&mode=stats` | 获取事件类型统计 |
| `GET /event-logs?api_key=KEY&mode=events` | 获取全部事件 |
| `GET /event-logs?api_key=KEY&mode=events&type=DNS_NAME` | 按类型筛选 |
| `GET /event-logs?api_key=KEY&mode=events&search=xxx` | 搜索事件值 |
| `GET /event-logs?api_key=KEY&mode=events&fp=xxx` | 查单个事件详情 |

旧路由 `/ai-logs` 已 302 重定向到 `/event-logs`。

## 目录结构

```
FlowScan3/
├── main.py                  # 入口（init/worker/inject/status/web）
├── config.yaml              # 主配置
├── black_list.cfg           # 文件默认黑名单
├── start_xray.sh            # Xray 被动代理启动
├── main_node_setup.sh       # 主节点一键部署
├── worker_node_setup.sh     # Worker 节点部署 + Go 缓存清理
├── modules/                 # 工具 YAML 定义（10 个）
├── flowscan3/               # 核心引擎
│   ├── worker.py            # Worker 主循环 + ThreadPoolExecutor
│   ├── pipeline.py          # transform → exec → parse → publish
│   ├── redis_store.py       # Redis 操作（Lua 原子锁 + 黑名单拦截）
│   ├── tool_module.py       # YAML → ToolModule 加载
│   ├── code_runner.py       # 沙箱 exec() 执行器
│   ├── config.py            # YAML 读取 + 模板渲染
│   ├── installer.py         # 工具初始化（无需 Redis）
│   ├── utils.py             # shell 命令执行
│   └── filter.py            # 黑名单引擎（文件规则 + Redis 规则，4 种匹配模式）
├── bin/                     # 配套脚本
│   ├── input.py             # INPUT → 事件提取
│   ├── fofa.py              # FOFA 查询客户端
│   ├── httpx.py             # httpx JSONL 清洗（http+400 自动丢弃）
│   ├── katana.py            # 智能 URL 过滤（静态资源/噪音参数/去重）
│   ├── is_root_domain.py    # 判断域名是否为主域名
│   └── xray/                # Xray 配置和 CA 证书
├── web_app/                 # Web 控制面板
│   ├── __init__.py          # Flask 应用（全部路由）
│   ├── templates/           # Jinja2 模板
│   └── static/              # CSS/JS
├── tools/                   # 工具脚本
│   ├── randomize_secrets.py # 随机化 config.yaml 密钥
│   └── migrate_blacklist.py # 黑名单格式迁移（旧→新，已执行）
├── prompts/                 # AI prompt 模板
├── state_snapshots/         # 状态导出 JSON
└── wordlists/               # 字典文件
```

## 扩展模块

创建新模块只需添加一个 YAML 文件到 `modules/`：

```yaml
name: my_tool_module
description: 工具描述
check:
  command: mytool --version
  expect_keyword: mytool
install:
  steps:
  - go install github.com/xxx/mytool@latest
  install_timeout_seconds: 600
runtime:
  max_concurrency: 2
  exec_timeout_seconds: 300
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

## 安全注意事项

- **代码执行风险**：YAML 模块中 `exec()` 在受限沙箱中运行。沙箱不含 `Exception` 类，`except` 必须使用裸 `except:`。仅加载可信来源的模块
- **命令注入**：transform 代码必须使用 `shlex.quote()` 做 shell 转义
- **Web 面板**：修改默认密码和 secret_key，生产环境使用 Nginx 反向代理 + TLS
- **Redis 持久化**：`main_node_setup.sh` 默认写入 `stop-writes-on-bgsave-error no`，防止磁盘满时 Redis 拒绝写入
- **AI 黑名单自动化**：开关默认开启，AI 仅在用户明确要求或 ≥5 条证据时操作
- **网络扫描合规**：仅扫描有明确授权的目标。详见文末免责声明

## 故障排查

### Worker 计数器死锁
```bash
redis-cli KEYS "fs3:running:*"
redis-cli DEL "fs3:running:<node>:<tool>"
```

### Redis bgsave 阻塞
部署时已默认禁用，无需手动操作。如需恢复：
```bash
redis-cli CONFIG SET stop-writes-on-bgsave-error yes
```

### 黑名单规则不生效
1. 日志搜索 `[BLACKLIST-FILE]` 或 `[BLACKLIST-REDIS]` 查看拦截
2. Web 面板 "实时测试" 验证规则命中
3. 文件规则修改后点击 "重载文件规则" 或重启 Worker

---

## 免责声明

本工具仅供授权的安全评估和防御研究使用。使用者应确保：

- 仅扫描**拥有合法授权**的目标系统
- 遵守目标所在国家/地区的法律法规
- 扫描过程中产生的网络流量和系统负载由使用者自行负责

作者不对任何未经授权的使用、滥用或由此产生的法律后果承担责任。使用本工具即表示您已阅读并同意上述条款。
