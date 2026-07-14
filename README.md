# FlowScan3

基于 Redis 的事件驱动安全扫描编排框架。通过 YAML 模块化配置串联多个安全工具，自动形成从资产发现到漏洞利用的完整扫描链路。

## 核心功能

- **事件驱动架构**：所有工具通过 Redis 交换事件，自动串联扫描链
- **10 个扫描模块**：资产输入解析、FOFA 搜索引擎、DNS 解析、RustScan 全端口扫描、Fscan 服务/漏洞探测、httpx HTTP 探活、Katana 爬虫、BBOT kitchen-sink 全量扫描、BBOT nuclear-meltdown 深度 Web 漏洞利用、Xray 被动代理
- **黑名单过滤**：文件默认规则（`black_list.cfg`）+ Redis 动态规则双重体系。支持 4 种匹配模式：后缀(suffix)、前缀(prefix)、正则包含(contains)、IP 范围(ip_range)。匹配忽略大小写，任一命中即在入队阶段拦截
- **多节点并行**：多个 Worker 节点通过 Redis Lua 原子锁协调任务分配
- **Web 控制面板**：事件查看/注入/删除/清空、事件图谱、执行流图可视化、黑名单管理、AI 分析（含黑名单自动化 + 定时调度）、YAML 模板实验室、Redis 命令执行器
- **状态快照**：全量 Redis 状态导出/恢复 JSON

## 事件类型

### 资产发现

| 事件类型 | 格式 | 示例 |
|---------|------|------|
| `INPUT` | 任意文本（JSON/URL/域名混合） | `{"url":"https://..."}` |
| `DNS_NAME` | 域名（含子域名） | `api.example.com` |
| `DNS_NAME_UNRESOLVED` | 无法解析的域名 | `nx.example.com` |
| `IP_ADDRESS` | IPv4 地址 | `104.20.23.154` |
| `IP_RANGE` | CIDR 网段 | `10.0.0.0/24` |
| `URL` | 完整 URL | `https://example.com/admin` |
| `URL_UNVERIFIED` | 未验证存活的 URL | `https://example.com` |
| `ICON_PATH` | favicon 图标 URL | `https://example.com/favicon.ico` |

### 端口与服务

| 事件类型 | 格式 | 示例 |
|---------|------|------|
| `OPEN_TCP_PORT` | `ip:port` | `1.2.3.4:443` |
| `OPEN_UDP_PORT` | `ip:port` | `1.2.3.4:53` |
| `HOST_TCP_PORT_OPEN` | `ip -> [port1,...]` | `1.2.3.4 -> [22,80,443]` |

### 指纹与技术

| 事件类型 | 格式 |
|---------|------|
| `TECHNOLOGY` | `host:port\|名称/版本\|原始JSON` |
| `ICON_PATH` | favicon 图标 URL |
| `WAF` | WAF 名称 @ URL |
| `HTTP_RESPONSE` | HTTP 响应数据 |
| `WEBSCREENSHOT` | 网页截图 |

### 漏洞与风险

| 事件类型 | 格式 |
|---------|------|
| `VULNERABILITY` | 原始 JSON（nuclei/fscan/xray/BBOT 格式各异） |
| `FINDING` | BBOT 综合分析发现 |
| `PASSWORD` / `HASHED_PASSWORD` | 明文/哈希密码 |

### 其他

`ASN`, `AZURE_TENANT`, `CODE_REPOSITORY`, `EMAIL_ADDRESS`, `FILESYSTEM`, `GEOLOCATION`, `MOBILE_APP`, `ORG_STUB`, `PROTOCOL`, `RAW_DNS_RECORD`, `SOCIAL`, `STORAGE_BUCKET`, `URL_HINT`, `USERNAME`, `VHOST`, `WEB_PARAMETER`

## 扫描模块

| 模块 | 输入 | 输出 | 工具 |
|------|------|------|------|
| `input_module` | INPUT | DNS_NAME, URL_UNVERIFIED, ICON_PATH, IP_ADDRESS, IP_RANGE | `./bin/input.py` |
| `fofa_module` | DNS_NAME, URL, URL_UNVERIFIED, IP_RANGE, ICON_PATH, IP_ADDRESS | DNS_NAME, IP_ADDRESS, URL_UNVERIFIED | `./bin/fofa.py` |
| `dns_name_resolve_module` | DNS_NAME | IP_ADDRESS | dnsx + cdncheck |
| `rustscan_module` | IP_ADDRESS | HOST_TCP_PORT_OPEN | rustscan (1-65535 SYN) |
| `fscan_module` | HOST_TCP_PORT_OPEN | URL, VULNERABILITY, TECHNOLOGY, OPEN_TCP_PORT | fscan |
| `httpx_module` | URL, URL_UNVERIFIED, OPEN_TCP_PORT | DNS_NAME, URL, ICON_PATH | httpx + `./bin/httpx.py` |
| `katana_module` | URL | URL | katana (via xray proxy) |
| `bbot_kitchen_sink_module` | DNS_NAME | 29 种 BBOT 事件 | bbot -p kitchen-sink |
| `bbot_nuclear_meltdown_preset_module` | URL | 29 种 BBOT 事件 | bbot -p nuclei-intense dirbust-heavy lightfuzz-superheavy web-thorough |
| `xray_passive_module` | INPUT (手动触发) | VULNERABILITY | xray webscan 被动代理 |

## 扫描链路

```
INPUT → input_module → DNS_NAME / URL / IP_ADDRESS / IP_RANGE / ICON_PATH

DNS_NAME → ip_resolve → IP_ADDRESS (过滤 CDN)
DNS_NAME → bbot_kitchen_sink → {29种BBOT事件}
DNS_NAME → fofa → DNS_NAME / IP_ADDRESS / URL

IP_ADDRESS → rustscan → HOST_TCP_PORT_OPEN → fscan → URL / VULNERABILITY / TECHNOLOGY / OPEN_TCP_PORT
IP_ADDRESS → fofa → DNS_NAME / IP_ADDRESS / URL

URL → httpx → DNS_NAME / URL / ICON_PATH
URL → bbot_nuclear_meltdown → {29种BBOT事件}
URL → katana → (xray 被动代理)
URL → fofa → ...

HOST_TCP_PORT_OPEN → fscan → URL/VULNERABILITY/TECHNOLOGY
OPEN_TCP_PORT → httpx → DNS_NAME/URL/ICON_PATH
```

## 黑名单系统

### 文件默认规则（`black_list.cfg`）

系统默认黑名单，手动编辑文件后通过 Web 面板"重载文件规则"或调用 `reload_file_rules()` 生效。

```
# 格式: 事件类型:匹配模式:匹配值
# * 表示匹配所有事件类型
# 匹配模式: contains(正则) | suffix | prefix | ip_range
# 匹配忽略大小写

DNS_NAME:suffix:cloudflare.com
DNS_NAME:contains:awsdns-
IP_ADDRESS:ip_range:104.16.0.0/12
*:suffix:qq.com
```

### Redis 动态规则

通过 Web 面板（事件管理 → 黑名单管理 tab）动态增删，立即生效。适合临时封禁或运行时补充。

### 检查流程

事件入队 `push_event()` 时依次检查：
1. 文件规则（内存缓存）→ 命中则丢弃
2. Redis 规则（实时查询）→ 命中则丢弃
3. 均未命中 → 正常入队

## 部署

### 依赖
- Python 3.10+
- Redis
- Go（编译 ProjectDiscovery 工具）
- BBOT v2.8.6

### 一键安装

```bash
cd FlowScan3
bash setup.sh
```

setup.sh 自动完成：系统依赖 → Redis 配置 → Python 依赖 → 扫描工具安装。

### 配置文件

`config.yaml` 关键配置项：

```yaml
redis:
  listen_host: 0.0.0.0    # Redis 监听地址
  remote_host: 127.0.0.1  # Worker 连接 Redis 地址
  port: 6379
  password: ""

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
  securitytrails_api_key: YOUR_KEY      # SecurityTrails API
  virustotal_api_key: YOUR_KEY          # VirusTotal API
  github_workflows_api_key: YOUR_KEY    # GitHub API

xray_listen_http_proxy: 0.0.0.0:7777    # Xray 代理监听
xray_remote_http_proxy: http://127.0.0.1:7777  # Xray 代理地址（katana 用）

ai_analysis:
  base_url: https://api.openai.com/v1   # 或 DeepSeek: https://api.deepseek.com/v1
  api_key: YOUR_API_KEY
  model: gpt-4o-mini
  timeout_seconds: 120
  max_events: 5000                      # 单次分析最多发送的事件数（上限 5000）
  log_api_key: YOUR_LOG_API_KEY         # AI 日志 API 访问密钥
  loop_interval_minutes: 0              # 全局默认定时间隔（0=不开启）
```

`black_list.cfg` 文件默认规则示例：
```
# === Cloudflare ===
DNS_NAME:suffix:cloudflare.com
DNS_NAME:suffix:cloudflare.net
IP_ADDRESS:ip_range:104.16.0.0/12

# === 关键词特征 ===
*:contains:awsdns-
```

## 使用

### 启动 Worker

```bash
python3 main.py worker --pool-size 20
python3 main.py worker --pool-size 20 --debug    # debug 模式
```

### 注入事件

```bash
# CLI
python3 main.py inject --event-type DNS_NAME --value example.com

# Web UI（推荐）: http://127.0.0.1:8080 → 事件管理 → 批量添加
# 不写 [类型] 前缀默认识别为 INPUT → 由 input_module 自动分类
```

### Web 控制面板

```bash
python3 main.py web --port 8080
```

功能页面：
- **仪表盘**：Redis 状态、事件/节点/工具数量、队列统计
- **事件管理**：批量注入/删除/清空/搜索，JSON 状态导出/恢复。**黑名单管理 tab**：查看文件默认规则（只读），增删 Redis 动态规则（立即生效），实时测试匹配
- **事件图谱**：可视化事件树，点击展开子事件，搜索链路追溯
- **AI 分析**：选事件类型 → LLM 分析 → 自动执行 5 种动作（add/del/blacklist_add/blacklist_del/log），支持定时调度。上下文自动附带最近 AI 日志以避免重复
- **执行流程**：vis.js 可视化工具间事件流向，节点可无限次拖动
- **模板实验室**：YAML 在线编辑 → validate/check/install/transform/scan/parse 六步测试
- **Redis 命令**：直接执行 Redis 命令
- **Xray 代理**：`bash start_xray.sh` 启动被动代理，katana 通过代理爬取

### 查看状态

```bash
python3 main.py status
```

## AI 分析动作类型

AI 可在回答末尾输出 JSON 动作块，系统自动解析并执行。执行顺序固定为：删除事件 → 删除黑名单 → 增加黑名单 → 增加事件 → 存储日志。

| 动作 | 说明 | 约束 |
|------|------|------|
| `add` | 注入新事件到扫描队列 | — |
| `del` | 移除无效/误报事件 | — |
| `blacklist_add` | 添加 Redis 动态黑名单规则 | 仅在用户明确要求或 ≥5 条独立证据时使用 |
| `blacklist_del` | 删除 Redis 动态黑名单规则 | 仅用户明确要求或确认规则已不再适用 |
| `log` | 记录分析日志 | 最近日志已在上下文中，如无必要不重复 |

6 个 toggle 开关可在页面独立控制每种动作的执行权限。

## 目录结构

```
FlowScan3/
├── main.py                  # 入口（worker/web/inject/init/status）
├── config.yaml              # 主配置
├── black_list.cfg           # 文件默认黑名单（event_type:match_mode:value 格式）
├── start_xray.sh            # Xray 被动代理启动脚本
├── setup.sh                 # 一键部署
├── requirements.txt         # Python 依赖
├── modules/                 # 工具 YAML 定义（10个）
├── flowscan3/               # 核心引擎
│   ├── worker.py            # Worker 主循环 + ThreadPoolExecutor
│   ├── pipeline.py          # transform → render → exec → parse → publish
│   ├── redis_store.py       # Redis 操作（含 Lua 原子锁 + 黑名单拦截）
│   ├── tool_module.py       # YAML → ToolModule 加载
│   ├── code_runner.py       # 沙箱 exec() 执行器
│   ├── config.py            # YAML 读取 + 模板渲染
│   ├── installer.py         # 工具初始化和安装
│   ├── utils.py             # shell 命令执行
│   └── filter.py            # 黑名单引擎（文件规则 + Redis 规则，4 种匹配模式）
├── bin/                     # 配套脚本
│   ├── input.py             # 资产提取器（INPUT→事件）
│   ├── fofa.py              # FOFA 查询客户端
│   ├── httpx.py             # httpx JSONL 清洗+资产抽取
│   └── xray/                # Xray 配置和 CA 证书
├── web_app/                 # Web 控制面板
│   ├── __init__.py          # Flask 应用 + 路由（含黑名单/ AI 动作 API）
│   ├── templates/           # Jinja2 模板（14个页面）
│   └── static/              # CSS/JS
├── tools/                   # 工具脚本
│   ├── randomize_secrets.py # 随机化 config.yaml 密钥
│   ├── migrate_blacklist.py # 黑名单格式迁移脚本（旧→新）
│   ├── ufw_setup.py         # UFW 防火墙配置
│   └── swap_setup.py        # 交换空间配置
├── prompts/                 # AI prompt 模板
│   └── ai_analysis.txt      # AI 分析 system prompt（含动作说明和约束）
├── state_snapshots/         # 状态导出 JSON
└── wordlists/               # 字典文件
```

## 安全注意事项

- **代码执行风险**：YAML 模块中的 `input_transform_code` 和 `output_parse_code` 通过 Python `exec()` 在受限沙箱中执行。虽然 builtins 是白名单，但 `__import__` 可用——模块作者可执行任意系统命令，仅加载可信来源的模块
- **命令注入**：transform 代码必须使用 `shlex.quote()` 对变量做 shell 转义
- **Web 面板**：修改默认用户名密码和 secret_key，生产环境使用 Nginx 反向代理 + TLS
- **Redis 密码**：密码明文在 config.yaml 中。若 `bgsave` 失败磁盘满，所有写操作阻塞——执行 `redis-cli CONFIG SET stop-writes-on-bgsave-error no`
- **AI 黑名单自动化**：`blacklist_add`/`blacklist_del` 开关默认开启。AI 仅在用户明确要求或 ≥5 条独立证据时才会添加黑名单规则；删除仅限于 Redis 动态规则，不影响文件规则
- **网络扫描合规**：仅扫描有明确授权的目标

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

## 故障排查

### Worker 计数器死锁
Worker 崩溃（OOM/SIGKILL）后 `fs3:running:*` 计数器可能永久卡死：
```bash
redis-cli KEYS "fs3:running:*"  # 查看
redis-cli DEL "fs3:running:<node>:<tool>"  # 手动恢复
```

### Redis bgsave 阻塞
```bash
redis-cli CONFIG SET stop-writes-on-bgsave-error no
```

### 黑名单规则不生效
1. 确认事件值格式与规则匹配模式一致
2. 日志中搜索 `[BLACKLIST-FILE]` 或 `[BLACKLIST-REDIS]` 查看拦截记录
3. 使用 Web 面板"实时测试"功能验证规则是否命中
4. 文件规则修改后需要点击"重载文件规则"或重启 Worker

---

## 免责声明

本工具仅供授权的安全评估和防御研究使用。使用者应确保：

- 仅扫描**拥有合法授权**的目标系统
- 遵守目标所在国家/地区的法律法规
- 扫描过程中产生的网络流量和系统负载由使用者自行负责

作者不对任何未经授权的使用、滥用或由此产生的法律后果承担责任。使用本工具即表示您已阅读并同意上述条款。
