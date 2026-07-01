# FlowScan3

基于 Redis 的事件驱动安全扫描编排框架。将 18 种安全工具抽象为事件消费者/生产者，自动形成从子域名枚举到漏洞利用的完整扫描链路。

## 核心功能

- **事件驱动架构**：所有工具通过 Redis 交换事件（DOMAIN → SUBDOMAIN → IP → PORT_OPEN → LIVE_URL → VULNERABILITY），自动串联
- **18 个扫描模块**：子域名枚举、端口扫描、服务识别、HTTP 探活、目录爆破、爬虫、WAF 检测、指纹识别、漏洞扫描、403 绕过、参数发现、密钥提取、TLS 证书扫描、弱口令/未授权检测、OS 识别、FOFA 资产查询
- **多节点并行**：多个 Worker 节点可同时运行，通过 Redis Lua 原子锁协调任务分配，互不冲突
- **Web 控制面板**：事件查看/注入/删除、状态快照导出/恢复、工具流程可视化、Redis 命令执行器、AI 分析、模板测试沙箱
- **AI 分析**：对接 OpenAI 兼容 API，对扫描结果进行智能分析和下一步建议
- **Debug 模式**：`--debug` 标志记录所有工具命令和完整输出到 Redis 日志

## 事件类型（23 种）

| 事件 | 生产者 | 消费者 |
|------|--------|--------|
| `DOMAIN` | manual, fofa | subfinder, dnsx_brute, fofa |
| `SUBDOMAIN` | subfinder, httpx, tlsx, nmap, dnsx_brute | dnsx_resolve, fofa, tlsx |
| `IP` | dnsx_resolve, httpx, fofa | rustscan, fofa |
| `PORT_OPEN` | rustscan | httpx, nmap, fscan |
| `LIVE_URL` | httpx, feroxbuster, nmap, fscan | feroxbuster, katana, nuclei, observer_ward, wafw00f, arjun, tlsx, secretfinder, jsfinder |
| `URL` | feroxbuster, katana, arjun, bypass403, jsfinder | httpx, fofa, secretfinder |
| `JS_URL` | feroxbuster, katana, jsfinder | secretfinder, jsfinder |
| `403_URL` | httpx, feroxbuster | bypass403 |
| `URL_INFO` | httpx, feroxbuster, katana, observer_ward, wafw00f, tlsx, arjun | (日志/Web UI 展示) |
| `VULNERABILITY` | nuclei, fscan, nmap, secretfinder | (日志/Web UI 展示) |
| `SERVICE` | nmap, fscan | (日志/Web UI 展示) |
| `TECH` | nmap, fscan | (日志/Web UI 展示) |
| `TITLE` | nmap | (日志/Web UI 展示) |
| `OS` | nmap | (日志/Web UI 展示) |
| `HOSTNAME` | nmap | (日志/Web UI 展示) |
| `FINGERPRINT` | nmap, observer_ward, tlsx | (日志/Web UI 展示) |
| `CERT_INFO` | nmap, tlsx | (日志/Web UI 展示) |
| `WAF` | wafw00f | (日志/Web UI 展示) |
| `DOMAIN` | httpx, nmap, fofa | subfinder, dnsx_brute, fofa |
| `CNAME` | dnsx_resolve | (日志/Web UI 展示) |

## 扫描链路

```
DOMAIN → subfinder/dnsx_brute → SUBDOMAIN → dnsx_resolve → IP
IP → rustscan → PORT_OPEN (127.0.0.1:[22,80,443])
PORT_OPEN → httpx → LIVE_URL + 403_URL + URL_INFO
PORT_OPEN → nmap → SERVICE/OS/CERT/VULN/FINGERPRINT...
PORT_OPEN → fscan → SERVICE/VULN/TECH
LIVE_URL → feroxbuster/katana/jsfinder → URL/JS_URL/403_URL
LIVE_URL → nuclei/afrog → VULNERABILITY
LIVE_URL → observer_ward → FINGERPRINT
LIVE_URL → wafw00f → WAF
403_URL  → bypass403 → URL/LIVE_URL
JS_URL   → secretfinder → VULNERABILITY
SUBDOMAIN → tlsx → CERT_INFO/SUBDOMAIN/FINGERPRINT
LIVE_URL → arjun → URL (with discovered params)
```

## 部署

### 依赖
- Python 3.10+
- Redis
- Go (用于编译 ProjectDiscovery 工具)

### 一键安装

```bash
cd FlowScan3
bash setup.sh
```

setup.sh 自动完成：
1. 安装系统依赖（git, python3, golang, redis-server）
2. 配置 Redis 密码（从 config.yaml 读取）
3. 安装 Python 依赖（PyYAML, redis）
4. 执行 `python3 main.py init` 安装所有扫描工具

### 配置文件

`config.yaml`:
```yaml
redis:
  host: 127.0.0.1
  port: 6379
  password: "your-password"
  db: 0

web_config:
  host: 0.0.0.0
  port: 8080
  username: admin
  password: admin
  session_ttl: 3600
  secret_key: change-me-in-production

worker:
  idle_sleep_seconds: 1.0
  scan_batch_size: 200
  max_local_pending: 40

fofa:
  api_key: YOUR_FOFA_API_KEY
  base_url: https://fofa.info
  query_policies: ...

ai_analysis:
  base_url: https://api.openai.com/v1
  api_key: YOUR_API_KEY
  model: gpt-4o-mini
```

## 使用

### 启动 Worker

```bash
# 普通模式
python3 main.py worker --pool-size 20

# Debug 模式（记录完整命令输出到日志）
python3 main.py worker --pool-size 20 --debug

# 指定节点标识
python3 main.py worker --node-id my-node-1
```

### 注入事件

```bash
# 注入域名开始扫描
python3 main.py inject --event-type DOMAIN --value example.com

# 注入 IP
python3 main.py inject --event-type IP --value 1.2.3.4

# 批量注入（通过 Web UI）
# 访问 http://127.0.0.1:8080 → 事件管理 → 批量添加事件
```

### Web 控制面板

```bash
python3 main.py web --port 8080
```

功能页面：
- **仪表盘**：Redis 状态、事件/节点/工具数量、队列统计
- **事件查询**：按类型/值/路径查询事件，查看事件树
- **事件管理**：批量注入/删除/清空，JSON 全量导出/恢复
- **AI 分析**：选择事件类型，向 LLM 提问分析扫描结果
- **执行流程**：vis.js 可视化工具间事件流向
- **模板测试**：在线编辑 YAML 模块，实时测试 transform/check/install/scan/parse
- **执行日志**：查看/下载 Redis 日志
- **Redis 命令**：直接执行 Redis 命令，含持久化/恢复命令参考

### 查看状态

```bash
python3 main.py status
```

## 安全注意事项

### 代码执行风险
YAML 模块中的 `input_transform_code` 和 `output_parse_code` 通过 Python `exec()` 执行。虽然代码在受限沙箱中运行（白名单 builtins），但 `__import__` 是允许的——这意味着模块代码可以导入任意 Python 模块（如 `os`、`subprocess`）。**任何能编写 YAML 模块的人都能在 Worker 节点上执行任意系统命令。**

### 命令注入风险
模块的 `command_template` 通过 `{{variable}}` 占位符渲染。如果 transform 代码没有使用 `shlex.quote()` 对变量进行 shell 转义，存在命令注入风险。

### Web 面板安全
- 默认用户名密码 `admin/admin`，务必修改
- Flask session 使用 `secret_key`，务必改为随机字符串
- Flask 开发服务器无 HTTPS，生产环境应使用 Nginx 反向代理 + TLS
- 无速率限制，暴力破解风险

### Redis 安全
- 密码明文存储在 `config.yaml` 中
- 如果 Redis bgsave 失败（磁盘满/权限问题），所有写操作被阻塞，扫描完全停止
- 修复：`redis-cli CONFIG SET stop-writes-on-bgsave-error no`

### 网络扫描合规
FlowScan3 执行主动网络扫描（端口扫描、目录爆破、漏洞探测）。在对非授权目标使用时可能违反法律法规。**仅扫描你有明确授权的目标。**

### 事件删除的竞态条件
通过 Web UI 删除事件时，正在执行中的任务不会被中止，可能产生孤儿子事件。删除操作会写入 `fs3:cancelled` 标记（24h TTL），后续子事件入队时会检查该标记。

### 模块来源
`modules/` 目录下的 YAML 文件包含可执行代码。仅加载来自可信来源的模块。

## 目录结构

```
FlowScan3/
├── main.py              # 入口（worker/web/inject/init/status）
├── config.yaml           # 主配置
├── setup.sh              # 一键部署脚本
├── requirements.txt      # Python 依赖
├── modules/              # 工具 YAML 定义（18个）
├── flowscan3/            # 核心引擎
│   ├── worker.py         # Worker 主循环
│   ├── pipeline.py       # 事件处理管线
│   ├── redis_store.py    # Redis 操作封装（含 Lua 原子锁）
│   ├── tool_module.py    # 工具模块加载
│   ├── code_runner.py    # 沙箱执行器
│   ├── config.py         # 配置/模板渲染
│   ├── installer.py      # 工具安装
│   └── utils.py          # 工具函数
├── web_app/              # Web 控制面板
│   ├── __init__.py       # Flask 应用 + 路由
│   ├── templates/        # Jinja2 模板
│   └── static/           # CSS/JS
├── prompts/              # AI prompt 模板
├── state_snapshots/      # 状态导出 JSON
└── wordlists/            # 字典文件
```

## 扩展模块

创建新模块只需添加一个 YAML 文件：

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
  - LIVE_URL
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
