# FlowScan - 自动化安全扫描编排引擎

## 📖 项目简介

FlowScan 是一个基于事件驱动架构的自动化安全扫描编排引擎，通过 YAML 配置模块实现灵活的漏洞扫描、资产发现和服务识别。支持多目标并发处理、智能事件路由和自动化工作流编排。

### 核心特性

- 🎯 **事件驱动架构**：基于事件总线的模块间通信，解耦各个扫描组件
- 🔄 **智能事件路由**：自动追踪事件流转，无消费者的事件自动落盘避免卡死
- ⚡ **高并发处理**：支持多目标同时扫描，双层信号量控制（全局+模块级）
- 📊 **可视化工作流**：自动打印模块关系图谱，清晰展示事件流转链路
- 🔧 **声明式配置**：YAML 配置解析规则，无需编写代码即可适配新工具
- 💾 **断点续扫**：自动记录已完成目标，重启后从断点继续
- 🐛 **Debug 模式**：完整保存每个模块的输出到日志文件，便于调试

---

## 🚀 快速开始

### 1. 安装依赖

```bash
git clone https://github.com/paokuwansui/FlowScan.git
cd FlowScan && chmod +x setup.sh && sudo ./setup.sh
```

### 2. 准备扫描工具

模块 YAML 已内置自动安装步骤：优先通过 `go install`、`pip install`、`apt install` 或 GitHub Release 在线安装工具。当前项目约定优先把第三方工具安装到 `$HOME/.local/bin`，项目内 Python 适配器保留在 `./bin/` 下并由模块显式调用，避免依赖系统级写入权限。

建议确保 PATH 包含用户本地 bin：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

FOFA/FoFaX 模块如需使用 API Key，可设置环境变量：

```bash
export FOFA_KEY='你的 FOFA API Key'
```

### 3. 创建目标文件

创建 `target.txt` 文件，每行一个目标：

```text
example.com
test.org
[IP]192.168.1.1
[URL]http://target.com
```

### 4. 启动扫描

```bash
# 基本用法（串行处理）
python batch_main.py

# 并发模式（同时处理10个目标）
python batch_main.py --concurrent 10

# Debug 模式（保存模块输出）
python batch_main.py --debug

# 指定 Worker、最大进程数和 seen_events 清理阈值
python batch_main.py -c 5 --workers 25 --max-processes 20 --seen-events-limit 1000000

# 组合使用
python batch_main.py -d -c 5
```

---

## 📋 命令行参数

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--concurrent N` | `-c N` | 最大并发目标数 | 1 |
| `--workers N` | - | 事件消费 Worker 数量 | 25 |
| `--max-processes N` | - | 全局最大并发底层扫描器进程数 | 20 |
| `--seen-events-limit N` | - | `seen_events` 去重集合清理阈值，超过后保留约一半 | 1000000 |
| `--debug` | `-d` | 开启 debug 模式 | false |

### 并发模式推荐配置

| 系统配置 | 推荐并发数 | 命令 |
|----------|-----------|------|
| 低配（2核4G） | 3-5 | `python batch_main.py -c 3` |
| 中配（4核8G） | 5-10 | `python batch_main.py -c 8` |
| 高配（8核16G+） | 10-20 | `python batch_main.py -c 15` |

---

## 📁 项目结构

```
skcn/
├── batch_main.py          # 主入口脚本
├── runner.py              # 核心编排引擎
├── loader.py              # 工具加载器
├── target.txt             # 目标文件（用户创建）
├── stop_event.txt         # 实时终止事件树（用户可编辑）
├── finish_target.txt      # 已完成目标记录（自动生成）
├── modules/               # 扫描模块配置（18 个 YAML 模块）
│   ├── dnsx.yaml / dnsx_resolve.yaml / subfinder.yaml
│   ├── afrog.yaml / fofa.yaml / httpx.yaml / naabu.yaml / nmap_service.yaml
│   ├── fscan.yaml / nuclei.yaml / xray.yaml
│   ├── rad.yaml / katana.yaml / dirsearch.yaml
│   ├── observer_ward.yaml / wafw00f.yaml / tlsx.yaml
│   └── secretfinder.yaml
├── bin/                   # 项目 Python 适配器和历史工具存放处
├── outputs/               # 扫描结果输出
│   ├── logs/              # Debug 日志（debug 模式下生成）
│   ├── web_alive_*.json
│   ├── nuclei_*.json
│   └── ...
└── wordlists/             # 字典文件
    └── subdomains.txt
```

---

## 🎯 目标文件格式

### 支持的格式

`target.txt` 支持两种格式：

**1. 默认格式（DOMAIN 类型）**
```text
example.com
test.org
```

**2. 指定事件类型格式**
```text
[IP]192.168.1.1
[URL]http://target.com
[LIVE_URL]https://admin.example.com
[SUBDOMAIN]api.example.com
```

### 事件类型说明

| 类型 | 说明 | 示例 |
|------|------|------|
| `DOMAIN` | 域名（默认） | `example.com` |
| `IP` | IP 地址 | `[IP]192.168.1.1` |
| `URL` | 未验证 URL/页面链接 | `[URL]http://target.com/a.js` |
| `LIVE_URL` | 已确认存活的 Web URL | `[LIVE_URL]https://admin.example.com` |
| `SUBDOMAIN` | 子域名 | `[SUBDOMAIN]api.example.com` |
| `PORT_OPEN` | 开放端口 | `[PORT_OPEN]192.168.1.1:443` |
| `ICON_PATH` | favicon/icon 完整 URL 或路径 | `[ICON_PATH]https://example.com/favicon.ico` |
| `ICON_HASH` | favicon hash | 通常由 httpx 产出 |
| `VULNERABILITY` | 漏洞结果 | 通常由 nuclei/afrog/fscan/xray 产出 |

---

## 🔄 工作流原理

### 事件驱动架构

```
用户输入 (DOMAIN/IP/URL)
    ↓
事件总线 (Event Queue)
    ↓
Worker 池 (10个并发 Worker)
    ↓
模块匹配 (根据 inputs 匹配模块)
    ↓
并行执行 (受 max_processes 限制)
    ↓
解析输出 (rules 引擎)
    ↓
产生新事件 → 回到事件总线
    ↓
数据落盘 (save 配置)
```

### 模块关系图谱

启动时会自动打印模块关系图谱：

```
================================================================================
📊 事件流图谱 - 模块关系可视化
================================================================================

🔧 模块详情（输入 → 输出）:
--------------------------------------------------------------------------------

   🔨 扫描任务: subfinder_module
   ──────────────────────────────────────────────────────────────
   📥 接收: DOMAIN
   📤 产出: SUBDOMAIN
   ⬆️  上游: [根节点 - 由用户输入]
   ⬇️  下游: fscan_module(SUBDOMAIN)

   🔨 扫描任务: fscan_module
   ──────────────────────────────────────────────────────────────
   📥 接收: IP, SUBDOMAIN
   📤 产出: LIVE_URL, PORT_OPEN, VULNERABILITY
   ⬆️  上游: dnsx_brute_module(SUBDOMAIN), subfinder_module(SUBDOMAIN)
   ⬇️  下游: dirsearch_module(LIVE_URL), nuclei_module(LIVE_URL), ...

🔄 事件流转链路:
--------------------------------------------------------------------------------
📍 DOMAIN ← [用户输入]
   📍 SUBDOMAIN ← dnsx_brute_module, subfinder_module
      📍 LIVE_URL ← fscan_module, httpx_module
         📍 URI ← dirsearch_module
         📍 VULNERABILITY ← fscan_module, nuclei_module, xray_passive_module
         ...

📈 统计信息:
--------------------------------------------------------------------------------
   总模块数: 18
   ├─ 背景服务: 1
   └─ 扫描任务: 17
   事件类型总数: 17+
```

---

## 🧩 内置模块清单

| 模块文件 | 模块名 | 输入 | 输出 | 功能 |
|---|---|---|---|---|
| `afrog.yaml` | `afrog_module` | `LIVE_URL` | `VULNERABILITY` | Afrog 高危/严重漏洞扫描（`-S high,critical`） |
| `dirsearch.yaml` | `dirsearch_module` | `LIVE_URL` | `URI` | Web 敏感目录与隐藏文件爆破 |
| `dnsx.yaml` | `dnsx_brute_module` | `DOMAIN` | `SUBDOMAIN` | 本地字典子域名爆破 |
| `dnsx_resolve.yaml` | `dnsx_resolve_module` | `SUBDOMAIN` | `IP` | 子域名 A 记录解析 |
| `fofa.yaml` | `fofa_module` | `DOMAIN, LIVE_URL, ICON_PATH` | `DOMAIN, SUBDOMAIN, IP, URL` | 基于 FoFaX 的网络空间测绘、证书和 icon 反查 |
| `fscan.yaml` | `fscan_module` | `IP, SUBDOMAIN` | `LIVE_URL, PORT_OPEN, VULNERABILITY` | 综合漏洞和弱口令扫描 |
| `httpx.yaml` | `httpx_module` | `URL, PORT_OPEN` | `LIVE_URL, DOMAIN, SUBDOMAIN, IP, ICON_PATH, ICON_HASH, CERT_ORG, CERT_FINGERPRINT` | HTTP 存活探测、favicon 和证书基础信息归一化 |
| `katana.yaml` | `katana_module` | `LIVE_URL` | `URL` | Web 爬虫，发现页面/接口/JS 链接 |
| `naabu.yaml` | `naabu_module` | `IP, SUBDOMAIN` | `PORT_OPEN` | 高速端口发现 |
| `nmap_service.yaml` | `nmap_service_module` | `PORT_OPEN` | `SERVICE, LIVE_URL` | 服务版本识别并补充 HTTP 类 LIVE_URL |
| `nuclei.yaml` | `nuclei_module` | `LIVE_URL` | `VULNERABILITY` | 模板化高危/严重漏洞扫描 |
| `observer_ward.yaml` | `observer_ward_module` | `LIVE_URL` | `FINGERPRINT` | Web 指纹识别 |
| `rad.yaml` | `rad_module` | `LIVE_URL` | `URL` | 动态爬虫和页面交互 URL 发现 |
| `secretfinder.yaml` | `secretfinder_module` | `URL, URI, LIVE_URL` | `SECRET, VULNERABILITY` | 前端敏感信息发现 |
| `subfinder.yaml` | `subfinder_module` | `DOMAIN` | `SUBDOMAIN` | 被动子域名发现 |
| `tlsx.yaml` | `tlsx_module` | `LIVE_URL, SUBDOMAIN` | `CERT_INFO, SUBDOMAIN` | TLS 证书信息和 SAN 子域名提取 |
| `wafw00f.yaml` | `wafw00f_module` | `LIVE_URL` | `WAF, FINGERPRINT` | WAF/CDN 识别 |
| `xray.yaml` | `xray_passive_module` | `START` | `VULNERABILITY` | Xray 被动漏洞代理监听 |

---

## 🔧 模块配置

### YAML 配置结构

每个模块由 YAML 文件定义，包含以下部分：

```yaml
name: "module_name"           # 模块名称
description: "模块描述"        # 功能描述

# 1. 验证命令是否可用
check:
  command: "tool -version"
  expect_keyword: "Version"
  exclude_keyword: "not found"

# 2. 自动安装步骤
install:
  steps:
    - "mkdir -p $HOME/.local/bin"
    - "GOBIN=$HOME/.local/bin go install example.com/tool@latest"

# 3. 执行配置
execute:
  inputs: ["DOMAIN"]           # 接收的事件类型
  outputs: ["SUBDOMAIN"]       # 产出的事件类型
  timeout: 900                 # 超时时间（秒）
  max_parallel_num: 1          # 模块级最大并发数
  command: "tool -d {{data}}"  # 执行命令

# 4. 结果解析器（声明式规则引擎）
parser:
  type: "rules"
  rules:
    - match:
        type: prefix | json_field | regex | multi_match
        # ... 匹配配置
      extract:
        FIELD_NAME: "{{variable}}"
      events:
        EVENT_TYPE: "{{FIELD_NAME}}"
      filters:
        EVENT_TYPE:
          if_not_empty: true
          transform: upper | lower | strip

# 5. 数据持久化
save:
  format: "json" | "text"
  template: "{{EVENT_TYPE}}"   # text 格式时使用
  output_path: "./outputs/result_{{DOMAIN}}.txt"
  mode: "append" | "write"
```

### 规则引擎详解

#### 匹配类型

**1. prefix - 前缀匹配**
```yaml
- match:
    type: prefix
    value: "[+]"
  extract:
    VULNERABILITY: "{{rest}}"
```

**2. json_field - JSON 字段匹配**
```yaml
# 顶层字段 equals
- match:
    type: json_field
    field: type
    equals: PORT
  extract:
    PORT_OPEN: "{{host}}:{{port}}"

# 嵌套字段 regex（Afrog 示例：只接收 high/critical）
- match:
    type: json_field
    field: info.severity
    regex: (?i)^(high|critical)$
  extract:
    SEVERITY: $.info.severity
    VULNERABILITY: "[afrog] [{{id}}] [{{SEVERITY}}] {{fulltarget}}"
```

**3. regex - 正则表达式**
```yaml
- match:
    type: regex
    pattern: "^Open port (?P<port>\d+) on (?P<ip>.+)$"
  extract:
    PORT_OPEN: "{{ip}}:{{port}}"
```

**4. multi_match - 多条件 AND**
```yaml
- match:
    type: multi_match
    conditions:
      - type: json_field_equals
        field: type
        equals: SERVICE
      - type: json_field_equals
        field: service
        equals: https
  extract:
    LIVE_URL: "https://{{host}}:{{port}}"
```

#### 过滤器

```yaml
filters:
  EVENT_TYPE:
    if_not_empty: true          # 值为空时跳过
    if_contains: "高危"         # 不包含指定文本时跳过
    transform: upper            # 转大写 (upper/lower/strip)
```

#### 🌟 模板方法链（高级功能）

支持在模板中使用 Python 字符串方法链式调用，实现灵活的数据转换：

```yaml
extract:
  # 字符串替换 - 将 "ssl" 转换为 "https"
  LIVE_URL: "{{service.replace('ssl','https')}}://{{host}}:{{port}}"
  
  # 方法链式调用 - 替换后转大写
  NORMALIZED: "{{service.replace('ssl','https').upper()}}"
  
  # 复杂链式调用 - 去空格 → 转小写 → 替换
  PROCESSED: "{{text.strip().lower().replace(' ','_')}}"
```

**常用方法：**
- 大小写转换：`upper()`, `lower()`, `capitalize()`, `title()`
- 清理操作：`strip()`, `lstrip()`, `rstrip()`
- 替换操作：`replace(old, new)`
- 分割操作：`split(sep)`, `rsplit(sep)`
- 查找操作：`find(sub)`, `count(sub)`, `startswith(prefix)`, `endswith(suffix)`

**安全机制：** 白名单保护 + AST 参数解析，阻止任意代码执行。

详见 [PARSER_GUIDE.md](PARSER_GUIDE.md) 的「模板替换引擎」章节。

---

## 💾 输出文件

### 结果文件

扫描结果保存在 `./outputs/` 目录：

- `web_alive_example.com_results.json` - HTTPX 存活检测结果
- `nuclei_example.com_vulns.json` - Nuclei 漏洞扫描结果
- `afrog_example.com_vulns.json` - Afrog 高危/严重漏洞扫描结果
- `fingerprints_example.com_results.json` - Observer Ward 指纹识别结果
- `rad_example.com_urls.txt` - Rad 爬虫发现的 URL
- `dirsearch_example.com_results.json` - Dirsearch 目录爆破结果

### 状态文件

- `finish_target.txt` - 已完成的目标列表（断点续扫用）
- `failed_targets.txt` - 失败的目标记录

### Debug 日志

开启 `--debug` 模式后，每个模块的完整输出会保存到：

```
./outputs/logs/
├── subfinder_module_DOMAIN_example.com_20260522_143025.txt
├── httpx_module_URL_http-example.com_20260522_143030.txt
└── ...
```

---

## 🛠️ 高级用法

### 实际应用场景：处理 fscan 的 ssl 服务名

**问题：** fscan 在检测 HTTPS 服务时，`service` 字段输出的是 `"ssl"` 而不是 `"https"`，导致生成的 URL 是 `ssl://example.com:443` 而不是 `https://example.com:443`。

**解决方案：** 使用模板方法链进行字符串替换：

```yaml
# modules/fscan.yaml
parser:
  type: "rules"
  rules:
    - match:
        type: json_field
        field: type
        equals: SERVICE
      extract:
        # 将 "ssl" 替换为 "https"，保持 "http" 不变
        LIVE_URL: "{{service.replace('ssl','https')}}://{{host}}:{{port}}"
```

**效果：**
- 输入：`{"type":"SERVICE","host":"example.com","port":443,"service":"ssl"}`
- 输出：`LIVE_URL: "https://example.com:443"` ✅

### 添加自定义模块

1. 在 `modules/` 目录创建新的 YAML 文件
2. 定义 inputs/outputs/command/parser/save
3. 重启程序自动加载

**示例：添加 masscan 模块**

```yaml
name: "masscan_module"
description: "高速端口扫描器"

check:
  command: "masscan --version"
  expect_keyword: "masscan"

execute:
  inputs: ["IP"]
  outputs: ["PORT_OPEN"]
  timeout: 300
  max_parallel_num: 2
  command: "masscan {{data}} -p1-65535 --rate=10000"

parser:
  type: "rules"
  rules:
    - match:
        type: regex
        pattern: "^Discovered open port (?P<port>\d+)/tcp on (.+)$"
      extract:
        PORT_OPEN: "{{port}}"

save:
  format: "json"
  output_path: "./outputs/masscan_{{DOMAIN}}_ports.json"
  mode: "append"
```

### 调整并发参数

在 `batch_main.py` 中修改：

```python
engine = Orchestrator(
    MODULES_DIR,
    max_workers=25,              # Worker 数量，可通过 --workers 指定
    max_processes=20,            # 最大并发进程数，可通过 --max-processes 指定
    debug=debug_mode,
    seen_events_limit=1000000    # 去重集合清理阈值，可通过 --seen-events-limit 指定
)
```

### 修改事件去重阈值

启动时通过参数指定：

```bash
python batch_main.py --seen-events-limit 1000000
```

或在直接实例化 `Orchestrator` 时传入：

```python
engine = Orchestrator("./modules", seen_events_limit=1000000)
```

---

## 🐛 故障排查

### 实时终止无关事件树

运行中可以编辑项目根目录的 `stop_event.txt`，每行格式和 `target.txt` 相同：

```text
[URL]http://www.baidu.com
[LIVE_URL]https://test.example.com
[DOMAIN]noise.example
```

程序会约每秒读取一次该文件。命中的事件及其所有子事件会被取消：已排队事件会被丢弃，运行中的模块任务会收到 cancel 并终止底层子进程，后续派生事件也不会再入队。适合临时停止无关紧要、占用进度的扫描分支。

---

### 问题1：模块不执行

**检查：**
1. 查看启动日志中的模块环境检查/自动安装信息
2. 确认模块 YAML 中显式调用的 `$HOME/.local/bin/<tool>` 文件存在且可执行
3. 单独运行 YAML 的 `check.command`，确认命中的是预期工具
4. 查看 `outputs/logs/` 中对应模块 debug 输出

### 问题2：事件卡死不继续

**原因：** 产生了没有消费者的事件

**解决：** 系统已自动处理，无消费者的事件会直接落盘而不出队

### 问题3：扫描结果丢失

**检查：**
1. `outputs/` 目录是否存在
2. 磁盘空间是否充足
3. 查看 save 配置中的 output_path

### 问题4：并发过高导致系统卡顿

**解决：** 降低并发数
```bash
python batch_main.py -c 3  # 降低到3
```

---

## 📊 性能优化建议

1. **根据系统资源调整并发**
   - CPU 密集型工具（如 nuclei）：降低 max_processes
   - IO 密集型工具（如 httpx）：可以提高并发

2. **合理设置模块级并发**
   ```yaml
   execute:
     max_parallel_num: 1  # 限制单个模块的并发数
   ```

3. **定期清理 seen_events**
   - 系统会自动清理超过 10000 条的去重记录
   - 可根据实际情况调整阈值

4. **使用 SSD 存储**
   - 大量文件写入操作，SSD 能显著提升性能

---

## 📝 许可证

本项目仅供学习和研究使用。

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📧 联系方式

如有问题或建议，请提交 Issue。
