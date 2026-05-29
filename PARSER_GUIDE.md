# 解析引擎使用指南

## 核心设计理念

解析引擎采用**声明式规则引擎**，通过YAML配置即可实现复杂的命令行输出解析逻辑。

### 主要特性

1. **简洁直观**：纯YAML配置，无需编写Python代码
2. **强大表达力**：支持一条输出产生多个不同类型的事件
3. **多条件匹配**：支持前缀、JSON字段、嵌套JSON字段、正则、多条件AND等匹配方式
4. **条件过滤**：内置过滤器支持空值检测、内容检测、大小写转换
5. **保存与派发分离**：`extract` 可保存富字段，`events` 精确控制继续流转的事件

---

## 规则引擎详解

### 基本结构

```yaml
parser:
  type: "rules"
  rules:
    - match:
        type: prefix | json_field | regex | multi_match
        # ... 匹配配置
      extract:
        # 保存字段：会写入 save.output_path
        FIELD_NAME: "模板字符串或 $.json.path"
      events:
        # 可选。事件字段：没有 events 时默认使用 extract。
        # 用于“保存更多字段，但只派发部分事件”。
        EVENT_TYPE: "模板字符串或 $.json.path"
      filters:
        FIELD_NAME:
          if_not_empty: true
          if_contains: "关键词"
          transform: upper | lower | strip
```

### 匹配类型

#### 1. prefix - 前缀匹配

适用于命令行工具的标准输出格式。

```yaml
- match:
    type: prefix
    value: "[+]"
  extract:
    VULNERABILITY: "{{rest}}"

# 输入: "[+] WebTitle:http://example.com code:200"
# 提取: {VULNERABILITY: "WebTitle:http://example.com code:200"}
```

**可用变量：**
- `{{rest}}` - 去除前缀后的剩余部分
- `{{full_line}}` - 完整行内容

#### 2. json_field - JSON字段条件匹配

根据JSON中的某个字段值决定是否提取，整个JSON对象都会放入context。

```yaml
- match:
    type: json_field
    field: type
    equals: PORT
  extract:
    PORT_OPEN: "{{host}}:{{port}}"

# 输入: '{"type":"PORT","host":"127.0.0.1","port":80}'
# 提取: {PORT_OPEN: "127.0.0.1:80"}
```

**特点：**
- 自动解析JSON
- 所有顶层JSON字段都可在模板中使用
- `field` 支持顶层字段和点路径字段，例如 `type`、`info.severity`
- 不写 `equals`/`regex` 时，只检查字段存在且非空
- `equals` 用于精确匹配，`regex` 用于正则匹配；二者同时存在时必须都满足

嵌套字段 + 正则过滤示例：

```yaml
- match:
    type: json_field
    field: info.severity
    regex: (?i)^(high|critical)$
  extract:
    AFROG_ID: '{{id}}'
    SEVERITY: $.info.severity
    MATCHED_AT: '{{fulltarget}}'
    VULNERABILITY: '[afrog] [{{AFROG_ID}}] [{{SEVERITY}}] {{MATCHED_AT}}'
  events:
    VULNERABILITY: '{{VULNERABILITY}}'
```

这类规则适合 Nuclei 或未来 JSON 输出模块：保存完整字段，同时只把 high/critical 风险继续派发。当前 `afrog.yaml` 为了贴近实时控制台输出，使用 regex fallback 解析 stdout 中的 HIGH/CRITICAL 行。

#### 3. regex - 正则表达式匹配

使用命名捕获组提取数据。

```yaml
- match:
    type: regex
    pattern: "^Open port (?P<port>\d+) on (?P<ip>.+)$"
  extract:
    PORT_OPEN: "{{ip}}:{{port}}"

# 输入: "Open port 80 on 192.168.1.1"
# 提取: {PORT_OPEN: "192.168.1.1:80"}
```

**可用变量：**
- 命名捕获组（如 `{{port}}`, `{{ip}}`）
- `{{full_match}}` - 完整匹配内容

#### 4. multi_match - 多条件AND匹配

所有条件都必须满足才触发提取。

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

# 输入: '{"type":"SERVICE","service":"https","host":"example.com","port":443}'
# 提取: {LIVE_URL: "https://example.com:443"}
```

**支持的条件类型：**
- `prefix` - 前缀匹配
- `json_field_equals` - JSON字段等于某值
- `contains` - 包含指定文本

---

## 高级特性

### 多事件产出

一条输出可以产生多个不同类型的事件。

```yaml
- match:
    type: json_field
    field: type
    equals: SERVICE
  extract:
    PORT_OPEN: "{{host}}:{{port}}"
    LIVE_URL: "{{service}}://{{host}}:{{port}}"

# 输入: '{"type":"SERVICE","service":"http","host":"127.0.0.1","port":8080}'
# 提取: 
#   {
#     PORT_OPEN: "127.0.0.1:8080",
#     LIVE_URL: "http://127.0.0.1:8080"
#   }
# 生成两个事件：PORT_OPEN 和 LIVE_URL
```


### extract 与 events 的区别

`extract` 定义“保存到结果文件的数据字段”；`events` 定义“发送到事件总线的新事件”。如果没有 `events`，系统会默认把 `extract` 同时当作事件来源。

这适合两类场景：

1. 简单模块：保存字段和事件完全一致，只写 `extract`。
2. 富结果模块：保存 `STATUS_CODE`、`METHOD`、`TITLE` 等辅助字段，但只把 `URL`、`LIVE_URL`、`IP` 等事件继续派发。

示例：

```yaml
- match:
    type: regex
    pattern: '^\[(?P<METHOD>GET|POST)\] (?P<URL>https?://.+)$'
  extract:
    METHOD: '{{METHOD}}'
    URL: '{{URL}}'
  events:
    URL: '{{URL}}'
```

注意：事件生成器只会派发 `execute.outputs` 中声明过的事件类型；未声明的 key 会被保存但不会变成事件。

### JSON Path 提取

`extract` 和 `events` 的值除了普通模板，也支持轻量 JSON Path：

```yaml
extract:
  TITLE: $.response.title
  SUBDOMAIN: $.cert.subject_an[*]
```

支持对象链、数组下标和 `[*]` 通配。通配结果是列表，事件生成器会为列表中的每个元素生成一个事件。`json_field.field` 的点路径匹配和这里的 JSON Path 使用同一套取值语义。

### 模板替换引擎

支持 `{{variable}}` 和 `{{variable.method().method()}}` 语法，自动从context中替换变量。

#### 基础用法

```yaml
extract:
  # 简单变量替换
  VULNERABILITY: "{{rest}}"
  
  # 组合模板
  LIVE_URL: "{{service}}://{{host}}:{{port}}"
  
  # 固定前缀 + 变量
  VULNERABILITY: "发现漏洞: {{vuln_name}} 在 {{target}}"
```

#### 🌟 方法链调用（高级功能）

支持 Python 字符串方法链式调用，可以对变量进行转换、替换、清理等操作：

```yaml
extract:
  # 单方法调用 - 转大写
  SERVICE_TYPE: "{{service.upper()}}"
  
  # 字符串替换 - 将 "ssl" 转换为 "https"
  LIVE_URL: "{{service.replace('ssl','https')}}://{{host}}:{{port}}"
  
  # 方法链式调用 - 替换后转大写
  NORMALIZED_URL: "{{service.replace('ssl','https').upper()}}://{{host}}"
  
  # 去除空格
  CLEAN_TEXT: "{{value.strip()}}"
  
  # 复杂链式调用 - 去空格 → 转小写 → 替换文本
  PROCESSED: "{{text.strip().lower().replace(' ','_')}}"
```

**支持的字符串方法：**

| 类别 | 方法 | 示例 |
|------|------|------|
| **大小写转换** | `upper()` | `"http".upper()` → `"HTTP"` |
| | `lower()` | `"HTTPS".lower()` → `"https"` |
| | `capitalize()` | `"hello".capitalize()` → `"Hello"` |
| | `title()` | `"hello world".title()` → `"Hello World"` |
| | `swapcase()` | `"Http".swapcase()` → `"hTTP"` |
| **清理操作** | `strip()` | `" hello ".strip()` → `"hello"` |
| | `lstrip()` | `" hello".lstrip()` → `"hello"` |
| | `rstrip()` | `"hello ".rstrip()` → `"hello"` |
| | `zfill(width)` | `"42".zfill(5)` → `"00042"` |
| **替换操作** | `replace(old, new)` | `"ssl".replace("ssl","https")` → `"https"` |
| **分割操作** | `split(sep)` | `"a.b.c".split(".")` → `["a", "b", "c"]` |
| | `rsplit(sep)` | 从右侧分割 |
| | `partition(sep)` | 分割为三元组 |
| **查找操作** | `find(sub)` | 返回子串位置 |
| | `count(sub)` | 统计出现次数 |
| | `startswith(prefix)` | 检查前缀 |
| | `endswith(suffix)` | 检查后缀 |

**实际应用场景：**

```yaml
# 场景1: fscan 输出 "ssl" 但需要转换为 "https"
- match:
    type: json_field
    field: type
    equals: SERVICE
  extract:
    LIVE_URL: "{{service.replace('ssl','https')}}://{{host}}:{{port}}"

# 场景2: 统一服务名称为大写
- match:
    type: json_field
    field: service
  extract:
    SERVICE_UPPER: "{{service.upper()}}"

# 场景3: 清理和标准化文本
- match:
    type: prefix
    value: "[INFO]"
  extract:
    MESSAGE: "{{rest.strip().lower()}}"
```

**安全机制：**

- ✅ **白名单保护**：只允许安全的字符串方法，阻止任意代码执行
- ✅ **参数验证**：使用 `ast.literal_eval()` 安全解析方法参数
- ✅ **异常处理**：方法调用失败时返回空字符串并记录警告日志

如果模板中有未替换的占位符，该提取会被自动跳过并记录debug日志。

### 条件过滤器

```yaml
filters:
  EVENT_TYPE:
    # 值为空时跳过该事件
    if_not_empty: true
    
    # 不包含指定文本时跳过
    if_contains: "高危"
    
    # 值转换
    transform: upper   # 转大写
    transform: lower   # 转小写
    transform: strip   # 去除首尾空格
```

---

## 完整示例：fscan.yaml

```yaml
name: "fscan_module"
description: "fscan扫描模块"

execute:
  inputs: ["IP", "SUBDOMAIN"]    
  outputs: ["LIVE_URL", "PORT_OPEN", "VULNERABILITY"]     
  timeout: 900
  max_parallel_num: 1
  command: "fscan -h {{data}} -no -silent -np -p 1-65535"

parser:
  type: "rules"
  rules:
    # 规则1: 提取 [+] 开头的漏洞信息
    - match:
        type: prefix
        value: "[+]"
      extract:
        VULNERABILITY: "{{rest}}"
    
    # 规则2: 提取开放端口
    - match:
        type: json_field
        field: type
        equals: PORT
      extract:
        PORT_OPEN: "{{host}}:{{port}}"
    
    # 规则3: 提取Web服务URL（支持方法链转换）
    - match:
        type: json_field
        field: type
        equals: SERVICE
      extract:
        # 🌟 使用模板方法链将 "ssl" 转换为 "https"
        LIVE_URL: "{{service.replace('ssl','https')}}://{{host}}:{{port}}"
    
    # 规则4: 异常Shell服务检测（带过滤）
    - match:
        type: json_field
        field: service
        equals: dps-shell
      extract:
        VULNERABILITY: "异常Shell监听服务: {{target}} [ {{banner}} ]"
      filters:
        VULNERABILITY:
          if_not_empty: true
          transform: strip

save:
  format: "json" 
  output_path: "./outputs/fscan_GLOBAL_BATCH_vulns.json"
  mode: "append"
```

---


## 目标文件与事件类型

批量入口读取 `target.txt`，已完成目标写入 `finish_target.txt`。每行目标支持：

```text
example.com                  # 默认 DOMAIN
[DOMAIN]example.com
[SUBDOMAIN]api.example.com
[IP]192.0.2.10
[URL]https://example.com/a.js
[LIVE_URL]https://example.com
[PORT_OPEN]192.0.2.10:443
```

模块通过 `execute.inputs` 订阅事件，通过 `execute.outputs` 声明可产出的事件。常见事件：

| 事件 | 含义 | 常见消费者 |
|---|---|---|
| `DOMAIN` | 根域名 | dnsx、subfinder、fofa |
| `SUBDOMAIN` | 子域名 | dnsx_resolve、naabu、fscan、tlsx |
| `IP` | IP 地址 | naabu、fscan |
| `PORT_OPEN` | `host:port` | nmap_service、httpx |
| `URL` | 未验证 URL | httpx、secretfinder |
| `LIVE_URL` | 存活 Web URL | nuclei、afrog、dirsearch、rad、katana、wafw00f、observer_ward、secretfinder、tlsx、fofa |
| `URI` | 目录/文件路径 URL | secretfinder |
| `SERVICE` | 服务识别结果 | 终端保存事件 |
| `VULNERABILITY` | 漏洞或风险 | 终端保存事件 |
| `SECRET` | 敏感信息 | 终端保存事件 |
| `FINGERPRINT` | 指纹 | 终端保存事件 |
| `WAF` | WAF/CDN 识别 | 终端保存事件 |
| `CERT_INFO` | 证书信息 | 终端保存事件 |
| `ICON_PATH` | favicon/icon URL 或路径 | fofa |
| `ICON_HASH` | favicon hash | 终端保存事件 |
| `CERT_ORG` | 证书组织 | 终端保存事件 |
| `CERT_FINGERPRINT` | 证书指纹 | 终端保存事件 |

没有消费者的事件会直接通过来源模块的 `save` 配置落盘，不会继续入队造成卡死。

---

## 最佳实践

1. **保持规则顺序**：规则按优先级从上到下匹配，第一条匹配的规则生效
2. **合理使用过滤器**：用`if_not_empty`避免生成空事件
3. **明确outputs声明**：只在outputs中声明你真正需要的事件类型
4. **调试技巧**：开启debug模式查看未匹配的模板替换警告
5. **优先使用json_field**：对于JSON输出，比regex更简洁可靠；嵌套字段用 `field: info.severity`，复杂筛选用 `regex`
6. **保存字段和事件分离**：需要保存辅助字段时用 `events` 只派发核心事件
7. **为解析器写回归测试**：把真实 stdout/JSONL 样例放进 `tests/`，同时断言 result 和 events；外部 CLI 可用 fake executable 验证 execute_and_parse 链路
8. **错误输出不应生成事件**：API/网络错误、usage、not found、进度条等人类可读错误行应解析为空结果
9. **规则不会叠加执行**：同一行输出按 rules 顺序命中第一条后立即返回；不要依赖后一条规则补充前一条规则的字段

---

## 常见问题

### Q: 为什么我的规则没有匹配？

A: 检查以下几点：
1. match_type是否正确（prefix/json_field/regex）
2. JSON 字段路径是否正确；嵌套字段应写 `info.severity`，提取值可写 `$.info.severity`
3. equals/regex 是否过于严格
4. 使用debug模式查看每行的解析过程

### Q: 多条规则会不会冲突？

A: 一般不会。解析器对每一行输出从上到下尝试规则，第一条匹配成功后立即返回，不会继续执行后续规则。因此 JSON 规则和文本 regex fallback 可以共存：JSON 行命中 json_field，普通文本行命中 regex。需要注意的是，后一条规则不能补充前一条规则的字段。

### Q: 如何让一条输出产生多个事件？

A: 在extract中声明多个键值对即可：
```yaml
extract:
  EVENT_TYPE_1: "{{var1}}"
  EVENT_TYPE_2: "{{var2}}"
```

### Q: 如何处理列表类型的值？

A: 事件生成器会自动处理list类型，为每个元素生成一个事件。

### Q: 如何在模板中转换字符串（如 ssl → https）？

A: 使用模板方法链功能：

```yaml
extract:
  # 将 "ssl" 替换为 "https"
  LIVE_URL: "{{service.replace('ssl','https')}}://{{host}}"
  
  # 多方法链式调用
  NORMALIZED: "{{text.strip().lower().replace(' ','_')}}"
```

详见上方「🌟 方法链调用（高级功能）」章节。

### Q: rules引擎性能如何？

A: rules引擎性能优秀：
1. 无需exec()动态执行代码
2. 匹配逻辑是预编译的
3. 减少了Python解释器开销
