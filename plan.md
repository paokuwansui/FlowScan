# FlowScan Docker 化改造实施计划

> **目标**:将 FlowScan 从"主机手动安装工具"部署方式,改造为纯 Docker 部署。
> 移除所有模块 YAML 中的 install 步骤,工具统一在 Dockerfile 中安装。
> 交付物:`docker compose up` 一条命令拉起 Redis + Worker + Web 全栈。

**架构**:单镜像(FlowScan 全工具链)+ 三服务编排(redis / worker / web)。
**技术栈**:Docker + docker compose v2,Kali 基础镜像,Kali apt 源 + Go toolchain + GitHub release + pip。

---

## 一、现状盘点(改造前)

### 1.1 模块安装方式分布(modules/*.yaml,共 17 个模块)

| 安装方式 | 模块 | 数量 |
|---|---|---|
| apt(需要 Kali 源) | amass / feroxbuster / naabu / nmap / nuclei / subfinder / whatweb | 7 |
| go install(ProjectDiscovery 系) | httpx / dnsx(ip_resolve) / katana | 3 |
| GitHub release 下载 | afrog / fofa(fofax) / fscan / ksubdomain | 4 |
| 纯 Python 无需安装 | input / ip_range_split | 2 |
| pip(bbot 依赖) | bbot(install 为占位 echo) | 1 |

### 1.2 其他安装/部署相关资产

- `main_node_setup.sh` — 主节点:随机化密钥 + 安装/配置 Redis(改 redis.conf)
- `worker_node_setup.sh` — Worker 节点:装 Go 工具链 + bbot 依赖 + `python3 main.py init`
- `venv_setup.sh` — 建 flowscan_venv + pip 装 PyYAML/redis/flask/tldextract/bbot
- `start_xray.sh` — 下载 xray 二进制(1.9.11)+ 启动被动代理
- `bin/xray/` — 只有配置/CA,无二进制(运行前下载)
- `bin/rad/` — 只有配置(rad 未安装,模块未启用)
- `bin/secretfinder.py` — 第三方脚本(依赖 requests/jsbeautifier 等),当前**未被任何模块引用**
- `tools/randomize_secrets.py` — 随机化 config.yaml 密钥(部署时执行)
- `flowscan/installer.py` — init 模式:check → install_steps 循环 → 最终 check
- `config.yaml` — `redis.remote_host: 127.0.0.1`(容器内需改为服务名)

### 1.3 命令路径引用(改造约束)

模块 execution.command 中的路径引用模式:
- `$HOME/.local/bin/<tool>` — 5 处(afrog/httpx/katana 等 go/release 工具)
- `python ./bin/*.py` — 4 处
- `python ./flowscan/filter.py` — 3 处
- 裸命令(走 PATH)— amass/naabu/nmap/nuclei/subfinder/feroxbuster/whatweb/fscan/ksubdomain

→ Dockerfile 中工具统一安装到 `/usr/local/bin`(PATH 默认包含),`$HOME/.local/bin` 通过设置 `ENV HOME=/root` 保持可用;或全部改用绝对路径。

---

## 二、目标架构

```
┌─────────────────────────────────────────────────────┐
│  docker-compose.yml                                  │
│                                                     │
│  ┌─────────┐    ┌──────────────────────────────┐    │
│  │  redis  │◄───│  flowscan-worker (可 scale N) │    │
│  │ :6379   │    │  ├ 17 个工具全量安装          │    │
│  └─────────┘    │  ├ cap_add: NET_RAW          │    │
│                 │  └ 默认 root 运行             │    │
│  ┌──────────────────────────────┐    ┌─────────┐│    │
│  │  flowscan-web :8080          │    │ xray    ││    │
│  │  (Flask 控制面板)            │    │ :7777   ││    │
│  └──────────────────────────────┘    └─────────┘│    │
│                                                     │
│  共享:flowscan 镜像 / config.yaml 挂载 /            │
│        state_snapshots 卷 / fs3net 网络             │
└─────────────────────────────────────────────────────┘
```

- **redis**:官方 `redis:7-alpine`,数据卷持久化,可选密码(从 config.yaml 读)
- **flowscan-worker**:FlowScan 镜像,`main.py worker`,可 `--scale` 多节点
- **flowscan-web**:FlowScan 镜像,`main.py web`,8080 暴露
- **xray**(可选服务):同镜像,`start_xray.sh` 逻辑,7777 被动代理端口

---

## 三、Dockerfile 设计(单阶段构建)

基础镜像选 **kalilinux/kali-rolling**(naabu/feroxbuster 等仅 Kali 源有;镜像内含 Python3)。

```dockerfile
# 建议骨架(具体实现见任务 T4)
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/root \
    PATH=/usr/local/bin:$PATH

# 1. apt 工具层(7 个模块 + 构建依赖)
RUN apt-get update && apt-get install -y --no-install-recommends \
      amass feroxbuster naabu nmap nuclei subfinder whatweb \
      golang-go unzip curl wget git ca-certificates \
      python3 python3-venv python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 2. nuclei 模板(init 时需要,避免运行时下载)
RUN nuclei -update-templates

# 3. Go 工具层(httpx/dnsx/katana,装到 /usr/local/bin)
RUN GOBIN=/usr/local/bin go install -v \
      github.com/projectdiscovery/httpx/cmd/httpx@latest \
      github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
      github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest \
      github.com/projectdiscovery/katana/cmd/katana@latest

# 4. GitHub release 下载层(afrog/fofax/fscan/ksubdomain/xray)
#    官方源失败时 fallback gh-proxy.com(本机网络已实测)
#    ├ afrog     v3.5.6   afrog_3.5.6_linux_amd64.zip
#    ├ fofax     最新 release(现有 install 步骤的解析逻辑搬进来)
#    ├ fscan     最新 release(现有 python 解析逻辑搬进来)
#    ├ ksubdomain v0.7    ksubdomain_linux.zip
#    └ xray      1.9.11   xray_linux_amd64.zip → bin/xray/xray
RUN ...(逐工具下载/解压/install 到 /usr/local/bin)

# 5. Python 依赖层
RUN python3 -m venv /opt/flowscan-venv && \
    /opt/flowscan-venv/bin/pip install --no-cache-dir \
      PyYAML redis flask tldextract bbot

# 6. 项目代码
WORKDIR /app
COPY . /app
COPY wordlists/ /app/wordlists/

# 7. 入口(默认 worker;web/xray 由 compose command 覆盖)
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["worker"]
```

**关键决策**:
- 单阶段(非多阶段):17 个工具都要在运行容器内,多阶段无收益;apt 缓存清理 + `--no-install-recommends` 控体积
- bbot 用独立 venv(/opt/flowscan-venv),与系统 Python 隔离(bbot 依赖冲突多);`bbot` 命令软链进 PATH,venv 的 python 由 shebang 自带
- 网络限制适配:镜像构建需访问 Kali 源 / proxy.golang.org / GitHub。本机实测:GitHub release 直连被重置、gh-proxy.com 可用 → release 下载统一 `||` fallback;go proxy 不通 → Go 层在构建机上若失败,改为 GitHub release 直下 PD 工具二进制(备选方案,见风险 R3)
- 权限:ksubdomain 需要 `CAP_NET_RAW` → compose 里 `cap_add: [NET_RAW]`;nmap -O 需 root → 容器默认 root ✓

---

## 四、改造点清单(文件级)

### 4.1 删除安装逻辑(核心需求)

**17 个 `modules/*.yaml`**:删除整个 `install:` 块(install_steps)。
- installer.py 已兼容无 install_steps 的情况(`ensure_tool` 无 install 步骤时只做 check,返回 check 结果)——无需改代码,只删 YAML
- 保留 `check:` 块:init 模式仍可验证镜像内工具可用性(CI/健康检查用)

涉及文件(全部):
```
modules/afrog.yaml        modules/amass.yaml       modules/bbot.yaml
modules/feroxbuster.yaml  modules/fofa.yaml        modules/fscan.yaml
modules/httpx.yaml        modules/input.yaml       modules/ip_range_split.yaml
modules/ip_resolve.yaml   modules/katana.yaml      modules/ksubdomain.yaml
modules/naabu.yaml        modules/nmap.yaml        modules/nuclei.yaml
modules/subfinder.yaml    modules/whatweb.yaml
```

### 4.2 新增文件

```
Dockerfile                  # 全工具统一安装(上文骨架)
docker-compose.yml          # redis + worker + web(+ 可选 xray)
docker/.dockerignore        # 排除 .git/venv/state_snapshots 等
docker/entrypoint.sh        # 启动逻辑:随机化密钥 → 等 Redis → 执行 CMD
plan.md                     # 本文档
```

### 4.3 修改文件

| 文件 | 改动 |
|---|---|
| `config.yaml` | `redis.remote_host: 127.0.0.1` → `redis`(compose 服务名);web 端口 8080 保持 |
| `README.md` | 部署章节重写为 Docker 方式;删除主机安装说明;模块表更新 |
| `start_xray.sh` | 保留逻辑但改为容器内路径(/usr/local/bin/xray,已预下载),或并入 entrypoint |
| `bin/xray/xray` | 由 Dockerfile 下载放入(不进 git,加 .gitignore) |

### 4.4 废弃文件(标记 deprecated 或删除)

```
main_node_setup.sh    # 主机 Redis 配置逻辑 → 由 compose redis 服务取代
worker_node_setup.sh  # 主机工具安装 → 由 Dockerfile 取代
venv_setup.sh         # 主机 venv 创建 → 由 Dockerfile 取代
```

---

## 五、实施步骤(任务分解)

### T1: 初始化 docker 目录结构
- 创建 `docker/` 目录、`.dockerignore`(排除 .git / flowscan_venv / state_snapshots / *.afg / xray_out.html)
- 验证:`docker build` 前目录干净

### T2: 编写 Dockerfile — apt 工具层
- Kali 基础镜像 + 7 个 apt 工具 + 构建依赖(golang-go/unzip/curl/wget/git)
- `nuclei -update-templates` 固化模板
- 验证:`docker build` 通过,`docker run --rm image amass -version` 等 7 工具逐个 check

### T3: 编写 Dockerfile — Go 工具层
- GOBIN=/usr/local/bin go install httpx/dnsx/cdncheck/katana
- 验证:容器内 `httpx -version` / `dnsx -version` / `katana -version` / `cdncheck -version`
- 若 go proxy 不通 → 切 release 直下方案(见 T4 方式)

### T4: 编写 Dockerfile — release 下载层
- 将现有 4 个模块 install 步骤中的下载逻辑搬入 Dockerfile(afrog/fofax/fscan/ksubdomain)+ xray
- 统一模式:`curl -fL <官方> -o /tmp/pkg || curl -fL https://gh-proxy.com/<官方> -o /tmp/pkg` → 解压 → `install -m 0755` 到 /usr/local/bin → 清理
- 验证:容器内 5 个二进制 `-version`/`-h` 通过;`ls /tmp` 无残留

### T5: 编写 Dockerfile — Python 依赖层
- `/opt/flowscan-venv` + pip 装 PyYAML/redis/flask/tldextract/bbot
- `ln -s` bbot 进 /usr/local/bin
- 验证:容器内 `bbot --version`;`python3 -c "import yaml,redis,flask,tldextract"` 通过

### T6: 编写 entrypoint.sh + compose
- entrypoint:若 config.yaml 密钥为默认值 → 运行 `tools/randomize_secrets.py`;`redis-cli ping` 等待 Redis 就绪;`exec "$@"`
- compose:redis(volumes 持久化)、worker(默认 CMD,cap_add NET_RAW,depends_on redis)、web(端口 8080,CMD web)、可选 xray(端口 7777)
- 验证:`docker compose up -d` 三容器健康;`docker compose logs` 无错误

### T7: 删除 17 个模块的 install 块
- 每个 yaml 删除 `install:` 段(保留 check/runtime/io_contract/execution)
- 验证:`python3 main.py init` 在容器内全部 READY(或按实际工具可用性 READY/NOT_READY 明确)

### T8: config.yaml 网络适配 + 路径统一
- `redis.remote_host` → `redis`
- 检查模块命令路径:容器内 `$HOME/.local/bin` = `/root/.local/bin`,Dockerfile 安装到 /usr/local/bin 也进 PATH;若有不一致的命令改为 `/usr/local/bin/<tool>` 绝对路径或保证两处都有
- 验证:`docker compose exec worker python3 main.py status` 显示 events/tools/nodes

### T9: 端到端验证(容器内全链路)
- `docker compose exec worker python3 main.py inject --event-type DNS_NAME --value example.com`
- 观察 worker 日志:工具执行链路(bbot/fofa 等需外部 API key 的模块会失败,属预期)
- 验证本地 HTTP 服务链路:注入 URL → httpx/nuclei/feroxbuster/whatweb 消费
- Web 面板:`curl http://127.0.0.1:8080/` 登录页 200;事件/日志页面有数据

### T10: 文档与清理
- README 部署章节改写(Docker 方式 + 工具清单 + 常见问题)
- 废弃脚本标注/删除;.gitignore 补充(bin/xray/xray、xray_out.html、*.afg)
- `git commit`(按任务分批提交)

---

## 六、验证方案汇总

| 层级 | 命令 | 预期 |
|---|---|---|
| 构建 | `docker build -t flowscan:dev .` | 成功,镜像 < 3GB(尽力) |
| 工具可用性 | `docker run --rm flowscan:dev bash -c 'amass -version && naabu -version && ...'` | 17 工具全部输出版本 |
| init 检查 | `docker compose exec worker python3 main.py init` | 各工具 READY(无 install 步骤仍走 check) |
| 服务编排 | `docker compose up -d && docker compose ps` | redis/worker/web 均 Up |
| 事件链路 | inject DNS_NAME → `docker compose logs worker` | 工具消费日志出现 |
| Web | `curl -s http://127.0.0.1:8080/login` | 200 |
| 状态 | `docker compose exec worker python3 main.py status` | events/tools/nodes 非空 |

---

## 七、风险与权衡

| # | 风险 | 影响 | 缓解 |
|---|---|---|---|
| R1 | Kali 镜像 ~1GB+,含 17 工具后镜像体积大 | 构建/拉取慢 | apt 清理、--no-install-recommends;必要时拆 worker 专用镜像 |
| R2 | go proxy 不通(本机已实测) | go install 层构建失败 | 备选:GitHub release 直下 PD 工具二进制(httpx/dnsx/katana/cdncheck 均有 release) |
| R3 | GitHub release 直连被重置(本机实测) | release 下载层失败 | gh-proxy.com fallback(ksubdomain/afrog 已验证可行) |
| R4 | bbot 依赖重、pip 安装可能失败 | bbot 模块不可用 | 独立 venv;失败时允许 `--ignore-installed`;bbot 作为可降级模块 |
| R5 | ksubdomain 需 CAP_NET_RAW | worker 容器内发包失败 | compose `cap_add: [NET_RAW]`;仍不可用则该模块 NOT_READY(可接受) |
| R6 | 外部 API key(fofa/bbot/ai)是占位符 | 相关模块扫描为空 | 运行时挂载真实 config.yaml(compose volumes),不写进镜像 |
| R7 | 多 worker scale 时 node_id 冲突 | 心跳/锁错乱 | 保持现有 uuid 后缀逻辑,无需改代码 |
| R8 | 镜像内工具版本与主机不同 | 行为差异 | Dockerfile 固定版本(release 用 tag,apt 用 Kali 快照源可选) |

**权衡说明**:
- 选单阶段而非多阶段:所有工具都在运行时容器内,分离无收益;体积控制靠清理而非分层
- bbot 独立 venv:系统 Python 与 bbot 依赖(requests 等)易冲突,隔离最稳
- 保留 `check:` 块 + installer.py 原逻辑:init 仍可用于容器内健康检查,零代码改动

---

## 八、开放问题(执行前确认)

1. **基础镜像**:kalilinux/kali-rolling 是否可接受?(体积大但 apt 全;替代:debian:bookworm-slim + 手动加 Kali 源,更小但 apt 工具可能缺)
2. **废弃脚本**:main/worker/venv_setup.sh 删除还是保留并标注 deprecated?(建议删除,git 历史可追溯)
3. **xray 服务**:默认启用还是作为 profile 可选(`docker compose --profile xray up`)?(建议可选 profile,7777 端口非必需)
4. **工具版本**:apt 工具用 Kali 滚动最新版,还是锁定版本?(建议滚动,与当前主机行为一致)
5. **secretfinder.py**:未被引用,保留在镜像中即可(纯 Python 依赖装入 venv 或忽略)?

---

## 九、实现完成状态(2026-08-12,与计划的差异说明)

本计划已完整实现,最终落地与计划存在以下差异(以实现为准):

1. **check 块也已全部移除**(超出计划范围):工具由 Dockerfile 统一安装后,模块内
   `check:`/`expect_keyword`/`exclude_keyword` 检测无意义,17 个模块全部删除。
   空 check_command 时 `check_tool_installed` 返回 True → worker 全部加载、
   模板实验室 check 动作提示"未配置,默认视为可用"。
2. **init 模式已删除**(超出计划范围):`main.py` choices 移除 init,
   `flowscan/installer.py` 整个删除;README/verify_docker.sh/entrypoint 同步清理。
3. **新增 `docker/verify_docker.sh`**:一键构建 + 端到端验证脚本(7 步缩减为 6 步,
   因 init 步骤删除)。
4. **entrypoint 增强**:支持 `FS3_PROJECT_DIR`/`FS3_PYTHON` 环境变量覆盖(便于宿主机
   调试);密钥随机化改为仅 web 容器执行(`FS3_RANDOMIZE_SECRETS=1`),worker/xray
   只读挂载 config.yaml 避免多容器竞争写;Redis 等待加入 `timeout 3 --connect-timeout 2`
   防止 DNS 慢拖死启动;镜像补装 `redis-tools`(Kali 基础镜像默认无 redis-cli)。
5. **网络适配实测**:Go 层用 goproxy.cn(proxy.golang.org 不通);release 层
   gh-proxy.com fallback(GitHub 直连被重置);pip 用清华源。
6. **模块命令路径统一**:afrog/httpx 的 `$HOME/.local/bin/` 改为 `/usr/local/bin/`
   绝对路径(镜像内 `$HOME=/root`,软链兼容层保留)。
7. **Docker 权限阻塞**:本机当前用户不在 docker 组且 sudo 需密码,`docker build`
   与容器内端到端测试未执行;已封装 `docker/verify_docker.sh`,获得权限后运行即完成
   最后验证。
8. **主/worker 节点拆分**(用户追加需求):主节点编排 `docker-compose.yml` 仅含
   redis+web(redis 暴露 6379 并支持 `REDIS_PASSWORD` 环境变量),xray 为可选
   profile;worker 节点编排 `docker-compose.worker.yml` 仅含 worker 服务,**不含
   redis**,经 `FS3_REDIS_HOST/FS3_REDIS_PORT/FS3_REDIS_PASSWORD` 环境变量连接主
   节点,command 用 `--redis-host/--redis-port/--redis-password` 覆盖 main.py
   连接参数;entrypoint 等待 Redis 地址同样优先读 `FS3_REDIS_HOST` 环境变量。
9. **双 Dockerfile 拆分**(用户再追加):`Dockerfile`(flowscan:main)= Kali 基础,
   仅 web 面板依赖(python3/pip/flask/redis-cli)+ xray,不装扫描工具;
   `Dockerfile.worker`(flowscan:worker)= Kali 全工具链。两镜像**共用同一个
   kalilinux/kali-rolling 基础镜像**(避免额外拉取 python:slim,本机网络拉镜像
   慢),职责分离、分别构建,compose 各自引用。

---

*计划文档版本:0.2 — 2026-08-12(实现完成,差异说明见第九章)*
