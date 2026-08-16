# ============================================================================
# FlowScan3 主节点镜像(web 控制面板 + 可选 xray)
# 构建: docker build -t flowscan:main .
# 基础: kalilinux/kali-rolling(与 worker 镜像共用同一基础,避免额外拉取 python:slim)
# 注意: 仅装 web 面板运行依赖,不装扫描工具(见 Dockerfile.worker)
# ============================================================================
FROM kalilinux/kali-rolling:latest

# ────────────────────────────────────────────────────────────────────────────
# 第 0 层:统一 Kali apt 源为清华镜像
# 官方 http.kali.org 是 302 重定向,会随机落到各镜像站(mirror.wane.kr 已不可达,
# 某些包只在不可达镜像有候选 → apt 装包失败 exit 100)。清华与 pip 同源,已验证可达。
# ────────────────────────────────────────────────────────────────────────────
RUN printf 'Types: deb\nURIs: http://mirrors.tuna.tsinghua.edu.cn/kali\nSuites: kali-rolling\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/kali-archive-keyring.gpg\n' > /etc/apt/sources.list.d/kali.sources

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/root \
    PATH=/usr/local/bin:/root/.local/bin:/usr/bin:/bin \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple

# ────────────────────────────────────────────────────────────────────────────
# 第 1 层:系统依赖(redis-server 内嵌主节点 redis;curl/unzip 下载 xray)
# ────────────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        redis-server \
        redis-tools \
        curl \
        wget \
        unzip \
        ca-certificates \
        libpcap0.8 \
        chromium \
        chromium-driver \
        fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

# ────────────────────────────────────────────────────────────────────────────
# 第 2 层:Python 依赖(web 面板运行所需)
# Kali python3-pip 默认 PEP668 externally-managed,需 --break-system-packages
# ────────────────────────────────────────────────────────────────────────────
RUN pip3 install --break-system-packages --no-cache-dir \
        PyYAML \
        redis \
        flask \
        tldextract \
        httpx \
        beautifulsoup4 \
        browser-use \
    && ln -sf /usr/bin/python3 /usr/local/bin/flowscan-python

# ────────────────────────────────────────────────────────────────────────────
# 第 3 层:xray 被动代理(可选服务,由 compose profile 控制是否启动)
# 官方源优先,失败 fallback gh-proxy.com
# ────────────────────────────────────────────────────────────────────────────
RUN set -eux; \
    mkdir -p /tmp/dl && cd /tmp/dl; \
    (curl -fsSL "https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip" -o xray.zip \
      || curl -fsSL "https://gh-proxy.com/https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip" -o xray.zip); \
    unzip -o xray.zip -d xray_pkg; \
    find xray_pkg -type f \( -name "xray" -o -name "xray_linux_amd64" \) -perm /111 -print -quit \
      | xargs -I{} install -m 0755 {} /usr/local/bin/xray; \
    rm -rf /tmp/dl

# xray 1.9.11 从二进制同目录查找 xray.yaml;module/plugin/CA 从 cwd 加载
# → xray.yaml 复制到 /usr/local/bin/,启动时 cwd 指向 /app/bin/xray

# ────────────────────────────────────────────────────────────────────────────
# 第 3.5 层:yaklang(yakit 脚本引擎,供 MCP/Agent 调用)
# 官方安装脚本(阿里云 OSS 源,国内可达):自动取最新版本、幂等(已装同版本
# 非交互下 read 直接 EOF 跳过)。镜像内 `yak mcp` 提供 SSE MCP server(11432)。
# ────────────────────────────────────────────────────────────────────────────
RUN set -eux; \
    curl -sS -L http://oss-qn.yaklang.com/install-latest-yak.sh -o /tmp/install_yak.sh; \
    bash /tmp/install_yak.sh; \
    rm -f /tmp/install_yak.sh; \
    command -v yak && yak version

# ────────────────────────────────────────────────────────────────────────────
# 项目代码(web 面板加载 modules/ 定义与 flowscan3 核心库)
# ────────────────────────────────────────────────────────────────────────────
WORKDIR /app
COPY . /app

# xray 配置:xray.yaml 复制到二进制同目录(1.9.11 从此查找主配置)
RUN cp /app/bin/xray/xray.yaml /usr/local/bin/xray.yaml

# ────────────────────────────────────────────────────────────────────────────
# 入口(默认 web;xray 由 compose command 覆盖)
# ────────────────────────────────────────────────────────────────────────────
COPY docker/entrypoint.sh /usr/local/bin/flowscan-entrypoint.sh
RUN chmod +x /usr/local/bin/flowscan-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/flowscan-entrypoint.sh"]
CMD ["web", "--host", "0.0.0.0", "--port", "8080"]
