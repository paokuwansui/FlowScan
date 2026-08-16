#!/usr/bin/env bash
# 安装 whatweb — 网站指纹识别
# 幂等:已安装则跳过。Kali 源需切换清华镜像(Dockerfile 已处理;裸机需自行配置)。
set -euo pipefail

if command -v whatweb >/dev/null 2>&1; then
    echo "[install] whatweb 已安装,跳过"
    exit 0
fi

echo "[install] 安装 whatweb ..."
apt-get update -qq
apt-get install -y --no-install-recommends whatweb
rm -rf /var/lib/apt/lists/*
command -v whatweb >/dev/null 2>&1
echo "[install] whatweb 安装完成"
