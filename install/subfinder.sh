#!/usr/bin/env bash
# 安装 subfinder — 被动子域名枚举
# 幂等:已安装则跳过。Kali 源需切换清华镜像(Dockerfile 已处理;裸机需自行配置)。
set -euo pipefail

if command -v subfinder >/dev/null 2>&1; then
    echo "[install] subfinder 已安装,跳过"
    exit 0
fi

echo "[install] 安装 subfinder ..."
apt-get update -qq
apt-get install -y --no-install-recommends subfinder
rm -rf /var/lib/apt/lists/*
command -v subfinder >/dev/null 2>&1
echo "[install] subfinder 安装完成"
