#!/usr/bin/env bash
# 安装 amass — 主动子域名枚举(主动+爆破)
# 幂等:已安装则跳过。Kali 源需切换清华镜像(Dockerfile 已处理;裸机需自行配置)。
set -euo pipefail

if command -v amass >/dev/null 2>&1; then
    echo "[install] amass 已安装,跳过"
    exit 0
fi

echo "[install] 安装 amass ..."
apt-get update -qq
apt-get install -y --no-install-recommends amass
rm -rf /var/lib/apt/lists/*
command -v amass >/dev/null 2>&1
echo "[install] amass 安装完成"
