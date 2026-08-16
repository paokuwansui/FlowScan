#!/usr/bin/env bash
# 安装 naabu — 全端口扫描
# 幂等:已安装则跳过。Kali 源需切换清华镜像(Dockerfile 已处理;裸机需自行配置)。
set -euo pipefail

if command -v naabu >/dev/null 2>&1; then
    echo "[install] naabu 已安装,跳过"
    exit 0
fi

echo "[install] 安装 naabu ..."
apt-get update -qq
apt-get install -y --no-install-recommends naabu
rm -rf /var/lib/apt/lists/*
command -v naabu >/dev/null 2>&1
echo "[install] naabu 安装完成"
