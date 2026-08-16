#!/usr/bin/env bash
# 安装 feroxbuster — 目录/路径扫描
# 幂等:已安装则跳过。Kali 源需切换清华镜像(Dockerfile 已处理;裸机需自行配置)。
set -euo pipefail

if command -v feroxbuster >/dev/null 2>&1; then
    echo "[install] feroxbuster 已安装,跳过"
    exit 0
fi

echo "[install] 安装 feroxbuster ..."
apt-get update -qq
apt-get install -y --no-install-recommends feroxbuster
rm -rf /var/lib/apt/lists/*
command -v feroxbuster >/dev/null 2>&1
echo "[install] feroxbuster 安装完成"
