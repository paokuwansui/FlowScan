#!/usr/bin/env bash
# 安装 arjun — HTTP 参数发现(Kali apt 源)
# 幂等:已安装则跳过。
set -euo pipefail

if command -v arjun >/dev/null 2>&1; then
    echo "[install] arjun 已安装,跳过"
    exit 0
fi

echo "[install] 安装 arjun ..."
apt-get update -qq
apt-get install -y --no-install-recommends arjun
rm -rf /var/lib/apt/lists/*
command -v arjun >/dev/null 2>&1
echo "[install] arjun 安装完成"
