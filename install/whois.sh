#!/usr/bin/env bash
# 安装 whois(注册信息查询)
# 幂等:已安装则跳过。
set -euo pipefail

if command -v whois >/dev/null 2>&1; then
    echo "[install] whois 已安装,跳过"
    exit 0
fi

echo "[install] 安装 whois ..."
apt-get update -qq
apt-get install -y --no-install-recommends whois
rm -rf /var/lib/apt/lists/*
command -v whois >/dev/null 2>&1
echo "[install] whois 安装完成"
