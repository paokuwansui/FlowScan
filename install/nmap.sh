#!/usr/bin/env bash
# 安装 nmap — 端口/版本/OS/漏洞脚本扫描
# 幂等:已安装则跳过。Kali 源需切换清华镜像(Dockerfile 已处理;裸机需自行配置)。
set -euo pipefail

if command -v nmap >/dev/null 2>&1; then
    echo "[install] nmap 已安装,跳过"
    exit 0
fi

echo "[install] 安装 nmap ..."
apt-get update -qq
apt-get install -y --no-install-recommends nmap
rm -rf /var/lib/apt/lists/*
command -v nmap >/dev/null 2>&1
echo "[install] nmap 安装完成"
