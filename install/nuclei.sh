#!/usr/bin/env bash
# 安装 nuclei — 漏洞模板扫描
# 幂等:已安装则跳过。Kali 源需切换清华镜像(Dockerfile 已处理;裸机需自行配置)。
set -euo pipefail

if command -v nuclei >/dev/null 2>&1; then
    echo "[install] nuclei 已安装,跳过"
    exit 0
fi

echo "[install] 安装 nuclei ..."
apt-get update -qq
apt-get install -y --no-install-recommends nuclei
rm -rf /var/lib/apt/lists/*
nuclei -update-templates || true
command -v nuclei >/dev/null 2>&1
echo "[install] nuclei 安装完成"
