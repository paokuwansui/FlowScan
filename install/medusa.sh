#!/usr/bin/env bash
# 安装 medusa(并行暴力破解,弱口令爆破)
# 幂等:已安装则跳过。Kali apt 源有 medusa 包。
set -euo pipefail

if command -v medusa >/dev/null 2>&1; then
    echo "[install] medusa 已安装,跳过"
    exit 0
fi

echo "[install] 安装 medusa ..."
apt-get update -qq
apt-get install -y --no-install-recommends medusa
rm -rf /var/lib/apt/lists/*
command -v medusa >/dev/null 2>&1
echo "[install] medusa 安装完成"
