#!/usr/bin/env bash
# 安装 chromium(网页截图,headless)
# 幂等:已安装 chromium 或 google-chrome 则跳过。Kali apt 源有 chromium。
set -euo pipefail

if command -v chromium >/dev/null 2>&1 || command -v google-chrome >/dev/null 2>&1; then
    echo "[install] chromium/chrome 已安装,跳过"
    exit 0
fi

echo "[install] 安装 chromium ..."
apt-get update -qq
apt-get install -y --no-install-recommends chromium
rm -rf /var/lib/apt/lists/*
command -v chromium >/dev/null 2>&1
echo "[install] chromium 安装完成"
