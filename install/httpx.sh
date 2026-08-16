#!/usr/bin/env bash
# 安装 httpx(ProjectDiscovery HTTP 探活/指纹提取)
# Kali 源包名为 httpx-toolkit(避免与 python3-httpx 库冲突)。
# 幂等:PATH 上已有 httpx 或 httpx-toolkit 则跳过;软链写入可写目录(root:/usr/local/bin,非 root:~/.local/bin)。
set -euo pipefail

if command -v httpx >/dev/null 2>&1; then
    echo "[install] httpx 已安装,跳过"
    exit 0
fi

if ! command -v httpx-toolkit >/dev/null 2>&1; then
    echo "[install] 安装 httpx-toolkit ..."
    apt-get update -qq
    apt-get install -y --no-install-recommends httpx-toolkit
    rm -rf /var/lib/apt/lists/*
fi

# 软链到 PATH 中的可写目录(幂等)
BIN_DIR="/usr/local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$HOME/.local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin"
mkdir -p "$BIN_DIR"
ln -sf "$(command -v httpx-toolkit)" "$BIN_DIR/httpx"
command -v httpx >/dev/null 2>&1
echo "[install] httpx 安装完成"
