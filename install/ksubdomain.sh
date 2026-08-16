#!/usr/bin/env bash
# 安装 ksubdomain v0.7 — 无状态子域名爆破
# 幂等:PATH 上已有 ksubdomain 则跳过;安装目录自动选择可写位置(root:/usr/local/bin,非 root:~/.local/bin)。
# GitHub 直连失败时走 gh-proxy.com 镜像。
set -euo pipefail

if command -v ksubdomain >/dev/null 2>&1; then
    echo "[install] ksubdomain 已安装,跳过"
    exit 0
fi

BIN_DIR="/usr/local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$HOME/.local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin"
BIN="$BIN_DIR/ksubdomain"

echo "[install] 安装 ksubdomain v0.7 ..."
CURL="curl -fsSL --connect-timeout 5 --max-time 600 --retry 3 --retry-delay 5"
URL="https://github.com/knownsec/ksubdomain/releases/download/v0.7/ksubdomain_linux.zip"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
$CURL "https://gh-proxy.com/$URL" -o dl.zip \
    || $CURL "https://ghproxy.net/$URL" -o dl.zip \
    || $CURL "$URL" -o dl.zip
mkdir -p pkg
unzip -o dl.zip -d pkg
mkdir -p "$BIN_DIR"
find pkg -type f -name "ksubdomain" -perm /111 -print -quit | xargs -I{} install -m 0755 {} "$BIN"
command -v ksubdomain >/dev/null 2>&1
echo "[install] ksubdomain 安装完成"
