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
URL="https://github.com/knownsec/ksubdomain/releases/download/v0.7/ksubdomain_linux.zip"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# 下载 + sha256 校验 + 离线包优先(见 install/_fetch.sh;可用 FS3_OFFLINE_DIR / FS3_SHA256)
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_fetch.sh"
cd "$TMP"
fs3_fetch dl.zip "$URL" || exit 1
mkdir -p pkg
unzip -o dl.zip -d pkg
mkdir -p "$BIN_DIR"
find pkg -type f -name "ksubdomain" -perm /111 -print -quit | xargs -I{} install -m 0755 {} "$BIN"
[ -x "$BIN_DIR/ksubdomain" ] || command -v ksubdomain >/dev/null 2>&1
echo "[install] ksubdomain 安装完成"
