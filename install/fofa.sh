#!/usr/bin/env bash
# 安装 fofax v0.1.48 — FOFA 搜索引擎查询(fofa 模块调用 fofax 二进制)
# 幂等:PATH 上已有 fofax 则跳过;安装目录自动选择可写位置(root:/usr/local/bin,非 root:~/.local/bin)。
# GitHub 直连失败时走 gh-proxy.com 镜像。
set -euo pipefail

if command -v fofax >/dev/null 2>&1; then
    echo "[install] fofax 已安装,跳过"
    exit 0
fi

BIN_DIR="/usr/local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$HOME/.local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin"
BIN="$BIN_DIR/fofax"

echo "[install] 安装 fofax v0.1.48 ..."
URL="https://github.com/xiecat/fofax/releases/download/v0.1.48/fofax_v0.1.48_linux_amd64.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# 下载 + sha256 校验 + 离线包优先(见 install/_fetch.sh;可用 FS3_OFFLINE_DIR / FS3_SHA256)
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_fetch.sh"
cd "$TMP"
fs3_fetch dl.tgz "$URL" || exit 1
mkdir -p pkg
tar -xzf dl.tgz -C pkg
mkdir -p "$BIN_DIR"
find pkg -type f -name "fofax*" -perm /111 -print -quit | xargs -I{} install -m 0755 {} "$BIN"
[ -x "$BIN_DIR/fofax" ] || command -v fofax >/dev/null 2>&1
echo "[install] fofax 安装完成"
