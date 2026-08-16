#!/usr/bin/env bash
# 安装 ip_resolve 模块依赖 — dnsx + cdncheck(均从 GitHub release 安装)
# 幂等:PATH 上已存在则跳过;安装目录自动选择可写位置(root:/usr/local/bin,非 root:~/.local/bin)。
# GitHub 直连失败时走 gh-proxy.com 镜像。
set -euo pipefail

BIN_DIR="/usr/local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$HOME/.local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin"
CURL="curl -fsSL --connect-timeout 5 --max-time 600 --retry 3 --retry-delay 5"

install_from_zip() {
    # install_from_zip <binary_name> <download_url> <zip_glob>
    local name="$1" url="$2" glob="$3"
    if command -v "$name" >/dev/null 2>&1; then
        echo "[install] $name 已安装,跳过"
        return 0
    fi
    echo "[install] 安装 $name ..."
    local tmp
    tmp="$(mktemp -d)"
    cd "$tmp"
    $CURL "https://gh-proxy.com/$url" -o dl.zip \
        || $CURL "https://ghproxy.net/$url" -o dl.zip \
        || $CURL "$url" -o dl.zip
    mkdir -p pkg
    unzip -o dl.zip -d pkg >/dev/null
    mkdir -p "$BIN_DIR"
    find pkg -type f -name "$glob" -perm /111 -print -quit | xargs -I{} install -m 0755 {} "$BIN_DIR/$name"
    rm -rf "$tmp"
    command -v "$name" >/dev/null 2>&1
    echo "[install] $name 安装完成"
}

install_from_zip dnsx "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.2/dnsx_1.2.2_linux_amd64.zip" "dnsx"
install_from_zip cdncheck "https://github.com/projectdiscovery/cdncheck/releases/download/v1.2.48/cdncheck_1.2.48_linux_amd64.zip" "cdncheck"

command -v dnsx >/dev/null 2>&1
command -v cdncheck >/dev/null 2>&1
echo "[install] ip_resolve 依赖安装完成"
