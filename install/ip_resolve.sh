#!/usr/bin/env bash
# 安装 ip_resolve 模块依赖 — dnsx + cdncheck(均从 GitHub release 安装)
# 幂等:PATH 上已存在则跳过;安装目录自动选择可写位置(root:/usr/local/bin,非 root:~/.local/bin)。
# GitHub 直连失败时走 gh-proxy.com 镜像。
set -euo pipefail

BIN_DIR="/usr/local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$HOME/.local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin"
# 下载 + sha256 校验 + 离线包优先(见 install/_fetch.sh;可用 FS3_OFFLINE_DIR / FS3_SHA256)
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_fetch.sh"

ORIG_PWD="$PWD"
TMP=""
# 异常退出也要清临时目录(此前只在函数末尾 rm,失败路径会残留)
trap 'rm -rf "$TMP"' EXIT

install_from_zip() {
    # install_from_zip <binary_name> <download_url> <zip_glob>
    local name="$1" url="$2" glob="$3"
    if command -v "$name" >/dev/null 2>&1; then
        echo "[install] $name 已安装,跳过"
        return 0
    fi
    echo "[install] 安装 $name ..."
    TMP="$(mktemp -d)"
    cd "$TMP"
    fs3_fetch dl.zip "$url" || { cd "$ORIG_PWD"; return 1; }
    mkdir -p pkg
    unzip -o dl.zip -d pkg >/dev/null
    mkdir -p "$BIN_DIR"
    find pkg -type f -name "$glob" -perm /111 -print -quit | xargs -I{} install -m 0755 {} "$BIN_DIR/$name"
    cd "$ORIG_PWD"       # 先回原目录再删,否则函数返回后 cwd 指向已删目录
    rm -rf "$TMP"
    TMP=""
    [ -x "$BIN_DIR/$name" ] || command -v "$name" >/dev/null 2>&1
    echo "[install] $name 安装完成"
}

install_from_zip dnsx "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.2/dnsx_1.2.2_linux_amd64.zip" "dnsx"
install_from_zip cdncheck "https://github.com/projectdiscovery/cdncheck/releases/download/v1.2.48/cdncheck_1.2.48_linux_amd64.zip" "cdncheck"

[ -x "$BIN_DIR/dnsx" ] || command -v dnsx >/dev/null 2>&1
[ -x "$BIN_DIR/cdncheck" ] || command -v cdncheck >/dev/null 2>&1
echo "[install] ip_resolve 依赖安装完成"
