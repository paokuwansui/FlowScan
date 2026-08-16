#!/usr/bin/env bash
# 安装 katana v1.7.0 — 爬虫
# 幂等:PATH 上已有 katana 则跳过;安装目录自动选择可写位置(root:/usr/local/bin,非 root:~/.local/bin)。
# GitHub 直连失败时走 gh-proxy.com 镜像。
set -euo pipefail

if command -v katana >/dev/null 2>&1; then
    echo "[install] katana 已安装,跳过"
    exit 0
fi

BIN_DIR="/usr/local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$HOME/.local/bin"
[ -w "$BIN_DIR" ] || BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin"
BIN="$BIN_DIR/katana"

echo "[install] 安装 katana v1.7.0 ..."
CURL="curl -fsSL --connect-timeout 5 --max-time 600 --retry 3 --retry-delay 5"
URL="https://github.com/projectdiscovery/katana/releases/download/v1.7.0/katana_1.7.0_linux_amd64.zip"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
$CURL "https://gh-proxy.com/$URL" -o dl.zip \
    || $CURL "https://ghproxy.net/$URL" -o dl.zip \
    || $CURL "$URL" -o dl.zip
mkdir -p pkg
unzip -o dl.zip -d pkg
mkdir -p "$BIN_DIR"
find pkg -type f -name "katana" -perm /111 -print -quit | xargs -I{} install -m 0755 {} "$BIN"
command -v katana >/dev/null 2>&1
echo "[install] katana 安装完成"

# ── 预下载 rod Chromium ──
# katana 用 go-rod 做 JS 渲染,首次运行会自动下载 Chromium 到 ~/.cache/rod/browser/,
# 下载进度日志会混入扫描 stdout 变成 FINDING 垃圾事件。
# 这里提前触发一次下载(指向不可达地址,只启动浏览器下载、不实际爬取)。
if [ -z "${ROD_BROWSER_PATH:-}" ] && ! ls "$HOME/.cache/rod/browser/"* 2>/dev/null | grep -q .; then
    echo "[install] 预下载 katana 的 Chromium(go-rod,约 150MB,耐心等待) ..."
    timeout 600 katana -u http://127.0.0.1:1 -silent -no-sandbox 2>&1 | head -20 || true
    if ls "$HOME/.cache/rod/browser/"* 2>/dev/null | grep -q .; then
        echo "[install] Chromium 预下载完成"
    else
        echo "[install] 警告: Chromium 预下载未完成(可手动运行一次 katana 触发)"
    fi
else
    echo "[install] 已存在系统/rod Chromium,跳过预下载"
fi
