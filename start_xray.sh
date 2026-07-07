#!/usr/bin/env bash
set -euo pipefail

# 进入项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 从 config.yaml 读取监听地址
LISTEN_ADDR=$(grep -E '^\s*xray_listen_http_proxy:' config.yaml 2>/dev/null | head -1 | cut -d: -f2- | xargs)
LISTEN_ADDR="${LISTEN_ADDR:-http://0.0.0.0:7777}"

echo "[xray] config listen address: $LISTEN_ADDR"

# 检查 ./bin/xray/xray 是否存在
if [ ! -f "./bin/xray/xray" ]; then
    echo "[xray] 未找到二进制，开始下载..."
    cd ./bin/xray
    curl -fL "https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip" -o xray.zip
    unzip -o xray.zip
    mv xray_linux_amd64 xray
    rm -f xray.zip
    chmod +x xray
    cd "$SCRIPT_DIR"
    echo "[xray] 安装完成"
fi

# 进入 ./bin/xray/ 目录启动
echo "[xray] 启动被动代理..."
cd ./bin/xray
exec ./xray webscan --listen "$LISTEN_ADDR" --html-output ../../xray_out.html 2>&1
