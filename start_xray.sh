#!/usr/bin/env bash
set -euo pipefail

# 进入项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 从 config.yaml 读取监听地址(去行尾注释,防 # 被带入地址)
LISTEN_ADDR=$(grep -E '^\s*xray_listen_http_proxy:' config.yaml 2>/dev/null | head -1 | cut -d: -f2- | sed 's/#.*//' | xargs)
LISTEN_ADDR="${LISTEN_ADDR:-http://0.0.0.0:65002}"

echo "[xray] config listen address: $LISTEN_ADDR"

# 检查 ./bin/xray/xray 或 /usr/local/bin/xray 是否存在
XRAY_BIN=""
if [ -f "./bin/xray/xray" ]; then
    XRAY_BIN="./bin/xray/xray"
elif [ -f "/usr/local/bin/xray" ]; then
    XRAY_BIN="/usr/local/bin/xray"
else
    echo "[xray] 未找到二进制，开始下载..."
    cd ./bin/xray
    curl -fL "https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip" -o xray.zip
    unzip -o xray.zip
    mv xray_linux_amd64 xray
    rm -f xray.zip
    chmod +x xray
    cd "$SCRIPT_DIR"
    XRAY_BIN="./bin/xray/xray"
    echo "[xray] 安装完成"
fi

# 进入 ./bin/xray/ 目录启动(CA 证书相对路径依赖)
echo "[xray] 启动被动代理..."
cd ./bin/xray
# xray 拒绝覆盖已存在的输出文件,输出到 reports 目录并先清理
mkdir -p ../../reports
rm -f ../../reports/xray_out.html ../../reports/xray_out.json
# 后台轮询放宽报告权限:xray 以 root 写 0640,web 进程(clay64)读不了——
# 文件写入后立即 chmod 644(2s 轮询,开销可忽略)
python3 - <<'PY' &
import time, os
d = "../../reports"
while True:
    try:
        for f in os.listdir(d):
            if f.startswith("xray_out"):
                p = os.path.join(d, f)
                if os.path.isfile(p):
                    os.chmod(p, 0o644)
    except OSError:
        pass
    time.sleep(2)
PY
exec "${XRAY_BIN}" webscan --listen "$LISTEN_ADDR" \
    --html-output ../../reports/xray_out.html \
    --json-output ../../reports/xray_out.json 2>&1
