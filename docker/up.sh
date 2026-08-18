#!/usr/bin/env bash
# FlowScan 主节点一键启动(配置驱动):
#   1) 随机化密钥(redis 密码/web 密码/secret_key)→ 同机 worker 配置自动同步新密码
#   2) 从 config.yaml 读取端口生成 .env → compose 端口映射/健康检查跟随配置
#
# 用法:
#   bash docker/up.sh [config.yaml 路径] [--build] [--no-randomize]
#     --build         重建镜像(改代码/依赖时用;仅改配置不需要)
#     --no-randomize  跳过密钥随机化(改端口等不想换密码时用)
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONFIG_PATH=""
EXTRA_ARGS=()
NO_RANDOMIZE=0
for a in "$@"; do
    case "$a" in
        --no-randomize) NO_RANDOMIZE=1 ;;
        --*) EXTRA_ARGS+=("$a") ;;
        *)
            # 第一个非 flag 参数 = config.yaml 路径(flag 可任意顺序)
            if [ -z "${CONFIG_PATH}" ]; then
                CONFIG_PATH="$a"
            else
                EXTRA_ARGS+=("$a")
            fi
            ;;
    esac
done
CONFIG_PATH="${CONFIG_PATH:-${PROJECT_DIR}/config.yaml}"

if [ ! -f "${CONFIG_PATH}" ]; then
    echo "[up] config.yaml 不存在: ${CONFIG_PATH}" >&2
    exit 1
fi

# ── 1. 随机化密钥(每次 up 换新密码,容器重启不再变)──
if [ "${NO_RANDOMIZE}" = "1" ]; then
    echo "[up] 跳过密钥随机化(--no-randomize)"
else
    echo "[up] randomizing secrets..."
    "${FS3_PYTHON:-python3}" "${PROJECT_DIR}/tools/randomize_secrets.py" "${CONFIG_PATH}" \
        || echo "[up] [WARN] randomize_secrets failed, continuing"
    # 同机 worker 配置存在时,自动同步新 redis 密码(worker 每 10s 重读 config 自动重连)
    if [ -f "${PROJECT_DIR}/config.worker.yaml" ]; then
        bash "${PROJECT_DIR}/docker/sync_worker_pass.sh" "${PROJECT_DIR}" || true
    fi
fi

# ── 2. 从 config.yaml 读端口 → .env(docker compose 自动加载,变量插值 ${WEB_PORT} 等)──
"${FS3_PYTHON:-python3}" - "${CONFIG_PATH}" "${PROJECT_DIR}" "${PROJECT_DIR}/.env" <<'PYEOF'
import json as _json
import os
import sys

config_path = sys.argv[1]
project_dir = sys.argv[2]
try:
    import yaml
    cfg = yaml.safe_load(open(config_path)) or {}
except Exception:
    cfg = {}
# 默认端口排布(65000-65535 段):web=65000 / redis=65001 / xray=65002 / phishing=65005
web = (cfg.get("web_config") or {}).get("port", 65000)
redis_port = (cfg.get("redis") or {}).get("redis_port", 65001)
xray = 65002
try:
    xl = str((cfg.get("xray_listen_http_proxy") or "0.0.0.0:65002"))
    xray = int(xl.rsplit(":", 1)[-1])
except Exception:
    pass
# XSS 反连服务器端口:config.yaml 的 phishing.port 优先(合并后统一在外层改),回退 phishing_server/config.json
phish = 65005
try:
    pc = (cfg.get("phishing") or {}).get("port") or _json.load(
        open(os.path.join(project_dir, "phishing_server", "config.json"))).get("port", 65005)
    phish = int(pc)
except Exception:
    pass
with open(sys.argv[3], "w", encoding="utf-8") as f:
    f.write(f"WEB_PORT={web}\nREDIS_PORT={redis_port}\nXRAY_PORT={xray}\nPHISH_PORT={phish}\n")
print(f"[up] config 驱动端口: WEB_PORT={web} REDIS_PORT={redis_port} XRAY_PORT={xray} PHISH_PORT={phish}")
PYEOF

cd "${PROJECT_DIR}"
if [ "${NO_RANDOMIZE}" = "1" ]; then
    # 未随机化:配置未变,compose 自行判断(端口变化时自动 recreate)
    exec docker compose up -d "${EXTRA_ARGS[@]}"
else
    # 已随机化:强制重建容器,让 web/redis 进程加载新密钥(仅改端口也可接受秒级重建)
    exec docker compose up -d --force-recreate "${EXTRA_ARGS[@]}"
fi
