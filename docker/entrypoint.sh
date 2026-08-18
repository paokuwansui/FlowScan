#!/usr/bin/env bash
# FlowScan3 容器入口
# 职责: 1) web 主节点:无条件随机化密钥 + 内嵌 redis + 内嵌 xray(后台)
#        2) 等待 Redis 就绪  3) 执行 CMD(worker/web/status/xray)
set -euo pipefail

PROJECT_DIR="${FS3_PROJECT_DIR:-/app}"
CONFIG_PATH="${PROJECT_DIR}/config.yaml"
PYTHON="${FS3_PYTHON:-/usr/local/bin/flowscan-python}"

echo "[ENTRYPOINT] starting FlowScan3 container (cmd: $*)"

MODE="${1:-}"

# 从 config.yaml 读取 redis 密码(用 yaml 解析,避免 grep/awk 对含引号的随机密码误提取;
# randomize_secrets 生成的密码首字符为特殊字符时 PyYAML 写回必加引号)
redis_password() {
    if [ -f "${CONFIG_PATH}" ] && command -v "${PYTHON}" >/dev/null 2>&1; then
        "${PYTHON}" -c 'import sys
try:
    import yaml
    cfg = yaml.safe_load(open(sys.argv[1])) or {}
    print((cfg.get("redis") or {}).get("password") or "", end="")
except Exception:
    pass' "${CONFIG_PATH}" 2>/dev/null
    fi
}

# 从 config.yaml 读取 redis 端口(配置驱动:配置文件写哪个端口就监听哪个)
redis_port() {
    if [ -f "${CONFIG_PATH}" ] && command -v "${PYTHON}" >/dev/null 2>&1; then
        "${PYTHON}" -c 'import sys
try:
    import yaml
    cfg = yaml.safe_load(open(sys.argv[1])) or {}
    print((cfg.get("redis") or {}).get("redis_port") or 6379, end="")
except Exception:
    print(6379, end="")' "${CONFIG_PATH}" 2>/dev/null
    fi
}

# ── 0. 配置兜底：镜像内无 config.yaml（docker run 未挂载）时用 example 生成 ──
if [ ! -f "${CONFIG_PATH}" ]; then
    if [ -f "${PROJECT_DIR}/config.yaml.example" ]; then
        echo "[ENTRYPOINT] config.yaml 不存在，从 config.yaml.example 生成"
        cp "${PROJECT_DIR}/config.yaml.example" "${CONFIG_PATH}"
    else
        echo "[ENTRYPOINT] [WARN] 无 config.yaml 且无 config.yaml.example，将以默认配置运行"
    fi
fi

# ── 1. web 主节点:启动内嵌 redis + xray ──
# (密钥随机化已挪至 docker/up.sh 执行,容器启动/重启不再变密码,以宿主 config.yaml 为准)
if [ "${MODE}" = "web" ]; then
    REDIS_PASS="$(redis_password)"
    REDIS_PORT="$(redis_port)"
    echo "[ENTRYPOINT] starting embedded redis (no persistence) on port ${REDIS_PORT}..."
    if [ -n "${REDIS_PASS}" ]; then
        redis-server --requirepass "${REDIS_PASS}" --port "${REDIS_PORT}" --save "" --appendonly no --daemonize yes
    else
        redis-server --port "${REDIS_PORT}" --save "" --appendonly no --daemonize yes
    fi

    if [ "${FS3_ENABLE_XRAY:-1}" = "1" ]; then
        echo "[ENTRYPOINT] starting xray passive proxy (background)..."
        (bash "${PROJECT_DIR}/start_xray.sh" >/tmp/xray.log 2>&1 &)
    fi

    if [ "${FS3_ENABLE_YAKIT_MCP:-1}" = "1" ]; then
        echo "[ENTRYPOINT] starting yakit mcp server (background)..."
        (bash "${PROJECT_DIR}/docker/start_yakit_mcp.sh" 2>&1 &)
    fi
fi

# ── 2. 等待 Redis 就绪(仅 web/status;worker 先装工具再连,由 main.py 重试) ──
NEEDS_REDIS=0
case "${MODE}" in
    web|status) NEEDS_REDIS=1 ;;
esac

if [ "${NEEDS_REDIS}" = "1" ]; then
    REDIS_HOST="${FS3_REDIS_HOST:-redis}"
    REDIS_PORT="${FS3_REDIS_PORT:-6379}"
    REDIS_PASS="${FS3_REDIS_PASSWORD:-}"

    if [ "${MODE}" = "web" ]; then
        # web 主节点连本机内嵌 redis(端口/密码都从 config.yaml 读,配置驱动)
        REDIS_HOST="127.0.0.1"
        REDIS_PORT="$(redis_port)"
        REDIS_PASS="$(redis_password)"
    elif [ -z "${REDIS_PASS}" ] && [ -f "${CONFIG_PATH}" ]; then
        # worker 未显式传密码时,回退读挂载的 config.yaml
        REDIS_PASS="$(redis_password)"
    fi

    echo "[ENTRYPOINT] waiting for Redis at ${REDIS_HOST}:${REDIS_PORT}..."
    for i in $(seq 1 30); do
        if [ -n "${REDIS_PASS}" ]; then
            PONG="$(timeout 3 redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" -a "${REDIS_PASS}" --no-auth-warning ping 2>/dev/null || true)"
        else
            PONG="$(timeout 3 redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" ping 2>/dev/null || true)"
        fi
        if echo "${PONG}" | grep -q "PONG"; then
            echo "[ENTRYPOINT] Redis ready"
            break
        fi
        [ "${i}" = "30" ] && echo "[ENTRYPOINT] [ERROR] Redis not reachable after 30s, continuing anyway"
        sleep 1
    done
fi

# ── 3. 执行实际命令 ──
cd "${PROJECT_DIR}"
if [ "${MODE}" = "xray" ]; then
    echo "[ENTRYPOINT] starting xray passive proxy..."
    exec bash "${PROJECT_DIR}/start_xray.sh"
fi
echo "[ENTRYPOINT] exec: python3 main.py $*"
exec "${PYTHON}" main.py "$@"
