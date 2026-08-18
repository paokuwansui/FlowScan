#!/usr/bin/env bash
# Worker 节点启动脚本(与 docker/up.sh 对称)。
#
# ① 密码同步:同机部署时自动把主节点 config.yaml 的 redis 密码写入 config.worker.yaml
#    (worker main.py 每 10s 重读配置自动重连,无需重启);跨机部署无主节点配置,需手动填
# ② 构建/启动:docker compose -f docker-compose.worker.yml up -d [--build]
#
# 用法:
#   bash docker/up_worker.sh            # 启动(镜像已构建)
#   bash docker/up_worker.sh --build    # 首次部署:构建镜像 + 启动
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BUILD=0
for a in "$@"; do
    case "$a" in
        --build) BUILD=1 ;;
        *)
            echo "[up-worker] 未知参数: $a(支持: --build)" >&2
            exit 1
            ;;
    esac
done

cd "${PROJECT_DIR}"

# ── 1. 同步主节点 redis 密码(同机部署;跨机跳过,手动填 config.worker.yaml) ──
if [ -f "${PROJECT_DIR}/config.yaml" ]; then
    if [ -f "${PROJECT_DIR}/config.worker.yaml" ]; then
        if bash "${PROJECT_DIR}/docker/sync_worker_pass.sh" "${PROJECT_DIR}" >/dev/null 2>&1; then
            echo "[up-worker] redis 密码已同步(主节点 config.yaml → config.worker.yaml)"
        else
            echo "[up-worker] 密码同步失败(继续启动,请确认 config.worker.yaml redis 密码正确)" >&2
        fi
    else
        echo "[up-worker] 未找到 config.worker.yaml,请先 cp config.worker.yaml.example config.worker.yaml 并填 redis_host 为主节点 IP" >&2
        exit 1
    fi
else
    echo "[up-worker] 未发现主节点 config.yaml(跨机部署):请确认 config.worker.yaml 的 redis.password 已手动填为主节点当前密码"
fi

# ── 2. 构建/启动(连接信息全部来自挂载的 config.worker.yaml;worker 无端口映射) ──
if [ "${BUILD}" = "1" ]; then
    exec docker compose -f docker-compose.worker.yml up -d --build
else
    exec docker compose -f docker-compose.worker.yml up -d
fi
