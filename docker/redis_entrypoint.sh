#!/usr/bin/env sh
# FlowScan redis 容器入口:从挂载的 config.yaml 读 redis.password 并以 requirepass 启动
set -e

CONFIG_PATH="/app/config.yaml"
REDIS_PASS=""
if [ -f "${CONFIG_PATH}" ]; then
    REDIS_PASS="$(grep -A5 '^redis:' "${CONFIG_PATH}" | grep 'password:' | head -1 | awk '{print $2}' | tr -d '"')"
fi

if [ -n "${REDIS_PASS}" ]; then
    echo "[REDIS] starting with requirepass (from config.yaml)"
    exec redis-server --requirepass "${REDIS_PASS}" --save "" --appendonly no
fi
echo "[REDIS] starting without password"
exec redis-server --save "" --appendonly no
