#!/usr/bin/env sh
# FlowScan redis 健康检查:与 entrypoint 相同方式解析密码后 ping
CONFIG_PATH="/app/config.yaml"
REDIS_PASS=""
if [ -f "${CONFIG_PATH}" ]; then
    REDIS_PASS="$(grep -A5 '^redis:' "${CONFIG_PATH}" | grep 'password:' | head -1 | awk '{print $2}' | tr -d '"')"
fi

if [ -n "${REDIS_PASS}" ]; then
    redis-cli -a "${REDIS_PASS}" --no-auth-warning ping 2>/dev/null | grep -q PONG
else
    redis-cli ping 2>/dev/null | grep -q PONG
fi
