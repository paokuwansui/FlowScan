#!/usr/bin/env bash
# 启动 yakit MCP server(SSE,127.0.0.1:11432)
# 与 config.yaml mcp.servers 的 yakit 条目(url: http://127.0.0.1:11432/sse)对应;
# 由 entrypoint.sh web 模式后台调用,日志直接进容器 stdout(docker logs 可见)。
set -euo pipefail

if ! command -v yak >/dev/null 2>&1; then
    echo "[yakit-mcp] yak 未安装,跳过 MCP 启动"
    exit 0
fi

echo "[yakit-mcp] starting yak mcp server (sse 127.0.0.1:11432, --enable-all)..."
# --enable-all: 暴露全部工具集(默认仅 12 个常用集合);FlowScan 侧有 schema 精简与缓存
exec yak mcp --transport sse --host 127.0.0.1 --port 11432 --enable-all 2>&1
