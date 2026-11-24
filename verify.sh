#!/usr/bin/env bash
# FlowScan 本地验证入口:转调回归脚本(六支, 纯本地, 不连真 Redis)。
#
#   bash verify.sh          # 或 ./verify.sh
#
# 回归脚本本体在技能目录(用户"交付物零痕迹"要求:项目内不放测试代码),
# 本文件只是给本地会话/工具一个可识别的入口 —— **交付前删除**。
# 换机器时可用 FLOWSCAN_VERIFY_DIR 指向脚本所在目录。
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="${FLOWSCAN_VERIFY_DIR:-$HOME/.hermes/skills/software-development/flowscan/scripts}"
RUNNER="$SCRIPTS/run_all_verify.sh"

if [ ! -f "$RUNNER" ]; then
    echo "verify.sh: 找不到回归脚本: $RUNNER" >&2
    echo "  设 FLOWSCAN_VERIFY_DIR=<脚本目录> 指定位置" >&2
    exit 2
fi
exec bash "$RUNNER" "$ROOT"
