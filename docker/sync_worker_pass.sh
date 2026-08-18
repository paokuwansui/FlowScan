#!/usr/bin/env bash
# 同步主节点 redis 密码到 worker 配置(同机部署用)。
#
# 背景:主节点 docker/up.sh 每次启动随机化 redis 密码(写 config.yaml),
# worker 挂载独立的 config.worker.yaml,密码不会自动更新 → worker 认证失败。
# 主节点每次 up.sh 后(或 docker/up_worker.sh 启动时)跑一次本脚本,
# worker(main.py 每 10s 重读 config)自动重连,无需重启 worker。
#
# 用法: bash docker/sync_worker_pass.sh [项目根目录]
set -euo pipefail
PROJECT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

python3 - "$PROJECT_DIR" <<'PYEOF'
import os
import sys

root = sys.argv[1]
main_cfg_path = os.path.join(root, "config.yaml")
worker_cfg_path = os.path.join(root, "config.worker.yaml")

import yaml

try:
    main_cfg = yaml.safe_load(open(main_cfg_path, encoding="utf-8")) or {}
except Exception as e:
    print(f"[sync] 读取主节点配置失败: {e}")
    sys.exit(1)

pw = str((main_cfg.get("redis") or {}).get("password") or "")
if not pw:
    print("[sync] 主节点 redis 密码为空,跳过")
    sys.exit(0)

try:
    worker_cfg = yaml.safe_load(open(worker_cfg_path, encoding="utf-8")) or {}
except Exception:
    worker_cfg = {}

worker_cfg.setdefault("redis", {})["password"] = pw
with open(worker_cfg_path, "w", encoding="utf-8") as f:
    yaml.safe_dump(worker_cfg, f, allow_unicode=True, sort_keys=False)
print(f"[sync] redis 密码已同步到 {os.path.basename(worker_cfg_path)}(worker 10s 内自动重连)")
PYEOF
