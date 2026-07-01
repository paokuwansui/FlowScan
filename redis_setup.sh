#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${CONFIG_PATH:-$PROJECT_DIR/config.yaml}"

sudo apt update
sudo apt install -y redis-server python3 python3-pip

# PyYAML is needed to read config.yaml. Prefer the project requirements when present.
if ! python3 - <<'PY' >/dev/null 2>&1
import yaml
PY
then
  python3 -m pip install PyYAML --break-system-packages
fi

read_redis_config() {
  python3 - "$CONFIG_PATH" <<'PY'
import sys
import yaml
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    cfg = yaml.safe_load(handle) or {}
redis_cfg = cfg.get("redis", {}) or {}
print(redis_cfg.get("host", "127.0.0.1"))
print(int(redis_cfg.get("port", 6379) or 6379))
print(redis_cfg.get("password", "") or "")
print(int(redis_cfg.get("db", 0) or 0))
PY
}

mapfile -t REDIS_LINES < <(read_redis_config)
REDIS_HOST="${REDIS_LINES[0]:-127.0.0.1}"
REDIS_PORT="${REDIS_LINES[1]:-6379}"
REDIS_PASSWORD="${REDIS_LINES[2]:-}"
REDIS_DB="${REDIS_LINES[3]:-0}"

configure_redis_password() {
  local conf=""
  for candidate in /etc/redis/redis.conf /etc/redis.conf; do
    if [ -f "$candidate" ]; then
      conf="$candidate"
      break
    fi
  done

  if [ -z "$conf" ]; then
    echo "[REDIS_SETUP] [WARN] Redis config file not found; skip requirepass configuration"
    return 0
  fi

  if [ -n "$REDIS_PASSWORD" ]; then
    echo "[REDIS_SETUP] Configuring redis-server requirepass from $CONFIG_PATH"
    local tmp
    tmp="$(mktemp)"
    REDIS_PASSWORD="$REDIS_PASSWORD" python3 - "$conf" > "$tmp" <<'PY'
import os
import sys
path = sys.argv[1]
password = os.environ["REDIS_PASSWORD"]
# Redis config supports quoted strings; quote and escape to keep spaces/#/quotes safe.
quoted_password = '"' + password.replace('\\', '\\\\').replace('"', '\\"') + '"'
with open(path, "r", encoding="utf-8", errors="replace") as handle:
    lines = handle.readlines()
updated = []
seen = False
for line in lines:
    stripped = line.lstrip()
    if stripped.startswith("requirepass ") or stripped.startswith("# requirepass "):
        if not seen:
            updated.append(f"requirepass {quoted_password}\n")
            seen = True
        continue
    updated.append(line)
if not seen:
    updated.append(f"\nrequirepass {quoted_password}\n")
sys.stdout.write("".join(updated))
PY
    sudo cp "$conf" "$conf.flowscan3.bak"
    sudo install -m 0644 "$tmp" "$conf"
    rm -f "$tmp"
  else
    echo "[REDIS_SETUP] Redis password in config.yaml is empty; disabling redis-server requirepass"
    local tmp
    tmp="$(mktemp)"
    python3 - "$conf" > "$tmp" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="replace") as handle:
    lines = handle.readlines()
updated = []
for line in lines:
    stripped = line.lstrip()
    if stripped.startswith("requirepass "):
        indent = line[:len(line) - len(stripped)]
        updated.append(f"{indent}# {stripped}")
    else:
        updated.append(line)
sys.stdout.write("".join(updated))
PY
    sudo cp "$conf" "$conf.flowscan3.bak"
    sudo install -m 0644 "$tmp" "$conf"
    rm -f "$tmp"
  fi
}

configure_redis_password
sudo systemctl enable --now redis-server 2>/dev/null || sudo service redis-server start || true
sudo systemctl restart redis-server 2>/dev/null || sudo service redis-server restart || true

if [ -n "$REDIS_PASSWORD" ]; then
  redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" -n "$REDIS_DB" --no-auth-warning ping
else
  redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" ping
fi

echo "[REDIS_SETUP] Redis setup completed: ${REDIS_HOST}:${REDIS_PORT} db=${REDIS_DB}"
