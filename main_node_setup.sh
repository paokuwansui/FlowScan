#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${PROJECT_DIR}/config.yaml"
VENV_PYTHON="${PROJECT_DIR}/flowscan_venv/bin/python3"

echo "============================================"
echo " FlowScan3 Main Node Setup"
echo "============================================"

# ── Step 1: Randomize secrets ──
echo ""
echo "[1/4] Randomizing secrets in config.yaml..."
if [ ! -f "${PROJECT_DIR}/tools/randomize_secrets.py" ]; then
    echo "ERROR: tools/randomize_secrets.py not found"
    exit 1
fi
"${VENV_PYTHON}" "${PROJECT_DIR}/tools/randomize_secrets.py" "${CONFIG_PATH}"

# ── Step 2: Read Redis config from config.yaml ──
echo ""
echo "[2/4] Reading Redis configuration from config.yaml..."
read_redis_config() {
    "${VENV_PYTHON}" - "${CONFIG_PATH}" <<'PY'
import sys, yaml
path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    cfg = yaml.safe_load(fh) or {}
r = cfg.get("redis", {}) or {}
print(r.get("listen_host", "127.0.0.1"))
print(int(r.get("port", 6379) or 6379))
print(r.get("password", "") or "")
print(int(r.get("db", 0) or 0))
PY
}

mapfile -t REDIS < <(read_redis_config)
LISTEN_HOST="${REDIS[0]:-127.0.0.1}"
PORT="${REDIS[1]:-6379}"
PASSWORD="${REDIS[2]:-}"
DB="${REDIS[3]:-0}"

echo "  listen_host = ${LISTEN_HOST}"
echo "  port        = ${PORT}"
echo "  password    = ${PASSWORD:0:8}..."
echo "  db          = ${DB}"

# ── Step 3: Install & configure Redis ──
echo ""
echo "[3/4] Installing and configuring redis-server..."

sudo apt update -qq
sudo apt install -y redis-server

# Locate redis.conf
REDIS_CONF=""
for candidate in /etc/redis/redis.conf /etc/redis.conf; do
    if [ -f "$candidate" ]; then
        REDIS_CONF="$candidate"
        break
    fi
done

if [ -z "$REDIS_CONF" ]; then
    echo "ERROR: redis.conf not found"
    exit 1
fi

# Backup original
sudo cp "$REDIS_CONF" "${REDIS_CONF}.flowscan3.bak"

# Apply config via Python (handles quoting, escaping, edge cases cleanly)
TMP_CONF="$(mktemp)"
VENV_PYTHON="${VENV_PYTHON}" \
LISTEN_HOST="${LISTEN_HOST}" \
PORT="${PORT}" \
PASSWORD="${PASSWORD}" \
"${VENV_PYTHON}" - "$REDIS_CONF" > "$TMP_CONF" <<'PY'
import os, shlex, sys

conf_path = sys.argv[1]
listen_host = os.environ["LISTEN_HOST"]
port = os.environ["PORT"]
password = os.environ["PASSWORD"]

with open(conf_path, encoding="utf-8", errors="replace") as fh:
    lines = fh.readlines()

bind_seen = False
port_seen = False
pass_seen = False
bgsave_seen = False
out = []

for line in lines:
    stripped = line.lstrip()

    # bind
    if stripped.startswith("bind ") or stripped.startswith("# bind "):
        if not bind_seen:
            out.append(f"bind {listen_host}\n")
            bind_seen = True
        continue

    # port
    if stripped.startswith("port ") or stripped.startswith("# port "):
        if not port_seen:
            out.append(f"port {port}\n")
            port_seen = True
        continue

    # requirepass
    if stripped.startswith("requirepass ") or stripped.startswith("# requirepass "):
        if not pass_seen:
            if password:
                qp = shlex.quote(password)
                out.append(f"requirepass {qp}\n")
            else:
                out.append(f"# requirepass (disabled — password empty in config.yaml)\n")
            pass_seen = True
        continue

    # stop-writes-on-bgsave-error
    if stripped.startswith("stop-writes-on-bgsave-error ") or stripped.startswith("# stop-writes-on-bgsave-error "):
        if not bgsave_seen:
            out.append("stop-writes-on-bgsave-error no\n")
            bgsave_seen = True
        continue

    out.append(line)

if not bind_seen:
    out.append(f"\nbind {listen_host}\n")
if not port_seen:
    out.append(f"port {port}\n")
if not pass_seen and password:
    qp = shlex.quote(password)
    out.append(f"requirepass {qp}\n")
if not bgsave_seen:
    out.append("\nstop-writes-on-bgsave-error no\n")

sys.stdout.write("".join(out))
PY

sudo install -m 0644 "$TMP_CONF" "$REDIS_CONF"
rm -f "$TMP_CONF"

echo "  redis.conf updated: bind=${LISTEN_HOST} port=${PORT} requirepass=$( [[ -n "$PASSWORD" ]] && echo 'set' || echo 'disabled' ) bgsave_write=always"

# ── Step 4: Start Redis & verify ──
echo ""
echo "[4/4] Starting Redis and verifying..."

sudo systemctl enable redis-server 2>/dev/null || true
sudo systemctl restart redis-server 2>/dev/null || sudo service redis-server restart 2>/dev/null || true

sleep 1

if [ -n "$PASSWORD" ]; then
    redis-cli -h "$LISTEN_HOST" -p "$PORT" -a "$PASSWORD" -n "$DB" --no-auth-warning ping
else
    redis-cli -h "$LISTEN_HOST" -p "$PORT" -n "$DB" ping
fi

echo ""
echo "============================================"
echo " Main node setup complete!"
echo " Redis:  ${LISTEN_HOST}:${PORT}  db=${DB}"
echo " Config: ${CONFIG_PATH}"
echo "============================================"
