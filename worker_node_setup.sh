#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Kali detection & repo bootstrap ──
if grep -qi kali /etc/os-release 2>/dev/null; then
    echo "[WORKER_SETUP] Kali Linux detected, skipping repo addition"
else
    echo "[WORKER_SETUP] Non-Kali system detected, adding Kali repository..."
    KALI_KEY_URL="https://archive.kali.org/archive-key.asc"
    KALI_REPO="deb http://http.kali.org/kali kali-rolling main non-free contrib"

    # Import Kali GPG key
    if command -v wget &>/dev/null; then
        wget -qO - "$KALI_KEY_URL" \
        | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/kali.gpg 2>/dev/null \
        || wget -qO - "$KALI_KEY_URL" | sudo apt-key add - 2>/dev/null \
        || echo "[WORKER_SETUP] [WARN] Could not import Kali GPG key"
    elif command -v curl &>/dev/null; then
        curl -fsSL "$KALI_KEY_URL" \
        | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/kali.gpg 2>/dev/null \
        || curl -fsSL "$KALI_KEY_URL" | sudo apt-key add - 2>/dev/null \
        || echo "[WORKER_SETUP] [WARN] Could not import Kali GPG key"
    fi

    echo "$KALI_REPO" | sudo tee /etc/apt/sources.list.d/kali.list > /dev/null

    # Apt pinning: prefer system packages over Kali by default to avoid breakage
    PIN_FILE="/etc/apt/preferences.d/kali-pin"
    if [ ! -f "$PIN_FILE" ]; then
        sudo tee "$PIN_FILE" > /dev/null <<'PIN'
Package: *
Pin: origin http.kali.org
Pin-Priority: 50
PIN
        echo "[WORKER_SETUP] Kali apt pinning applied (priority 50, won't override system packages)"
    fi
fi
sudo apt update -qq
sudo apt install -y golang-go unzip wget curl
mkdir -p "$HOME/.local/bin" "$HOME/go/tmp"

EXPORT_CMD='export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"'
GOTMPDIR_CMD='export GOTMPDIR="$HOME/go/tmp"'
for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
  if [ -f "$rc" ]; then
    grep -Fq "$EXPORT_CMD" "$rc" || echo "$EXPORT_CMD" >> "$rc"
    grep -Fq "$GOTMPDIR_CMD" "$rc" || echo "$GOTMPDIR_CMD" >> "$rc"
  fi
done

export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
export GOTMPDIR="$HOME/go/tmp"

# Pre-install bbot system dependencies from venv (massdns, subfinder, etc.)
echo "[WORKER_SETUP] Installing bbot dependencies..."
"$PROJECT_DIR/flowscan_venv/bin/bbot" --install-all-deps 2>&1 || echo "[WORKER_SETUP] [WARN] bbot --install-all-deps had issues; continuing"

python3 main.py init
