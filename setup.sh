#!/usr/bin/env bash


add-apt-repository ppa:deadsnakes/ppa
apt update
apt install pipx python3 python3-pip python-is-python3 python3.13 python3.13-venv -y
python3 -m pip install -r requirements.txt --break-system-packages
pipx ensurepath
pipx install bbot --pip-args="--upgrade --force-reinstall" --python python3.13
bbot --install-all
source ~/.bashrc
# set -euo pipefail

# PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# sudo apt update
# sudo apt install -y git python3 python3-pip python-is-python3 golang-go unzip wget curl
# mkdir -p "$HOME/.local/bin" "$HOME/go/tmp"

# EXPORT_CMD='export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"'
# GOTMPDIR_CMD='export GOTMPDIR="$HOME/go/tmp"'
# for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
#   if [ -f "$rc" ]; then
#     grep -Fq "$EXPORT_CMD" "$rc" || echo "$EXPORT_CMD" >> "$rc"
#     grep -Fq "$GOTMPDIR_CMD" "$rc" || echo "$GOTMPDIR_CMD" >> "$rc"
#   fi
# done

# export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
# export GOTMPDIR="$HOME/go/tmp"
# python3 -m pip install -r "$PROJECT_DIR/requirements.txt" --break-system-packages

# cd "$PROJECT_DIR"
# python3 main.py init
