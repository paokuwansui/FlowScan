#!/bin/bash

# ====================================================================
# 脚本功能: 自动配置环境依赖
# ====================================================================
sudo apt update && sudo apt install -y git python3 python3-pip python-is-python3 golang-go unzip
mkdir -p "$HOME/.local/bin"
mkdir -p "$HOME/go/tmp"
git clone https://github.com/0xGuigui/Katoolin3.git
cd Katoolin3
chmod +x katoolin3.py
sudo ./katoolin3.py
cd ..
EXPORT_CMD='export PATH="$HOME/.local/bin:$PATH"'
GOTMPDIR_CMD='export GOTMPDIR="$HOME/go/tmp"'
# 判断并写入 .zshrc
if [ -f "$HOME/.zshrc" ]; then
    echo "$EXPORT_CMD" >> "$HOME/.zshrc"
    echo "$GOTMPDIR_CMD" >> "$HOME/.zshrc"
    echo "成功添加到 ~/.zshrc"
    source "$HOME/.zshrc" 2>/dev/null || true
fi

# 判断并写入 .bashrc
if [ -f "$HOME/.bashrc" ]; then
    echo "$EXPORT_CMD" >> "$HOME/.bashrc"
    echo "$GOTMPDIR_CMD" >> "$HOME/.bashrc"
    echo "成功添加到 ~/.bashrc"
    source "$HOME/.bashrc" 2>/dev/null || true
fi

export PATH="$HOME/.local/bin:$PATH"
export GOTMPDIR="$HOME/go/tmp"
python loader.py
