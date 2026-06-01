#!/bin/bash

# ====================================================================
# 脚本功能: 自动配置环境依赖
# ====================================================================
sudo apt update && sudo apt install -y git python3 python3-pip python-is-python3 
git clone https://github.com/0xGuigui/Katoolin3.git
cd Katoolin3
chmod +x katoolin3.py
sudo ./katoolin3.py
mkdir -p "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"
xport_cmd='export PATH="$HOME/.local/bin:$PATH"'

# 判断并写入 .zshrc
if [ -f "$HOME/.zshrc" ]; then
    echo "$export_cmd" >> "$HOME/.zshrc"
    echo "成功添加到 ~/.zshrc"
    source "$HOME/.zshrc" 2>/dev/null || true
fi

# 判断并写入 .bashrc
if [ -f "$HOME/.bashrc" ]; then
    echo "$export_cmd" >> "$HOME/.bashrc"
    echo "成功添加到 ~/.bashrc"
    source "$HOME/.bashrc" 2>/dev/null || true
fi
python loader.py
