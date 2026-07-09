setup_flowscan_venv.sh
#!/bin/bash

# 确保脚本在遇到错误时立即停止执行
set -e

echo "=== 1. 开始更新系统并安装 Python 3.13 ==="
sudo apt update
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install python3.13 python3.13-venv python3.13-dev -y

echo "=== 2. 验证 Python 3.13 安装 ==="
python3.13 --version

echo "=== 3. 获取当前绝对路径并创建虚拟环境 ==="
CURRENT_DIR=$(pwd)
ENV_NAME="flowscan_venv"
VENV_PATH="$CURRENT_DIR/$ENV_NAME"

echo "当前工作目录: $CURRENT_DIR"
python3.13 -m venv "$VENV_PATH"

echo "=== 4. 激活虚拟环境并更新 pip ==="
# 在脚本中激活虚拟环境，后续的 pip 安装会在该环境中进行
source "$VENV_PATH/bin/activate"
pip install --upgrade pip

echo "=== 5. 安装所需的 Python 依赖包 ==="
pip install PyYAML redis flask tldextract bbot==2.8.6

echo "=== 6. 创建 bbot 全局软链接 ==="
# 使用绝对路径创建软链接，确保全局可访问
# 如果软链接已存在，先删除旧的以防报错
if [ -L "/usr/local/bin/bbot" ] || [ -f "/usr/local/bin/bbot" ]; then
    echo "检测到已存在 /usr/local/bin/bbot，正在覆盖..."
    sudo rm -f /usr/local/bin/bbot
fi

sudo ln -s "$VENV_PATH/bin/bbot" /usr/local/bin/bbot

echo "=== 部署完成！ ==="
echo "提示：由于脚本在子 Shell 中运行，当前终端尚未激活环境。"
echo "请手动执行以下命令进入虚拟环境："
echo "source $ENV_NAME/bin/activate"
