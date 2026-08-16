"""
@module: pwd
@desc: 显示当前工作目录
"""
import os

MODULE = {
    "desc": "显示当前工作目录",
    "params": [],
}


def run():
    """返回当前工作目录的绝对路径"""
    return os.getcwd()


if __name__ == "__main__":
    print(f"pwd: {run()}")
