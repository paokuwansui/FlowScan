"""
@module: kill
@desc: 终止 Beacon 进程 (os._exit)
"""
import os

MODULE = {
    "desc": "终止 Beacon 进程 (os._exit)",
    "params": [],
}


def run():
    os._exit(0)


if __name__ == "__main__":
    pass
