"""
@module: set_port
@desc: 修改 Beacon 回连端口(验证后生效,失败自动回退)
"""
MODULE = {
    "desc": "修改 Beacon 回连端口(最多回连验证 10 次,失败自动回退)",
    "params": [("port", "必填")],
}


def run(port):
    """新端口先写入 _SET_PENDING, 主循环用新端口回连验证:
    成功(welcome)即生效; 连续 10 次失败回退原端口。"""
    _p = int(port)
    _sp = globals().get("_SET_PENDING")
    if not isinstance(_sp, dict):
        _sp = {}
    _sp["port"] = _p
    globals()["_SET_PENDING"] = _sp
    globals()["_SET_TRY"] = 0
    return (f"pending port={_p}——接下来最多回连验证 10 次, "
            f"成功即生效, 失败自动回退原端口")


if __name__ == "__main__":
    print("usage: set_port <port>")
