"""
@module: set_key
@desc: 修改 Beacon XOR 密钥 (需同步更新 Server 配置)
@contract: 依赖 implant 全局变量 _K (5.5/D2)
"""
MODULE = {
    "desc": "修改 Beacon XOR 密钥 (需同步更新 Server 配置)",
    "params": [("key_hex", "必填，64 字符 hex")],
}


def run(key_hex):
    global _K
    _K = bytes.fromhex(key_hex)
    return f"key updated ({len(_K)} bytes)"


if __name__ == "__main__":
    print("usage: set_key <64-char-hex-key>")
