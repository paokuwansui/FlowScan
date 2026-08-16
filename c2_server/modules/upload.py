"""
@module: upload
@desc: 写入文件分块（append 模式），由 server 端 upload 命令推送
"""
import base64
import os

MODULE = {
    "desc": "写入文件分块（append），upload 命令推送",
    "params": [("path", "必填"), ("data_b64", "必填"),
               ("append", "默认 1；0=覆盖")],
}


def run(path, data_b64, append=1):
    """把 base64 数据写入 path。append='0' 覆盖，否则追加。"""
    try:
        data = base64.b64decode(data_b64)
    except (ValueError, TypeError) as e:
        return f"(error: bad base64: {e})"
    mode = "ab" if str(append) != "0" else "wb"
    try:
        with open(path, mode) as f:
            f.write(data)
        return f"(written {len(data)} bytes to {path})"
    except OSError as e:
        return f"(error: {e})"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("usage: upload <path> <data_b64> [append]")
        sys.exit(1)
    a = sys.argv[3] if len(sys.argv) > 3 else "1"
    print(run(sys.argv[1], sys.argv[2], a))
