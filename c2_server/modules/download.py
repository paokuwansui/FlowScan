"""
@module: download
@desc: 读取文件指定分块（base64 JSON 回传），由 server 端 download 命令自动续传
"""
import base64
import json
import os

MODULE = {
    "desc": "读取文件分块（base64），download 命令自动续传",
    "params": [("path", "必填"), ("chunk", "默认 0")],
}

_CHUNK = 250 * 1024  # 原始字节/块（base64 后 ~333KB，帧内）


def run(path, chunk=0):
    """返回 {"chunk","total","data","path"} JSON；data 为 base64。"""
    try:
        chunk = int(chunk)
    except (TypeError, ValueError):
        chunk = 0
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return json.dumps({"error": str(e)})
    total = max(1, (size + _CHUNK - 1) // _CHUNK)
    if chunk >= total:
        return json.dumps({"chunk": chunk, "total": total,
                           "data": "", "path": path})
    try:
        with open(path, "rb") as f:
            f.seek(chunk * _CHUNK)
            data = f.read(_CHUNK)
    except OSError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"chunk": chunk, "total": total,
                       "data": base64.b64encode(data).decode("ascii"),
                       "path": path})


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: download <path> [chunk]")
        sys.exit(1)
    c = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    print(run(sys.argv[1], c))
