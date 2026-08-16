"""
@module: cat
@desc: 读取文件内容
"""
import os

MODULE = {
    "desc": "读取文件内容",
    "params": [("path", "必填"), ("lines", "默认 0=全部")],
}


def run(path, lines=0):
    """
    读取文件内容。

    Args:
        path: 文件路径
        lines: 读取行数，0=全部（dispatcher 传参为字符串，先转 int）
    """
    try:
        lines = int(lines)
    except (TypeError, ValueError):
        lines = 0
    if not os.path.isfile(path):
        return f"(not found or not a file: {path})"

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            if lines and lines > 0:
                content = "".join(f.readline() for _ in range(lines))
            else:
                content = f.read()
        if not content:
            return "(empty)"
        if len(content) > 65536:
            content = content[:65536] + f"\n... (truncated, {len(content)} bytes total)"
        return content.rstrip("\n")
    except PermissionError:
        return f"(permission denied: {path})"
    except Exception as e:
        return f"(error: {e})"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: cat <path> [lines]")
        sys.exit(1)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    print(f"cat {sys.argv[1]}:")
    print(run(sys.argv[1], n))
