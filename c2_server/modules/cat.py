"""
@module: cat
@desc: 读取文件内容(-h N 开头 N 行 / -t N 结尾 N 行 / 数字=开头 / 空=全部)
"""
import os

MODULE = {
    "desc": "读取文件内容(-h 10 开头10行 / -t 10 结尾10行 / 10=开头 / 空=全部)",
    "params": [("path", "必填"),
               ("mode", "可选；-h 10(开头10行) / -t 10(结尾10行) / "
                        "10(开头N行) / 空(全部)")],
}

_TRUNC = 65536
_BLOCK = 8192


def _parse_mode(arg):
    """解析模式参数 → (mode, n): all/head/tail;非法返回 (None, None)。"""
    arg = str(arg or "").strip()
    if not arg or arg == "0":
        return "all", 0
    low = arg.lower()
    if low.startswith("-h"):
        rest = arg[2:].strip()
        if not rest:
            return "head", 10
        if rest.isdigit():
            return "head", int(rest)
        return None, None
    if low.startswith("-t"):
        rest = arg[2:].strip()
        if not rest:
            return "tail", 10
        if rest.isdigit():
            return "tail", int(rest)
        return None, None
    if arg.isdigit():
        return ("head", int(arg)) if int(arg) > 0 else ("all", 0)
    return None, None


def _read_all(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _read_head(path, n):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return "".join(f.readline() for _ in range(n))


def _read_tail(path, n):
    """从文件尾倒读 n 行(块读, 大文件高效; 二进制拼接后统一解码避免跨块乱码)。"""
    with open(path, "rb") as f:
        f.seek(0, 2)
        pos = f.tell()
        data = b""
        while pos > 0 and data.count(b"\n") <= n:
            take = min(_BLOCK, pos)
            pos -= take
            f.seek(pos)
            data = f.read(take) + data
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return "\n".join(lines[-n:])


def run(path, mode="0"):
    m, n = _parse_mode(mode)
    if m is None:
        return (f"(cat: 无法解析参数 {mode!r}——支持 -h 10 / -t 10 / "
                f"10(开头N行) / 空(全部))")
    try:
        if m == "all":
            content = _read_all(path)
        elif m == "head":
            content = _read_head(path, n)
        else:
            content = _read_tail(path, n)
        if not content.strip():
            return "(empty)"
        if len(content) > _TRUNC:
            content = content[:_TRUNC] + \
                f"\n... (truncated, {len(content)} bytes total)"
        return content.rstrip("\n")
    except FileNotFoundError:
        return f"(not found or not a file: {path})"
    except PermissionError:
        return f"(permission denied: {path})"
    except Exception as e:
        return f"(error: {e})"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: cat <path> [-h 10 | -t 10 | 10]")
        sys.exit(1)
    m = sys.argv[2] if len(sys.argv) > 2 else "0"
    print(run(sys.argv[1], m))
