"""
@module: find
@desc: 按文件名（子串匹配）递归搜索文件
"""
import os
import stat

MODULE = {
    "desc": "按文件名子串递归搜索（默认当前目录，最多 200 条）",
    "params": [("keyword", "必填；文件名子串（不区分大小写）"),
               ("path", '默认 "."')],
}

_MAX_RESULTS = 200
_MAX_DEPTH = 12


def run(keyword, path="."):
    """递归搜索文件名包含 keyword 的文件，返回路径 + 大小。"""
    if not keyword:
        return "(usage: find <keyword> [path])"
    needle = keyword.lower()
    results = []

    def _walk(root, depth):
        if len(results) >= _MAX_RESULTS or depth > _MAX_DEPTH:
            return
        try:
            entries = sorted(os.listdir(root))
        except (PermissionError, FileNotFoundError, NotADirectoryError):
            return
        for entry in entries:
            if len(results) >= _MAX_RESULTS:
                return
            full = os.path.join(root, entry)
            try:
                st = os.stat(full)
            except OSError:
                continue
            if needle in entry.lower():
                size = st.st_size
                kind = "D" if stat.S_ISDIR(st.st_mode) else "F"
                results.append(f"  [{kind}] {size:>10}  {full}")
            if stat.S_ISDIR(st.st_mode):
                _walk(full, depth + 1)

    _walk(path, 0)
    if not results:
        return f"(no match: {keyword} under {path})"
    out = "\n".join(results)
    if len(results) >= _MAX_RESULTS:
        out += f"\n... (truncated at {_MAX_RESULTS})"
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: find <name> [path]")
        sys.exit(1)
    n = sys.argv[1]
    p = sys.argv[2] if len(sys.argv) > 2 else "."
    print(f"find {n} under {p}:")
    print(run(n, p))
