"""grep_dir — 递归在目录下的文件中查找包含某字符串的行(纯标准库)。

用法(console 或页面模块执行):
  grep_dir <path> <pattern> [depth]
  path:    目录路径(必填)
  pattern: 要查找的字符串(支持正则表达式; 非法正则自动按字面匹配)
  depth:   递归层数, 留空/不填 = 不限; 0 = 仅当前目录下文件
输出: 匹配行(相对路径:行号: 内容, 超长截断), 结尾统计。
实现: os.scandir 递归, 不跟随符号链接目录(防环); 跳过 >5MB 与不可读文件;
匹配行最多 500 条(超出提示)。
"""
import os
import re

MODULE = {"desc": "递归查找目录下文件中包含某字符串的行(支持正则)", "params": [
    ("path", "目录路径(必填)"),
    ("pattern", "要查找的字符串(支持正则表达式)"),
    ("depth", "递归层数(留空=不限, 0=仅当前目录文件)"),
]}

_MAX_FILE_BYTES = 5 * 1024 * 1024  # 跳过 >5MB 文件(防误读二进制大文件)
_MAX_MATCHES = 500                 # 最多显示 500 行匹配
_MAX_LINE_SHOW = 200               # 匹配行内容截断长度


def _parse_depth(v):
    if v is None or v == "":
        return None, ""
    try:
        return int(v), ""
    except (TypeError, ValueError):
        return None, f"depth 参数无效: {v!r} (应为非负整数或留空)"


def _compile(pattern):
    """正则编译; 非法正则回退字面(escape)。返回 (rx, 是否字面回退)。"""
    try:
        return re.compile(pattern), False
    except re.error:
        return re.compile(re.escape(pattern)), True


def _search_file(path, rel, rx, out, matches):
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return
        with open(path, "rb") as f:
            head = f.read(1024)
            if b"\x00" in head:
                return  # 二进制文件(含 NUL)跳过
            f.seek(0)
            for lineno, raw in enumerate(f, 1):
                try:
                    line = raw.decode("utf-8")
                except UnicodeDecodeError:
                    return  # 非 utf-8 文本跳过
                if rx.search(line):
                    matches[0] += 1
                    if len(out) < _MAX_MATCHES:
                        text = line.rstrip("\r\n")
                        if len(text) > _MAX_LINE_SHOW:
                            text = text[:_MAX_LINE_SHOW] + "..."
                        out.append(f"{rel}:{lineno}: {text}")
    except (OSError, UnicodeDecodeError):
        pass


def _walk(base, rx, max_d, cur, rel_base, out, matches, files):
    """递归扫描。cur = base 距根层级(path=0); 文件层数 ≤ max_d 才进入子目录。"""
    try:
        with os.scandir(base) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError:
        return
    for e in entries:
        try:
            if e.is_dir(follow_symlinks=False):
                if max_d is None or cur + 1 <= max_d:
                    _walk(e.path, rx, max_d, cur + 1,
                          os.path.join(rel_base, e.name), out, matches, files)
            elif e.is_file(follow_symlinks=False):
                files[0] += 1
                _search_file(e.path, os.path.join(rel_base, e.name),
                             rx, out, matches)
        except OSError:
            continue


def run(path=".", pattern="", depth=None):
    base = os.path.abspath(os.path.expanduser(str(path or ".")))
    if not os.path.isdir(base):
        return f"(grep_dir: {base!r} 不是目录或不存在)"
    pattern = str(pattern or "")
    if not pattern.strip():
        return "(grep_dir: pattern 不能为空)"
    max_d, err = _parse_depth(depth)
    if err:
        return f"(grep_dir: {err})"
    if max_d is not None and max_d < 0:
        return "(grep_dir: depth 必须是非负整数或留空)"
    rx, literal = _compile(pattern.strip())
    out = []
    matches = [0]
    files = [0]
    rel_root = str(path) or "."
    _walk(base, rx, max_d, 0, rel_root, out, matches, files)
    note = "(pattern 不是合法正则, 已按字面字符串匹配)" if literal else ""
    if not out:
        return (note + "\n" if note else "") + \
            f"(grep_dir: 未找到匹配(扫描 {files[0]} 个文件))"
    lines = list(out)
    if matches[0] > _MAX_MATCHES:
        lines.append(f"... (共 {matches[0]} 行匹配, 仅显示前 {_MAX_MATCHES})")
    if literal:
        lines.insert(0, "(pattern 不是合法正则, 已按字面字符串匹配)")
    lines.append(f"{files[0]} 个文件, {matches[0]} 行匹配")
    return "(grep_dir:\n" + "\n".join(lines) + "\n)"
