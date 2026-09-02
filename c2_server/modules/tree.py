"""tree — 递归列举目录树(纯标准库)。

用法(console 或页面模块执行):
  tree <path> [depth]
  path:  目录路径(必填)
  depth: 递归深度, 留空/不填 = 不限; 0 = 只显示目录本身; 1 = 仅直接子项
输出: 树形缩进(├──/└──)递归列出文件与目录(目录带 / 后缀), 结尾统计。
实现: os.scandir 递归, 不跟随符号链接目录(防环), 按名称排序。
"""
import os

MODULE = {"desc": "递归列举目录树(支持深度限制)", "params": [
    ("path", "目录路径(必填)"),
    ("depth", "递归深度(留空=不限, 0=仅目录本身, 1=直接子项)"),
]}


def _parse_depth(v):
    """None/空 = 不限; 数字字符串转 int; 非法返回 None(按不限处理)并标记错误。"""
    if v is None or v == "":
        return None, ""
    try:
        return int(v), ""
    except (TypeError, ValueError):
        return None, f"depth 参数无效: {v!r} (应为非负整数或留空)"


def _walk(base: str, max_d, cur: int, prefix: str, out: list):
    """递归列目录。返回 (子目录数, 文件数)。"""
    dirs = files = 0
    try:
        with os.scandir(base) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError as e:
        out.append(prefix + f"[读取失败: {e}]")
        return 0, 0
    for i, e in enumerate(entries):
        last = i == len(entries) - 1
        branch = "└── " if last else "├── "
        sub_prefix = prefix + ("    " if last else "│   ")
        try:
            is_dir = e.is_dir(follow_symlinks=False)
        except OSError:
            is_dir = False
        out.append(prefix + branch + e.name + ("/" if is_dir else ""))
        if is_dir:
            dirs += 1
            # 深度未达上限(或不限)才展开子目录
            if max_d is None or cur + 1 < max_d:
                d2, f2 = _walk(e.path, max_d, cur + 1, sub_prefix, out)
                dirs += d2
                files += f2
        else:
            files += 1
    return dirs, files


def run(path=".", depth=None):
    base = os.path.abspath(os.path.expanduser(str(path or ".")))
    if not os.path.isdir(base):
        return f"(tree: {base!r} 不是目录或不存在)"
    max_d, err = _parse_depth(depth)
    if err:
        return f"(tree: {err})"
    if max_d is not None and max_d < 0:
        return "(tree: depth 必须是非负整数或留空)"
    out = [base]
    if max_d == 0:
        dirs = files = 0
    else:
        dirs, files = _walk(base, max_d, 0, "", out)
    out.append(f"{dirs} 个目录, {files} 个文件")
    return "(tree:\n" + "\n".join(out) + "\n)"
