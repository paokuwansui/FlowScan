"""rm — 删除文件或目录(纯标准库)。

用法(console 或页面模块执行):
  rm <path>          删除文件/符号链接(目录需 -r)
  rm -r <path>       递归删除目录树
  rm -f <path>       目标不存在时不报错(可组合: -rf / -fr)
实现: 拒绝删除根目录 / . / ..; 符号链接只删链接本身(不跟随);
目录无 -r 拒绝(防误删); 权限不足返回明确错误。
"""
import os
import shutil

MODULE = {"desc": "删除文件或目录(支持 -r 递归 / -f 忽略不存在)", "params": [
    ("target", "rest；rm [-r] [-f] <路径>"),
]}

_DENY = {"/", os.sep}


def run(target):
    parts = str(target or "").strip().split()
    opts = set()
    while parts and parts[0].startswith("-") and parts[0] != "-":
        opts.update(parts.pop(0)[1:])
    if not parts:
        return "(rm: 未指定路径, 用法: rm [-r] [-f] <路径>)"
    raw = " ".join(parts)
    recursive = "r" in opts
    force = "f" in opts
    path = os.path.abspath(os.path.expanduser(raw))
    if path in _DENY or os.path.dirname(path) == path:
        return f"(rm: 拒绝删除 {raw!r})"
    if not os.path.lexists(path):
        return "(rm: ok(目标不存在, -f 忽略))" if force \
            else f"(rm: 目标不存在: {raw!r})"
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            if not recursive:
                return f"(rm: {raw!r} 是目录, 需加 -r 递归删除)"
            shutil.rmtree(path)
        else:
            os.remove(path)
    except PermissionError:
        return f"(rm: 权限不足: {raw!r})"
    except OSError as e:
        return f"(rm: 删除失败: {e})"
    return f"(rm: 已删除 {raw!r})"
