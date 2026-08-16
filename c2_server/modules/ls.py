"""
@module: ls
@desc: 列出目录内容（权限/属主/大小/时间）
"""
import os
import stat
import time

MODULE = {
    "desc": "列出目录内容（权限/属主/大小/时间）",
    "params": [("path", '默认 "."')],
}


def _owner_group(st):
    """尝试解析属主/属组名，失败退回数字 uid/gid。"""
    try:
        import pwd
        import grp
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
    except Exception:
        owner, group = str(st.st_uid), str(st.st_gid)
    return owner, group


def run(path="."):
    """列出指定目录（ls -l 风格：权限/属主/大小/时间）"""
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return f"(permission denied: {path})"
    except FileNotFoundError:
        return f"(not found: {path})"
    except NotADirectoryError:
        return f"(not a directory: {path})"

    if not entries:
        return "(empty)"

    lines = []
    for name in entries:
        full = os.path.join(path, name)
        try:
            st = os.stat(full)
        except OSError:
            lines.append(f"  ???  {name}")
            continue
        mode = stat.filemode(st.st_mode)
        owner, group = _owner_group(st)
        size = st.st_size
        mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
        if stat.S_ISDIR(st.st_mode):
            name = f"{name}/"
        lines.append(f"  {mode} {owner:>8} {group:<8} {size:>10} "
                     f"{mtime}  {name}")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"ls {p}:")
    print(run(p))
