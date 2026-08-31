"""chmod — 修改文件/目录权限位。

用法(console 或页面模块执行):
  chmod <path> <mode>
  mode 支持八进制写法: "0777" / "777" / "0o777"(统一按 8 进制解析)
返回: 改前/改后权限(八进制显示),便于确认。
"""

import os

MODULE = {
    "desc": "修改文件/目录权限位(八进制 mode)",
    "params": [("path", "必填；文件/目录路径"),
               ("mode", "必填；八进制权限,如 0777 / 777 / 0o777")],
}


def _parse_mode(s):
    """解析权限字符串 → 0..0o7777 的整数;非法返回 None。"""
    s = str(s).strip()
    if not s:
        return None
    low = s.lower()
    if low.startswith("0o"):
        s = s[2:]
    try:
        m = int(s, 8)
    except ValueError:
        return None
    if m < 0 or m > 0o7777:
        return None
    return m


def run(path, mode):
    try:
        old = os.stat(path).st_mode & 0o7777
    except OSError as e:
        return f"(chmod: 无法访问 {path}: {e})"
    m = _parse_mode(mode)
    if m is None:
        return (f"(chmod: 无法解析权限 {mode!r}——"
                f"支持八进制如 0777 / 777 / 0o777)")
    try:
        os.chmod(path, m)
    except OSError as e:
        return f"(chmod: 设置失败 {path}: {e})"
    new = os.stat(path).st_mode & 0o7777
    return f"(chmod: {path}\n  改前 {oct(old)} → 改后 {oct(new)})"


if __name__ == "__main__":
    print("usage: chmod <path> <mode>")
