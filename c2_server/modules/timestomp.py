"""timestomp — 修改文件时间戳(atime/mtime; ctime 由内核维护不可直接改)。

用法(console 或页面模块执行):
  timestomp <path> [参照路径 | 时间戳]
  - 第二参为空:  默认改到"过去一年内"随机时间(往前波动一年)
  - 第二参是路径: 参照该文件的时间戳(mtime)修改
  - 第二参是时间戳: 支持 epoch 秒(10位)/毫秒(13位) / "YYYY-MM-DD HH:MM:SS" / "YYYY-MM-DD"
返回: 改前/改后 atime·mtime(ISO 格式),便于确认。
"""

import os
import random
import time

MODULE = {
    "desc": "修改文件时间戳(atime/mtime; 参照路径/指定时间戳/默认波动一年)",
    "params": [("path", "必填；目标文件"),
               ("ref", "可选；参照文件路径 | 时间戳(epoch秒/毫秒 或 "
                       "YYYY-MM-DD[ HH:MM:SS]),空=过去一年内随机")],
}


def _parse_ts(s):
    """解析时间戳字符串 → epoch 秒(float);无法解析返回 None。"""
    s = s.strip()
    if not s:
        return None
    if s.isdigit():
        v = int(s)
        return v / 1000.0 if v > 10 ** 12 else float(v)  # 13位=毫秒,10位=秒
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(s, fmt))
        except ValueError:
            continue
    return None


def _iso(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def run(path, ref=""):
    try:
        st = os.stat(path)
    except OSError as e:
        return f"(timestomp: 无法访问 {path}: {e})"
    old = (st.st_atime, st.st_mtime)

    ref = (ref or "").strip()
    if ref:
        if os.path.exists(ref):
            new_ts = os.stat(ref).st_mtime
            src = f"参照 {ref}"
        else:
            t = _parse_ts(ref)
            if t is None:
                return (f"(timestomp: 无法解析第二参 {ref!r}——支持: "
                        f"已存在路径 / epoch秒·毫秒 / YYYY-MM-DD[ HH:MM:SS])")
            new_ts = t
            src = f"时间戳 {ref}"
    else:
        # 默认: 往前波动一年(过去一年内随机)
        new_ts = time.time() - random.uniform(0, 365 * 86400)
        src = "默认(过去一年内随机)"

    try:
        os.utime(path, (new_ts, new_ts))
    except OSError as e:
        return f"(timestomp: 设置失败 {path}: {e})"

    st2 = os.stat(path)
    return (f"(timestomp: {src}\n"
            f"  改前 atime={_iso(old[0])} mtime={_iso(old[1])}\n"
            f"  改后 atime={_iso(st2.st_atime)} mtime={_iso(st2.st_mtime)}\n"
            f"  注: Linux ctime 由内核维护, 无法直接修改)")


if __name__ == "__main__":
    print("usage: timestomp <path> [ref_path | timestamp]")
