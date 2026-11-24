"""sleep — 植入物整体睡眠(暂停回连,任务照常执行)。

用法(console 或页面模块执行):
  sleep <duration>
  duration 支持: 10s / 10m / 10h / 90(纯数字=秒) / 1h30m(组合)

效果(2026-09-16 改):把时长写进植入物的**下一轮睡眠计数**(_NXT)——
本轮回连结束后即按该值暂停回连;期间已启动的任务线程照常执行,结果暂存
本地(_PENDING),睡眠期间若结果入缓存会临时加速回连上报(5s±20%),
报完继续把剩余的暂停睡完(下次 sleep 覆盖旧值)。
"""

import re

MODULE = {
    "desc": "植入物整体睡眠(设置下一轮回连间隔,任务照常执行)",
    "params": [("duration", "必填;10s / 10m / 10h / 90(秒) / 1h30m")],
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
    # 写"下一轮睡眠计数"(globals 字符串键: 跨文件写状态, 见 set_interval @contract):下一轮回连结束后
    # 按该值睡眠;不再使用绝对截止时间 _SLP_UNTIL(2026-09-16 睡眠模型重写)
    globals()["_NXT"] = float(secs)
    return (f"(sleep: 下一轮回连后开始暂停回连 {secs}s; "
            f"任务照常执行, 结果暂存, 期间如有结果会临时加速上报后继续暂停)")


if __name__ == "__main__":
    print("usage: sleep <10s|10m|10h|90|1h30m>")
