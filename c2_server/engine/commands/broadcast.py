"""broadcast — 批量下发: broadcast [@组名] <module|raw> [args...]
以 @ 开头为组名过滤（tag 命令打的标签）。"""

from server.task_queue import Task


def run(disp, args):
    if not args:
        return "[!] usage: broadcast [@组名] <module|raw> [args...]"

    group = ""
    if args[0].startswith("@"):
        group = args[0][1:]
        args = args[1:]
        if not args:
            return "[!] usage: broadcast @组名 <module|raw> [args...]"

    beacons = [c for c in disp.mgr.list_clients() if not c.is_client]
    if group:
        beacons = [c for c in beacons if group in getattr(c, "tags", [])]
        if not beacons:
            return f"[!] 组 {group} 没有 beacon（先 tag <bid> {group}）"
    if not beacons:
        return "(no beacons connected)"

    if args[0].lower() == "raw":
        code = " ".join(args[1:])
        if not code:
            return "[!] usage: broadcast raw <code>"
        task = Task(code=code)
    else:
        try:
            task = disp.build_task(args[0], args[1:], platform="")
        except ValueError as e:
            return f"[!] {e}"
        if task is None:
            return f"[!] unknown module: {args[0]}"

    count = 0
    for c in beacons:
        # 每个 beacon 独立 Task（独立 task_id），日志/结果可按批次区分
        t = Task(code=task.code,
                 result_processor=task.result_processor,
                 proc_arg=task.proc_arg)
        if disp.tq.push(c.client_id, t):
            count += 1
    return f"[+] 已向 {count}/{len(beacons)} 个 Beacon 下发任务"
