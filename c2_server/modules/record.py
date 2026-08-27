"""record — 查看植入物本地任务记录(record 型任务: 只记录不上报)。

record list             列出全部记录(task_id + 时间 + 摘要)
record get <task_id>    查看单条记录完整内容
record clear            清空全部记录

配合: console `record_exec <bid> <代码...>` 下发只记录不上报的任务,
或 TASKS 帧带 record 标记。本模块查询结果正常上报。
"""

import time as _tm

MODULE = {
    "desc": "查看植入物本地任务记录(record 型任务: 只记录不上报)",
    "params": [("action", "list|get|clear"),
               ("task_id", "get 时必填")],
}


def run(action="list", task_id=""):
    action = (action or "list").strip().lower()
    if action == "clear":
        with _RECORDS_LOCK:
            n = len(_RECORDS)
            _RECORDS.clear()
        return f"(cleared {n} records)"
    if action == "get":
        with _RECORDS_LOCK:
            rec = _RECORDS.get(task_id)
        if not rec:
            return f"(record not found: {task_id})"
        out = (rec.get("output") or "").rstrip("\n")
        err = rec.get("error") or ""
        ts = _tm.strftime("%m-%d %H:%M:%S", _tm.localtime(rec.get("ts", 0)))
        body = out or "(no output)"
        if err:
            body += "\n[error] " + err
        return f"[{task_id}] {ts}\n{body}"
    # list
    with _RECORDS_LOCK:
        if not _RECORDS:
            return "(no records)"
        items = sorted(_RECORDS.items())
    lines = [f"(records: {len(items)})"]
    for tid, rec in items:
        summary = (rec.get("output") or rec.get("error") or "").strip()
        lines.append(f"  {tid} :: {summary[:60]}")
    return "\n".join(lines)
