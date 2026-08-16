"""result — 查看 Beacon 执行结果"""


def run(disp, args):
    bid, extra = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon"
    rec = disp.mgr.get_client(bid)
    if not rec or not rec.results:
        return "(no results)"
    try:
        n = int(extra[0]) if extra else 5
    except ValueError:
        return "[!] result count must be an integer"
    if n <= 0:
        n = 1  # L1：results[-0:] 会返回全部，0 视为 1
    results = list(rec.results)[-n:]  # deque → list 切片
    lines = []
    for r in results:
        lines.append(f"--- {r.task_id[:8]}... ---")
        lines.append(r.output or r.error)
    return "\n".join(lines)
