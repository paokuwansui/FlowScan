"""tasks — 查看 beacon 当前正在运行的任务(含持久任务/死循环):

tasks <beacon_id>   列出运行中任务(植入物每轮回连上报)

说明: 运行中列表来自植入物 register 帧的 running 字段——只包含
"已领取且未执行完"的任务;死循环/持久任务会一直停留在此列表,
普通任务执行完自动消失。终止任务用 stop 命令。
"""


def run(disp, args):
    bid, _ = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon"
    rec = disp.mgr.get_client(bid)
    if rec is None:
        return f"[!] beacon 不存在: {bid}"
    running = list(getattr(rec, "running_tasks", []) or [])
    if not running:
        return f"[*] {bid[:8]}: 无运行中任务"
    lines = [f"[*] {bid[:8]} 运行中任务 ({len(running)}):"]
    for tid in running:
        lines.append(f"  {tid}")
    lines.append("  终止: stop <beacon_id> <task_id> | stop <beacon_id> -all")
    return "\n".join(lines)
