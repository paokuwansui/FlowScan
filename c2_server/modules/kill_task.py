"""kill_task — 终止指定运行中任务(模块版, 等价 console stop 命令):

kill_task <task_id>   终止该任务(向任务线程异步抛 _TaskCancelled)

被终止的任务线程静默退出、不产生结果、从运行中列表移除;
死循环(while True: pass)可打断;阻塞在 time.sleep/socket.recv 的任务
延迟到 IO 返回。终止后任务会进入 _KNOWN(已领取)不再重复执行。
查看运行中任务: tasks 命令 / record list。
"""

MODULE = {
    "desc": "终止指定运行中任务(死循环/持久任务)",
    "params": [("task_id", "必填")],
}


def run(task_id=""):
    task_id = (task_id or "").strip()
    if not task_id:
        return "(usage: kill_task <task_id>)"
    if _cancel_task(task_id):
        return f"(killed {task_id})"
    return f"(not running: {task_id})"
