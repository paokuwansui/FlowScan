"""
server/task_queue.py — 每客户端独立 FIFO 任务队列，线程安全。

Task: 单个待执行任务 (task_id, code, created_at, result_processor)
TaskQueue: 管理所有客户端的任务队列（deque 实现，T4.7）
"""

import uuid
import threading
from collections import deque
from datetime import datetime
from typing import Optional


class Task:
    """单个任务"""

    def __init__(self, code: str, is_init: bool = False,
                 task_id: Optional[str] = None,
                 result_processor: str = "",
                 proc_arg: str = "",
                 record: bool = False):
        self.task_id = task_id or str(uuid.uuid4())
        self.code = code
        self.is_init = is_init
        self.created_at = datetime.now()
        self.result_processor = result_processor  # Q7：结果处理 server 模块名
        self.proc_arg = proc_arg                  # 处理器参数（如 download 落盘路径）
        self.record = record                      # True=植入物只记录不上报(record_exec)

    def __repr__(self) -> str:
        return f"Task({self.task_id[:8]}..., init={self.is_init})"


class TaskQueue:
    """线程安全的任务队列管理器。

    每个 client_id 维护独立 FIFO 队列（deque）。
    支持 push / pop / push_front / peek / clear / pending_count。
    """

    def __init__(self, max_tasks_per_client: int = 100):
        self._max_tasks = max_tasks_per_client
        self._queues: dict[str, deque] = {}
        self._lock = threading.Lock()

    def push(self, client_id: str, task: Task) -> bool:
        """将任务入队（队尾）。返回 True 成功，False 队列满。"""
        with self._lock:
            if client_id not in self._queues:
                self._queues[client_id] = deque()
            if len(self._queues[client_id]) >= self._max_tasks:
                return False
            self._queues[client_id].append(task)
            return True

    def push_front(self, client_id: str, task: Task) -> bool:
        """将任务插到队头（断线重发保序，10.2）。"""
        with self._lock:
            if client_id not in self._queues:
                self._queues[client_id] = deque()
            if len(self._queues[client_id]) >= self._max_tasks:
                return False
            self._queues[client_id].appendleft(task)
            return True

    def pop(self, client_id: str) -> Optional[Task]:
        """从队列头部弹出一个任务 (FIFO)。"""
        with self._lock:
            queue = self._queues.get(client_id)
            if not queue:
                return None
            return queue.popleft()

    def peek(self, client_id: str) -> Optional[Task]:
        """查看队列头但不移除。"""
        with self._lock:
            queue = self._queues.get(client_id)
            if not queue:
                return None
            return queue[0]

    def update_task(self, client_id: str, task_id: str,
                    code: Optional[str] = None,
                    result_processor: Optional[str] = None,
                    proc_arg: Optional[str] = None) -> bool:
        """修改队列中指定任务字段(至少一个非 None)。返回是否找到。"""
        with self._lock:
            queue = self._queues.get(client_id)
            if not queue:
                return False
            for task in queue:
                if task.task_id == task_id:
                    if code is not None:
                        task.code = code
                    if result_processor is not None:
                        task.result_processor = result_processor
                    if proc_arg is not None:
                        task.proc_arg = proc_arg
                    return True
            return False

    def delete_task(self, client_id: str, task_id: str) -> bool:
        """删除队列中指定任务。返回是否找到并删除。"""
        with self._lock:
            queue = self._queues.get(client_id)
            if not queue:
                return False
            for i, task in enumerate(queue):
                if task.task_id == task_id:
                    del queue[i]
                    return True
            return False

    def clear(self, client_id: str) -> None:
        """清空指定客户端的所有任务。"""
        with self._lock:
            self._queues.pop(client_id, None)

    def pending_count(self, client_id: str) -> int:
        """返回待处理任务数。"""
        with self._lock:
            queue = self._queues.get(client_id)
            return len(queue) if queue else 0

    def set_max_tasks(self, n: int) -> None:
        """更新每客户端任务上限（reload 命令热重载配置用）。"""
        self._max_tasks = n
