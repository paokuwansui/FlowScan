"""Beacon 会话（T4.3）。

流程: 握手（register/welcome）→ 注册 → auto_commands（首次上线）→
任务循环（pop → task → result → 存库 → 结果处理器 → 事件；空 → pong）→ 断开。

fire-and-forget 语义（10.2）: 结果收到就存，没收到就拉倒；连接中断时
未发完的任务推回队头，下次回连继续。不追踪任务状态。

register / 结果落库 / auto_commands / 结果处理器 已抽到 sessions/engine.py，
与 HTTPS/DNS 传输共用同一实现（修 via/fork/shell 元数据与结果处理器漂移）。
"""

import json

from server.core.protocol import (
    send_frame, recv_frame, validate_message, TASK, RESULT, PONG,
)
from server.core.events import (
    EVT_DISCONNECT, EVT_TASK_SENT, EVT_AUTO_CMD_SENT,
)
from server.core.log import get_logger
from .base import handshake, send_welcome, send_error, SessionError
from .engine import register_beacon, store_result, build_auto_tasks

logger = get_logger("beacon_session")


class BeaconSession:
    """Beacon 连接会话。"""

    def __init__(self, sock, key: bytes, expected_role: str,
                 mgr, tq, events, config, modules, smods, dispatcher=None):
        self._sock = sock
        self._key = key
        self._expected_role = expected_role
        self._mgr = mgr
        self._tq = tq
        self._events = events
        self._config = config
        self._modules = modules
        self._smods = smods
        self._dispatcher = dispatcher  # 结果处理器续传 + auto_commands 用
        self._client_id = ""           # 注册成功后填充（close 清 active 用）
        self._is_fork = False          # 注册时标记（跳过 auto_commands）

    def run(self) -> None:
        try:
            self._sock.settimeout(self._config.socket_timeout)
            reg = handshake(self._sock, self._key, self._expected_role,
                            self._config.max_frame_size)
            # 注册（含 via 标记）先于 welcome：welcome 语义 = 注册成功
            client_id, is_new = self._register(reg)
            self._client_id = client_id
            send_welcome(self._sock, self._key)
            self._task_cycle(client_id, is_new)
        except SessionError as e:
            logger.warning("handshake failed: %s", e.message)
            send_error(self._sock, self._key, e.code, e.message)
        except (ConnectionError, ValueError):
            logger.debug("beacon connection closed")
        except Exception:
            logger.exception("beacon session error")

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass
        # 会话结束：清活跃标记（cleanup 竞态防护，S9）
        rec = self._mgr.get_client(self._client_id)
        if rec:
            rec.active = False

    # ── 主流程 ──

    def _register(self, reg: dict) -> tuple:
        """注册 + via/fork/shell 标记 + 上线事件（共享引擎）。"""
        self._is_fork = bool(reg.get("fork", False))
        return register_beacon(reg, self._mgr, self._events)

    def _task_cycle(self, client_id: str, is_new: bool) -> None:
        # fork 分裂出的 beacon 跳过 auto_commands：auto 命令（如
        # set_interval 5）会改共享全局，干扰主 beacon（S9）
        if is_new and not self._is_fork:
            self._run_auto_commands(client_id)

        while True:
            task = self._tq.pop(client_id)
            if not task:
                break
            if not self._send_and_wait(client_id, task):
                self._tq.push_front(client_id, task)  # 断线保序重发
                break
            # shell 文本任务 exit/break 已确认执行：立即复位 is_shell，
            # 消除退出后到下次基础注册之间的误路由窗口（真机测试发现）
            if task.code.strip() in ("exit", "break"):
                rec = self._mgr.get_client(client_id)
                if rec is not None:
                    rec.is_shell = False

        try:
            send_frame(self._sock,
                       json.dumps({"type": PONG}).encode("utf-8"), self._key)
        except Exception:
            pass
        self._events.emit(EVT_DISCONNECT, client_id)

    def _send_and_wait(self, client_id: str, task) -> bool:
        """发送 task → 接收 result → 存库/回填/事件。

        Returns: True 成功；False 连接中断（任务需重试）。
        """
        try:
            task_msg = json.dumps({
                "type": TASK, "task_id": task.task_id, "code": task.code,
            })
            send_frame(self._sock, task_msg.encode("utf-8"), self._key)
            self._events.emit(EVT_TASK_SENT, client_id,
                              task_id=task.task_id)

            # 长任务：等待结果期间把 socket 超时放宽到 client_timeout。
            old_timeout = self._sock.gettimeout()
            self._sock.settimeout(self._config.client_timeout)
            try:
                raw = recv_frame(self._sock, self._key,
                                 max_frame_size=self._config.max_frame_size)
            finally:
                self._sock.settimeout(old_timeout)
            result = json.loads(raw.decode("utf-8"))
            # S2：result 帧同样过 validate_message
            vcode = validate_message(result)
            if vcode:
                logger.warning("beacon %s sent invalid result: %s",
                               client_id[:8], vcode)
                return False
            if result.get("type") != RESULT:
                logger.warning("beacon %s sent non-result: %s",
                               client_id[:8], result.get("type"))
                return False

            store_result(client_id, task.task_id,
                         result.get("output", ""), result.get("error", ""),
                         self._mgr, self._events,
                         self._config.max_result_size,
                         smods=self._smods, dispatcher=self._dispatcher,
                         result_processor=task.result_processor,
                         proc_arg=getattr(task, "proc_arg", ""))
            return True

        except (ConnectionError, ValueError, json.JSONDecodeError):
            return False

    # ── auto_commands（T3.4 语义迁移） ──

    def _run_auto_commands(self, client_id: str) -> None:
        tasks = build_auto_tasks(self._config.auto_commands, client_id,
                                 self._dispatcher)
        for task in tasks:
            self._events.emit(EVT_AUTO_CMD_SENT, client_id,
                              task_id=task.task_id)
            if not self._send_and_wait(client_id, task):
                self._tq.push_front(client_id, task)
                return
