"""
server/sessions/client.py — Client 会话（T4.4）

流程: 握手（role=client）→ welcome → COMMAND/RESPONSE 循环。
每会话一个 Dispatcher 实例（current_beacon 会话级隔离；on_exit=None——
远程 exit 只断开连接，不停止 Server）。

协议（7.5）:
  请求: {"type": "command", "line": "<命令文本>"}
  响应: {"type": "response", "status": "ok"|"error", "output": "..."}
"""

import json

from server.core.protocol import (
    send_frame, recv_frame, COMMAND, RESPONSE, ERROR, UNKNOWN_TYPE,
)
from server.core.log import get_logger
from server.engine.dispatcher import Dispatcher, CommandContext
from .base import handshake, send_welcome, send_error, SessionError

logger = get_logger("client_session")


class ClientSession:
    """操作员 Client 连接会话。"""

    def __init__(self, sock, key: bytes, expected_role: str,
                 components: dict):
        """
        Args:
            components: 共享组件 dict（mgr/tq/logger/config/modules/smods）
        """
        self._sock = sock
        self._key = key
        self._expected_role = expected_role
        ctx = CommandContext(**components, on_exit=None)
        self._config = ctx.config
        self._dispatcher = Dispatcher(ctx)

    def run(self) -> None:
        try:
            self._sock.settimeout(self._config.socket_timeout)
            handshake(self._sock, self._key, self._expected_role,
                      self._config.max_frame_size)
            send_welcome(self._sock, self._key)
            self._command_loop()
        except SessionError as e:
            logger.warning("client handshake failed: %s", e.message)
            send_error(self._sock, self._key, e.code, e.message)
        except (ConnectionError, ValueError):
            logger.debug("client connection closed")
        except Exception:
            logger.exception("client session error")

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    # ── 主流程 ──

    def _command_loop(self) -> None:
        while True:
            try:
                raw = recv_frame(self._sock, self._key,
                                 max_frame_size=self._config.max_frame_size)
                msg = json.loads(raw.decode("utf-8"))
            except (ConnectionError, ValueError):
                break

            if not isinstance(msg, dict) or msg.get("type") != COMMAND:
                send_error(self._sock, self._key, UNKNOWN_TYPE,
                           "expected command message")
                break

            line = msg.get("line", "")
            # L5: line 非 str（dict/list）→ lower() 会 AttributeError 杀会话
            if not isinstance(line, str):
                send_error(self._sock, self._key, UNKNOWN_TYPE,
                           "line must be a string")
                break
            if not line or line.lower() == "exit":
                break  # 远程 exit：仅断开本连接

            output = self._dispatcher.execute(line)
            resp = {"type": RESPONSE, "status": "ok", "output": output}
            try:
                send_frame(self._sock, json.dumps(resp).encode("utf-8"),
                           self._key)
            except Exception:
                break
