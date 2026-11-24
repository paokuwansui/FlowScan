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
    send_frame, recv_frame, COMMAND, RESPONSE, UNKNOWN_TYPE,
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
            # 远程会话终止:exit(旧名)与 s_exit(新名,与本地 console 对齐)都只断开
            # 本连接,不停止 Server(2026-09-28:s_exit 此前落到引擎处理器而 ClientSession
            # 的 on_exit 为 None → 只回一句"session ended"却不关连接)
            if not line or line.lower() in ("exit", "s_exit"):
                break  # 远程 exit/s_exit:仅断开本连接

            output = self._dispatcher.execute(line)
            # 响应截断(2026-09-04 B11): 超帧上限的大输出(result <bid> 全量
            # 等)会让 send_frame 长度头超过对端 max_frame_size, 被对端
            # recv_frame 拒收并断开——截断到安全余量并标注
            lim = int(getattr(self._config, "max_frame_size", 512 * 1024) * 0.6)
            if len(output) > lim:
                output = (output[:lim]
                          + f"\n... (truncated, {len(output)} bytes total)")
            resp = {"type": RESPONSE, "status": "ok", "output": output}
            try:
                send_frame(self._sock, json.dumps(resp).encode("utf-8"),
                           self._key)
            except Exception:
                break
