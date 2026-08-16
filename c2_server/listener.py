"""
server/listener.py — 网络监听层（T4.2）

双监听器（10.1 端口/密钥分离）:
  - implant 端口: 只接受 role=beacon，用 implant_key
  - client 端口: 只接受 role=client，用 client_key
role 与端口绑定校验由会话层完成（expected_role 传入，不匹配 → error + 断开）。

活跃连接计数 > max_connections → 拒绝新连接（防连接耗尽，10.5）。
优雅退出: stop() 关闭监听 socket，accept 循环自然退出。
"""

import socket
import threading

from server.core.log import get_logger

logger = get_logger("listener")


class Listener:
    """双端口监听器。"""

    def __init__(self, host: str, ports: dict, session_factory,
                 max_connections: int = 256):
        """
        Args:
            host: 监听地址
            ports: {"implant": (port, key_bytes), "client": (port, key_bytes)}
            session_factory: callable(conn, key, expected_role) -> session
            max_connections: 活跃连接上限
        """
        self._host = host
        self._ports = ports
        self._session_factory = session_factory
        self._max_connections = max_connections
        self._sockets: list = []
        self._threads: list = []
        self._active = 0
        self._lock = threading.Lock()
        self._stopped = False

    def start(self) -> None:
        """启动所有监听线程。"""
        for role, (port, key) in self._ports.items():
            self._listen_one(port, key, role)

    def _listen_one(self, port: int, key: bytes, expected_role: str) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self._host, port))
        srv.listen(128)
        self._sockets.append(srv)
        t = threading.Thread(target=self._accept_loop,
                             args=(srv, key, expected_role), daemon=True)
        t.start()
        self._threads.append(t)
        logger.info("listening %s:%d (role=%s)", self._host, port,
                    expected_role)

    def _accept_loop(self, srv: socket.socket, key: bytes,
                     expected_role: str) -> None:
        while not self._stopped:
            try:
                srv.settimeout(1.0)
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with self._lock:
                if self._active >= self._max_connections:
                    logger.warning("max_connections reached (%d), "
                                   "rejecting %s", self._max_connections, addr)
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                self._active += 1

            session = self._session_factory(conn, key, expected_role)
            if session is None:
                # 工厂拒绝（如 TLS 握手失败，conn 已关闭）：归还计数，
                # 否则 _active 只增不减 → 最终耗尽 max_connections（S1）
                with self._lock:
                    if self._active > 0:
                        self._active -= 1
                continue
            t = threading.Thread(target=self._run_session,
                                 args=(session,), daemon=True)
            t.start()

    def _run_session(self, session) -> None:
        try:
            session.run()
        except Exception:
            logger.exception("session error")
        finally:
            try:
                session.close()
            except Exception:
                pass
            with self._lock:
                if self._active > 0:
                    self._active -= 1

    @property
    def active_connections(self) -> int:
        with self._lock:
            return self._active

    def stop(self) -> None:
        """停止监听。

        注: Linux 上阻塞的 accept 不会被 close(fd) 打断——socket 对象
        在 accept 返回前仍持有监听；置停止标志后 accept 循环在
        下一个 1s 超时点退出，端口随后释放（≤1s 延迟）。
        """
        self._stopped = True
        for s in self._sockets:
            try:
                s.close()
            except OSError:
                pass
