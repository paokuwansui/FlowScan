"""面板状态加密落盘(2026-09-28): 代码片段库 + 终端命令历史。

原先这两样存在浏览器 localStorage(易被 XSS 读取、换浏览器/清缓存即丢)。
现在改为**服务端本地文件 + 加密存储**:

· 密码学: 复用 c2_server/core/crypto.py 的 seal / open_sealed
  (ChaCha20 + HMAC-SHA256, encrypt-then-MAC, 每次随机 nonce, 纯标准库, 无新依赖)
· 密钥: c2_server/config.json 的 state_key(2026-09-28 改:原先放 config.yaml 的
  web_config.state_key, 现统一到 C2 配置文件 —— 与 C2 运行态落盘共用同一密钥/同一处,
  首次使用自动生成 64 位 hex 并原子写回)
· 文件: <项目根>/web_app/state/c2_state.enc(密文; .gitignore 已忽略)
· 失败策略: 解密/MAC 失败 → 抛错并把原文件留成 .bak,**绝不静默清库**
· 并发: 进程内锁 + 原子写(tmp + os.replace);片段库整表保存带版本号(乐观锁)
"""
from __future__ import annotations

import importlib
import json
import os
import secrets
import sys
import threading
import time

from flowscan.config import load_yaml
from flowscan.utils import project_root

HISTORY_MAX = 20000          # 命令历史保留上限(条)
HISTORY_LINE_MAX = 8192      # 单条命令上限(字符)
SNIPPET_MAX = 200            # 片段上限(条)
SNIPPET_NAME_MAX = 120
SNIPPET_NOTE_MAX = 200
SNIPPET_CODE_MAX = 65536

_lock = threading.RLock()
_config_path = ""


class StoreError(RuntimeError):
    """存储层错误(路由层转 500 + 人话提示)。"""


class StoreCorrupt(StoreError):
    """密文损坏 / MAC 不匹配(原文件已留 .bak)。"""


def set_config_path(path: str) -> None:
    """create_app 时注入实际使用的 config.yaml 路径。"""
    global _config_path
    _config_path = str(path or "")


def _config_file() -> str:
    return _config_path or os.path.join(project_root(), "config.yaml")


def c2_config_file() -> str:
    """密钥所在文件:c2 段指向的 C2 配置文件(默认 <项目根>/c2_server/config.json)。"""
    try:
        cfg = load_yaml(_config_file()) or {}
    except Exception:
        cfg = {}
    c2 = cfg.get("c2") or {}
    root = str(c2.get("project_root") or "c2_server")
    name = str(c2.get("config_file") or "config.json")
    base = root if os.path.isabs(root) else os.path.join(project_root(), root)
    return os.path.join(base, name)


def state_dir() -> str:
    d = os.path.join(project_root(), "web_app", "state")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def state_file() -> str:
    return os.path.join(state_dir(), "c2_state.enc")


def _atomic_write(path: str, data: bytes, mode: int | None = None) -> None:
    """原子写: 临时文件 + os.replace;mode=None 时沿用原文件权限。"""
    tmp = path + ".tmp"
    if mode is None:
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            mode = 0o600
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


# ── 加密实现(复用 c2_server/core/crypto.py) ──

_crypto: tuple | None = None


def _load_crypto():
    """加载 seal / open_sealed。c2_server 是拍平的 server 包, 按别名机制注册。"""
    global _crypto
    if _crypto is not None:
        return _crypto
    c2_dir = os.path.join(project_root(), "c2_server")
    if not os.path.isdir(c2_dir):
        raise StoreError(f"找不到 C2 目录 {c2_dir}, 无法加载加密实现")
    parent = os.path.dirname(c2_dir)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    try:
        sys.modules.setdefault("server", importlib.import_module(os.path.basename(c2_dir)))
        from server.core.crypto import open_sealed, seal   # noqa: PLC0415
    except Exception as exc:                               # pragma: no cover
        raise StoreError(f"加载 core/crypto 失败: {exc}") from exc
    _crypto = (seal, open_sealed)
    return _crypto


# ── 密钥(c2_server/config.json → state_key) ──
# 2026-09-28:原放 config.yaml 的 web_config.state_key,现统一到 C2 配置文件:
# 与 C2 运行态落盘(c2_server/data/c2_state.enc)共用同一个密钥与同一个文件,
# 运维只需看一处;config.json 本来就在 .gitignore 里。

def ensure_key() -> bytes:
    """取 state_key;缺失/非法则生成 64 位 hex 并原子写回 C2 配置文件。

    与 c2_server 的 ensure_state_key 读写同一位置同一键名 —— 两边谁先生成,
    另一边直接复用(校验长度与外层一致,不会互相覆盖成不同值)。
    """
    path = c2_config_file()
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError as exc:
        raise StoreError(f"找不到 C2 配置文件 {path}(面板状态密钥存放在这里): {exc}") from exc
    except (OSError, ValueError) as exc:
        raise StoreError(f"读取 {path} 失败: {exc}") from exc
    if not isinstance(raw, dict):
        raise StoreError(f"{path} 内容不是 JSON 对象, 无法写入 state_key")

    cur = str(raw.get("state_key") or "")
    if len(cur) == 64:
        try:
            return bytes.fromhex(cur)
        except ValueError:
            pass          # 非法 hex → 重新生成(与 c2_server 侧同口径)

    key = secrets.token_hex(32)
    raw["state_key"] = key
    _atomic_write(path, json.dumps(raw, indent=2, ensure_ascii=False).encode("utf-8"))
    try:
        with open(path, encoding="utf-8") as f:
            got = str((json.load(f) or {}).get("state_key") or "")
    except Exception as exc:
        raise StoreError(f"写入 state_key 后读回失败({exc});请检查 {path} 权限") from exc
    if got != key:
        raise StoreError(f"写入 state_key 失败(读回不一致);请检查 {path} 权限")
    return bytes.fromhex(key)


# ── 状态结构 ──

def _empty() -> dict:
    # remarks/hidden: 2026-09-28 从 Redis(纯内存不落盘, 重启即丢)搬来这里 ——
    # 面板的"备注/隐藏"属于面板自己的数据, 归面板加密存储, 重启不再丢。
    return {"version": 0, "snippets": [], "history": [],
            "remarks": {}, "hidden": {}}


def _normalize(data) -> dict:
    """结构/类型/上限归一(收窄历史与片段, 防止文件被撑爆)。"""
    out = _empty()
    if not isinstance(data, dict):
        return out
    try:
        out["version"] = max(0, int(data.get("version") or 0))
    except (TypeError, ValueError):
        out["version"] = 0
    snips = data.get("snippets")
    if isinstance(snips, list):
        for item in snips[:SNIPPET_MAX]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()[:SNIPPET_NAME_MAX]
            code = str(item.get("code") or "")
            if not name or not code.strip():
                continue
            out["snippets"].append({
                "name": name,
                "note": str(item.get("note") or "")[:SNIPPET_NOTE_MAX],
                "code": code[:SNIPPET_CODE_MAX],
            })
    hist = data.get("history")
    if isinstance(hist, list):
        lines = [str(x)[:HISTORY_LINE_MAX] for x in hist if str(x).strip()]
        out["history"] = lines[-HISTORY_MAX:]
    rem = data.get("remarks")
    if isinstance(rem, dict):
        for bid, txt in rem.items():
            txt = str(txt or "").strip()[:500]
            if bid and txt:
                out["remarks"][str(bid)[:64]] = txt
    hid = data.get("hidden")
    if isinstance(hid, dict):
        for bid, ts in hid.items():
            try:
                out["hidden"][str(bid)[:64]] = float(ts)
            except (TypeError, ValueError):
                continue
    return out


class SecureStore:
    """加密状态文件读写。path/key 可注入(测试用默认即生产路径/密钥)。"""

    def __init__(self, path: str | None = None, key: bytes | None = None):
        self._path = path or state_file()
        self._key = key

    def _master(self) -> bytes:
        return self._key if self._key else ensure_key()

    def load(self) -> dict:
        _, open_sealed = _load_crypto()
        try:
            with open(self._path, "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            return _empty()
        except OSError as exc:
            raise StoreError(f"读状态文件失败: {exc}") from exc
        if not blob:
            return _empty()
        try:
            data = json.loads(open_sealed(blob, self._master()).decode("utf-8"))
        except Exception as exc:
            bak = f"{self._path}.bak-{int(time.time())}"
            try:
                os.replace(self._path, bak)
            except OSError:
                bak = "(改名失败)"
            raise StoreCorrupt(f"状态文件解密/解析失败({exc});原文件已留为 {bak}") from exc
        return _normalize(data)

    def save(self, data: dict) -> dict:
        seal, _ = _load_crypto()
        data = _normalize(data)
        data["version"] = int(data.get("version", 0)) + 1
        blob = seal(json.dumps(data, ensure_ascii=False).encode("utf-8"), self._master())
        _atomic_write(self._path, blob, mode=0o600)
        return data

    # ── 高层操作(锁内读-改-写) ──

    def get_state(self) -> dict:
        with _lock:
            return self.load()

    def add_history(self, line) -> dict:
        line = str(line or "")[:HISTORY_LINE_MAX].strip()
        with _lock:
            st = self.load()
            if not line or (st["history"] and st["history"][-1] == line):
                return st                       # 空/与上一条重复 → 不写
            st["history"].append(line)
            st["history"] = st["history"][-HISTORY_MAX:]
            return self.save(st)

    def clear_history(self) -> dict:
        with _lock:
            st = self.load()
            st["history"] = []
            return self.save(st)

    def set_remark(self, client_id: str, text: str) -> dict:
        """写/清 beacon 备注(空串 = 删除)。"""
        with _lock:
            st = self.load()
            cid, text = str(client_id)[:64], str(text or "").strip()[:500]
            if text:
                st["remarks"][cid] = text
            else:
                st["remarks"].pop(cid, None)
            return self.save(st)

    def set_hidden(self, client_id: str, hidden: bool, ts: float | None = None) -> dict:
        """隐藏/恢复 beacon(记隐藏时刻, 收纳列表按它排序 + 判过期)。"""
        with _lock:
            st = self.load()
            cid = str(client_id)[:64]
            if hidden:
                st["hidden"][cid] = float(ts if ts is not None else time.time())
            else:
                st["hidden"].pop(cid, None)
            return self.save(st)

    def set_snippets(self, snippets) -> dict:
        """整表覆盖写入片段库。不做 version 乐观锁校验:多标签页编辑片段极易撞版本,
        保存被拒 + 强制重载比丢一次保存更糟(35B 决策;其它分区行为不变)。"""
        with _lock:
            st = self.load()
            st["snippets"] = snippets if isinstance(snippets, list) else []
            return self.save(st)
