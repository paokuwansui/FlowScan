"""
server/ui/console.py — 交互式控制台（纯 UI，T3.3/T4.6）

职责: 读输入（readline 历史/补全）、调 dispatcher.execute、渲染输出。
无任何业务逻辑——命令实现全部在 engine/commands/ 与模块层。

与 Client 通道共享同一 dispatcher（命令入口收敛，Q6 多 UI）。

事件实时渲染（Q6/10.3）: 后台转发线程轮询事件文件增量（200ms），
新事件经 safe_print 打断渲染——会话只写文件，UI 只读文件。
"""

import json as _json
import os as _os
import readline
import secrets as _secrets
import sys as _sys
import threading
import time
from typing import Optional

from server.core.config import update_config_file
from server.core.log import get_logger
from server.infra.event_writer import EventWriter

logger = get_logger("console")

_FORWARD_POLL_INTERVAL = 0.2  # 秒（8.3 风险项：可接受）


def enrich_result_output(mgr, rec: dict) -> dict:
    """task_result 事件只记元数据(out_len/ok)，完整输出从内存结果队列按 task_id 取。

    2026-09-28:事件里不再写 output 内容(事件文件是明文, 写内容会绕过加密落盘),
    所以这里必须从内存补全;取不到(如结果已被上限挤出/重启后不在内存)时给出
    明确的元数据说明, 而不是显示成"空结果"。
    """
    bid = rec.get("beacon", "")
    task_id = rec.get("task_id", "")
    rec = dict(rec)
    if bid and task_id:
        client = mgr.get_client(bid)
        if client:
            for r in client.results:
                if r.task_id == task_id:
                    rec["output"] = r.output
                    return rec
    if "output" not in rec:
        bits = []
        if rec.get("out_len") is not None:
            bits.append(f"{rec.get('out_len')} 字符")
        if rec.get("ok") is False:
            bits.append("执行失败")
        rec["output"] = "(结果已不在内存" + ("; " + ", ".join(bits) if bits else "") + ")"
    return rec


def render_event(rec: dict) -> str:
    """事件记录 → 控制台渲染文本（只渲染用户关注的事件，其余返回空串）。"""
    ev = rec.get("event", "")
    bid = str(rec.get("beacon", "-"))[:8]
    if ev == "connect":
        # 只渲染新上线；周期性回连的 connect 事件不刷屏
        # （事件文件仍完整记录每次 connect/disconnect，审计不丢）
        if not rec.get("first"):
            return ""
        fork = " (fork)" if rec.get("fork") else ""
        return f"[+] 上线: {bid}...{fork}"
    if ev == "disconnect":
        # R22:正常收尾(每 60s 一次)与失联移除不渲染,避免刷屏;
        # 异常中断(收帧断开/非法消息/发送失败/回放失败)提示一行,便于当场发现
        reason = str(rec.get("reason") or "")
        if reason in ("", "normal", "timeout"):
            return ""
        return f"[!] 连接中断: {bid}... 原因={reason}"
    if ev == "task_sent":
        # 完整 task_id（36 字符 UUID）+ 完整 beacon id，便于与入队消息对照
        return f"[>] {rec.get('beacon', '-')} 任务下发: {rec.get('task_id', '')}"
    if ev == "task_result":
        # 事件只有元数据;完整输出由 enrich_result_output 从内存补全后传入。
        # 结果从新行开始，避免长输出挤在"结果:"同一行。
        head = "" if rec.get("ok", True) else " (失败)"
        return f"[*] {rec.get('beacon', '-')} 结果{head}:\n{rec.get('output', '')}"
    return ""


class Console:
    """交互式命令行控制台（纯 UI 前端）。"""

    def __init__(self, dispatcher, on_exit=None):
        self._dispatcher = dispatcher
        self._on_exit = on_exit
        self._running = True
        self.safe_print = print  # P4 事件转发线程会替换为 readline 安全版

    @property
    def running(self) -> bool:
        return self._running

    @property
    def dispatcher(self):
        return self._dispatcher

    def execute(self, line: str) -> str:
        """转发给命令引擎（无业务逻辑）。"""
        return self._dispatcher.execute(line)

    def stop(self) -> None:
        self._running = False


def _history_master(console: Console) -> Optional[bytes]:
    """CLI 历史加密主密钥:config.json 的 history_key(缺则生成并原子写回)。

    与 web 面板状态同思路(密钥托管在项目配置文件里):配置文件本身已 gitignore,
    不额外引出密钥文件。取不到配置(如自定义部署)时返回 None → 历史不落盘,
    只保留本次会话内存历史, 并打印原因(不静默)。
    """
    try:
        cfg = getattr(console.dispatcher, "config", None)
        path = getattr(cfg, "config_path", "") or ""
        if not path or not _os.path.isfile(path):
            print("[历史] 未取到 C2 配置文件路径; 历史本次不落盘")
            return None
        with open(path, encoding="utf-8") as f:
            raw = _json.load(f)
        key = str(raw.get("history_key") or "")
        if not key:
            key = _secrets.token_hex(32)
            update_config_file(path, history_key=key)
            print(f"[历史] 已在 {_os.path.basename(path)} 生成 history_key(历史加密用)")
        return key.encode()
    except Exception as exc:
        print(f"[历史] 密钥准备失败, 本次历史不落盘: {exc}")
        return None


def _history_load(path: str, master: bytes) -> None:
    """读加密历史(JSON 数组)→ readline 历史;解密失败只提示, 不删原文件。"""
    try:
        from server.core.crypto import open_sealed
        with open(path, "rb") as f:
            blob = f.read()
        if not blob:
            return
        data = _json.loads(open_sealed(blob, master).decode("utf-8"))
        for line in (data if isinstance(data, list) else []):     # 文件顺序=从旧到新
            readline.add_history(str(line))
    except FileNotFoundError:
        return
    except Exception as exc:
        print(f"[历史] 解密失败({exc}); 本次从空历史开始, 原文件保留在 {path}")


def _history_save(path: str, master: bytes) -> bool:
    """readline 历史 → JSON → 加密(0600)原子写。成功返回 True。"""
    try:
        from server.core.crypto import seal
        n = readline.get_current_history_length()
        lines = [readline.get_history_item(i) for i in range(1, n + 1)]
        lines = [str(x) for x in lines if x and str(x).strip()]
        blob = seal(_json.dumps(lines, ensure_ascii=False).encode("utf-8"), master)
        tmp = path + ".tmp"
        fd = _os.open(tmp, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
        with _os.fdopen(fd, "wb") as f:
            f.write(blob)
        _os.replace(tmp, path)
        return True
    except Exception as exc:
        print(f"[历史] 加密保存失败: {exc}")
        return False


def console_loop(console: Console) -> None:
    """交互式控制台主循环。exit 经 dispatcher 触发 on_exit（server.stop）。"""

    # 历史加密落盘(2026-09-28): ~/.pyexec2_history.enc(ChaCha20+HMAC, 0600)
    # 旧的明文 ~/.pyexec2_history 若存在则本次导入, 加密写成功后再删除(不兼容保留)。
    hist_file = _os.path.expanduser("~/.pyexec2_history.enc")
    hist_plain = _os.path.expanduser("~/.pyexec2_history")
    hist_master = _history_master(console)
    _hist_migrated = False
    if hist_master:
        if _os.path.isfile(hist_file):
            _history_load(hist_file, hist_master)
        elif _os.path.isfile(hist_plain):
            try:
                readline.read_history_file(hist_plain)
                _hist_migrated = True
                print(f"[历史] 检测到明文历史, 本次会话结束后迁移为加密存储 {hist_file}")
            except OSError as exc:
                print(f"[历史] 明文历史读取失败: {exc}")

    disp = console.dispatcher

    def _completer(text: str, state: int) -> Optional[str]:
        options = list(disp.command_names())
        try:
            for m in disp.modules.list_modules():
                options.append(m["name"])
            if disp.smods:
                for m in disp.smods.list_modules():
                    options.append(m["name"])
            for c in disp.mgr.list_clients():
                options.append(c.client_id)
        except Exception:
            pass
        matches = sorted(w for w in options if w.startswith(text))
        return matches[state] if state < len(matches) else None

    readline.set_completer(_completer)
    readline.parse_and_bind("tab: complete")

    def safe_print(*args, **kwargs):
        """后台线程安全打印，不破坏 readline 提示符。

        无论用户是否正在输入（buf 可能为空），打印后都重绘提示符；
        否则事件到达时 \r\033[K 清掉当前行后提示符就消失了。
        """
        try:
            buf = readline.get_line_buffer()
            _sys.stdout.write("\r\033[K")
        except Exception:
            buf = ""
        print(*args, **kwargs)
        _sys.stdout.write(f"pyexec> {buf}")
        _sys.stdout.flush()

    console.safe_print = safe_print

    print("PyExec2 Server Console")
    print("Type 'help' for commands, 's_exit' to quit.\n")

    # 事件转发线程（T4.6）：只转发 console 启动后产生的新事件
    offset = _os.path.getsize(disp.audit.path) \
        if _os.path.isfile(disp.audit.path) else 0
    stopped = threading.Event()

    def _forward() -> None:
        nonlocal offset
        while not stopped.is_set():
            try:
                lines, new_offset = disp.audit.read_from(offset)
                if new_offset:
                    offset = new_offset
                for line in lines:
                    rec = EventWriter.parse_line(line)
                    if rec.get("event") == "task_result":
                        rec = enrich_result_output(disp.mgr, rec)
                    text = render_event(rec)
                    if text:
                        console.safe_print(text)
            except Exception:
                pass
            time.sleep(_FORWARD_POLL_INTERVAL)

    forward_thread = threading.Thread(target=_forward, daemon=True)
    forward_thread.start()

    while console.running:
        try:
            line = input("pyexec> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] exiting...")
            break

        if not line:
            continue

        output = console.execute(line)
        if output:
            _sys.stdout.write("\r\033[K")
            print(output)
            _sys.stdout.flush()

    stopped.set()
    forward_thread.join(timeout=1)

    if hist_master:
        readline.set_history_length(1000)
        if _history_save(hist_file, hist_master):
            if _hist_migrated:      # 加密写成功后才删明文(失败则保留, 不丢历史)
                try:
                    _os.unlink(hist_plain)
                    print(f"[历史] 已迁移为加密存储并删除明文: {hist_file}")
                except OSError as exc:
                    print(f"[历史] 明文历史删除失败({exc}); 已加密保存, 明文请手工删除")
