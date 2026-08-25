"""engine/commands — 内置命令注册（每命令一模块，自动扫描）。

约定: 目录下每个 .py 导出 run(disp, args) -> str。
加载方式与 server_module_loader 一致：spec_from_file_location，
不走 sys.path 包解析（避免缓存冲突）。
"""

import importlib.util
import os
import sys
from pathlib import Path

_COMMANDS_DIR = Path(os.path.dirname(os.path.abspath(__file__)))


def _load_command(path: Path):
    mod_name = f"server.engine.commands.{path.stem}"
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(mod_name, None)
        return None
    return mod


def load_commands() -> dict:
    """扫描本目录，返回 {命令名: run}。"""
    commands = {}
    for f in sorted(_COMMANDS_DIR.glob("*.py")):
        if f.stem == "__init__" or f.stem.startswith("_"):
            continue  # 下划线前缀 = 内部共享模块, 不作为命令注册
        mod = _load_command(f)
        if mod is not None and hasattr(mod, "run"):
            commands[f.stem] = mod.run
    return commands
