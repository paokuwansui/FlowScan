import os
from typing import Any, Dict, Optional

from .config import render_template
from .tool_module import ToolModule, load_tools
from .utils import check_tool_installed, is_local_command_done, mark_local_command, run_cmd


def ensure_tool(tool: ToolModule, config: Dict[str, Any], redis_client: Optional[Any] = None) -> bool:
    check_cmd = render_template(tool.check_command, {}, config)
    if check_tool_installed(check_cmd, tool.expect_keyword, tool.exclude_keyword, timeout=30):
        print(f"[INIT] {tool.name} ready")
        return True
    if not tool.install_steps:
        print(f"[INIT] {tool.name} missing and no install steps")
        return False
    print(f"[INIT] {tool.name} installing ({len(tool.install_steps)} steps)")
    for raw_cmd in tool.install_steps:
        cmd = render_template(raw_cmd, {}, config)
        if is_local_command_done(cmd):
            print(f"[INIT] {tool.name} skip local: {cmd}")
            continue
        if redis_client and redis_client.is_command_executed(cmd):
            print(f"[INIT] {tool.name} skip global: {cmd}")
            mark_local_command(cmd)
            continue
        mark_local_command(cmd)
        ok, output, code = run_cmd(cmd, timeout=tool.install_timeout)
        if not ok:
            print(f"[INIT] {tool.name} install failed exit={code}: {cmd}\n{output[-1000:]}")
            return False
        if redis_client:
            redis_client.mark_command_executed(cmd)
        print(f"[INIT] {tool.name} ok: {cmd}")
    return check_tool_installed(check_cmd, tool.expect_keyword, tool.exclude_keyword, timeout=30)


def init_all(modules_dir: str, config: Dict[str, Any], redis_client: Optional[Any] = None) -> Dict[str, bool]:
    tools = load_tools(modules_dir)
    result: Dict[str, bool] = {}
    for tool in tools.values():
        result[tool.name] = ensure_tool(tool, config, redis_client)
    return result
