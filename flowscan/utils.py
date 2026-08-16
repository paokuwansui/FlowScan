import os
import subprocess
from typing import Any, Dict, Tuple

from .config import load_yaml

_EXECUTED_COMMANDS: set[str] = set()


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cmd(cmd: str, timeout: int | None = None, cwd: str | None = None) -> Tuple[bool, str, int]:
    # timeout=None 表示不限时:模块命令跑多久都不杀,直到自然退出。
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd or project_root(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore",
            timeout=timeout,
        )
        return result.returncode == 0, result.stdout or "", result.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        return False, f"Timeout after {timeout}s: {cmd}\n{output}", 124
    except Exception as exc:
        return False, f"Exec error: {exc}", 1


def check_tool_installed(check_command: str, expect_keyword: str = "", exclude_keyword: str = "", timeout: int = 30) -> bool:
    if not check_command:
        return True
    ok, output, _ = run_cmd(check_command, timeout=timeout)
    if not ok:
        return False
    haystack = output.lower()
    expected = (expect_keyword or "").lower()
    excluded = (exclude_keyword or "").lower()
    if excluded and excluded in haystack:
        return False
    if expected:
        return expected in haystack
    return True


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    return load_yaml(path)


def mark_local_command(cmd: str) -> None:
    _EXECUTED_COMMANDS.add(cmd)


def is_local_command_done(cmd: str) -> bool:
    return cmd in _EXECUTED_COMMANDS
