"""
@module: ps
@desc: 列出当前进程
"""
import os

MODULE = {
    "desc": "列出当前进程",
    "params": [],
}


def run():
    """通用入口（平台未知时自动判定）。"""
    if os.name == "nt":
        return run_windows()
    return run_linux()


def run_linux():
    """读取 /proc 获取进程列表"""
    lines = []
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except PermissionError:
        return "(cannot read /proc)"
    for pid in sorted(pids, key=int)[:100]:
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                comm = f.read().strip()
        except (PermissionError, FileNotFoundError):
            comm = "?"
        try:
            with open(f"/proc/{pid}/cmdline", "r") as f:
                cmdline = f.read().replace("\x00", " ").strip() or comm
        except (PermissionError, FileNotFoundError):
            cmdline = comm
        lines.append(f"{pid:>6}  {cmdline[:80]}")
    header = f"PID     Command\n{'-'*50}\n"
    return header + "\n".join(lines) if lines else "(no processes)"


def run_windows():
    """调用 tasklist 获取进程列表"""
    import subprocess
    try:
        out = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            timeout=10, text=True,
        )
        return out.strip()
    except Exception as e:
        return f"(error: {e})"


if __name__ == "__main__":
    print(run_linux())
