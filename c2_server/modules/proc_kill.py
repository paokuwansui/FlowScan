"""proc_kill — 按 pid 或监听端口杀进程(纯标准库)。

用法(console 或页面模块执行):
  proc_kill <pid>           直接数字 = pid
  proc_kill -pid <pid>      显式 pid
  proc_kill -listen <port>  杀监听该端口的进程(Linux /proc/net/tcp[6] + fd inode 匹配)
返回: 被杀的 pid / 结果; 无权限或不存在会明确提示。
"""

import os
import re
import signal

MODULE = {
    "desc": "按 pid 或监听端口杀进程(-listen <port> / -pid <pid> / 数字=pid)",
    "params": [("target", "必填；<pid> | -pid <pid> | -listen <port>")],
}

try:
    SIGKILL = signal.SIGKILL
except AttributeError:
    SIGKILL = signal.SIGTERM  # Windows 无 SIGKILL


def _pid_by_inode(inode):
    """遍历 /proc/<pid>/fd 符号链接, 匹配 socket:[inode] → pid 列表。"""
    pids = []
    try:
        for ent in os.listdir("/proc"):
            if not ent.isdigit():
                continue
            fd_dir = f"/proc/{ent}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            for fd in fds:
                try:
                    link = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                if link == f"socket:[{inode}]":
                    pids.append(int(ent))
                    break
    except OSError:
        pass
    return pids


def _pid_listen(port):
    """找出监听指定端口的 pid 列表(仅 LISTEN 状态, tcp + tcp6)。"""
    want = "%04X" % int(port)  # /proc/net/tcp 端口为小端 hex, 如 22 → 0016
    inodes = []
    for tbl in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(tbl, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            local, st, inode = parts[1], parts[3], parts[9]
            if st != "0A":  # 仅 LISTEN
                continue
            if local.partition(":")[2].upper() == want:
                inodes.append(inode)
    pids = []
    for inode in inodes:
        for pid in _pid_by_inode(inode):
            if pid not in pids:
                pids.append(pid)
    return pids


def _kill(pid):
    """杀进程。True=已杀, None=不存在, False=权限不足/失败。"""
    try:
        os.kill(pid, SIGKILL)
        return True
    except ProcessLookupError:
        return None
    except (PermissionError, OSError):
        return False


def _fmt(r):
    if r is True:
        return "已杀"
    if r is None:
        return "不存在"
    return "权限不足"


def run(target):
    t = str(target).strip()
    if t.startswith("-listen"):
        port_s = t[len("-listen"):].strip()
        if not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
            return f"(proc_kill: 无效端口 {port_s!r})"
        pids = _pid_listen(port_s)
        if not pids:
            return f"(proc_kill: 端口 {port_s} 无监听进程)"
        parts = [f"pid {pid} {_fmt(_kill(pid))}" for pid in pids]
        return "(proc_kill: " + "; ".join(parts) + ")"
    if t.startswith("-pid"):
        pid_s = t[len("-pid"):].strip()
    elif t.isdigit():
        pid_s = t
    else:
        return (f"(proc_kill: 无法解析 {target!r}——支持 "
                f"<pid> / -pid <pid> / -listen <port>)")
    if not pid_s.isdigit() or int(pid_s) <= 0:
        return f"(proc_kill: 无效 pid {pid_s!r})"
    pid = int(pid_s)
    return f"(proc_kill: pid {pid} {_fmt(_kill(pid))})"


if __name__ == "__main__":
    print("usage: proc_kill <pid> | -pid <pid> | -listen <port>")
