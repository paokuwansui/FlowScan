"""
@module: sandbox_check
@desc: 沙箱/虚拟机自检（CPU 核数、内存、hypervisor、常见沙箱进程）
"""
import os
import subprocess

MODULE = {
    "desc": "沙箱/VM 自检（部署前防蜜罐，可选）",
    "params": [],
}

_SUSPECT_PROCS = ("vboxservice", "vboxtray", "vmwaretray", "vmwareuser",
                  "procmon", "wireshark", "ida", "x64dbg", "ollydbg",
                  "windbg", "qemu", "frida", "xenservice", "dnx")


def run():
    import multiprocessing
    flags = []
    try:
        cpus = multiprocessing.cpu_count()
        if cpus <= 2:
            flags.append(f"CPU 核数过少: {cpus}")
    except Exception:
        pass
    try:
        with open("/proc/meminfo") as f:
            total_kb = int([l for l in f if l.startswith("MemTotal")]
                           [0].split()[1])
        if total_kb < 2_000_000:
            flags.append(f"内存过小: {total_kb // 1024}MB")
    except Exception:
        pass
    try:
        with open("/proc/cpuinfo") as f:
            if "hypervisor" in f.read():
                flags.append("hypervisor 标志（虚拟机）")
    except Exception:
        pass
    try:
        if os.name == "nt":
            out = subprocess.check_output(["tasklist"], text=True,
                                          timeout=10)
        else:
            out = subprocess.check_output(["ps", "-A", "-o", "comm="],
                                          text=True, timeout=10)
        low = out.lower()
        for n in _SUSPECT_PROCS:
            if n in low:
                flags.append(f"沙箱进程: {n}")
    except Exception:
        pass
    if not flags:
        return "[*] 未发现可疑环境（CPU/内存/进程正常）"
    return "沙箱/VM 自检:\n" + "\n".join(f"  [!] {f}" for f in flags)
