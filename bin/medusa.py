#!/usr/bin/env python3
"""Medusa 弱口令爆破。

输入 ip:port(OPEN_TCP_PORT),按端口映射 Medusa 服务模块,用内置弱口令
字典做暴力破解,产出 FINDING(发现的凭证)。不在映射内的端口(未知服务)
跳过不爆破。

用法:
  python ./bin/medusa.py 1.2.3.4:22
  python ./bin/medusa.py 1.2.3.4:3306

输出(每行一个 JSON):
  {"FINDING": "weak credential: ssh://root:toor@1.2.3.4:22"}
"""

import json
import os
import re
import subprocess
import sys

# 端口 -> Medusa 服务模块映射(仅覆盖 Medusa 明确支持的服务级弱口令)
PORT_MODULE = {
    22: "ssh",
    21: "ftp",
    23: "telnet",
    3306: "mysql",
    1433: "mssql",
    5432: "postgres",
    5900: "vnc",
    5901: "vnc",
    5902: "vnc",
    3389: "rdp",
    139: "smbnt",
    445: "smbnt",
    25: "smtp",
    110: "pop3",
    143: "imap",
}

# Medusa 成功输出示例:
#   ACCOUNT FOUND: [ssh] Host: 192.168.1.1 User: root Password: toor [SUCCESS]
FOUND_RE = re.compile(
    r"ACCOUNT FOUND:\s*\[(\w+)\]\s*Host:\s*(\S+)\s*User:\s*(\S+)\s*"
    r"Password:\s*(\S+)\s*\[SUCCESS\]"
)


def main() -> int:
    target = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if ":" not in target:
        print(f"[medusa] invalid target: {target!r}", file=sys.stderr)
        return 1

    host, port_str = target.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        print(f"[medusa] invalid port: {port_str!r}", file=sys.stderr)
        return 1

    module = PORT_MODULE.get(port)
    if not module:
        # 未知服务端口,不爆破
        return 0

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    users = os.path.join(base, "wordlists", "users.txt")
    passes = os.path.join(base, "wordlists", "passwords.txt")
    if not (os.path.isfile(users) and os.path.isfile(passes)):
        print("[medusa] missing wordlists/users.txt or passwords.txt", file=sys.stderr)
        return 1

    cmd = [
        "medusa", "-h", host, "-n", str(port), "-M", module,
        "-U", users, "-P", passes,
        "-t", "4", "-f", "-e", "ns",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        print(f"[medusa] failed: {exc}", file=sys.stderr)
        return 1

    out = (r.stdout or "") + "\n" + (r.stderr or "")
    for m in FOUND_RE.finditer(out):
        mod, h, u, p = m.groups()
        finding = f"weak credential: {mod}://{u}:{p}@{h}"
        print(json.dumps({"FINDING": finding}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
