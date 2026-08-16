#!/usr/bin/env python3
"""反向 DNS(PTR)查询:IP_ADDRESS → DNS_NAME。

用系统 resolver 对 IP 做反向解析(PTR),找出该 IP 对应的域名。无 PTR
记录的 IP 静默跳过。纯 stdlib(socket)。

用法:
  python ./bin/ptr.py 8.8.8.8

输出(每行一个 JSON):
  {"DNS_NAME": "dns.google"}
"""

import json
import socket
import sys

socket.setdefaulttimeout(5)


def main() -> int:
    ip = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if not ip:
        print("[ptr] no ip", file=sys.stderr)
        return 1

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return 0  # 无 PTR 记录

    hostname = (hostname or "").strip().lower().rstrip(".")
    if hostname and hostname != ip:
        print(json.dumps({"DNS_NAME": hostname}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
