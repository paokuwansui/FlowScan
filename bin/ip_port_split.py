#!/usr/bin/env python3
"""HOST_TCP_PORT_OPEN → 单个 OPEN_TCP_PORT 拆分器。

naabu 产出的是聚合格式 "1.2.3.4 -> [80,443,8080]",httpx 消费的却是
单个 "1.2.3.4:80"。本脚本把聚合格式拆成 N 个 ip:port,补上 naabu→httpx
之间的断点。

用法:
  python ./bin/ip_port_split.py "1.2.3.4 -> [80,443,8080]"
  echo "1.2.3.4 -> [22,80]" | python ./bin/ip_port_split.py

输出(每行一个 JSON):
  {"OPEN_TCP_PORT": "1.2.3.4:80"}
  {"OPEN_TCP_PORT": "1.2.3.4:443"}
  {"OPEN_TCP_PORT": "1.2.3.4:8080"}
"""

import json
import sys


def main() -> int:
    value = ""
    if len(sys.argv) > 1:
        value = sys.argv[1]
    else:
        value = sys.stdin.read().strip()

    value = value.strip()
    if "->" not in value:
        print(f"[ip_port_split] invalid HOST_TCP_PORT_OPEN: {value!r}", file=sys.stderr)
        return 1

    host_part, ports_part = value.split("->", 1)
    host = host_part.strip()
    ports_text = ports_part.strip().strip("[]")
    if not host or not ports_text:
        print(f"[ip_port_split] empty host/ports: {value!r}", file=sys.stderr)
        return 1

    ports = [p.strip() for p in ports_text.split(",") if p.strip()]
    seen = set()
    for p in ports:
        target = f"{host}:{p}"
        if target in seen:
            continue
        seen.add(target)
        print(json.dumps({"OPEN_TCP_PORT": target}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
