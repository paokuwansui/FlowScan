#!/usr/bin/env python3
"""whois 查询,提取注册邮箱 + NS 关联域名。

输入域名,调 Kali 的 whois 命令,正则提取注册邮箱(产出 FINDING)和
NS 关联域名(产出 DNS_NAME),用于发现同一主体的关联资产。

用法:
  python ./bin/whois.py example.com

输出(每行一个 JSON):
  {"FINDING": "whois email: abuse@example.com"}
  {"DNS_NAME": "example.net"}
"""

import json
import re
import subprocess
import sys


def root_domain(name: str) -> str:
    """取 NS 主机名的注册级域名(近似:最后两段)。"""
    parts = [p for p in name.strip(".").split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return name


def main() -> int:
    domain = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if not domain:
        print("[whois] no domain", file=sys.stderr)
        return 1

    try:
        out = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=30
        ).stdout
    except Exception as exc:
        print(f"[whois] failed: {exc}", file=sys.stderr)
        return 1

    # 注册邮箱(去重)
    emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", out))

    # NS 关联域名(去重,排除目标域名自身)
    ns_domains = set()
    for m in re.finditer(r"(?i)name\s*server\s*:\s*(\S+)", out):
        ns_domains.add(root_domain(m.group(1).strip().lower()))

    for e in sorted(emails):
        print(json.dumps({"FINDING": f"whois email: {e}"}, ensure_ascii=False), flush=True)

    for d in sorted(ns_domains):
        if d and d != domain.lower():
            print(json.dumps({"DNS_NAME": d}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
