#!/usr/bin/env python3
"""反向 whois:用域名/组织名反查关联域名。

先 whois 拿注册组织名,再用组织名与域名查 viewdns.info 免费反向 whois,
正则提取关联域名,产出 DNS_NAME。纯 stdlib(urllib + whois 命令)。

用法:
  python ./bin/reverse_whois.py tesla.com

输出(每行一个 JSON):
  {"DNS_NAME": "tesla.net"}
  {"DNS_NAME": "teslamotors.com"}
"""

import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request

DOMAIN_RE = re.compile(r"<td>([a-zA-Z0-9.-]+\.[a-z]{2,})</td>")
EXCLUDE = {"viewdns.info", "example.com", "iana.org", "verisign.com"}


def main() -> int:
    query = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if not query:
        print("[reverse_whois] no query", file=sys.stderr)
        return 1
    query = query.strip().lower().lstrip("*.")

    # 1. whois 拿注册组织名(作为反向查询关键词)
    org = None
    try:
        out = subprocess.run(
            ["whois", query], capture_output=True, text=True, timeout=20
        ).stdout
        m = re.search(
            r"(?i)(?:registrant\s+organization|org-name|organisation)\s*:\s*(.+)",
            out,
        )
        if m:
            org = m.group(1).strip()
    except Exception:
        pass

    keywords = [k for k in (org, query) if k]
    domains = set()
    for kw in keywords[:2]:
        url = f"https://viewdns.info/reversewhois/?q={urllib.parse.quote(kw)}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                html = resp.read().decode("utf-8", "ignore")
        except Exception as exc:
            print(f"[reverse_whois] query failed: {exc}", file=sys.stderr)
            continue
        for m in DOMAIN_RE.finditer(html):
            d = m.group(1).strip().lower().lstrip("*.")
            if d and d not in EXCLUDE:
                domains.add(d)

    for d in sorted(domains):
        print(json.dumps({"DNS_NAME": d}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
