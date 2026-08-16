#!/usr/bin/env python3
"""crt.sh 证书透明度(CT)日志查询,产出子域名 DNS_NAME。

输入域名,查 crt.sh 的证书透明度日志,提取所有出现过的域名(含子域名)。
纯 stdlib(urllib),无外部依赖。是子域名枚举的强补充来源。

用法:
  python ./bin/crtsh.py example.com

输出(每行一个 JSON):
  {"DNS_NAME": "www.example.com"}
  {"DNS_NAME": "api.example.com"}
"""

import json
import sys
import urllib.request


def main() -> int:
    domain = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if not domain:
        print("[crtsh] no domain", file=sys.stderr)
        return 1

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", "ignore")
    except Exception as exc:
        print(f"[crtsh] query failed: {exc}", file=sys.stderr)
        return 1

    try:
        rows = json.loads(raw)
    except Exception:
        rows = []

    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        name_value = row.get("name_value", "") or ""
        # name_value 可能一行一个域名(换行分隔)
        for name in name_value.splitlines():
            name = name.strip().lower().lstrip("*.")
            if not name or name in seen:
                continue
            seen.add(name)
            print(json.dumps({"DNS_NAME": name}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
