#!/usr/bin/env python3
"""wayback machine 历史 URL 聚合。

输入域名,查 web.archive.org 的 CDX API,聚合该域名历史抓取过的所有 URL,
产出 URL_UNVERIFIED(历史 URL 可能已失效,交给 httpx 探活后升级为 URL)。
纯 stdlib(urllib),无外部依赖。

用法:
  python ./bin/wayback.py example.com

输出(每行一个 JSON):
  {"URL_UNVERIFIED": "http://example.com/old/path"}
  {"URL_UNVERIFIED": "https://example.com/admin.php"}
"""

import json
import sys
import urllib.parse
import urllib.request


def main() -> int:
    domain = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if not domain:
        print("[wayback] no domain", file=sys.stderr)
        return 1

    # CDX API: collapse=urlkey 去重,filter 只收 200 状态码
    params = urllib.parse.urlencode({
        "url": f"*.{domain}",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "filter": "statuscode:200",
        "limit": "5000",
    })
    url = f"http://web.archive.org/cdx/search/cdx?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=40) as resp:
            raw = resp.read().decode("utf-8", "ignore")
    except Exception as exc:
        print(f"[wayback] query failed: {exc}", file=sys.stderr)
        return 1

    seen = set()
    for line in raw.strip().splitlines():
        try:
            row = json.loads(line)
        except Exception:
            continue
        if not isinstance(row, list) or not row:
            continue
        u = str(row[0]).strip()
        # 首行是表头 "original"
        if u in ("original", "") or not u.startswith(("http://", "https://")):
            continue
        if u in seen:
            continue
        seen.add(u)
        print(json.dumps({"URL_UNVERIFIED": u}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
