#!/usr/bin/env python3
"""ASN 枚举:域名/组织名 → ASN → IP 范围。

查 bgpview.io 免费 API(无需 key):先 search 匹配 ASN 及直接关联前缀,
再逐 ASN 拉完整前缀,产出 IP_RANGE(网段)。纯 stdlib(urllib)。

用法:
  python ./bin/asn.py tesla.com

输出(每行一个 JSON):
  {"IP_RANGE": "8.244.131.0/24"}
  {"IP_RANGE": "8.45.124.0/24"}
"""

import json
import sys
import urllib.parse
import urllib.request


def _get(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def main() -> int:
    term = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if not term:
        print("[asn] no query term", file=sys.stderr)
        return 1
    term = term.strip().lower().lstrip("*.")

    prefixes = set()
    asns = []

    # 1. search:匹配的 ASN + 直接关联前缀
    try:
        data = _get(f"https://api.bgpview.io/search?query_term={urllib.parse.quote(term)}")
    except Exception as exc:
        print(f"[asn] search failed: {exc}", file=sys.stderr)
        return 1

    d = data.get("data", {}) or {}
    for p in d.get("ipv4_prefixes", []) or []:
        prefix = p.get("prefix")
        if prefix:
            prefixes.add(prefix)
    for a in d.get("asns", []) or []:
        asn = a.get("asn")
        if asn:
            asns.append(asn)

    # 2. 逐 ASN 拉完整前缀(上限 10 个 ASN,防爆炸)
    for asn in asns[:10]:
        try:
            ad = _get(f"https://api.bgpview.io/asn/{asn}/prefixes")
        except Exception:
            continue
        for p in (ad.get("data", {}).get("ipv4_prefixes", []) or []):
            prefix = p.get("prefix")
            if prefix:
                prefixes.add(prefix)

    for prefix in sorted(prefixes):
        print(json.dumps({"IP_RANGE": prefix}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
