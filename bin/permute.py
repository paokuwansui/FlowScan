#!/usr/bin/env python3
"""子域名排列变异:从已发现子域名生成变体,产出 DNS_NAME。

dnsgen 风格精简版:对子域名标签做 前后缀 + 数字 变异,产出变体供
subfinder/ksubdomain/crtsh 二次验证(形成递归)。纯本地计算,无网络。

用法:
  python ./bin/permute.py api.example.com

输出(每行一个 JSON):
  {"DNS_NAME": "api-dev.example.com"}
  {"DNS_NAME": "dev-api.example.com"}
  {"DNS_NAME": "api1.example.com"}
"""

import json
import sys

WORDS = [
    "dev", "test", "staging", "prod", "qa", "uat", "beta", "api", "app",
    "admin", "internal", "vpn", "mail", "web", "old", "new", "backup",
]
DIGITS = ["1", "2", "01", "02", "3"]


def main() -> int:
    domain = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if not domain:
        print("[permute] no domain", file=sys.stderr)
        return 1

    labels = domain.strip().lower().rstrip(".").split(".")
    if len(labels) < 3:
        return 0  # 裸主域(example.com),无子域名标签可排列

    base = ".".join(labels[1:])
    sub = labels[0]

    variants = set()
    for w in WORDS:
        variants.add(f"{sub}-{w}")
        variants.add(f"{w}-{sub}")
    for d in DIGITS:
        variants.add(f"{sub}{d}")
        variants.add(f"{sub}-{d}")

    for v in sorted(variants):
        print(json.dumps({"DNS_NAME": f"{v}.{base}"}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
