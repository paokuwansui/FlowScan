#!/usr/bin/env python3
"""
判断 DNS_NAME 是否为主域名（非子域名）。

使用 tldextract 解析域名，提取注册域名（domain.suffix）。
如果输入值等于注册域名，则为主域名，exit 0；否则 exit 1。

用法:
  python ./bin/is_root_domain.py example.com      # exit 0（主域名）
  python ./bin/is_root_domain.py www.example.com  # exit 1（子域名）
  python ./bin/is_root_domain.py example.co.uk    # exit 0（主域名，双后缀）
  python ./bin/is_root_domain.py api.example.co.uk# exit 1（子域名）

在 YAML 命令中搭配 && 使用:
  python ./flowscan3/filter.py {{value}} && python ./bin/is_root_domain.py {{value}} && bbot -t {{value}} ...
"""

import sys

import tldextract


def is_root_domain(value: str) -> bool:
    """判断给定值是否为注册域名（非子域名）。"""
    value = value.strip().strip(".").lower()
    if not value or "." not in value:
        return False

    ext = tldextract.extract(value)
    if not ext.domain or not ext.suffix:
        return False

    registered = f"{ext.domain}.{ext.suffix}"
    # 如果 subdomain 为空（或等于 registered 本身），则是主域名
    if not ext.subdomain or value == registered:
        return True

    return False


def main() -> int:
    if len(sys.argv) < 2:
        print("[is_root_domain] usage: is_root_domain.py <domain>", file=sys.stderr)
        return 1

    raw = sys.argv[1].strip()
    if not raw:
        return 1

    result = is_root_domain(raw)
    if result:
        print(f"[is_root_domain] {raw} is root domain", file=sys.stderr)
        return 0
    else:
        print(f"[is_root_domain] {raw} is subdomain, skipping", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
