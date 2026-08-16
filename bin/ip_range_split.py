#!/usr/bin/env python3
"""IP_RANGE → 单个 IP_ADDRESS 展开器。

输入一个或多个 CIDR(逗号分隔),逐 IP 输出 JSON 行,供 FlowScan3
output_parse_code 消费。不做任何过滤(黑名单/CDN/私网均不过滤),
不设展开上限 —— 注意 ipaddress 迭代对任意前缀长度均不设防
(IPv4 /0、IPv6 /64 也能迭代),网段越大输出行数越多,请自行评估
扫描规模。

用法:
  python ./bin/ip_range_split.py 10.0.0.0/24
  python ./bin/ip_range_split.py 1.2.3.0/24,5.6.7.0/28
  python ./bin/ip_range_split.py 2001:db8::/120 --allow-ipv6

输出(每行一个 JSON):
  {"IP_ADDRESS": "10.0.0.0"}
  {"IP_ADDRESS": "10.0.0.1"}
  ...
"""

import argparse
import ipaddress
import json
import os
import sys


def expand_cidr(cidr: str) -> int:
    """展开单个 CIDR,输出 JSON 行。返回 0 成功 / 1 失败。"""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        print(f"[ip_range_split] invalid CIDR: {cidr} ({exc})", file=sys.stderr)
        return 1
    try:
        for ip in network:
            print(json.dumps({"IP_ADDRESS": str(ip)}, ensure_ascii=False), flush=True)
    except BrokenPipeError:
        # 下游管道提前关闭(head/wc 等):重定向 stdout 到 devnull,
        # 避免解释器退出时二次 flush 打印 BrokenPipeError 噪音
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except TypeError as exc:
        # 个别 Python 实现/版本对超大网段迭代有限制时兜底
        print(f"[ip_range_split] cannot expand: {cidr} ({exc})", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="IP_RANGE 网段展开为单个 IP_ADDRESS 事件",
    )
    parser.add_argument(
        "cidrs",
        help="一个或多个 CIDR,逗号分隔,如 10.0.0.0/24,5.6.7.0/28",
    )
    args = parser.parse_args()

    rc = 0
    for cidr in args.cidrs.split(","):
        if cidr.strip():
            rc |= expand_cidr(cidr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
