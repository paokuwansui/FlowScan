#!/usr/bin/env python3
"""
CDN 黑名单过滤器。
  作为 CLI 工具: python bin/filter_cdn.py <target>
    exit 0 = 放行, exit 1 = 拦截 (含 cdncheck 二次验证)

  作为可导入模块: from bin.filter_cdn import load_blacklist, is_blacklisted
    供 pipeline.py 调用，仅检测 black_list.cfg 静态规则，不调用 cdncheck
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
import sys


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


CONFIG_PATH = os.path.join(_project_root(), "black_list.cfg")


# ============================================================
# 配置文件加载
# ============================================================


def load_blacklist(config_path: str = CONFIG_PATH) -> tuple[
    list[str],  # 域名后缀
    list[str],  # 关键词
    list[ipaddress.IPv4Network | ipaddress.IPv6Network],  # IP 段
]:
    """解析 black_list.cfg，返回 (后缀列表, 关键词列表, IP段列表)"""
    suffixes: list[str] = []
    keywords: list[str] = []
    ip_ranges: list[str] = []

    if not os.path.exists(config_path):
        return suffixes, keywords, []

    with open(config_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 关键词 ~xxx
            if line.startswith("~"):
                kw = line[1:].strip()
                if kw:
                    keywords.append(kw)
                continue
            # IP CIDR
            if "/" in line:
                try:
                    ipaddress.ip_network(line, strict=False)
                    ip_ranges.append(line)
                    continue
                except ValueError:
                    pass
            # 域名后缀
            suffixes.append(line)

    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in ip_ranges:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue

    return suffixes, keywords, nets


# 模块级缓存，首次 import 时加载一次
_SUFFIXES, _KEYWORDS, _NETWORKS = load_blacklist()


def reload_blacklist() -> None:
    """重新加载配置文件（如果运行时被修改）"""
    global _SUFFIXES, _KEYWORDS, _NETWORKS
    _SUFFIXES, _KEYWORDS, _NETWORKS = load_blacklist()


# ============================================================
# 检测逻辑（纯静态规则，不调 cdncheck）
# ============================================================


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _matches_ip_cidr(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _NETWORKS)


def _matches_domain(target: str) -> bool:
    if not target:
        return False
    # 关键词
    if any(kw in target for kw in _KEYWORDS):
        return True
    # 后缀
    for suffix in _SUFFIXES:
        if target == suffix or target.endswith("." + suffix):
            return True
    return False


def is_blacklisted(target: str) -> bool:
    """供 pipeline.py 调用 — 仅检测静态规则，不调 cdncheck"""
    target = target.strip().strip("[]").lower()
    if not target:
        return False
    if _is_ip(target):
        return _matches_ip_cidr(target)
    return _matches_domain(target)


# ============================================================
# CLI 入口（含 cdncheck 二次验证）
# ============================================================


def main() -> int:
    if len(sys.argv) < 2:
        return 0

    raw_target = sys.argv[1].strip()
    if not raw_target:
        return 0

    target = raw_target.strip("[]").lower()

    # ── 1. 静态黑名单 ──
    if is_blacklisted(target):
        print(f"[filter_cdn] BLOCK: {raw_target}", file=sys.stderr)
        return 1

    # ── 2. cdncheck 验证 ──
    try:
        r = subprocess.run(
            ["cdncheck", "-i", target, "-cdn", "-resp", "-silent"],
            capture_output=True, text=True, timeout=10,
        )
        if r.stdout.strip():
            print(
                f"[filter_cdn] BLOCK (cdncheck): {raw_target} -> {r.stdout.strip()}",
                file=sys.stderr,
            )
            return 1
    except Exception as exc:
        print(f"[filter_cdn] cdncheck error, allowing: {exc}", file=sys.stderr)

    print(f"[filter_cdn] PASS: {raw_target}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
