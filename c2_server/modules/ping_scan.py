"""ping_scan — 用 ICMP(ping 命令)探测主机是否存活(纯标准库)。

用法(console 或页面模块执行):
  ping_scan <ips>
  ips:  192.168.0.0/24(CIDR) | 192.168.0.1-255(末段范围) | 192.168.0.1(单 IP)
        | 192.168.0.1,192.168.0.2(逗号列表),可混用
行为: 展开目标 → 并发 ping(-c 1 -W 2) → 列出存活主机(含 RTT)与统计。
"""

import ipaddress
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

MODULE = {
    "desc": "ICMP 主机存活探测(ping; IP 支持 CIDR/末段范围/逗号列表)",
    "params": [("ips", "必填；192.168.0.0/24 | 192.168.0.1-255 | "
                        "192.168.0.1,192.168.0.2")],
}

_MAX_TARGETS = 4096    # 目标数保护上限
_MAX_WORKERS = 32      # 并发 ping 上限
_TIMEOUT = 2.0         # 单 ping 超时(秒)


def _parse_ips(s):
    """展开 IP 参数 → 去重排序的字符串列表;非法返回 None。"""
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                out.extend(str(h) for h in net.hosts())  # 排除网络/广播地址
            except ValueError:
                return None
        elif "-" in part:
            head, _, tail = part.rpartition("-")
            if "." not in head or not tail.isdigit():
                return None
            try:
                base = ipaddress.ip_address(head)
            except ValueError:
                return None
            last = int(head.rsplit(".", 1)[1])
            if int(tail) <= last:
                return None
            for i in range(last, int(tail) + 1):
                out.append(str(ipaddress.ip_address(int(base) + (i - last))))
        else:
            try:
                out.append(str(ipaddress.ip_address(part)))
            except ValueError:
                return None
    if not out:
        return None
    return sorted(set(out), key=lambda x: int(ipaddress.ip_address(x)))


def _ping(ip, timeout=_TIMEOUT):
    """单 IP 单次 ping → RTT 秒; 不可达/失败返回 None。"""
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip],
            capture_output=True, text=True, timeout=timeout + 3)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        if "time=" in line:
            try:
                return float(line.split("time=")[1].split()[0])
            except (IndexError, ValueError):
                return 0.0
    return None


def run(ips):
    targets = _parse_ips(str(ips))
    if not targets:
        return (f"(ping_scan: 无法解析 {ips!r}——支持 "
                f"192.168.0.0/24 / 192.168.0.1-255 / 192.168.0.1,192.168.0.2)")
    total = len(targets)
    if total > _MAX_TARGETS:
        return f"(ping_scan: 目标数 {total} 超过上限 {_MAX_TARGETS}, 请缩小范围)"
    t0 = time.time()
    alive = []
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        for ip, rtt in zip(targets, ex.map(_ping, targets)):
            if rtt is not None:
                alive.append((ip, rtt))
    cost = time.time() - t0
    if not alive:
        return (f"(ping_scan: 无存活主机"
                f"(探测 {total} 个, 耗时 {cost:.1f}s))")
    lines = [f"存活 {len(alive)}/{total}  耗时 {cost:.1f}s:"]
    for ip, rtt in alive:
        lines.append(f"  {ip:<16} {rtt * 1000:.1f}ms")
    return "(ping_scan:\n" + "\n".join(lines) + "\n)"
