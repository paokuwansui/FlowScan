"""portscan — TCP 端口扫描(纯标准库,无第三方依赖)。

用法(console 或页面模块执行):
  portscan <ip> <ports>
  ip:    1.2.3.4 | 1.2.3.4,5.6.7.8(逗号列表) | 192.168.1.0/24(CIDR)
         | 192.168.10.1-5(末段范围),可混用逗号分隔
  ports: 22,80,443 | 22-24 | 2221,22,22-24(列表+范围混用)
返回: 按 IP 分组的开放端口列表;无开放端口则返回空结果提示。
"""

import ipaddress
import socket
import threading

MODULE = {
    "desc": "TCP 端口扫描(纯 stdlib; IP 支持列表/CIDR/范围,端口支持列表/范围)",
    "params": [("ip", "必填；1.2.3.4 | 1.2.3.4,5.6.7.8 | 192.168.1.0/24 | "
                      "192.168.10.1-5"),
               ("ports", "必填；22,80,443 | 22-24 | 2221,22,22-24")],
}

_TIMEOUT = 1.0          # 单连接超时(秒)
_MAX_CONNS = 20000      # 连接数保护上限
_MAX_THREADS = 50       # 并发上限


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


def _parse_ports(s):
    """解析端口参数(列表+范围) → 去重排序的端口列表;非法返回 None。"""
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if not a.isdigit() or not b.isdigit():
                return None
            a, b = int(a), int(b)
            if not (1 <= a <= b <= 65535):
                return None
            out.extend(range(a, b + 1))
        else:
            if not part.isdigit() or not 1 <= int(part) <= 65535:
                return None
            out.append(int(part))
    if not out:
        return None
    return sorted(set(out))


def _scan(ip, ports, results, lock):
    open_list = []
    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(_TIMEOUT)
            if s.connect_ex((ip, p)) == 0:
                open_list.append(p)
            s.close()
        except OSError:
            try:
                s.close()
            except OSError:
                pass
    if open_list:
        with lock:
            results[ip] = open_list


def run(ip, ports):
    ips = _parse_ips(ip)
    if ips is None:
        return (f"(portscan: 无法解析 IP 参数 {ip!r}——支持 1.2.3.4 / "
                f"1.2.3.4,5.6.7.8 / 192.168.1.0/24 / 192.168.10.1-5)")
    pl = _parse_ports(ports)
    if pl is None:
        return (f"(portscan: 无法解析端口参数 {ports!r}——"
                f"支持 22,80,443 / 22-24 / 2221,22,22-24)")
    if len(ips) * len(pl) > _MAX_CONNS:
        return (f"(portscan: 连接数 {len(ips)}×{len(pl)} 超上限 "
                f"{_MAX_CONNS}, 请缩小 IP/端口范围)")

    results = {}
    lock = threading.Lock()
    sem = threading.Semaphore(_MAX_THREADS)
    threads = []

    def worker(ip):
        with sem:
            _scan(ip, pl, results, lock)

    for ip in ips:
        t = threading.Thread(target=worker, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    if not results:
        return (f"(portscan: 无开放端口 "
                f"({len(ips)} IP × {len(pl)} 端口, 超时 {_TIMEOUT}s))")
    lines = [f"(portscan: 开放端口 {len(results)}/{len(ips)} IP "
             f"× {len(pl)} 端口"]
    for ip in ips:
        if ip in results:
            lines.append(f"  {ip}: {' '.join(map(str, results[ip]))}")
    lines.append(")")
    return "\n".join(lines)


if __name__ == "__main__":
    print("usage: portscan <ip> <ports>")
