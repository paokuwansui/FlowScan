"""icmp_probe — 用 ping 命令(ICMP echo)探测网段可达性。

用法(console 或页面模块执行):
  icmp_probe
行为: 枚举本机所有 IPv4 网段, 对每个网段探测两个关键地址:
  - .1   网段第一个可用地址(通常为网关, 可达=网段对外连通)
  - .255 网段广播地址(可达=网段内有活跃主机/允许广播应答)
实现: 调用系统 ping -c 1 -W 1(ICMP echo; ping 命令通常带 cap_net_raw,
      非 root 也可用)。解析返回的 RTT。
"""

import fcntl
import os
import socket
import struct
import subprocess

MODULE = {
    "desc": "ping 命令探测网段可达性(每网段探测 .1 网关 与 .255 广播)",
    "params": [],
}

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B


def _iface_ipv4():
    """{ifname: (ip, mask)} — 本机所有 IPv4 接口地址。"""
    out = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo":
                continue
            packed = struct.pack("256s", name.encode()[:15])
            try:
                ip = socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(), SIOCGIFADDR, packed)[20:24])
                mask = socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(), SIOCGIFNETMASK, packed)[20:24])
            except OSError:
                continue  # 无地址接口
            out[name] = (ip, mask)
    except OSError:
        pass
    finally:
        s.close()
    return out


def _ping_cmd(ip, timeout=2.0):
    """系统 ping 单次 ICMP echo → RTT 秒; 失败返回 None。"""
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


def _probe(ip, timeout):
    """ping 探测 → (ok, rtt_ms 或 "-")。"""
    rtt = _ping_cmd(ip, timeout)
    if rtt is None:
        return False, "-"
    return True, f"{rtt * 1000:.1f}ms"


def run():
    ifaces = _iface_ipv4()
    if not ifaces:
        return "(icmp_probe: 未发现带 IPv4 地址的网卡)"
    blocks = []
    for name in sorted(ifaces):
        ip, mask = ifaces[name]
        ipn = struct.unpack("!I", socket.inet_aton(ip))[0]
        maskn = struct.unpack("!I", socket.inet_aton(mask))[0]
        net = ipn & maskn
        bcast = net | (~maskn & 0xFFFFFFFF)
        first = net + 1
        if first > bcast:
            continue  # /31 /32 无可用地址
        lines = [f"{name}  {ip}/{_mask_prefix(mask)}"]
        for label, target in ((".1", first), (".255", bcast)):
            if target < 1 or target > 0xFFFFFFFE:
                continue
            tip = socket.inet_ntoa(struct.pack("!I", target))
            ok, rtt = _probe(tip, 2.0)
            lines.append(f"  {label:<5} {tip:<16} "
                         f"{'可达 ' + rtt if ok else '不可达'}")
        blocks.append("\n".join(lines))
    return "(icmp_probe:\n" + "\n".join(blocks) + "\n)"


def _mask_prefix(mask: str) -> int:
    return sum(bin(int(o)).count("1") for o in mask.split("."))
