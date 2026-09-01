"""netinfo — 查看网卡信息(纯标准库, 不依赖 ip/ifconfig 外部命令)。

用法(console 或页面模块执行):
  netinfo
输出: 每个网卡: 接口名 / 状态(UP/DOWN) / MTU / MAC / 速率 /
      IPv4 地址(CIDR) / IPv6 地址 / 收发包统计。
数据来源: /sys/class/net + ioctl(SIOCGIFADDR/SIOCGIFNETMASK) + /proc/net/if_inet6。
"""

import fcntl
import os
import socket
import struct

MODULE = {
    "desc": "查看网卡信息(接口/MAC/IP/状态/MTU/收发包统计)",
    "params": [],
}

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
IFF_UP = 0x1


def _read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _mask_to_prefix(mask: str) -> int:
    return sum(bin(int(o)).count("1") for o in mask.split("."))


def _ipv4(ifname: str) -> str:
    """接口主 IPv4(CIDR)。无地址返回空串。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", ifname.encode()[:15])
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), SIOCGIFADDR, packed)[20:24])
        mask = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), SIOCGIFNETMASK, packed)[20:24])
        return f"{ip}/{_mask_to_prefix(mask)}"
    except OSError:
        return ""
    finally:
        s.close()


def _ipv6_map():
    """/proc/net/if_inet6 → {ifindex: [ipv6, ...]}。"""
    out = {}
    try:
        with open("/proc/net/if_inet6", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                addr_hex, idx = parts[0], parts[1]
                try:
                    groups = [int(addr_hex[i:i + 4], 16)
                              for i in range(0, 32, 4)]
                    ip = socket.inet_ntop(socket.AF_INET6,
                                          struct.pack(">8H", *groups))
                except (ValueError, OSError):
                    continue
                out.setdefault(idx, []).append(ip)
    except OSError:
        pass
    return out


def run():
    base = "/sys/class/net"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return "(netinfo: 无法读取 /sys/class/net)"
    if not names:
        return "(netinfo: 未发现任何网卡)"
    v6 = _ipv6_map()
    blocks = []
    for name in names:
        b = f"{base}/{name}"
        try:
            flags = int(_read(f"{b}/flags") or "0", 16)
        except ValueError:
            flags = 0
        state = "UP" if flags & IFF_UP else "DOWN"
        mac = _read(f"{b}/address") or "-"
        mtu = _read(f"{b}/mtu") or "-"
        speed = _read(f"{b}/speed") or ""
        rx = _read(f"{b}/statistics/rx_bytes")
        tx = _read(f"{b}/statistics/tx_bytes")
        idx = _read(f"{b}/ifindex")
        ips4 = _ipv4(name)
        ips6 = v6.get(idx, [])
        head = f"{name}  {state}  mtu={mtu}  mac={mac}"
        if speed and speed != "-1":
            head += f"  speed={speed}Mb/s"
        sub = []
        if ips4:
            sub.append(f"  ipv4: {ips4}")
        for ip6 in ips6:
            sub.append(f"  ipv6: {ip6}")
        if rx or tx:
            sub.append(f"  rx: {rx or 0}B   tx: {tx or 0}B")
        blocks.append("\n".join([head] + sub))
    return "(netinfo:\n" + "\n".join(blocks) + "\n)"
