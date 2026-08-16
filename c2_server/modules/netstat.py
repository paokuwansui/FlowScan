"""
@module: netstat
@desc: 列出网络连接
"""
import os
import socket

MODULE = {
    "desc": "列出网络连接",
    "params": [],
}


def _decode_hex_addr(hex_str: str) -> str:
    """/proc/net 地址字段 → "ip:port"。

    字段形如 "<ip_hex>:<port_hex>"：
      v4:  0100007F:1F90 → 127.0.0.1:8080（4 字节网络序倒序）
      v6:  00000000000000000000000001000000:1F90 → ::1:8080
           （16 字节网络序 inet_ntop；含 v4-mapped ::ffff:a.b.c.d）
    """
    parts = hex_str.split(":")
    if len(parts) != 2:
        return hex_str
    ip_hex, port_hex = parts[0], parts[1]
    try:
        port = str(int(port_hex, 16))
        raw = bytes.fromhex(ip_hex)
        if len(raw) == 4:
            ip = ".".join(str(b) for b in reversed(raw))
        elif len(raw) == 16:
            # /proc/net/tcp6 每 4 字节一组小端 → 反转每组恢复网络序
            groups = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]
            ip = socket.inet_ntop(socket.AF_INET6, b"".join(groups))
        else:
            return hex_str
    except (ValueError, OSError):
        return hex_str
    return f"{ip}:{port}"


def run():
    """通用入口（平台未知时自动判定）。"""
    if os.name == "nt":
        return run_windows()
    return run_linux()


def _tcp_state(code: int) -> str:
    states = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV",
              4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
              7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK",
              10: "LISTEN", 11: "CLOSING"}
    return states.get(code, f"UNKNOWN({code})")


def run_linux():
    """读取 /proc/net/* 获取网络连接"""
    results = []
    for proto, path in [("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"),
                        ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")]:
        try:
            with open(path, "r") as f:
                lines = f.readlines()
        except (PermissionError, FileNotFoundError):
            continue
        if len(lines) < 2:
            continue
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = _decode_hex_addr(parts[1])
            remote = _decode_hex_addr(parts[2])
            # L9：/proc 行格式异常（非 16 进制状态）不崩模块
            try:
                state = (_tcp_state(int(parts[3], 16))
                         if "tcp" in proto else "")
            except ValueError:
                state = ""
            results.append(f"{proto:<6} {local:<30} {remote:<30} {state}")
    return "\n".join(results) if results else "(no connections)"


def run_windows():
    """调用 netstat 获取网络连接"""
    import subprocess
    try:
        out = subprocess.check_output(["netstat", "-ano"], timeout=10, text=True)
        return out.strip()
    except Exception as e:
        return f"(error: {e})"


if __name__ == "__main__":
    print(run_linux())
