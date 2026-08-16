"""break — 逐层退出：最内层增强会话退出一层。

分层语义（一层一层退出，由 fork/shell 模块设置活跃标志判定）:
  1. 分裂线程（fork）内执行 → 退出分裂线程，主 beacon 继续
  2. 交互式 shell 内执行 → 退出 shell，退回基础 beacon 循环
  3. 主载荷（最底层基础循环）→ 不支持 break，退出进程请用 kill

嵌套时退最内层增强层（fork 优先于 shell）。
"""

MODULE = {
    "desc": "逐层退出（分裂线程 > shell > 主载荷不支持，退出用 kill）",
    "params": [],
}


def run():
    G = globals()
    if G.get("_IN_FORK"):
        G["_FORK_BREAK"] = True
        return "(break: 分裂线程已退出，主 beacon 继续)"
    if G.get("_IN_SHELL"):
        G["_BS"] = True
        return "(break: 已退出交互式 shell，退回基础循环)"
    return "(break: 主载荷不支持 break，如需退出请用 kill 模块)"


if __name__ == "__main__":
    print("break: 由 server 下发执行，不直接运行")
