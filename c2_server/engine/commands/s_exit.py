"""s_exit — 退出会话/关闭 Server

2026-09-28:原命令名 `exit` 在 beacon 处于交互式 shell 时会与"退子 shell"的
`exit` 文本冲突(dispatcher 在 handler 查找前拦截 exit/break),导致本命令
永不可达。故 server 侧退出命令更名为 `s_exit`;shell 模式里的 `exit` 语义不变
(仍为退子 shell)。
"""


def run(disp, args):
    if disp.on_exit:
        disp.on_exit()
        return "[*] Server shutting down..."
    return "[*] session ended"
