"""exit — 退出会话/关闭 Server"""


def run(disp, args):
    if disp.on_exit:
        disp.on_exit()
        return "[*] Server shutting down..."
    return "[*] session ended"
