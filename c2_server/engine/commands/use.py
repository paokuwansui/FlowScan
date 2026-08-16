"""use — 选中当前 Beacon"""


def run(disp, args):
    if not args:
        return "[!] usage: use <beacon_id>"
    bid = args[0]
    if not disp.mgr.get_client(bid):
        return f"[!] beacon not found: {bid}"
    disp.current_beacon = bid
    # S5：同步到中继通道共享槽（socks5 用——headless/远程 client 也生效）
    hub = getattr(disp, "hub", None)
    if hub is not None and hasattr(hub, "set_current"):
        hub.set_current(bid)
    return f"[*] 当前 Beacon: {bid}"
