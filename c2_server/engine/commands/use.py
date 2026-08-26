"""use — 选中当前 Beacon"""


def run(disp, args):
    if not args:
        return "[!] usage: use <beacon_id>"
    bid = args[0]
    if not disp.mgr.get_client(bid):
        return f"[!] beacon not found: {bid}"
    disp.current_beacon = bid
    return f"[*] 当前 Beacon: {bid}"
