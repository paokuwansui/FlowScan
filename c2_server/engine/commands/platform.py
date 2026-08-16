"""platform — 手动设置 Beacon 平台"""

_VALID = ("linux", "windows", "macos")


def run(disp, args):
    if not args:
        return "[!] usage: platform [beacon_id] <linux|windows|macos>"
    bid, rest = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon"
    if not rest:
        return "[!] usage: platform [beacon_id] <linux|windows|macos>"
    plat = rest[0].lower()
    if plat not in _VALID:
        return "[!] platform must be 'linux', 'windows' or 'macos'"
    disp.mgr.set_platform(bid, plat)
    return f"[*] {bid[:8]}... 平台已设为: {plat}"
