"""log — 查看审计/事件日志"""


def run(disp, args):
    try:
        n = int(args[0]) if args else 20
    except ValueError:
        return "[!] log count must be an integer"
    entries = disp.audit.tail(n)
    if not entries:
        return "(no log entries)"
    return "\n".join(entries[-n:])
