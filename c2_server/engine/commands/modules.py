"""modules — 列出可用植入模块"""


def run(disp, args):
    mods = disp.modules.list_modules()
    if not mods:
        return "(no modules loaded)"
    lines = ["Available modules:"]
    for m in mods:
        extra = ""
        if m["type"] == "python" and m.get("params"):
            names = ", ".join(
                p[0] for p in m["params"]
                if isinstance(p, (list, tuple)) and p)
            extra = f" [{names}]"
        elif m["type"] == "json":
            extra = f" ({m['steps']} steps)"
        lines.append(f"  {m['name']:<15} ({m['type']}){extra} - {m['desc']}")
    return "\n".join(lines)
