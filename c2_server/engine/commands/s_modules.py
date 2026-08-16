"""s_modules — 列出 server 端模块"""


def _fmt_params(params):
    params = params or []
    names = [p[0] for p in params if isinstance(p, (list, tuple)) and p]
    return f" [{', '.join(names)}]" if names else ""


def run(disp, args):
    if not disp.smods:
        return "(s_modules not available)"
    mods = disp.smods.list_modules()
    if not mods:
        return "(no server modules)"
    lines = ["Server modules:"]
    for m in mods:
        lines.append(f"  {m['name']:<15}{_fmt_params(m.get('params'))}"
                     f" - {m['desc']}")
    return "\n".join(lines)
