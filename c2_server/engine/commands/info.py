"""info — 模块详情（先查 server 模块，再查植入模块）"""


def _fmt_params(params):
    params = params or []
    parts = []
    for p in params:
        if isinstance(p, (list, tuple)) and len(p) >= 1:
            name = p[0]
            hint = p[1] if len(p) > 1 else ""
            parts.append(f"{name} {hint}".strip())
    return ", ".join(parts) if parts else "无"


def run(disp, args):
    if not args:
        return "[!] usage: info <module_name>"
    name = args[0]

    if disp.smods:
        smod = disp.smods.get_module(name)
        if smod:
            return (f"[server] Module: {smod['name']}\n"
                    f"Description: {smod.get('desc', 'N/A')}\n"
                    f"Params: {_fmt_params(smod.get('params'))}")

    mod = disp.modules.get_module(name)
    if not mod:
        return f"[!] module not found: {name}"
    lines = [f"[implant] Module: {mod['name']} ({mod['type']})"]
    lines.append(f"Description: {mod.get('desc', 'N/A')}")
    if mod["type"] == "python":
        lines.append(f"Params: {_fmt_params(mod.get('params'))}")
        rp = mod.get("result_processor", "")
        if rp:
            lines.append(f"Result processor: {rp}")
    else:
        lines.append(f"Steps: {len(mod.get('steps', []))}")
    return "\n".join(lines)
