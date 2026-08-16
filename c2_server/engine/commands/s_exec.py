"""s_exec — 执行 server 端模块 (run(*args))"""


def run(disp, args):
    if not disp.smods:
        return "[!] s_modules not available"
    if not args:
        return "[!] usage: s_exec <module> [arg1 arg2 ...]"
    name = args[0]
    try:
        return disp.smods.run(name, args[1:])
    except ValueError as e:
        return f"[!] {e}"
    except ImportError as e:
        return f"[!] {e}"
