"""help — 命令帮助

2026-09-15:改为**按已注册命令动态生成**。此前是手写清单,新增命令不会出现在
帮助里(实测漏了 10 个已实现命令);现在以 disp.command_names() 为准,已知命令
附一句话说明,未登记的也会列出来(只是没有说明)。
"""

# 已知命令的一句话说明(没写在这里的新命令仍会被列出,只是没有描述)
_DESC = {
    "beacon": "列出所有 Beacon",
    "use": "选中 Beacon",
    "show": "Beacon 详情",
    "modules": "列出可用植入模块",
    "info": "模块详情",
    "raw": "下发原始 Python 代码",
    "broadcast": "对所有 Beacon 批量下发",
    "platform": "手动设置平台",
    "result": "查看执行结果",
    "sysinfo": "收集用户名和 OS 版本",
    "log": "审计日志",
    "reload": "重载配置并热加载模块",
    "config": "显示配置",
    "s_modules": "列出 server 端模块",
    "s_exec": "执行 server 端模块",
    "uplevel": "升级通道(tls,多级回退)",
    "help": "本帮助",
    "exit": "退出",
}

# 参数形态提示(有则拼在命令名后面)
_USAGE = {
    "use": "<beacon_id>",
    "show": "[beacon_id]",
    "info": "<module>",
    "raw": "[beacon_id] <code>",
    "broadcast": "<module|raw> ...",
    "platform": "[id] <linux|win|mac>",
    "result": "[beacon_id] [n]",
    "sysinfo": "[beacon_id]",
    "log": "[n]",
    "s_exec": "<mod> [args]",
    "uplevel": "[id] <proto> <host> <port> <key> [fp] [retry] [timeout]",
}


def _names(disp) -> list:
    try:
        return list(disp.command_names())
    except Exception:
        return sorted(_DESC)


def run(disp, args):
    lines = ["内置命令:"]
    for name in _names(disp):
        head = name + (" " + _USAGE[name] if name in _USAGE else "")
        lines.append(f"  {head:<44}{_DESC.get(name, '')}")
    lines.append("  <module> [args...]                  执行植入模块(如 ls ./;清单见 modules)")
    for label, holder in (("植入模块", "modules"), ("server 模块", "smods")):
        src = getattr(disp, holder, None) if disp is not None else None
        if not src:
            continue
        try:
            names = sorted(m["name"] for m in src.list_modules())
        except Exception:
            continue
        if names:
            lines.append(f"  可用{label}({len(names)}): {', '.join(names)}")
    return "\n".join(lines)
