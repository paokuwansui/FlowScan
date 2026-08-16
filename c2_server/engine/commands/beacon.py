"""beacon — 列出所有 Beacon (ID / Fork / Tag / Last / User / Plat / OS)"""


def run(disp, args):
    clients = disp.mgr.list_clients()
    if not clients:
        return "(no beacons connected)"
    lines = [f"{'ID':<18} {'Fork':<5} {'Tag':<10} {'Last':<8} "
             f"{'User':<14} {'Plat':<8} {'OS':<22}"]
    for c in clients:
        marker = " *" if c.client_id == disp.current_beacon else "  "
        last = c.last_seen.strftime("%H:%M:%S")
        fork = "fork" if getattr(c, "is_fork", False) else ""
        tag = ",".join(getattr(c, "tags", []))[:10]
        lines.append(
            f"{c.client_id:<18} {fork:<5} {tag:<10} {last:<8} "
            f"{c.sys_user:<14} {c.sys_platform:<8} {c.sys_os[:21]:<22}{marker}"
        )
    return "\n".join(lines)
