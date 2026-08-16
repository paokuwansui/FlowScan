"""tag — 给 beacon 打标签/分组（22）:
tag <beacon_id> <标签>   设置标签（可多个，空格分隔）
tag <beacon_id> -        清除全部标签
tag @<组名> <新标签>     给整个组加标签
"""


def run(disp, args):
    if len(args) < 2:
        return "[!] usage: tag <beacon_id> <标签...> | tag <beacon_id> -"
    bid = args[0]
    rest = args[1:]

    recs = []
    if bid.startswith("@"):
        group = bid[1:]
        recs = [c for c in disp.mgr.list_clients()
                if group in getattr(c, "tags", [])]
        if not recs:
            return f"[!] 组 {group} 没有 beacon"
    else:
        rec = disp.mgr.get_client(bid)
        if rec is None:
            return f"[!] beacon 不存在: {bid}"
        recs = [rec]

    if rest == ["-"]:
        for rec in recs:
            rec.tags = []
        names = ", ".join(r.client_id[:8] for r in recs)
        return f"[-] 已清除标签: {names}"

    for rec in recs:
        for t in rest:
            if t not in rec.tags:
                rec.tags.append(t)
    names = ", ".join(r.client_id[:8] for r in recs)
    return f"[+] 已打标签 {rest} → {names}"
