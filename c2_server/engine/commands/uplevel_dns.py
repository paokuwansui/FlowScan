"""uplevel_dns — 植入物协议升级为 DNS 隧道(连 agent_dns 前置, 原执行逻辑不变)"""
from server.engine.commands._uplevel_common import run as _run


def run(disp, args):
    return _run(disp, args, "dns")
