"""uplevel_tcp — 植入物协议升级为 TCP 直连(连 agent_tcp 前置, 原执行逻辑不变)"""
from server.engine.commands._uplevel_common import run as _run


def run(disp, args):
    return _run(disp, args, "tcp")
