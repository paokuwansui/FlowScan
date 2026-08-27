"""
@module: file_server
@desc: 生成 file_server 一键部署载荷: HTTP PUT(curl -T)上传 / GET(wget)下载,
启动目录即文件根; GET 目录返回 HTML 文件列表(wget -r 整目录拉取);
失败请求在部署机 stderr 打印 [fs3] 日志(载荷端只报统计)。
@params: port [token] [out_dir]
"""
import os

from server.core.bootstrap import deploy_command

MODULE = {
    "desc": "生成 file_server 一键部署载荷(PUT 上传/GET 下载/目录列表)",
    "params": [
        ("port", "必填；监听端口"),
        ("token", "可选；访问令牌(默认空=不校验)。非空时 PUT/GET 需带 X-Token 头"),
        ("out_dir", "默认 s_modules/output"),
    ],
}

_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

# 服务端载荷(纯 stdlib, 短名风格, 与 socks_server 一致)。
# 启动目录即文件根; 路径 unquote 后拒绝绝对路径/.. 穿越;
# token 为空时不校验(_chk 恒放行, 默认关闭)。
_CODE = '''\
import http.server as _h,os as _o,sys as _i,urllib.parse as _u
_R=_o.getcwd()
_T={token}
def _s(p):
 p=_u.unquote(p)
 if p.startswith("/"):p=p[1:]
 if ".." in p.split("/"):return None
 return p
def _chk(s):
 if _T and s.headers.get("X-Token")!=_T:
  s.send_error(401);return False
 return True
class _H(_h.BaseHTTPRequestHandler):
 protocol_version="HTTP/1.1"
 def log_message(s,*a):pass
 def _ok(s,n):
  s.send_response(200);s.send_header("Content-Length",str(n));s.end_headers()
 def do_PUT(s):
  if not _chk(s):return
  p=_s(s.path.split("?")[0])
  if p is None:
   s.send_error(400);print("[fs3] REJECT",s.path,file=_i.stderr);return
  try:
   fp=_o.path.join(_R,p)
   _o.makedirs(_o.path.dirname(fp) or _R,exist_ok=True)
   n=int(s.headers.get("Content-Length") or 0)
   with open(fp,"wb") as f:
    left=n
    while left>0:
     c=s.rfile.read(min(65536,left))
     if not c:break
     f.write(c);left-=len(c)
   s._ok(2);s.wfile.write(b"ok")
  except Exception as e:
   s.send_error(500,str(e)[:200]);print("[fs3] FAIL",s.path,e,file=_i.stderr)
 def do_GET(s):
  if not _chk(s):return
  p=_s(s.path.split("?")[0])
  if p is None:s.send_error(400);return
  fp=_o.path.join(_R,p)
  if _o.path.isdir(fp):
   items=sorted(_o.listdir(fp))
   rows=[]
   for n in items:
    q=_o.path.join(fp,n)
    if _o.path.isdir(q):rows.append('<a href="%s/">%s/</a>'%(n,n))
    elif _o.path.isfile(q):rows.append('<a href="%s">%s</a>'%(n,n))
   body=('<html><head><title>%s</title></head><body><h1>%s</h1><pre>%s</pre></body></html>'%(p or "/",p or "/","<br>".join(rows))).encode()
   s._ok(len(body));s.wfile.write(body);return
  if not _o.path.isfile(fp):
   s.send_error(404);print("[fs3] MISS",s.path,file=_i.stderr);return
  try:
   sz=_o.path.getsize(fp)
   s._ok(sz)
   with open(fp,"rb") as f:
    while 1:
     c=f.read(65536)
     if not c:break
     s.wfile.write(c)
  except Exception as e:
   print("[fs3] FAIL",s.path,e,file=_i.stderr)
def run():
 h=_h.ThreadingHTTPServer(("0.0.0.0",{port}),_H)
 print("[fs3] file_server on 0.0.0.0:{port}, root:",_R)
 h.serve_forever()
run()
'''


def run(port, token="", out_dir=None):
    """生成 file_server 代码与一键部署命令。"""
    port = int(port)
    token = str(token or "")
    code = _CODE.format(port=port, token=repr(token))
    compile(code, "<file_server>", "exec")  # 生成即校验

    command = deploy_command(code)
    out_dir = out_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)
    cmd_file = os.path.join(out_dir, "file_server_command.txt")
    with open(cmd_file, "w", encoding="utf-8") as f:
        f.write(command + "\n")

    return {
        "status": "ok",
        "port": port,
        "token": token,
        "command": command,
        "code": code,
        "code_len": len(code),
        "file": cmd_file,
        "usage": (
            f"1) 部署: 把上面 command 粘贴执行(启动目录=文件根, cd 换根目录再起)\n"
            f"2) 上传: curl -T local.txt http://<ip>:{port}/dir/name.txt (自动建目录)\n"
            f"3) 下载: wget http://<ip>:{port}/dir/name.txt\n"
            f"4) 整目录: wget -r http://<ip>:{port}/dir/ (目录页 HTML 列表)\n"
            f"5) 碎片回传: console 下发 upload_to_server <ip> {port} <本地目录> [远程根]\n"
            f"6) 失败明细: 部署机 stderr 的 [fs3] FAIL 行"
            + ("" if not token else
               f"\n   注意: 已启用 token, PUT/GET 需带 X-Token: {token} 头")
        ),
    }


if __name__ == "__main__":
    print("usage: s_exec file_server <port> [token]")
