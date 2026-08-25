"""
@module: proxy
@desc: 生成一行 python3 -c 端口转发命令(TCP 双向转发, 贴 bash 直接跑)
@params: listen_port target_host target_port [out_dir]
"""
import os

MODULE = {
    "desc": "生成一行 python3 -c 端口转发命令",
    "params": [
        ("listen_port", "必填，本地监听端口"),
        ("target_host", "必填，目标地址"),
        ("target_port", "必填，目标端口"),
        ("out_dir", "默认 s_modules/output"),
    ],
}

_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

_FWD_CODE = (
    "import socket as s,threading as t;"
    "L=s.socket();L.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR,1);"
    "L.bind((\"0.0.0.0\",{lp}));L.listen(64)\n"
    "def c(a,b):\n"
    " try:\n"
    "  while 1:\n"
    "   d=a.recv(65536)\n"
    "   if not d:break\n"
    "   b.sendall(d)\n"
    " except:pass\n"
    " finally:\n"
    "  try:a.close()\n"
    "  except:pass\n"
    "  try:b.close()\n"
    "  except:pass\n"
    "def h():\n"
    " while 1:\n"
    "  a,_=L.accept()\n"
    "  try:\n"
    "   b=s.socket();b.connect((\"{th}\",{tp}))\n"
    "   t.Thread(target=c,args=(a,b),daemon=True).start()\n"
    "   c(b,a)\n"
    "  except:pass\n"
    "t.Thread(target=h,daemon=True).start();t.Event().wait()"
)


def run(listen_port, target_host, target_port, out_dir=None):
    """生成一行 python3 -c 端口转发命令（TCP 双向转发）。"""
    code = _FWD_CODE.format(lp=int(listen_port), th=str(target_host),
                            tp=int(target_port))
    compile(code, "<proxy-fwd>", "exec")  # 生成即校验
    command = f"python3 -c '{code}'"

    out_dir = out_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "proxy_fwd_command.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(command + "\n")

    return {
        "status": "ok",
        "command": command,
        "file": path,
        "usage": f"在任意可达机器粘贴执行: {command[:60]}...",
    }


if __name__ == "__main__":
    print("usage: s_exec proxy <listen_port> <target_host> <target_port>")
