"""Agent 通用工具执行器:网络请求 / Python 代码 / 系统命令。

只接收 AI 发起的调度命令(由 web_app 的 agent 循环 dispatch_tool 调用),
执行后返回结果字符串(JSON)供 AI 循环查看。本身不落库、不写事件、不暴露
框架内部对象(redis 客户端等)——AI 若要把结论沉淀,需调用 log 工具。
"""

import json
import subprocess
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 30
MAX_OUTPUT = 4000  # 输出截断上限(字符)


def _truncate(text: str, limit: int = MAX_OUTPUT) -> str:
    if text is None:
        return ""
    if len(text) > limit:
        return text[:limit] + f"\n...(截断,原 {len(text)} 字符)"
    return text


def exec_http(method: str = "GET", url: str = "", headers: dict = None, body: str = "", timeout: int = DEFAULT_TIMEOUT) -> str:
    """发起 HTTP 请求。返回 JSON 字符串 {ok, status, headers, body(截断), size}。"""
    method = (method or "GET").upper()
    if not url.startswith(("http://", "https://")):
        return json.dumps({"ok": False, "error": f"invalid url: {url!r}"}, ensure_ascii=False)
    timeout = min(max(int(timeout or DEFAULT_TIMEOUT), 1), 120)
    headers = headers or {}
    if not isinstance(headers, dict):
        return json.dumps({"ok": False, "error": "headers 必须是对象"}, ensure_ascii=False)
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "Mozilla/5.0", **headers}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
            resp_headers = dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        raw = exc.read() or b""
        status = exc.code
        resp_headers = dict(exc.headers.items()) if exc.headers else {}
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)
    text = raw.decode("utf-8", errors="replace")
    return json.dumps(
        {"ok": True, "status": status, "headers": resp_headers, "body": _truncate(text), "size": len(raw)},
        ensure_ascii=False,
    )


def exec_python(code: str = "", timeout: int = DEFAULT_TIMEOUT) -> str:
    """在独立子进程执行 Python 代码。返回 JSON {ok, exit, stdout(截断), stderr(截断)}。"""
    timeout = min(max(int(timeout or DEFAULT_TIMEOUT), 1), 60)
    if not code or not code.strip():
        return json.dumps({"ok": False, "error": "code 为空"}, ensure_ascii=False)
    try:
        r = subprocess.run(["python3", "-c", code], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return json.dumps({"ok": False, "error": f"超时({timeout}s)"}, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)
    return json.dumps(
        {"ok": r.returncode == 0, "exit": r.returncode, "stdout": _truncate(r.stdout or ""), "stderr": _truncate(r.stderr or "")},
        ensure_ascii=False,
    )


def exec_shell(command: str = "", timeout: int = DEFAULT_TIMEOUT) -> str:
    """执行系统命令。返回 JSON {ok, exit, stdout(截断), stderr(截断)}。"""
    timeout = min(max(int(timeout or DEFAULT_TIMEOUT), 1), 120)
    if not command or not command.strip():
        return json.dumps({"ok": False, "error": "command 为空"}, ensure_ascii=False)
    try:
        r = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return json.dumps({"ok": False, "error": f"超时({timeout}s)"}, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)
    return json.dumps(
        {"ok": r.returncode == 0, "exit": r.returncode, "stdout": _truncate(r.stdout or ""), "stderr": _truncate(r.stderr or "")},
        ensure_ascii=False,
    )
