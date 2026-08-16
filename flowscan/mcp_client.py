"""MCP (Model Context Protocol) 轻量客户端 — 零第三方依赖。

供 FlowScan Agent 把 config.yaml 中配置的 MCP server 工具接入 function calling。

支持三种传输:
  - sse  : HTTP+SSE（GET 握手取 endpoint，POST JSON-RPC，响应 JSON 或 SSE）
  - http : Streamable HTTP（直接 POST JSON-RPC 到 URL）
  - stdio: 子进程 stdin/stdout 换行分隔 JSON-RPC

协议版本 2024-11-05。仅实现 initialize / notifications/initialized /
tools/list / tools/call 四个调用，够用即可。
"""

import json
import queue
import shlex
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PROTOCOL_VERSION = "2024-11-05"
DEFAULT_TIMEOUT = 30


class McpError(RuntimeError):
    """MCP 调用错误。"""


def _ssl_ctx():
    """本地 MCP（如 yakit）常为自签/无证书，与 mcp_verify 行为一致。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _sse_handshake(url: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """SSE 握手:流式迭代读取,拿到 event: endpoint 即返回。

    标准 MCP SSE 服务器(FastMCP 等)GET /sse 后保持长连接推送消息,
    全量 read() 会阻塞到超时(2026-08 修复);逐行读,读到 endpoint 事件或
    socket 超时即停,不读全量。返回 endpoint(相对/绝对路径),未找到返回 ""。
    """
    req = urllib.request.Request(url, headers={
        "Accept": "text/event-stream",
        "User-Agent": "FlowScan-MCP/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            event = None
            deadline = time.time() + timeout
            for raw in resp:
                if time.time() > deadline:
                    break
                line = raw.decode("utf-8", "replace").strip()
                if line.startswith("event:"):
                    event = line[6:].strip()
                    continue
                if line.startswith("data:") and event == "endpoint":
                    return line[5:].strip()
    except socket.timeout:
        pass  # 长连接未发 endpoint:按未找到处理
    except Exception:
        raise
    return ""


def _http_post(url: str, payload: dict, timeout: int = DEFAULT_TIMEOUT):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "FlowScan-MCP/1.0",
        },
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
        return resp.status, resp.headers.get("Content-Type", ""), resp.read()


def _parse_sse_payloads(body: bytes):
    """从 SSE 文本提取 data: 行 JSON；整个 body 是 JSON 时直接解析。"""
    text = body.decode("utf-8", "replace").strip()
    if not text:
        return []
    if text.startswith("{") or text.startswith("["):
        try:
            return [json.loads(text)]
        except Exception:
            return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            raw = line[5:].strip()
            if not raw or raw == "[DONE]":
                continue
            try:
                out.append(json.loads(raw))
            except Exception:
                continue
    return out


class McpClient:
    """单个 MCP server 的轻量客户端。

    server dict 字段与 config.yaml mcp.servers 一致:
      type: sse | http | stdio
      url : sse/http 用
      command: stdio 用
    """

    def __init__(self, server: dict, timeout: int = DEFAULT_TIMEOUT):
        self._server = server or {}
        self._timeout = timeout
        self._stype = (self._server.get("type") or "sse").strip().lower()
        self._url = (self._server.get("url") or "").strip()
        self._cmd = (self._server.get("command") or "").strip()
        self._endpoint = self._url
        self._proc = None
        self._stdout_q = None
        self._initialized = False

    # ── 传输层 ──

    def _connect(self) -> None:
        if self._stype == "stdio":
            if not self._cmd:
                raise McpError("stdio 类型需要 command 字段")
            try:
                self._proc = subprocess.Popen(
                    shlex.split(self._cmd),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
            except Exception as exc:
                raise McpError(f"stdio 进程启动失败: {exc}") from exc
            self._stdout_q = queue.Queue()
            threading.Thread(target=self._stdio_reader, daemon=True).start()
            return
        if not self._url.startswith(("http://", "https://")):
            raise McpError(f"invalid url: {self._url!r}")
        if self._stype == "sse":
            try:
                endpoint = _sse_handshake(self._url, timeout=self._timeout)
            except Exception as exc:
                raise McpError(f"SSE 握手失败: {exc}") from exc
            self._endpoint = (urllib.parse.urljoin(self._url, endpoint)
                              if endpoint else self._url)
        # http: 直接 POST 到 url

    def _stdio_reader(self) -> None:
        try:
            while True:
                line = self._proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    self._stdout_q.put(json.loads(line))
                except Exception:
                    self._stdout_q.put({"jsonrpc": "2.0", "id": None,
                                        "error": {"code": -32700, "message": "parse error"}})
        except Exception:
            pass

    def _rpc(self, method: str, params: dict = None, notify: bool = False):
        msg_id = None if notify else str(uuid.uuid4())
        req = {"jsonrpc": "2.0", "method": method}
        if msg_id is not None:
            req["id"] = msg_id
        if params is not None:
            req["params"] = params

        if self._stype == "stdio":
            if self._proc is None or self._proc.poll() is not None:
                raise McpError(f"{method}: stdio 进程不可用")
            try:
                self._proc.stdin.write(json.dumps(req) + "\n")
                self._proc.stdin.flush()
            except Exception as exc:
                raise McpError(f"{method}: 写入 stdio 失败: {exc}") from exc
            if notify:
                return None
            deadline = time.time() + self._timeout
            while time.time() < deadline:
                try:
                    resp = self._stdout_q.get(timeout=0.5)
                except queue.Empty:
                    continue
                if resp.get("id") == msg_id:
                    if "error" in resp:
                        raise McpError(f"{method}: {resp['error']}")
                    return resp.get("result")
            raise McpError(f"{method}: stdio 响应超时")

        try:
            _status, _ctype, body = _http_post(self._endpoint, req, timeout=self._timeout)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = (exc.read() or b"").decode("utf-8", "replace")[:300]
            except Exception:
                pass
            raise McpError(f"{method}: HTTP {exc.code} {detail}") from exc
        except Exception as exc:
            raise McpError(f"{method}: {exc}") from exc
        if notify:
            return None
        for item in _parse_sse_payloads(body):
            if isinstance(item, dict) and item.get("id") == msg_id:
                if "error" in item:
                    raise McpError(f"{method}: {item['error']}")
                return item.get("result")
        raise McpError(f"{method}: 响应中未找到匹配的 id（{_status}）")

    # ── 高层 API ──

    def initialize(self) -> dict:
        self._connect()
        result = self._rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "flowscan", "version": "1.0"},
        })
        try:
            self._rpc("notifications/initialized", {}, notify=True)
        except Exception:
            pass
        self._initialized = True
        return result or {}

    def list_tools(self) -> list:
        self._ensure_connected()
        result = self._rpc("tools/list", {}) or {}
        tools = result.get("tools") or []
        return [t for t in tools if isinstance(t, dict) and t.get("name")]

    def call_tool(self, name: str, arguments: dict = None) -> dict:
        self._ensure_connected()
        result = self._rpc("tools/call", {"name": name,
                                          "arguments": arguments or {}}) or {}
        text_parts = []
        for item in result.get("content") or []:
            if isinstance(item, dict) and item.get("type") == "text":
                text_parts.append(str(item.get("text", "")))
        return {
            "content": "\n".join(text_parts),
            "isError": bool(result.get("isError", False)),
            "raw": result,
        }

    def _ensure_connected(self) -> None:
        if not self._initialized:
            self.initialize()

    def close(self) -> None:
        """关闭 stdio 子进程:terminate → 等 1.5s → kill 兜底(防 SIGTERM 无效残留)。"""
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=1.5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None


def list_all_mcp_tools(servers: list, timeout: int = DEFAULT_TIMEOUT) -> list:
    """批量列出所有启用 server 的工具（单个失败不拖垮整体）。

    Returns:
        [{server, ok, tools?|error}]
    """
    out = []
    for s in servers or []:
        if not isinstance(s, dict) or not s.get("name"):
            continue
        try:
            cli = McpClient(s, timeout=timeout)
            tools = cli.list_tools()
            cli.close()
            out.append({
                "server": s.get("name"),
                "ok": True,
                "tools": [
                    {"name": t.get("name"), "description": t.get("description", ""),
                     "inputSchema": t.get("inputSchema", {})}
                    for t in tools
                ],
            })
        except Exception as exc:
            out.append({"server": s.get("name"), "ok": False, "error": str(exc)})
    return out
