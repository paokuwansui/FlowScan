"""MCP server 配置验证 — 检查 MCP server 可达性/协议端点，并尝试真实 MCP 握手。

支持 sse / http 类型的 MCP server 可达性验证(HTTP 请求 + Content-Type 检查),
stdio 类型校验命令是否存在；进阶验证会走一遍真实的 MCP 协议
(initialize → tools/list)，成功时返回该 server 暴露的工具名列表。
不引入 mcp 库依赖,轻量即可用。
"""

import shutil
import ssl
import urllib.error
import urllib.request


def verify_mcp_server(server: dict, timeout: int = 10):
    """验证单个 MCP server 配置。返回 (ok, message, detail)。

    server 字段: type(sse/http/stdio) / url(sse,http) / command(stdio)

    detail 包含:
      - 基础可达性信息（status/content_type/body_head）
      - 进阶 MCP 握手结果（mcp_ok/mcp_error/tools）
    """
    stype = (server.get("type") or "sse").strip().lower()
    if stype == "stdio":
        cmd = (server.get("command") or "").strip()
        if not cmd:
            return False, "stdio 类型需要 command 字段", {}
        binary = cmd.split()[0]
        path = shutil.which(binary)
        if not path:
            return False, f"命令 {binary} 不存在(不在 PATH)", {}
        return _try_mcp_handshake(server, timeout,
                                  f"命令 {binary} 存在({path})")

    url = (server.get("url") or "").strip()
    if not url:
        return False, "url 为空", {}
    if not url.startswith(("http://", "https://")):
        return False, f"invalid url: {url}", {}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 本地 MCP(如 yakit)常为自签/无证书
    req = urllib.request.Request(url, headers={"Accept": "text/event-stream", "User-Agent": "FlowScan-MCP-Verify/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read(1024).decode("utf-8", "replace")
            detail = {"status": status, "content_type": ctype, "body_head": body[:200]}
            if stype == "sse":
                if "text/event-stream" in ctype:
                    return _try_mcp_handshake(server, timeout,
                                              f"SSE 端点可达 (HTTP {status}, event-stream)",
                                              detail)
                # 有的 SSE 端点握手后返回 endpoint 事件而非直接 event-stream
                if status == 200:
                    return _try_mcp_handshake(
                        server, timeout,
                        f"端点可达 (HTTP {status})，但 Content-Type 非 event-stream: {ctype or '无'}",
                        detail)
                return False, f"HTTP {status}", detail
            if status == 200:
                return _try_mcp_handshake(server, timeout, f"可达 (HTTP {status})", detail)
            return False, f"HTTP {status}", detail
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}", {"status": exc.code}
    except Exception as exc:
        return False, str(exc), {}


def _try_mcp_handshake(server: dict, timeout: int, ok_msg: str, detail: dict = None):
    """进阶验证：真实走一遍 MCP initialize + tools/list，返回工具名列表。"""
    detail = dict(detail or {})
    try:
        from .mcp_client import McpClient  # 懒加载，避免循环依赖
        cli = McpClient(server, timeout=max(3, min(timeout, 30)))
        cli.initialize()
        tools = cli.list_tools()
        cli.close()
        names = [t.get("name") for t in tools if isinstance(t, dict) and t.get("name")]
        detail["mcp_ok"] = True
        detail["tools"] = names
        return True, f"{ok_msg}；MCP 握手成功，{len(names)} 个工具", detail
    except Exception as exc:
        detail["mcp_ok"] = False
        detail["mcp_error"] = str(exc)[:300]
        return True, f"{ok_msg}；MCP 握手失败: {exc}", detail
