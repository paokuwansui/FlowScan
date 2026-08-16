"""Agent 模式:ReAct 循环 + function calling 工具调度。

会话管理 / 审计 / 工具调度 / 增量事件拉取 / LLM 调用 / 循环引擎 / 路由。
"""
import json
import re
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import jsonify, redirect, request, url_for

from flowscan import c2_bridge
from flowscan import webshell as ws
from flowscan.agent_tools import exec_http, exec_python, exec_shell
from flowscan.config import load_yaml
from flowscan.filter import add_redis_rule
from flowscan.llm import llm_chat_completions
from flowscan.redis_store import FlowScanRedis

from ._common import _json_or_raw, login_required
from ._helpers import _active_nodes, _event_types, _list_events, _remove_event, _tool_registry, xray_load_findings
from .ai_config import _ai_config, _read_skill_content, _scan_skills, _skills_config, _skill_prompt_section
from .ai_logs import _ai_log_entry
from . import browser_tools


AGENT_TOOLS = [
    {"type": "function", "function": {"name": "list_events", "description": "查询扫描事件列表,可按类型过滤、限制数量、按值搜索。", "parameters": {"type": "object", "properties": {
        "event_types": {"type": "array", "items": {"type": "string"}, "description": "事件类型列表,空表示全部"},
        "limit": {"type": "integer", "description": "返回数量上限,默认 50"},
        "search": {"type": "string", "description": "按值模糊搜索关键字,可选"}}}}},
    {"type": "function", "function": {"name": "get_children", "description": "查询某事件的递归子事件(需要指纹 fp)。", "parameters": {"type": "object", "properties": {
        "fingerprint": {"type": "string", "description": "事件指纹 fp"}}, "required": ["fingerprint"]}}},
    {"type": "function", "function": {"name": "scan_status", "description": "查看扫描节点/工具/事件总量状态。", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "inject", "description": "向扫描队列注入事件触发 worker 扫描。执行后调度器会自动拉取新增事件摘要供你查看。", "parameters": {"type": "object", "properties": {
        "event_type": {"type": "string", "description": "事件类型,如 DNS_NAME/IP_ADDRESS/IP_RANGE/URL"},
        "value": {"type": "string", "description": "事件值"}}, "required": ["event_type", "value"]}}},
    {"type": "function", "function": {"name": "remove_event", "description": "删除事件(默认含子事件)。", "parameters": {"type": "object", "properties": {
        "event_type": {"type": "string"}, "value": {"type": "string"},
        "remove_children": {"type": "boolean", "description": "是否同时删除子事件,默认 true"}}, "required": ["event_type", "value"]}}},
    {"type": "function", "function": {"name": "blacklist_add", "description": "向 Redis 动态黑名单添加规则,匹配的事件会被拦截。", "parameters": {"type": "object", "properties": {
        "event_type": {"type": "string", "description": "事件类型或 *"},
        "match_mode": {"type": "string", "enum": ["suffix", "prefix", "contains", "ip_range"]},
        "value": {"type": "string"}, "comment": {"type": "string"}}, "required": ["event_type", "match_mode", "value"]}}},
    {"type": "function", "function": {"name": "http_request", "description": "发起 HTTP 请求(只接收 AI 调度,返回状态码+响应体)。", "parameters": {"type": "object", "properties": {
        "method": {"type": "string", "description": "GET/POST 等,默认 GET"}, "url": {"type": "string"},
        "headers": {"type": "object"}, "body": {"type": "string"}, "timeout": {"type": "integer"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "run_python", "description": "执行 Python 代码(只接收 AI 调度,返回 stdout/stderr)。", "parameters": {"type": "object", "properties": {
        "code": {"type": "string"}, "timeout": {"type": "integer"}}, "required": ["code"]}}},
    {"type": "function", "function": {"name": "run_shell", "description": "执行系统命令(只接收 AI 调度,返回 stdout/stderr)。", "parameters": {"type": "object", "properties": {
        "command": {"type": "string"}, "timeout": {"type": "integer"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "log", "description": "记录分析结论/事实到 AI 日志(跨会话沉淀,供后续分析参考)。", "parameters": {"type": "object", "properties": {
        "message": {"type": "string"}, "priority": {"type": "string", "enum": ["high", "medium", "low"]},
        "target": {"type": "string"}}, "required": ["message"]}}},
    {"type": "function", "function": {"name": "read_ai_logs", "description": "读取历史 AI 分析/Agent 沉淀的日志(跨会话知识,含此前任务的结论/动作)。做同类任务前先看这里复用结论。", "parameters": {"type": "object", "properties": {
        "limit": {"type": "integer", "description": "返回条数,默认 20,最大 100"},
        "priority": {"type": "string", "enum": ["high", "medium", "low"], "description": "按优先级过滤,可选"},
        "search": {"type": "string", "description": "按消息内容模糊搜索,可选"}}}}},
    {"type": "function", "function": {"name": "c2_beacons", "description": "列出所有在线 C2 beacon(含平台/用户/标签/上线时间)。", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "c2_exec", "description": "执行 C2 命令(use <bid>/sysinfo/exec <cmd>/result/show/tag/upload/download/portfwd 等),返回输出文本。", "parameters": {"type": "object", "properties": {
        "command": {"type": "string", "description": "完整 C2 命令文本"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "c2_result", "description": "查看指定 beacon 的最近执行结果。", "parameters": {"type": "object", "properties": {
        "client_id": {"type": "string", "description": "beacon 的 16 字符 ID"},
        "count": {"type": "integer", "description": "结果条数,默认 10"}}, "required": ["client_id"]}}},
    {"type": "function", "function": {"name": "c2_modules", "description": "列出 C2 的植入模块与 server 模块（名称/描述/参数）。", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "c2_module_build", "description": "dry-run 构建 C2 模块下发代码（不实际执行，用于测试模块构建）。", "parameters": {"type": "object", "properties": {
        "name": {"type": "string", "description": "模块名"},
        "args": {"type": "array", "items": {"type": "string"}, "description": "位置参数列表"},
        "platform": {"type": "string", "description": "目标平台 linux/windows/macos，空则通用"}}, "required": ["name"]}}},
    {"type": "function", "function": {"name": "c2_module_exec", "description": "构建模块任务并下发到指定 beacon 执行。", "parameters": {"type": "object", "properties": {
        "client_id": {"type": "string"}, "name": {"type": "string"},
        "args": {"type": "array", "items": {"type": "string"}}}, "required": ["client_id", "name"]}}},
    {"type": "function", "function": {"name": "c2_module_add", "description": "添加 C2 植入模块文件(.py/.json)并热加载。", "parameters": {"type": "object", "properties": {
        "filename": {"type": "string", "description": "如 mymod.py"},
        "content": {"type": "string", "description": "模块文件内容"}}, "required": ["filename", "content"]}}},
    {"type": "function", "function": {"name": "c2_module_delete", "description": "删除 C2 植入模块文件(按文件名)并热生效。", "parameters": {"type": "object", "properties": {
        "filename": {"type": "string", "description": "如 mymod.py"}}, "required": ["filename"]}}},
    {"type": "function", "function": {"name": "c2_raw", "description": "把原始 Python 代码原样下发到指定 beacon 执行(多行代码)。", "parameters": {"type": "object", "properties": {
        "client_id": {"type": "string"}, "code": {"type": "string", "description": "完整 Python 代码"}}, "required": ["client_id", "code"]}}},
    {"type": "function", "function": {"name": "c2_auto_commands", "description": "查看 C2 首次上线自动下发命令列表(auto_commands)。", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "c2_auto_commands_set", "description": "更新 C2 首次上线自动下发命令列表(auto_commands，写回 config.json)。", "parameters": {"type": "object", "properties": {
        "commands": {"type": "array", "items": {"type": "string"}, "description": "如 [\"sysinfo\", \"set_interval 10 0.2\"]"}}, "required": ["commands"]}}},
    {"type": "function", "function": {"name": "webshell_connections", "description": "列出所有已保存的 WebShell 连接(密码脱敏)。", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "webshell_exec", "description": "在指定 WebShell 连接上执行系统命令(HTTP 代理向 webshell URL 发 pass+cmd 请求)。", "parameters": {"type": "object", "properties": {
        "conn_id": {"type": "string", "description": "连接 ID(ws_ 开头)"},
        "command": {"type": "string", "description": "要执行的系统命令"}}, "required": ["conn_id", "command"]}}},
    {"type": "function", "function": {"name": "webshell_fileop", "description": "在指定 WebShell 连接上执行文件操作(list/read/write/delete/mkdir/rename,按目标 OS 生成命令)。", "parameters": {"type": "object", "properties": {
        "conn_id": {"type": "string"}, "action": {"type": "string", "enum": ["list", "read", "write", "delete", "mkdir", "rename"]},
        "path": {"type": "string"}, "content": {"type": "string", "description": "write 时的内容"},
        "target_path": {"type": "string", "description": "rename 时的新路径"}}, "required": ["conn_id", "action", "path"]}}},
    {"type": "function", "function": {"name": "get_spill", "description": "取回之前被截断的工具输出的完整内容(按 spill 引用)。", "parameters": {"type": "object", "properties": {
        "ref": {"type": "string", "description": "截断标记里的 spill 引用(如 spill_1234567890)"}}, "required": ["ref"]}}},
    {"type": "function", "function": {"name": "mcp_tools", "description": "列出已配置并启用的 MCP server 暴露的全部工具(名称/描述/参数)，调用 mcp_call 前先看这里。", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "mcp_call", "description": "调用指定 MCP 工具(如 yakit 的 DNSLog 验证)。server 与 tool 名来自 mcp_tools 的返回结果。", "parameters": {"type": "object", "properties": {
        "server": {"type": "string", "description": "MCP server 名称"},
        "tool": {"type": "string", "description": "工具名称"},
        "arguments": {"type": "object", "description": "工具参数(JSON 对象)"}}, "required": ["server", "tool"]}}},
    {"type": "function", "function": {"name": "search_skills", "description": "在全部技能库中按关键词搜索技能(匹配名称/分类/描述)。技能索引只显示前 100 个,索引外的技能必须先 search_skills 找到名字,再用 load_skill 取全文。", "parameters": {"type": "object", "properties": {
        "keywords": {"type": "string", "description": "搜索关键词,如 xss / webshell / log4j"},
        "limit": {"type": "integer", "description": "最多返回条数(默认 10,上限 50)"}}, "required": ["keywords"]}}},
    {"type": "function", "function": {"name": "load_skill", "description": "按需获取某个技能(SKILL.md)的操作步骤全文(分段读取,每段约 3000 字符)。已滑块开启的 skill 全文已注入 system prompt；未开启的(渐进式)可用本工具取全文。大技能用 part 参数分段取。", "parameters": {"type": "object", "properties": {
        "name": {"type": "string", "description": "技能名(见系统提示词中的技能列表,或 search_skills 搜索结果)"},
        "part": {"type": "integer", "description": "分段序号(从 1 开始);返回 total_parts 指示总段数,未读完继续取下一段"}}, "required": ["name"]}}},
    {"type": "function", "function": {"name": "web_search", "description": "搜索引擎搜索(无需 API key)。返回标题/URL/摘要列表,用于情报收集、漏洞资料查询、公开信息检索。", "parameters": {"type": "object", "properties": {
        "query": {"type": "string", "description": "搜索关键词"},
        "limit": {"type": "integer", "description": "结果条数,默认 8"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "web_browse", "description": "浏览网页并返回正文文本(httpx 直取;JS 渲染页面自动用无头浏览器渲染)。用于查看网页内容、读取漏洞详情、爬取公开页面信息。", "parameters": {"type": "object", "properties": {
        "url": {"type": "string", "description": "完整 URL(含 http/https 协议)"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "browser_navigate", "description": "无头浏览器导航到 URL(完整浏览器自动化,支持 JS 页面)。", "parameters": {"type": "object", "properties": {
        "url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "browser_state", "description": "读取浏览器当前页面:URL/标题 + 带索引的 DOM 元素文本。返回的索引供 browser_click/browser_type 使用。", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "browser_click", "description": "按索引点击浏览器页面元素(索引来自 browser_state 的 dom)。用于点击链接/按钮/表单提交。", "parameters": {"type": "object", "properties": {
        "index": {"type": "integer", "description": "browser_state 返回的 DOM 元素索引"}}, "required": ["index"]}}},
    {"type": "function", "function": {"name": "browser_type", "description": "按索引聚焦浏览器页面输入框并输入文本(用于表单填写)。", "parameters": {"type": "object", "properties": {
        "index": {"type": "integer", "description": "browser_state 返回的输入框索引"},
        "text": {"type": "string", "description": "要输入的文本"}}, "required": ["index", "text"]}}},
    {"type": "function", "function": {"name": "browser_screenshot", "description": "对浏览器当前页面截图,返回截图文件路径(Web 端可查看)。", "parameters": {"type": "object", "properties": {
        "path": {"type": "string", "description": "截图保存路径,可选(默认 /tmp/fs3-browser-<时间戳>.png)"}}}}},
    {"type": "function", "function": {"name": "xray_report", "description": "读取 xray 被动扫描 JSON 报告(reports/xray_out.json),返回漏洞发现列表(严重等级/插件/URL/payload),可搜索、限量。", "parameters": {"type": "object", "properties": {
        "limit": {"type": "integer", "description": "返回条数上限,默认 20"},
        "search": {"type": "string", "description": "按插件名/漏洞类别/URL/payload 模糊搜索关键字,可选"}}}}},
]

_AGENT_DANGEROUS = ("remove_event", "blacklist_add", "http_request", "run_python", "run_shell", "c2_exec",
                    "c2_raw", "c2_module_add", "c2_module_delete", "c2_auto_commands_set",
                    "webshell_exec", "webshell_fileop", "mcp_call",
                    "web_browse", "browser_navigate", "browser_click", "browser_type")

# ── 工具集按需裁剪 ──
# core 必有(事件/扫描指挥基础能力);其余按任务关键词 + 历史使用记录动态注入,
# 省 token(29 个工具 schema ≈ 4000+ token/轮)并减少 AI 误调用无关工具。
_CORE_TOOL_NAMES = {"list_events", "get_children", "scan_status", "inject", "remove_event",
                    "blacklist_add", "log", "read_ai_logs", "get_spill", "xray_report", "load_skill", "search_skills"}

_TOOL_GROUP_NAMES = {
    "c2": ["c2_beacons", "c2_exec", "c2_result", "c2_modules", "c2_module_build", "c2_module_exec",
           "c2_module_add", "c2_module_delete", "c2_raw", "c2_auto_commands", "c2_auto_commands_set"],
    "webshell": ["webshell_connections", "webshell_exec", "webshell_fileop"],
    "mcp": ["mcp_tools", "mcp_call"],
    "exec": ["http_request", "run_python", "run_shell"],
    "web": ["web_search", "web_browse", "browser_navigate", "browser_state",
            "browser_click", "browser_type", "browser_screenshot"],
}

# 任务关键词 → 工具组(命中任一即注入该组)
_TOOL_GROUP_KEYWORDS = {
    "c2": ["c2", "beacon", "控制", "渗透", "内网", "主机", "远控", "后渗透", "sysinfo", "提权", "横向"],
    "webshell": ["webshell", "shell", "后门", "蚁剑", "冰蝎", "菜刀", "马"],
    "mcp": ["mcp", "yakit", "dnslog", "外部工具", "被动扫描工具"],
    "exec": ["python", "脚本", "代码", "命令", "执行", "bash", "写文件", "跑一下", "curl", "http 请求"],
}
_DEFAULT_EXTRA_GROUPS = ("web",)   # 搜索/浏览默认开(情报收集基础能力)

_TOOL_GROUP_OF = {name: group for group, names in _TOOL_GROUP_NAMES.items() for name in names}


def _select_agent_tools(user_input: str, history: List[Dict[str, Any]],
                        config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """按任务关键词 + 历史工具使用记录裁剪工具集。core 必有,其余组命中才注入。"""
    text = " ".join([
        str(user_input or ""),
        *[str(m.get("content") or "") for m in (history or [])[-6:]],
    ]).lower()
    # 历史里用过的工具 → 其所在组保留(任务连续性,防止中途裁掉正在用的工具)
    used = set()
    for m in (history or []):
        for tc in (m.get("tool_calls") or []):
            used.add((tc.get("function") or {}).get("name", ""))
    groups = set(_DEFAULT_EXTRA_GROUPS)
    # 已启用 MCP server 时 mcp 组默认注入(system prompt 有 [已接入 MCP 工具] 摘要,
    # 工具必须可用,否则 Agent 想调 mcp_tools/mcp_call 却找不到工具)
    try:
        if _mcp_servers(config or {}):
            groups.add("mcp")
    except Exception:
        pass
    for group, kws in _TOOL_GROUP_KEYWORDS.items():
        if any(k in text for k in kws) or any(_TOOL_GROUP_OF.get(t) == group for t in used):
            groups.add(group)
    allowed = set(_CORE_TOOL_NAMES)
    for g in groups:
        allowed |= set(_TOOL_GROUP_NAMES[g])
    return [t for t in AGENT_TOOLS if t["function"]["name"] in allowed]


def _dispatch_agent_tool_safe(name: str, args: Dict[str, Any], redis: FlowScanRedis,
                              session_id: str, config: Optional[Dict[str, Any]] = None) -> str:
    """工具调用兜底:任何异常转成工具结果喂回 LLM(它可自行调整),不让异常炸掉整个 Agent 循环。"""
    try:
        return _dispatch_agent_tool(name, args, redis, session_id, config)
    except Exception as exc:
        return json.dumps({"ok": False, "error": f"工具 {name} 执行异常: {exc}"}, ensure_ascii=False)


def _agent_system_prompt(skill_section: str = "") -> str:
    base = (
        "你是 FlowScan 的自主扫描指挥 Agent。你的任务是:根据用户的任务,调用工具查看事件、"
        "注入扫描、分析结果,并循环推进直到目标达成。\n"
        "工作方式:先用 list_events/scan_status 了解现状,再用 inject 注入目标触发扫描,"
        "调度器会自动把注入后的新增事件摘要喂给你,你据此决定下一步(继续扩展、拉黑噪音、或收工)。\n"
        "重要发现用 log 工具沉淀(priority: high 立即关注/medium 值得跟进/low 备忘)。\n"
        "漏洞扫描结果(如 xray 被动扫描)可用 xray_report 工具读取 reports/xray_out.json。\n"
        "原则:基于事实(工具返回的结果)决策,不编造;注入事件要复用已有的正确事件类型和格式;"
        "除非明确需要,不要删除事件或加黑名单。"
    )
    if skill_section:
        base += "\n\n" + skill_section
    return base


# ── 会话管理 ──

def _create_agent_session(redis: FlowScanRedis, title: str, model: str) -> Dict[str, Any]:
    session_id = uuid.uuid4().hex[:12]
    now = time.time()
    data = {
        "session_id": session_id, "title": title, "model": model,
        "created_at": now, "created_at_iso": datetime.fromtimestamp(now).isoformat(),
        "last_active": now, "message_count": 0,
    }
    redis.conn.hset(f"fs3:agent:session:{session_id}", mapping={k: json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v for k, v in data.items()})
    redis.conn.zadd("fs3:agent:sessions", {session_id: now})
    return data


def _load_agent_session(redis: FlowScanRedis, session_id: str) -> Optional[Dict[str, Any]]:
    raw = redis.conn.hgetall(f"fs3:agent:session:{session_id}")
    if not raw:
        return None
    return {k: _json_or_raw(v) for k, v in raw.items()}


def _list_agent_sessions(redis: FlowScanRedis) -> List[Dict[str, Any]]:
    sessions = []
    for sid in redis.conn.zrevrange("fs3:agent:sessions", 0, 200):
        s = _load_agent_session(redis, sid)
        if s:
            sessions.append(s)
    return sessions


def _delete_agent_session(redis: FlowScanRedis, session_id: str) -> bool:
    existed = bool(redis.conn.exists(f"fs3:agent:session:{session_id}"))
    pipe = redis.conn.pipeline()
    pipe.delete(f"fs3:agent:session:{session_id}")
    pipe.delete(f"fs3:agent:session:{session_id}:messages")
    pipe.delete(f"fs3:agent:session:{session_id}:state")
    pipe.delete(f"fs3:agent:session:{session_id}:audit")
    pipe.zrem("fs3:agent:sessions", session_id)
    pipe.execute()
    return existed


def _recover_orphan_agent_sessions(redis: FlowScanRedis) -> int:
    """web 重启后把残留 status=running 的会话标记为 interrupted。

    任务线程表(_AGENT_TASKS)是进程内存,web 重启即清空,但 redis 里 state.status
    仍停在 running → 前端永远显示"运行中"却没线程在跑(假死)。
    启动时扫一遍,标记中断并提示,让用户重新发起即可。
    """
    n = 0
    for sid in redis.conn.zrevrange("fs3:agent:sessions", 0, 200):
        try:
            state = _get_agent_state(redis, sid)
        except Exception:
            continue
        if state.get("status") == "running":
            try:
                _append_agent_message(redis, sid, {"role": "system",
                                                   "content": "[已中断] web 服务重启,原任务已停止,可重新发起。"})
                _set_agent_state(redis, sid, {"status": "interrupted", "error": "web restart"})
                n += 1
            except Exception:
                continue
    return n


def _append_agent_message(redis: FlowScanRedis, session_id: str, msg: Dict[str, Any]) -> None:
    msg = {**msg, "ts": time.time()}
    redis.conn.rpush(f"fs3:agent:session:{session_id}:messages", json.dumps(msg, ensure_ascii=False))
    redis.conn.ltrim(f"fs3:agent:session:{session_id}:messages", -500, -1)
    redis.conn.hincrby(f"fs3:agent:session:{session_id}", "message_count", 1)
    redis.conn.hset(f"fs3:agent:session:{session_id}", "last_active", time.time())


def _get_agent_messages(redis: FlowScanRedis, session_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    raw = redis.conn.lrange(f"fs3:agent:session:{session_id}:messages", -limit, -1)
    return [json.loads(x) for x in raw if x.strip()]


def _get_agent_state(redis: FlowScanRedis, session_id: str) -> Dict[str, Any]:
    raw = redis.conn.hgetall(f"fs3:agent:session:{session_id}:state")
    state = {k: _json_or_raw(v) for k, v in raw.items()} if raw else {}
    state["queue_length"] = _agent_queue_len(redis, session_id)
    return state


def _set_agent_state(redis: FlowScanRedis, session_id: str, updates: Dict[str, Any]) -> None:
    redis.conn.hset(f"fs3:agent:session:{session_id}:state", mapping={k: json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v for k, v in updates.items()})


# ── 审计(全自动 + 人工审计 + AI 自动审计) ──

def _audit_agent_action(redis: FlowScanRedis, session_id: str, tool: str, args: Dict[str, Any], result: str, duration: float) -> None:
    entry = {
        "tool": tool,
        "args": json.dumps(args, ensure_ascii=False)[:500],
        "result": (result or "")[:500],
        "duration": round(duration, 2),
        "ts": time.time(),
        "ts_iso": datetime.fromtimestamp(time.time()).isoformat(),
    }
    redis.conn.rpush(f"fs3:agent:session:{session_id}:audit", json.dumps(entry, ensure_ascii=False))
    redis.conn.ltrim(f"fs3:agent:session:{session_id}:audit", -500, -1)


def _audit_summary(redis: FlowScanRedis, session_id: str, limit: int = 20) -> str:
    raw = redis.conn.lrange(f"fs3:agent:session:{session_id}:audit", -limit, -1)
    lines = []
    for x in raw:
        try:
            e = json.loads(x)
        except Exception:
            continue
        lines.append(f"- {e.get('tool')}({e.get('args', '')[:80]}) -> {e.get('result', '')[:100]}")
    return "\n".join(lines)


# ── 工具调度器 ──

def _dispatch_agent_tool(name: str, args: Dict[str, Any], redis: FlowScanRedis,
                         session_id: str, config: Optional[Dict[str, Any]] = None) -> str:
    args = args or {}
    t0 = time.time()
    if name == "list_events":
        types = list(args.get("event_types") or [])
        limit = min(int(args.get("limit") or 50), 200)
        search = (args.get("search") or "").strip().lower()
        events = []
        if types:
            for t in types:
                events.extend(_list_events(redis, event_type=t, limit=limit))
        else:
            events = _list_events(redis, limit=limit)
        if search:
            events = [e for e in events if search in (e.get("value") or "").lower()]
        seen, out = set(), []
        for e in events:
            fp = e.get("fingerprint", "")
            if fp in seen:
                continue
            seen.add(fp)
            out.append({"type": e.get("event_type"), "value": (e.get("value") or "")[:200], "fp": fp[:16], "source": e.get("source_tool")})
            if len(out) >= limit:
                break
        result = json.dumps({"ok": True, "count": len(out), "events": out}, ensure_ascii=False)
    elif name == "get_children":
        fp = str(args.get("fingerprint") or "").strip()
        data = redis.get_recursive_children(fp) if fp else {"error": "fingerprint 为空"}
        result = json.dumps(data, ensure_ascii=False)
    elif name == "scan_status":
        result = json.dumps({"ok": True, "nodes": len(_active_nodes(redis)), "tools": len(_tool_registry(redis)),
                             "event_types": _event_types(redis), "total_events": int(redis.conn.scard("fs3:event:all") or 0)}, ensure_ascii=False)
    elif name == "inject":
        event_type = str(args.get("event_type") or "").strip()
        value = str(args.get("value") or "").strip()
        if not event_type or not value:
            result = json.dumps({"ok": False, "error": "event_type/value 为空"}, ensure_ascii=False)
        else:
            fp = redis.push_event(event_type, value, source_tool="ai_agent")
            result = json.dumps({"ok": True, "injected": True, "event_type": event_type, "value": value, "fp": (fp or "")[:16]}, ensure_ascii=False)
    elif name == "remove_event":
        event_type = str(args.get("event_type") or "").strip()
        value = str(args.get("value") or "").strip()
        fp = FlowScanRedis.fingerprint(event_type, value) if (event_type and value) else ""
        removed = _remove_event(redis, fp, remove_children=bool(args.get("remove_children", True))) if fp else 0
        result = json.dumps({"ok": True, "removed": removed, "event_type": event_type, "value": value}, ensure_ascii=False)
    elif name == "blacklist_add":
        et = str(args.get("event_type") or "").strip()
        mm = str(args.get("match_mode") or "").strip()
        val = str(args.get("value") or "").strip()
        comment = str(args.get("comment") or "").strip() or "AI Agent"
        if not et or not val or mm not in ("contains", "suffix", "prefix", "ip_range"):
            result = json.dumps({"ok": False, "error": "event_type/value 为空或 match_mode 无效"}, ensure_ascii=False)
        else:
            fp = add_redis_rule(redis, et, mm, val, comment)
            result = json.dumps({"ok": True, "fp": (fp or "")[:16] if fp else "已存在"}, ensure_ascii=False)
    elif name == "http_request":
        result = exec_http(args.get("method", "GET"), args.get("url", ""), args.get("headers"), args.get("body", ""), args.get("timeout", 30))
    elif name == "run_python":
        result = exec_python(args.get("code", ""), args.get("timeout", 30))
    elif name == "run_shell":
        result = exec_shell(args.get("command", ""), args.get("timeout", 30))
    elif name == "log":
        entry = _ai_log_entry(redis, {"type": "log", "message": str(args.get("message", "")),
                                      "priority": str(args.get("priority", "medium")), "target": str(args.get("target", ""))}, source="agent")
        result = json.dumps({"ok": True, "log_id": entry.get("log_id", "")}, ensure_ascii=False)
    elif name == "read_ai_logs":
        limit = min(int(args.get("limit") or 20), 100)
        priority = str(args.get("priority") or "").strip().lower()
        search = str(args.get("search") or "").strip().lower()
        log_ids = redis.conn.zrevrange("fs3:ai:logs", 0, max(0, limit - 1))
        entries = []
        for lid in log_ids:
            raw = redis.conn.hgetall(f"fs3:ai:log:{lid}")
            if not raw:
                continue
            e = {k: _json_or_raw(v) for k, v in raw.items()}
            if priority and str(e.get("priority", "") or "").lower() != priority:
                continue
            msg = str(e.get("message", "") or "")
            if search and search not in msg.lower():
                continue
            entries.append({
                "log_id": e.get("log_id", ""),
                "priority": e.get("priority", "medium"),
                "source": e.get("source", ""),
                "target": str(e.get("target", "") or "")[:80],
                "message": msg[:300],
                "created_at_iso": e.get("created_at_iso", ""),
            })
            if len(entries) >= limit:
                break
        result = json.dumps({"ok": True, "count": len(entries), "logs": entries}, ensure_ascii=False)
    elif name == "c2_beacons":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            beacons = c2_bridge.list_beacons()
            result = json.dumps({"ok": True, "count": len(beacons), "beacons": beacons}, ensure_ascii=False)
    elif name == "c2_exec":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            out = c2_bridge.execute(str(args.get("command", "") or ""))
            result = json.dumps({"ok": True, "output": out}, ensure_ascii=False)
    elif name == "c2_result":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            b = c2_bridge.get_beacon(str(args.get("client_id", "") or ""))
            if not b:
                result = json.dumps({"ok": False, "error": "beacon not found"}, ensure_ascii=False)
            else:
                results = b.get("results", [])
                count = min(int(args.get("count", 10) or 10), len(results))
                result = json.dumps({"ok": True, "client_id": b["client_id"], "results": results[-count:]}, ensure_ascii=False)
    elif name == "c2_modules":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            result = json.dumps({"ok": True, "implant": c2_bridge.list_modules(),
                                 "server": c2_bridge.list_smodules(),
                                 "commands": c2_bridge.list_commands()}, ensure_ascii=False)
    elif name == "c2_module_build":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            ok, out = c2_bridge.build_module_task(str(args.get("name", "") or ""),
                                                  list(args.get("args") or []),
                                                  str(args.get("platform", "") or ""))
            result = json.dumps({"ok": ok, "code" if ok else "error": out}, ensure_ascii=False)
    elif name == "c2_module_exec":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            ok, msg = c2_bridge.exec_module_to_beacon(str(args.get("client_id", "") or ""),
                                                      str(args.get("name", "") or ""),
                                                      list(args.get("args") or []))
            result = json.dumps({"ok": ok, "message": msg}, ensure_ascii=False)
    elif name == "c2_module_add":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            ok, msg = c2_bridge.add_module(str(args.get("filename", "") or ""),
                                           str(args.get("content", "") or ""))
            result = json.dumps({"ok": ok, "message": msg}, ensure_ascii=False)
    elif name == "c2_module_delete":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            ok, msg = c2_bridge.delete_module(str(args.get("filename", "") or ""))
            result = json.dumps({"ok": ok, "message": msg}, ensure_ascii=False)
    elif name == "c2_raw":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            ok, msg = c2_bridge.push_raw(str(args.get("client_id", "") or ""),
                                         str(args.get("code", "") or ""))
            result = json.dumps({"ok": ok, "message": msg}, ensure_ascii=False)
    elif name == "c2_auto_commands":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            result = json.dumps({"ok": True, "auto_commands": c2_bridge.get_auto_commands()}, ensure_ascii=False)
    elif name == "c2_auto_commands_set":
        srv = c2_bridge.init_from_flowscan_config()
        if not srv:
            result = json.dumps({"ok": False, "error": "C2 未启用或启动失败: " + c2_bridge.init_error()}, ensure_ascii=False)
        else:
            ok, msg = c2_bridge.set_auto_commands(list(args.get("commands") or []))
            result = json.dumps({"ok": ok, "message": msg}, ensure_ascii=False)
    elif name == "webshell_connections":
        conns = ws.list_connections(redis)
        conns = [{k: ("****" if k == "password" else v) for k, v in c.items()} for c in conns]
        result = json.dumps({"ok": True, "count": len(conns), "connections": conns}, ensure_ascii=False)
    elif name == "webshell_exec":
        conn = ws.get_connection(redis, str(args.get("conn_id", "") or ""))
        if not conn:
            result = json.dumps({"ok": False, "error": "connection not found"}, ensure_ascii=False)
        else:
            output, ok, err = ws.exec_command(conn, str(args.get("command", "") or ""))
            result = json.dumps({"ok": True, "exec_ok": ok, "output": output, "error": err}, ensure_ascii=False)
    elif name == "webshell_fileop":
        conn = ws.get_connection(redis, str(args.get("conn_id", "") or ""))
        if not conn:
            result = json.dumps({"ok": False, "error": "connection not found"}, ensure_ascii=False)
        else:
            output, ok, err = ws.file_op(conn, str(args.get("action", "") or ""), str(args.get("path", "") or ""),
                                         str(args.get("content", "") or ""), str(args.get("target_path", "") or ""))
            result = json.dumps({"ok": True, "exec_ok": ok, "output": output, "error": err}, ensure_ascii=False)
    elif name == "get_spill":
        ref = str(args.get("ref") or "").strip()
        full = redis.conn.hget(f"fs3:agent:spill:{session_id}", ref) if ref else ""
        result = json.dumps({"ok": bool(full), "content": full or ""}, ensure_ascii=False)
    elif name == "mcp_tools":
        out = []
        for s in _mcp_servers(config or {}):
            sname = str(s.get("name") or "")
            cli, from_cache = None, False
            try:
                cached = _mcp_cached_tools(sname)
                if cached:
                    out.append({"server": sname, "ok": True, "tools": cached, "cached": True})
                    continue
                cli, from_cache = _mcp_client_for(s)
                tools = cli.list_tools()
                compact = [{"name": t.get("name"),
                            "description": str(t.get("description") or "")[:120],
                            "inputSchema": _compact_mcp_schema(t.get("inputSchema") or {})}
                           for t in tools if isinstance(t, dict) and t.get("name")]
                _mcp_store_tools(sname, compact)
                out.append({"server": sname, "ok": True, "tools": compact, "cached": False})
            except Exception as exc:
                out.append({"server": sname, "ok": False, "error": str(exc)})
            finally:
                _mcp_client_release(sname, from_cache)
        result = json.dumps({"ok": True, "enabled": bool(_mcp_servers(config or {})),
                             "servers": out}, ensure_ascii=False)
    elif name == "mcp_call":
        sname = str(args.get("server") or "").strip()
        tool = str(args.get("tool") or "").strip()
        arguments = args.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        server = next((s for s in _mcp_servers(config or {}) if s.get("name") == sname), None)
        if server is None:
            result = json.dumps({"ok": False, "error": f"MCP server '{sname}' 未配置或未启用"}, ensure_ascii=False)
        elif not tool:
            result = json.dumps({"ok": False, "error": "tool 不能为空"}, ensure_ascii=False)
        else:
            cli, from_cache = None, False
            try:
                cli, from_cache = _mcp_client_for(server)
                out = cli.call_tool(tool, arguments)
                result = json.dumps({"ok": not out.get("isError"), "server": sname, "tool": tool,
                                     "content": out.get("content", ""), "isError": out.get("isError", False)},
                                    ensure_ascii=False)
            except Exception as exc:
                result = json.dumps({"ok": False, "server": sname, "tool": tool,
                                     "error": str(exc)}, ensure_ascii=False)
            finally:
                _mcp_client_release(sname, from_cache)
    elif name == "load_skill":
        skill_name = str(args.get("name") or "").strip()
        try:
            part = max(1, int(args.get("part") or 1))
        except (TypeError, ValueError):
            part = 1
        if not skill_name:
            result = json.dumps({"ok": False, "error": "name 不能为空"}, ensure_ascii=False)
        else:
            scfg = _skills_config(config or {})
            if not scfg["enabled"]:
                result = json.dumps({"ok": False, "error": "Skill 加载未启用(配置 skills.enabled)"}, ensure_ascii=False)
            elif skill_name not in {sk.get("name") for sk in _scan_skills(scfg["dirs"])}:  # _scan_skills 返回 dict 列表,取 name 集合比对(勿 set() 整个列表,会 unhashable)
                result = json.dumps({"ok": False, "error": f"skill '{skill_name}' 不存在"}, ensure_ascii=False)
            else:
                content = _read_skill_content(scfg["dirs"], skill_name)
                if content is None:
                    result = json.dumps({"ok": False, "error": f"skill '{skill_name}' 文件不存在"}, ensure_ascii=False)
                else:
                    # 分段读取:每段 3000 字符,大技能用 part 参数逐段取,避免单轮上下文被大 SKILL.md 吃光
                    chunk_size = 3000
                    total_parts = max(1, (len(content) + chunk_size - 1) // chunk_size)
                    if part > total_parts:
                        result = json.dumps({"ok": True, "name": skill_name, "part": part,
                                             "total_parts": total_parts, "content": "",
                                             "done": True}, ensure_ascii=False)
                    else:
                        chunk = content[(part - 1) * chunk_size: part * chunk_size]
                        result = json.dumps({"ok": True, "name": skill_name, "part": part,
                                             "total_parts": total_parts, "content": chunk,
                                             "done": part >= total_parts}, ensure_ascii=False)
                    # 记录最近使用(Redis zset,索引置顶/常用排序用)
                    if redis is not None:
                        try:
                            redis.conn.zincrby("fs3:ai:skill_usage", 1, skill_name)
                        except Exception:
                            pass
    elif name == "search_skills":
        keywords = str(args.get("keywords") or "").strip().lower()
        try:
            limit = min(max(1, int(args.get("limit") or 10)), 50)
        except (TypeError, ValueError):
            limit = 10
        scfg = _skills_config(config or {})
        if not scfg["enabled"]:
            result = json.dumps({"ok": False, "error": "Skill 加载未启用(配置 skills.enabled)"}, ensure_ascii=False)
        elif not keywords:
            result = json.dumps({"ok": False, "error": "keywords 不能为空"}, ensure_ascii=False)
        else:
            # 全库搜索(走 30s 缓存,919 个 skill 不会每次全量解析)
            hits = []
            for sk in _scan_skills(scfg["dirs"]):
                hay = f"{sk.get('name', '')} {sk.get('category', '')} {sk.get('description', '')}".lower()
                if keywords in hay:
                    hits.append({"name": sk.get("name", ""), "category": sk.get("category", ""),
                                 "description": str(sk.get("description") or "")[:200]})
                    if len(hits) >= limit:
                        break
            result = json.dumps({"ok": True, "count": len(hits), "results": hits}, ensure_ascii=False)
    elif name == "web_search":
        result = browser_tools.web_search(str(args.get("query") or ""), int(args.get("limit") or 8))
    elif name == "web_browse":
        result = browser_tools.web_browse(str(args.get("url") or ""))
    elif name == "browser_navigate":
        result = browser_tools.browser_navigate(str(args.get("url") or ""))
    elif name == "browser_state":
        result = browser_tools.browser_state()
    elif name == "browser_click":
        raw_index = args.get("index")
        # index=0(第一个元素)是合法值,勿用 `or -1`(0 会被当成假值变 -1)
        index = int(raw_index) if raw_index is not None else -1
        result = browser_tools.browser_click(index)
    elif name == "browser_type":
        raw_index = args.get("index")
        index = int(raw_index) if raw_index is not None else -1
        result = browser_tools.browser_type(index, str(args.get("text") or ""))
    elif name == "browser_screenshot":
        result = browser_tools.browser_screenshot(str(args.get("path") or ""))
    elif name == "xray_report":
        limit = min(int(args.get("limit") or 20), 100)
        search = (args.get("search") or "").strip().lower()
        findings = xray_load_findings()
        if not findings:
            result = json.dumps({"ok": False, "count": 0,
                                 "error": "reports/xray_out.json 不存在或无内容(等待 xray 被动扫描输出 JSON 报告)"}, ensure_ascii=False)
        else:
            if search:
                findings = [f for f in findings if search in (
                    f.get("plugin", "") + " " + f.get("vuln_class", "") + " " +
                    f.get("url", "") + " " + f.get("payload", "")).lower()]
            total = len(findings)
            out = [{"severity": f.get("severity", "info"),
                    "plugin": f.get("plugin", ""),
                    "vuln_class": f.get("vuln_class", ""),
                    "url": (f.get("url") or "")[:300],
                    "payload": (f.get("payload") or "")[:400],
                    "create_time_iso": f.get("create_time_iso", "")} for f in findings[:limit]]
            result = json.dumps({"ok": True, "total": total, "returned": len(out),
                                 "findings": out}, ensure_ascii=False)
    else:
        result = json.dumps({"ok": False, "error": f"未知工具: {name}"}, ensure_ascii=False)
    duration = time.time() - t0
    if name in _AGENT_DANGEROUS:
        _audit_agent_action(redis, session_id, name, args, result, duration)
    return result


# ── 增量事件拉取 ──

def _new_events_since(redis: FlowScanRedis, cursor: float) -> List[Dict[str, Any]]:
    """注入后拉取新增事件（时间索引增量查询，不再全量扫 event:all）。"""
    return redis.events_since(cursor, limit=500)


def _summarize_new_events(events: List[Dict[str, Any]]) -> str:
    by_type: Dict[str, int] = {}
    for e in events:
        by_type[e.get("event_type", "?")] = by_type.get(e.get("event_type", "?"), 0) + 1
    lines = [f"{t}: {n}" for t, n in sorted(by_type.items())]
    high = [e for e in events if e.get("event_type") in ("VULNERABILITY", "FINDING")]
    if high:
        lines.append("高价值条目:")
        for e in high[:10]:
            lines.append(f"  - {e.get('event_type')} {str(e.get('value', ''))[:150]}")
    return "\n".join(lines) if lines else "无新增"


# ── LLM 调用(function calling) ──

def _llm_chat(ai_cfg: Dict[str, Any], messages: List[Dict[str, Any]],
              tools: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """OpenAI 兼容 /chat/completions 调用核心（含重试与溢出检测）。

    tools 为 None 时是普通对话（AI 审批用），否则带 function calling。
    统一实现在 flowscan/llm.py（与手动分析/定时任务共用，瞬时故障指数退避重试）。
    """
    return llm_chat_completions(ai_cfg, messages, tools=tools)


def _call_llm_with_tools(ai_cfg: Dict[str, Any], messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> Dict[str, Any]:
    return _llm_chat(ai_cfg, messages, tools=tools)


def _call_llm_plain(ai_cfg: Dict[str, Any], messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    return _llm_chat(ai_cfg, messages)


# ── Agent 循环引擎 ──

_AGENT_TASKS: Dict[str, Dict[str, Any]] = {}
_AGENT_TASKS_LOCK = threading.Lock()

# ── 打断标志 + 消息队列(回车=排队发送 / Ctrl+回车=打断发送) ──
_AGENT_INTERRUPT: Dict[str, bool] = {}
_AGENT_INTERRUPT_LOCK = threading.Lock()


def _request_interrupt(session_id: str) -> None:
    with _AGENT_INTERRUPT_LOCK:
        _AGENT_INTERRUPT[session_id] = True


def _consume_interrupt(session_id: str) -> bool:
    with _AGENT_INTERRUPT_LOCK:
        return _AGENT_INTERRUPT.pop(session_id, False)


def _agent_queue_key(session_id: str) -> str:
    return f"fs3:agent:queue:{session_id}"


def _agent_queue_push(redis: FlowScanRedis, session_id: str, text: str) -> None:
    redis.conn.rpush(_agent_queue_key(session_id), text)


def _agent_queue_pop(redis: FlowScanRedis, session_id: str) -> str:
    raw = redis.conn.lpop(_agent_queue_key(session_id))
    if not raw:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def _agent_queue_len(redis: FlowScanRedis, session_id: str) -> int:
    try:
        return int(redis.conn.llen(_agent_queue_key(session_id)) or 0)
    except Exception:
        return 0

# ── 危险操作审批模式 ──
#   auto  : 自动放行（仅落审计）
#   ai    : 执行前由 AI 安全审批员审核（不确定/越界即拒绝，fail-closed）
#   human : 执行前暂停等待人工批准（HITL）
_APPROVAL_MODES = ("auto", "ai", "human")
_APPROVAL_LABELS = {"auto": "自动放行", "ai": "AI 审批", "human": "人工审批"}

_APPROVE_PROMPT = (
    "你是 FlowScan 的危险操作安全审批员。根据用户任务与当前会话上下文，"
    "判断下列 AI 发起的工具调用是否必要、是否符合任务目标、且没有越界或恶意迹象。\n"
    "只输出一个 JSON 对象: {\"approve\": true 或 false, \"reason\": \"简短理由\"}。\n"
    "与任务无关、范围过大、涉及凭据/密钥上传、删除数据或明显越界时一律拒绝；"
    "拿不准就拒绝。"
)

_SPILL_MAX = 4000  # 工具结果超过此长度则 spill 到 Redis,截断 + 引用


def _resolve_approval_mode(ai_cfg: Dict[str, Any]) -> str:
    """解析审批模式；兼容旧配置 agent_require_approval=true → human。"""
    mode = str(ai_cfg.get("agent_approval_mode", "") or "").strip().lower()
    if mode in _APPROVAL_MODES:
        return mode
    return "human" if ai_cfg.get("agent_require_approval") else "auto"


def _ai_approve_decision(redis: FlowScanRedis, session_id: str, ai_cfg: Dict[str, Any],
                         name: str, args: Dict[str, Any], task: str = "") -> Dict[str, Any]:
    """AI 审批：调 LLM 判断危险工具调用是否放行。失败一律拒绝（fail-closed）。"""
    goal = (task or "").strip()
    if not goal:
        for m in reversed(_get_agent_messages(redis, session_id, limit=200)):
            if m.get("role") == "user" and m.get("content"):
                goal = str(m["content"])
                break
    messages = [
        {"role": "system", "content": _APPROVE_PROMPT},
        {"role": "user", "content": (
            f"用户任务目标:\n{goal or '(未知)'}\n\n"
            f"待审批的工具调用:\n工具: {name}\n"
            f"参数: {json.dumps(args, ensure_ascii=False)[:2000]}")},
    ]
    try:
        resp = _call_llm_plain(ai_cfg, messages)
        if not resp.get("ok"):
            return {"approved": False, "reason": f"审批 LLM 调用失败: {str(resp.get('error', ''))[:200]}"}
        m = re.search(r"\{[\s\S]*\}", (resp.get("answer") or "").strip())
        data = json.loads(m.group(0)) if m else {}
        if not isinstance(data, dict) or "approve" not in data:
            return {"approved": False, "reason": "审批输出格式非法(缺少 approve 字段)"}
        approved = data.get("approve") is True
        return {"approved": approved, "reason": str(data.get("reason", ""))[:300]}
    except Exception as exc:
        return {"approved": False, "reason": f"审批异常: {exc}"}


def _mcp_servers(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """已启用且带名称的 MCP server 列表。"""
    mcp = (config or {}).get("mcp", {}) or {}
    if not mcp.get("enabled"):
        return []
    return [s for s in (mcp.get("servers") or [])
            if isinstance(s, dict) and s.get("name") and s.get("enabled", True)]


# ── MCP 连接/工具列表缓存(2026-08):避免每次 mcp_tools/mcp_call 重复握手 ──
_MCP_CLIENT_TTL = 300.0    # 连接复用窗口(stdio 子进程保活/SSE 免重复握手)
_MCP_TOOLS_TTL = 30.0      # 工具列表缓存窗口
_mcp_clients: Dict[str, Dict[str, Any]] = {}   # name -> {"cli": McpClient, "ts": float}
_mcp_tools_cache: Dict[str, Dict[str, Any]] = {}  # name -> {"ts": float, "tools": list}


def _mcp_client_for(server: dict):
    """取 MCP 客户端:缓存命中返回 (cli, True),否则新建并缓存 (cli, False)。"""
    name = str(server.get("name") or "")
    now = time.time()
    hit = _mcp_clients.get(name)
    if hit and now - hit["ts"] < _MCP_CLIENT_TTL:
        return hit["cli"], True
    from flowscan.mcp_client import McpClient
    cli = McpClient(server)
    _mcp_clients[name] = {"cli": cli, "ts": now}
    return cli, False


def _mcp_client_release(name: str, from_cache: bool) -> None:
    """释放客户端:缓存复用则不关(保活);新建的用完后关闭并移出缓存。"""
    if from_cache:
        return
    hit = _mcp_clients.pop(name, None)
    if hit:
        try:
            hit["cli"].close()
        except Exception:
            pass


def _mcp_cached_tools(name: str) -> list:
    """工具列表缓存(30s)。"""
    hit = _mcp_tools_cache.get(name)
    if hit and time.time() - hit["ts"] < _MCP_TOOLS_TTL:
        return hit["tools"]
    return []


def _mcp_store_tools(name: str, tools: list) -> None:
    _mcp_tools_cache[name] = {"ts": time.time(), "tools": tools}


def _compact_mcp_schema(schema: dict) -> dict:
    """精简 MCP 工具 inputSchema:只留属性名/type/required,描述等长文本丢弃,
    避免几十个工具的全量 schema 撑爆上下文。"""
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    out_props = {}
    if isinstance(props, dict):
        for k, v in props.items():
            if not isinstance(v, dict):
                continue
            item = {"type": v.get("type", "any")}
            out_props[k] = item
    return {"type": "object", "properties": out_props,
            "required": schema.get("required", []) if isinstance(schema.get("required"), list) else []}


def _mcp_prompt_section(config: Dict[str, Any]) -> str:
    """把已接入的 MCP server 摘要注入 Agent system prompt。"""
    servers = _mcp_servers(config)
    if not servers:
        return ""
    lines = ["\n\n[已接入 MCP 工具]"]
    for s in servers:
        lines.append(f"- {s.get('name')} ({s.get('type') or 'sse'}): "
                     "先用 mcp_tools 查看其工具列表，再用 mcp_call 调用")
    return "\n".join(lines)


def _truncate_for_context(text: str, max_chars: int, spill_ref: str = "") -> str:
    """截断长文本:保留头尾 + marker。spill_ref 非空时提示完整内容可取回。"""
    if not text or len(text) <= max_chars:
        return text
    marker = f"\n\n...[已截断,完整内容见 spill:{spill_ref}]...\n\n" if spill_ref else "\n\n...[已截断]...\n\n"
    budget = max_chars - len(marker)
    if budget <= 0:
        return marker
    head = budget // 2
    tail = budget - head
    return text[:head] + marker + text[-tail:]


def _messages_char_count(messages: List[Dict[str, Any]]) -> int:
    total = 0
    for m in messages:
        total += len(str(m.get("content", "")))
        for tc in (m.get("tool_calls") or []):
            total += len(str(tc))
    return total


def _split_message_rounds(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把消息序列切成"轮":assistant(可能带 tool_calls)+ 紧随其后的 tool 结果配对成一轮;
    独立消息(user/system)自成一轮。压缩时按轮丢弃,保证 tool_call/tool_result 永不拆散。"""
    rounds: List[Dict[str, Any]] = []
    cur = None
    for m in messages:
        role = m.get("role")
        if role == "assistant":
            if cur:
                rounds.append(cur)
            cur = {"head": m, "tools": []}
        elif role == "tool":
            if cur is None:
                cur = {"head": None, "tools": []}
            cur["tools"].append(m)
        else:
            if cur:
                rounds.append(cur)
            cur = None
            rounds.append({"head": m, "tools": []})
    if cur:
        rounds.append(cur)
    return rounds


def _flatten_rounds(rounds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in rounds:
        if r["head"]:
            out.append(r["head"])
        out.extend(r["tools"])
    return out


def _compact_agent_messages(messages: List[Dict[str, Any]], max_chars: int) -> List[Dict[str, Any]]:
    """上下文预算压缩:先截断超长工具输出;仍超限则按"轮"丢弃最旧中间轮(保首尾)。

    按轮为单位(assistant 的 tool_calls 与其 tool 结果同生共死),
    避免旧实现逐条丢消息导致 tool_call/tool_result 错配被 API 拒绝。
    """
    if _messages_char_count(messages) <= max_chars or len(messages) <= 2:
        return messages
    msgs = []
    for m in messages:
        if m.get("role") == "tool" and len(str(m.get("content", ""))) > 2000:
            m = {**m, "content": _truncate_for_context(str(m["content"]), 2000)}
        msgs.append(m)
    if _messages_char_count(msgs) <= max_chars:
        return msgs
    rounds = _split_message_rounds(msgs)
    if not rounds:
        return msgs
    head, tail = [rounds[0]], [rounds[-1]]   # 保留首轮(system)+ 末轮(最新)
    middle = rounds[1:-1]
    while middle and _messages_char_count(_flatten_rounds(head + middle + tail)) > max_chars:
        middle = middle[1:]
    return _flatten_rounds(head + middle + tail)


def _parse_plan(answer: str) -> List[str]:
    """从 LLM 回答解析 JSON 计划 {steps:[...]},失败返回空列表。"""
    if not answer:
        return []
    m = re.search(r"\{[\s\S]*\"steps\"[\s\S]*\}", answer.strip())
    if not m:
        return []
    try:
        steps = (json.loads(m.group(0)) or {}).get("steps") or []
        return [str(x) for x in steps if str(x).strip()]
    except Exception:
        return []


def _finalize_agent_turn(answer: str, did_tools: bool, last_failed: bool) -> Dict[str, Any]:
    """终结判定:LLM 无 tool_calls 时判断是否真可终结。"""
    answer = (answer or "").strip()
    if not answer or answer in ("无", "无内容", "None"):
        return {"finalizable": False, "reason": "empty_response",
                "nudge": "你尚未给出结论,请基于已有工具返回的结果给出明确的分析结论,不要空回复。"}
    if did_tools and last_failed:
        return {"finalizable": False, "reason": "tool_failed",
                "nudge": "你上一轮的工具调用全部失败了,请先修正参数或改用其他工具重试,不要直接下结论。"}
    return {"finalizable": True, "reason": "verified", "nudge": None}


def _tool_result_failed(result: str) -> bool:
    """判断工具返回是否失败(JSON 里 ok=false)。HITL 挂起不算失败。"""
    try:
        rj = json.loads(result)
    except Exception:
        return False
    if rj.get("hitl"):
        return False
    return rj.get("ok") is False


def _generate_agent_report(redis: FlowScanRedis, session_id: str, answer: str) -> Optional[Dict[str, Any]]:
    """收工自动生成结构化报告:任务目标/注入/删除/拉黑/工具统计/结论 → AI 日志沉淀。

    落 fs3:ai:logs(事件日记页可见,read_ai_logs 工具跨会话可读),做同类任务时直接复用。
    """
    state = _get_agent_state(redis, session_id)
    msgs = _get_agent_messages(redis, session_id, limit=200)
    goal = ""
    tool_counts: Dict[str, int] = {}
    injects, dels, blacks, others = [], [], [], []
    for m in msgs:
        if m.get("role") == "user" and m.get("content") and not goal:
            goal = str(m["content"])[:200]
        for tc in (m.get("tool_calls") or []):
            fn = tc.get("function") or {}
            name = str(fn.get("name") or "")
            try:
                targs = json.loads(fn.get("arguments") or "{}")
            except Exception:
                targs = {}
            tool_counts[name] = tool_counts.get(name, 0) + 1
            if name == "inject":
                injects.append(f"{targs.get('event_type', '?')}={str(targs.get('value', ''))[:60]}")
            elif name == "remove_event":
                dels.append(f"{targs.get('event_type', '?')}={str(targs.get('value', ''))[:60]}")
            elif name == "blacklist_add":
                blacks.append(f"{targs.get('match_mode', '?')}:{str(targs.get('value', ''))[:60]}")
            elif name not in ("list_events", "get_children", "scan_status", "get_spill", "log", "read_ai_logs"):
                others.append(name)
    lines = [
        f"Agent 会话报告 [{session_id}]",
        f"任务目标: {goal or '(无)'}",
        f"状态: {state.get('status')} | 工具调用总数: {sum(tool_counts.values())}",
        f"工具使用: {', '.join(f'{k}×{v}' for k, v in sorted(tool_counts.items())) or '无'}",
    ]
    if injects:
        lines.append("注入事件: " + "; ".join(injects[:10]))
    if dels:
        lines.append("删除事件: " + "; ".join(dels[:10]))
    if blacks:
        lines.append("拉黑规则: " + "; ".join(blacks[:10]))
    if others:
        lines.append("其他动作: " + ", ".join(dict.fromkeys(others))[:200])
    lines.append(f"结论: {(answer or '')[:500]}")
    report = "\n".join(lines)
    try:
        return _ai_log_entry(redis, {"type": "log", "message": report, "priority": "medium",
                                     "target": f"agent:{session_id}"}, source="agent_report")
    except Exception:
        return None


def _finish_agent_loop(redis: FlowScanRedis, session_id: str, ai_cfg: Dict[str, Any],
                       config: Optional[Dict[str, Any]], max_iterations: int, scan_gap_seconds: int,
                       status: str, iteration: int, answer: str,
                       tail_msg: Optional[Dict[str, Any]] = None) -> None:
    """收尾:落尾部消息/状态;若队列中有打断或排队的新指令,直接续跑(同线程延续上下文)。"""
    if tail_msg:
        _append_agent_message(redis, session_id, tail_msg)
    queued = _agent_queue_pop(redis, session_id)
    if queued:
        _set_agent_state(redis, session_id, {"status": "running", "iteration": 0})
        _run_agent_loop(redis, session_id, queued, ai_cfg, config,
                        max_iterations=max_iterations, scan_gap_seconds=scan_gap_seconds, resume=False)
        return
    _set_agent_state(redis, session_id, {"status": status, "iteration": iteration, "answer": answer})
    # 收工自动生成结构化报告(done/blocked 有产出;interrupted/error 不生成)
    if status in ("done", "blocked"):
        _generate_agent_report(redis, session_id, answer)


def _run_agent_loop(redis: FlowScanRedis, session_id: str, user_input: str, ai_cfg: Dict[str, Any],
                    config: Optional[Dict[str, Any]] = None,
                    max_iterations: int = 50, scan_gap_seconds: int = 5, resume: bool = False) -> None:
    _set_agent_state(redis, session_id, {"status": "running", "iteration": 0, "error": ""})
    config = config or {}
    context_max = int(ai_cfg.get("agent_context_max_chars", 60000) or 60000)
    plan_mode = bool(ai_cfg.get("agent_plan_mode", False))
    approval_mode = _resolve_approval_mode(ai_cfg)
    approval_note = (
        f"\n\n[危险操作审批模式] {_APPROVAL_LABELS.get(approval_mode, approval_mode)}："
        + ("危险工具调用直接执行并落审计。"
           if approval_mode == "auto"
           else ("危险工具调用执行前会先由 AI 安全审批员审核（与任务无关/越界即拒绝），"
                 "被拒绝后请调整方案或放弃该操作。"
                 if approval_mode == "ai"
                 else "危险工具调用会暂停等待人工批准；若被拒绝请调整方案。"))
    )
    prompt_suffix = (
        # 传 redis:常用技能(load_skill 使用计数)索引置顶
        _skill_prompt_section(config, for_agent=True, redis=redis)
        + _mcp_prompt_section(config)
        + approval_note
    ).strip()
    # 重建历史消息
    messages: List[Dict[str, Any]] = [{"role": "system", "content": _agent_system_prompt(prompt_suffix)}]
    for m in _get_agent_messages(redis, session_id, limit=100):
        role = m.get("role")
        if role == "tool":
            messages.append({"role": "tool", "tool_call_id": m.get("tool_call_id", ""), "content": m.get("content", "")})
        elif role in ("user", "assistant"):
            msg = {"role": role, "content": m.get("content", "")}
            if role == "assistant" and m.get("tool_calls"):
                msg["tool_calls"] = m.get("tool_calls")
            messages.append(msg)
    if user_input and not resume:
        messages.append({"role": "user", "content": user_input})
        _append_agent_message(redis, session_id, {"role": "user", "content": user_input})

    # 工具集按需裁剪:core 必有,任务关键词/历史使用触发 c2/webshell/mcp/exec 组
    # (config 传入:已启用 MCP server 时 mcp 组默认注入)
    tools_for_run = _select_agent_tools(user_input, _get_agent_messages(redis, session_id, limit=20), config)

    plan: List[str] = []
    last_cursor = time.time()
    if resume:
        # resume(如 HITL 批准后续跑):恢复上次保存的增量游标,否则注入后到挂起
        # 之间产生的事件会漏拉(游标重置到"现在"就看不见那段窗口)
        try:
            saved_cursor = _get_agent_state(redis, session_id).get("last_cursor")
            if saved_cursor:
                last_cursor = float(saved_cursor)
        except (TypeError, ValueError):
            pass
    did_tools = False
    last_failed = False
    interrupted = False
    for iteration in range(max_iterations):
        _set_agent_state(redis, session_id, {"status": "running", "iteration": iteration + 1})
        # 打断检查(轮次边界):立即停止当前任务
        if _consume_interrupt(session_id):
            interrupted = True
            _append_agent_message(redis, session_id, {"role": "system", "content": "[已打断] 用户打断了当前任务,停止推进并接入新指令。"})
            break
        # AI 自动审计 + 计划注入
        audit = _audit_summary(redis, session_id)
        system_content = _agent_system_prompt(prompt_suffix)
        if plan:
            steps = "\n".join(f"{i + 1}. {s}" for i, s in enumerate(plan))
            system_content += f"\n\n[执行计划] 请按以下步骤推进(已完成可跳过,完成后收工):\n{steps}"
        if audit:
            system_content += f"\n\n[你已执行的操作历史(请自我审查,避免重复/越界)]\n{audit}"
        messages[0] = {"role": "system", "content": system_content}
        # 上下文预算压缩
        messages = _compact_agent_messages(messages, context_max)

        resp = _call_llm_with_tools(ai_cfg, messages, tools_for_run)
        if not resp.get("ok"):
            err = resp.get("error", "")
            # 上下文溢出:激进压缩后重试一次
            if resp.get("context_overflow"):
                messages = _compact_agent_messages(messages, context_max // 2)
                resp = _call_llm_with_tools(ai_cfg, messages, tools_for_run)
            if not resp.get("ok"):
                err = resp.get("error", "") or err
                _append_agent_message(redis, session_id, {"role": "error", "content": err})
                _set_agent_state(redis, session_id, {"status": "error", "error": err})
                return
        tool_calls = resp.get("tool_calls") or []
        answer = resp.get("answer") or ""
        reasoning = resp.get("reasoning") or ""

        # Plan-Execute:plan_mode 首轮先要计划
        if plan_mode and not plan and not tool_calls:
            plan = _parse_plan(answer)
            if plan:
                _append_agent_message(redis, session_id, {"role": "assistant", "content": answer, "reasoning": reasoning})
                _append_agent_message(redis, session_id, {"role": "system", "content": f"计划已生成:共 {len(plan)} 步,开始执行。"})
                messages.append({"role": "assistant", "content": answer})
                messages.append({"role": "user", "content": "请开始执行计划第一步。"})
                continue

        if not tool_calls:
            # 终结判定
            dec = _finalize_agent_turn(answer, did_tools, last_failed)
            if dec["finalizable"]:
                _append_agent_message(redis, session_id, {"role": "assistant", "content": answer, "reasoning": reasoning})
                _finish_agent_loop(redis, session_id, ai_cfg, config, max_iterations, scan_gap_seconds,
                                   "done", iteration + 1, answer)
                return
            nudge = dec["nudge"]
            _append_agent_message(redis, session_id, {"role": "assistant", "content": answer, "reasoning": reasoning})
            _append_agent_message(redis, session_id, {"role": "system", "content": f"[终结判定:{dec['reason']}] {nudge}"})
            messages.append({"role": "assistant", "content": answer})
            messages.append({"role": "user", "content": nudge})
            continue

        # 打断检查(LLM 返回后、执行工具前):省掉即将执行的危险/耗时工具
        if _consume_interrupt(session_id):
            interrupted = True
            _append_agent_message(redis, session_id, {"role": "system", "content": "[已打断] 当前步骤的工具调用被跳过,接入新指令。"})
            break

        # 有 tool_calls:执行
        _append_agent_message(redis, session_id, {"role": "assistant", "content": answer, "tool_calls": tool_calls, "reasoning": reasoning})
        messages.append({"role": "assistant", "content": answer, "tool_calls": tool_calls})
        did_inject = False
        hitl_hit = False
        round_results: List[str] = []
        for call in tool_calls:
            if _consume_interrupt(session_id):
                interrupted = True
                _append_agent_message(redis, session_id, {"role": "system", "content": "[已打断] 剩余工具调用被跳过,接入新指令。"})
                break
            fn = call.get("function", {})
            name = fn.get("name", "")
            tool_call_id = call.get("id", "")
            # 软错误恢复:参数 JSON 解析失败转 LLM 可读错误,不静默
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except Exception:
                result = json.dumps({"ok": False,
                                     "error": f"[参数错误] 工具 {name} 的参数不是合法 JSON: {str(fn.get('arguments', ''))[:200]},请修正后重试。"},
                                    ensure_ascii=False)
            else:
                if name == "inject":
                    did_inject = True
                gate = approval_mode if name in _AGENT_DANGEROUS else "auto"
                if gate == "human":
                    # HITL:危险工具挂起等人工批准(存 tool_call_id,批准后补 tool 结果,故此处跳过 append)
                    pending_id = uuid.uuid4().hex[:12]
                    entry = {"pending_id": pending_id, "name": name, "args": args, "tool_call_id": tool_call_id, "ts": time.time()}
                    redis.conn.rpush(f"fs3:agent:session:{session_id}:pending", json.dumps(entry, ensure_ascii=False))
                    hitl_hit = True
                    continue
                if gate == "ai":
                    # AI 审批:先由安全审批员审核,通过才执行;失败一律拒绝(fail-closed)
                    t0 = time.time()
                    dec = _ai_approve_decision(redis, session_id, ai_cfg, name, args, user_input)
                    _audit_agent_action(redis, session_id, f"ai_approve:{name}",
                                        {"args": args, "decision": dec},
                                        json.dumps(dec, ensure_ascii=False),
                                        round(time.time() - t0, 2))
                    if dec.get("approved"):
                        _append_agent_message(redis, session_id, {"role": "system",
                                            "content": f"[AI 审批] 已批准 {name} — {dec.get('reason', '')}"})
                        result = _dispatch_agent_tool_safe(name, args, redis, session_id, config)
                    else:
                        result = json.dumps({"ok": False, "rejected": True, "approver": "ai",
                                             "reason": dec.get("reason", "")}, ensure_ascii=False)
                        _append_agent_message(redis, session_id, {"role": "system",
                                            "content": f"[AI 审批] 已拒绝 {name} — {dec.get('reason', '')}"})
                else:
                    result = _dispatch_agent_tool_safe(name, args, redis, session_id, config)
            # spill 溢出保护:大结果截断 + 存完整内容
            if len(result) > _SPILL_MAX:
                ref = f"spill_{int(time.time() * 1000)}"
                redis.conn.hset(f"fs3:agent:spill:{session_id}", ref, result)
                result = _truncate_for_context(result, _SPILL_MAX, ref)
            _append_agent_message(redis, session_id, {"role": "tool", "tool_call_id": tool_call_id, "name": name, "content": result})
            messages.append({"role": "tool", "tool_call_id": tool_call_id, "content": result})
            round_results.append(result)
        if interrupted:
            break
        did_tools = True
        last_failed = bool(round_results) and all(_tool_result_failed(r) for r in round_results)

        # HITL 挂起:暂停等人工批准
        if hitl_hit:
            _append_agent_message(redis, session_id, {"role": "system", "content": "检测到待人工批准的危险操作,已暂停。请在界面批准/拒绝后继续。"})
            _set_agent_state(redis, session_id, {"status": "awaiting_hitl", "iteration": iteration + 1})
            return

        if did_inject:
            time.sleep(scan_gap_seconds)
            new_events = _new_events_since(redis, last_cursor)
            last_cursor = time.time()
            _set_agent_state(redis, session_id, {"last_cursor": last_cursor})
            if new_events:
                summary = f"[调度器] 注入后新增 {len(new_events)} 个事件摘要:\n{_summarize_new_events(new_events)}"
                _append_agent_message(redis, session_id, {"role": "system", "content": summary})
                messages.append({"role": "user", "content": summary})
    # 收尾:被打断 → interrupted;正常撞上限 → blocked/done。队列有消息则续跑。
    if interrupted:
        _finish_agent_loop(redis, session_id, ai_cfg, config, max_iterations, scan_gap_seconds,
                           "interrupted", iteration + 1, "任务被用户打断")
    else:
        _finish_agent_loop(redis, session_id, ai_cfg, config, max_iterations, scan_gap_seconds,
                           "blocked" if did_tools else "done", max_iterations, "达到轮数上限",
                           tail_msg={"role": "assistant", "content": f"已达到最大轮数 {max_iterations},停止。"})


def _start_agent_task(redis: FlowScanRedis, session_id: str, user_input: str, ai_cfg: Dict[str, Any],
                      config: Optional[Dict[str, Any]] = None, resume: bool = False) -> None:
    """后台异步跑 agent 循环。"""
    max_iterations = int(ai_cfg.get("agent_max_iterations", 50) or 50)
    scan_gap_seconds = int(ai_cfg.get("agent_scan_gap_seconds", 5) or 5)

    def worker():
        with _AGENT_TASKS_LOCK:
            _AGENT_TASKS[session_id] = {"status": "running"}
        try:
            _run_agent_loop(redis, session_id, user_input, ai_cfg, config,
                            max_iterations=max_iterations, scan_gap_seconds=scan_gap_seconds, resume=resume)
        except Exception as exc:
            _set_agent_state(redis, session_id, {"status": "error", "error": str(exc)})
            _append_agent_message(redis, session_id, {"role": "error", "content": str(exc)})
        finally:
            with _AGENT_TASKS_LOCK:
                _AGENT_TASKS.pop(session_id, None)

    threading.Thread(target=worker, daemon=True).start()


def register(app):
    @app.route("/agent")
    @login_required
    def agent_page():
        return redirect(url_for("ai_analysis", tab="agent"))

    @app.route("/api/agent/session/create", methods=["POST"])
    @login_required
    def agent_session_create():
        redis = app.config["get_redis"]()
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        data = request.get_json(silent=True) or {}
        title = str(data.get("title", "") or "").strip() or "新会话"
        session = _create_agent_session(redis, title, ai_cfg.get("model", ""))
        return jsonify({"ok": True, "session": session})

    @app.route("/api/agent/sessions")
    @login_required
    def agent_sessions():
        redis = app.config["get_redis"]()
        return jsonify({"sessions": _list_agent_sessions(redis)})

    @app.route("/api/agent/run", methods=["POST"])
    @login_required
    def agent_run():
        redis = app.config["get_redis"]()
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        data = request.get_json(silent=True) or {}
        session_id = str(data.get("session_id", "") or request.form.get("session_id", ""))
        user_input = str(data.get("message", "") or request.form.get("message", "")).strip()
        mode = str(data.get("mode", "") or "").strip().lower() or "normal"
        if mode not in ("normal", "queue", "interrupt"):
            mode = "normal"
        if not session_id or not user_input:
            return jsonify({"ok": False, "error": "session_id/message 为空"}), 400
        if not _load_agent_session(redis, session_id):
            return jsonify({"ok": False, "error": "会话不存在"}), 404
        state_status = _get_agent_state(redis, session_id).get("status")
        with _AGENT_TASKS_LOCK:
            task_running = session_id in _AGENT_TASKS
        if task_running or state_status == "running":
            # 运行中:interrupt=打断并注入新指令;normal/queue=排队(回车=队列发送)。
            # 先入队再置打断标志:循环消费标志后总能取到该消息。
            _agent_queue_push(redis, session_id, user_input)
            if mode == "interrupt":
                _request_interrupt(session_id)
            return jsonify({"ok": True, "queued": True,
                            "interrupted": mode == "interrupt",
                            "queue_length": _agent_queue_len(redis, session_id)})
        if state_status == "awaiting_hitl":
            if mode in ("queue", "interrupt"):
                # 人工审批挂起中:新指令排队,批准完成后按打断标志优先接入
                _agent_queue_push(redis, session_id, user_input)
                if mode == "interrupt":
                    _request_interrupt(session_id)
                return jsonify({"ok": True, "queued": True,
                                "interrupted": mode == "interrupt",
                                "queue_length": _agent_queue_len(redis, session_id)})
            return jsonify({"ok": False, "error": "存在待人工批准的危险操作，请先在界面批准/拒绝后再继续"}), 400
        # 空闲/完成/被打断/出错 → 开新任务(清掉残留打断标记)
        with _AGENT_INTERRUPT_LOCK:
            _AGENT_INTERRUPT.pop(session_id, None)
        _start_agent_task(redis, session_id, user_input, ai_cfg, config)
        return jsonify({"ok": True, "session_id": session_id})

    @app.route("/api/agent/session/<session_id>/state")
    @login_required
    def agent_session_state(session_id: str):
        redis = app.config["get_redis"]()
        return jsonify(_get_agent_state(redis, session_id))

    @app.route("/api/agent/session/<session_id>/messages")
    @login_required
    def agent_session_messages(session_id: str):
        redis = app.config["get_redis"]()
        messages = _get_agent_messages(redis, session_id, limit=200)
        after = request.args.get("after", "")
        if after:
            try:
                after_ts = float(after)
                messages = [m for m in messages if float(m.get("ts", 0)) > after_ts]
            except ValueError:
                pass
        return jsonify({"messages": messages, "state": _get_agent_state(redis, session_id)})

    @app.route("/api/agent/session/<session_id>/audit")
    @login_required
    def agent_session_audit(session_id: str):
        redis = app.config["get_redis"]()
        raw = redis.conn.lrange(f"fs3:agent:session:{session_id}:audit", 0, -1)
        entries = [json.loads(x) for x in raw if x.strip()]
        return jsonify({"audit": entries})

    @app.route("/api/agent/session/<session_id>/pending")
    @login_required
    def agent_session_pending(session_id: str):
        redis = app.config["get_redis"]()
        raw = redis.conn.lrange(f"fs3:agent:session:{session_id}:pending", 0, -1)
        entries = [json.loads(x) for x in raw if x.strip()]
        return jsonify({"pending": entries})

    @app.route("/api/agent/session/<session_id>/hitl", methods=["POST"])
    @login_required
    def agent_session_hitl(session_id: str):
        redis = app.config["get_redis"]()
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        data = request.get_json(silent=True) or {}
        action = str(data.get("action", "") or "")
        pending_id = str(data.get("pending_id", "") or "")
        if action not in ("approve", "reject") or not pending_id:
            return jsonify({"ok": False, "error": "action/pending_id 无效"}), 400
        raw = redis.conn.lrange(f"fs3:agent:session:{session_id}:pending", 0, -1)
        target = None
        rest = []
        for x in raw:
            try:
                e = json.loads(x)
            except Exception:
                continue
            if e.get("pending_id") == pending_id:
                target = e
            else:
                rest.append(x)
        if target is None:
            return jsonify({"ok": False, "error": "待批准请求不存在或已处理"}), 404
        redis.conn.delete(f"fs3:agent:session:{session_id}:pending")
        for x in rest:
            redis.conn.rpush(f"fs3:agent:session:{session_id}:pending", x)
        name = target.get("name", "")
        args = target.get("args", {})
        tool_call_id = target.get("tool_call_id", "")
        if action == "approve":
            result = _dispatch_agent_tool_safe(name, args, redis, session_id, config)
            if len(result) > _SPILL_MAX:
                ref = f"spill_{int(time.time() * 1000)}"
                redis.conn.hset(f"fs3:agent:spill:{session_id}", ref, result)
                result = _truncate_for_context(result, _SPILL_MAX, ref)
            _append_agent_message(redis, session_id, {"role": "tool", "tool_call_id": tool_call_id, "name": name, "content": result})
            note = f"已批准执行 {name}"
        else:
            result = json.dumps({"ok": False, "rejected": True, "message": f"人工拒绝了 {name} 操作"}, ensure_ascii=False)
            _append_agent_message(redis, session_id, {"role": "tool", "tool_call_id": tool_call_id, "name": name, "content": result})
            note = f"已拒绝 {name}"
        _append_agent_message(redis, session_id, {"role": "system", "content": note + ",继续。"})
        _set_agent_state(redis, session_id, {"status": "running"})
        _start_agent_task(redis, session_id, "", ai_cfg, config, resume=True)
        return jsonify({"ok": True, "action": action, "tool": name})

    @app.route("/api/agent/session/<session_id>/delete", methods=["POST"])
    @login_required
    def agent_session_delete(session_id: str):
        redis = app.config["get_redis"]()
        return jsonify({"ok": _delete_agent_session(redis, session_id)})
