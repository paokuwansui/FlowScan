"""AI 分析执行核心:分析请求 → LLM 调用 → 动作解析 → 动作执行。

被 ai_analysis(页面路由)与 ai_schedule(定时任务)共享,只依赖 ai_config /
ai_logs / helpers / filter,不依赖任何路由模块,避免循环导入。
"""
import json
import re
import threading
import uuid
from typing import Any, Dict, List, Tuple

from flowscan.filter import _fingerprint, add_redis_rule, delete_redis_rule
from flowscan.llm import llm_chat_completions
from flowscan.redis_store import FlowScanRedis

from ._common import _json_or_raw, _to_int
from ._helpers import _list_events, _remove_event
from .ai_logs import _ai_log_entry


def _default_ai_toggles() -> Dict[str, bool]:
    """动作自动执行开关：勾选=分析完成后自动执行该类型动作；不勾选=进入预览审核列表。默认全不勾选。"""
    return {"add": False, "del": False, "del_children": False,
            "blacklist_add": False, "blacklist_del": False, "log": False}


def _analysis_request_from_form(form: Any, ai_cfg: Dict[str, Any]) -> Tuple[List[str], str, int, Dict[str, bool]]:
    selected_types = [item.strip() for item in form.getlist("event_types") if item.strip()]
    question = form.get("question", "").strip()
    max_events = _to_int(form.get("max_events"), int(ai_cfg.get("max_events", 5000)))
    toggles = {
        "add": form.get("toggle_add") == "1",
        "del": form.get("toggle_del") == "1",
        "del_children": form.get("toggle_del_children") == "1",
        "blacklist_add": form.get("toggle_blacklist_add") == "1",
        "blacklist_del": form.get("toggle_blacklist_del") == "1",
        "log": form.get("toggle_log") == "1",
    }
    return selected_types, question, max_events, toggles


def _run_ai_analysis_once(
    redis: FlowScanRedis,
    ai_cfg: Dict[str, Any],
    selected_types: List[str],
    question: str,
    max_events: int,
    toggles: Dict[str, bool],
    run_source: str = "manual",
    schedule_id: str = "",
    dry_run: bool = False,
) -> Dict[str, Any]:
    context_events = _events_for_ai(redis, selected_types, max_events)
    result = _call_ai_analysis(ai_cfg, selected_types, context_events, question, redis)
    parsed_actions: List[Dict[str, Any]] = []
    action_results: List[Dict[str, Any]] = []
    if result and result.get("ok") and result.get("answer"):
        parsed_actions = _parse_ai_actions(result["answer"])
        if parsed_actions and not dry_run:
            action_results = _execute_ai_actions(parsed_actions, redis, toggles, source=run_source, schedule_id=schedule_id)
        result["action_results"] = action_results
        result["action_count"] = len(action_results)
        result["parsed_action_count"] = len(parsed_actions)
    return {
        "result": result,
        "context_events": context_events,
        "parsed_actions": parsed_actions,
        "action_results": action_results,
    }


# 后台 AI 分析任务表(web 单进程内存态;task_id -> 状态)
_AI_TASKS: Dict[str, Dict[str, Any]] = {}
_AI_TASKS_LOCK = threading.Lock()


def _start_ai_task(
    redis: FlowScanRedis,
    ai_cfg: Dict[str, Any],
    selected_types: List[str],
    question: str,
    max_events: int,
    toggles: Dict[str, bool],
) -> str:
    """后台异步跑一次 AI 分析。

    新语义：toggles 即"自动执行开关"——勾选的类型在解析完成后立即自动执行；
    未勾选的类型保留在 parsed_actions 里进入预览审核列表，由用户点"一键执行"落地。
    """
    task_id = uuid.uuid4().hex[:12]
    with _AI_TASKS_LOCK:
        _AI_TASKS[task_id] = {
            "status": "running",
            "result": None,
            "parsed_actions": [],
            "context_events": [],
            "toggles": toggles,
            "executed": False,
            "auto_action_results": [],
            "action_results": [],
        }

    def worker() -> None:
        try:
            run_data = _run_ai_analysis_once(
                redis, ai_cfg, selected_types, question, max_events, toggles,
                run_source="manual", dry_run=True,
            )
            result = run_data["result"] or {}
            parsed_actions = run_data["parsed_actions"]
            auto_results: List[Dict[str, Any]] = []
            remaining: List[Dict[str, Any]] = []
            if result.get("ok") and parsed_actions:
                # 勾选的类型 → 自动执行；未勾选 → 进预览审核列表
                auto_actions = [a for a in parsed_actions if toggles.get(a.get("type"))]
                remaining = [a for a in parsed_actions if not toggles.get(a.get("type"))]
                if auto_actions:
                    auto_view = {**toggles,
                                 **{t: True for t in ("add", "del", "blacklist_add", "blacklist_del", "log")}}
                    auto_results = _execute_ai_actions(auto_actions, redis, auto_view, source="manual")
            with _AI_TASKS_LOCK:
                _AI_TASKS[task_id] = {
                    "status": "done",
                    "result": result,
                    "parsed_actions": remaining,
                    "context_events": run_data["context_events"],
                    "toggles": toggles,
                    "executed": False,
                    "auto_action_results": auto_results,
                    "action_results": [],
                }
        except Exception as exc:
            with _AI_TASKS_LOCK:
                _AI_TASKS[task_id] = {"status": "error", "error": str(exc)}

    threading.Thread(target=worker, daemon=True).start()
    return task_id


def _events_for_ai(redis: FlowScanRedis, event_types: List[str], max_events: int) -> List[Dict[str, Any]]:
    max_events = max(1, min(max_events, 5000))
    events = []
    for event_type in event_types:
        events.extend(_list_events(redis, event_type=event_type, limit=max_events))
    events.sort(key=lambda item: float(item.get("created_at") or 0), reverse=True)
    return events[:max_events]


def _format_value_for_ai(event_type: str, value: str) -> str:
    """为 AI 上下文格式化事件 value。SCREENSHOT/ICON 事件 value 含 base64,剥离 b64 只留 url/path。"""
    if event_type in ("SCREENSHOT", "ICON"):
        try:
            data = json.loads(value)
            return f"url={data.get('url', '')} path={data.get('path', '')}"
        except Exception:
            return value[:200]
    return value


def _format_context_for_ai(events: List[Dict[str, Any]], redis: Any) -> str:
    lines = []
    for index, event in enumerate(events, 1):
        created = event.get("created_at") or event.get("timestamp") or ""
        event_type = event.get("event_type", "")
        value = _format_value_for_ai(event_type, event.get("value", ""))
        lines.append(
            f"{index}. type={event_type} value={value} "
            f"source={event.get('source_tool', '')} parent={event.get('parent_fp', '')[:12]} "
            f"root={event.get('root_fp', '')[:12]} fp={event.get('fingerprint', '')[:12]} created_at={created}"
        )
    # 追加最近 AI 日志摘要（供 AI 参考，避免重复）
    lines.append("")
    lines.append("最近 AI 分析日志（供参考，相同事件/结论无需重复记录）：")
    recent_ids = redis.conn.zrevrange("fs3:ai:logs", 0, 49) if redis else []
    appended = 0
    for lid in recent_ids:
        raw = redis.conn.hgetall(f"fs3:ai:log:{lid}")
        if not raw:
            continue
        p = str(raw.get("priority", "medium"))
        msg = _json_or_raw(raw.get("message", ""))
        target = _json_or_raw(raw.get("target", ""))
        msg_str = str(msg)[:120] if msg else "-"
        tgt_str = str(target)[:80] if target else "-"
        lines.append(f"- [{p}] {msg_str} | target={tgt_str}")
        appended += 1
    if not appended:
        lines.append("  （暂无历史日志）")
    return "\n".join(lines) if lines else "未找到所选事件类型的事件。"


def _call_ai_analysis(ai_cfg: Dict[str, Any], selected_types: List[str], events: List[Dict[str, Any]], question: str, redis: Any = None) -> Dict[str, Any]:
    base_url = ai_cfg.get("base_url", "")
    api_key = ai_cfg.get("api_key", "")
    model = ai_cfg.get("model", "")
    if not base_url or not api_key or api_key.startswith("YOUR_"):
        return {"ok": False, "error": "AI 配置不完整，请在 config.yaml 的 ai_analysis 中配置 base_url/api_key/model。"}
    user_content = (
        "用户问题：\n"
        f"{question}\n\n"
        "已选择事件类型：\n"
        f"{', '.join(selected_types)}\n\n"
        "事件日志上下文：\n"
        f"{_format_context_for_ai(events, redis)}"
    )
    messages = [
        {"role": "system", "content": ai_cfg.get("system_prompt", "")},
        {"role": "user", "content": user_content},
    ]
    # 统一 LLM 调用核心(flowscan.llm):含 429/5xx/网络抖动指数退避重试,
    # 与 Agent 循环(_llm_chat)行为一致,瞬时故障不再直接失败。
    result = llm_chat_completions(ai_cfg, messages)
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error", ""), "event_count": len(events), "model": model}
    return {"ok": True, "answer": result.get("answer", ""), "raw": result.get("raw"),
            "event_count": len(events), "model": model}


_ACTION_ALIASES = {
    "delete": "del", "remove": "del", "remove_event": "del",
    "add_event": "add", "inject": "add",
    "block": "blacklist_add", "blacklist": "blacklist_add",
    "unblock": "blacklist_del", "blacklist_remove": "blacklist_del",
    "note": "log", "record": "log",
}


def _repair_json(text: str) -> Any:
    """轻量修复常见 JSON 语法错误(去 BOM、去尾逗号、截取首 { 到末 })。失败返回 None。"""
    t = text.strip().lstrip("\ufeff").strip()
    if not t:
        return None
    start, end = t.find("{"), t.rfind("}")
    if start != -1 and end != -1 and end > start:
        t = t[start:end + 1]
    t = re.sub(r",\s*([}\]])", r"\1", t)  # 去尾逗号
    try:
        return json.loads(t)
    except Exception:
        return None


def _parse_ai_actions(text: str) -> List[Dict[str, Any]]:
    """从 AI 回答文本中提取结构化动作。优先读 ```json 代码块,兼容纯 JSON,并做类型别名归一与 JSON 修复。"""
    candidates = re.findall(r"```json\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)
    for block in candidates:
        parsed = _repair_json(block)
        if not isinstance(parsed, dict) or not isinstance(parsed.get("actions"), list):
            continue
        actions: List[Dict[str, Any]] = []
        for action in parsed["actions"]:
            if not isinstance(action, dict):
                continue
            atype = str(action.get("type", "")).strip().lower()
            atype = _ACTION_ALIASES.get(atype, atype)
            if atype in ("add", "del", "blacklist_add", "blacklist_del", "log"):
                action["type"] = atype
                actions.append(action)
        if actions:
            return actions
    return []


def _execute_ai_actions(
    actions: List[Dict[str, Any]],
    redis: Any,
    toggles: Dict[str, bool],
    source: str = "manual",
    schedule_id: str = "",
) -> List[Dict[str, Any]]:
    """执行 AI 动作列表，返回执行结果。

    toggles 控制是否执行对应类型。动作固定按 del -> blacklist_del -> blacklist_add -> add -> log 五段执行，
    避免 AI 同一轮同时删除和新增时，新事件被旧删除动作误伤；AI 新增事件不带
    parent/root 参数，始终作为根事件入队运行。
    """
    results = []
    ordered_actions = [
        action
        for action_type in ("del", "blacklist_del", "blacklist_add", "add", "log")
        for action in actions
        if action.get("type", "") == action_type
    ]
    remove_children = bool(toggles.get("del_children", True))
    for action in ordered_actions:
        atype = action.get("type", "")
        if atype not in ("add", "del", "blacklist_add", "blacklist_del", "log"):
            continue
        if not toggles.get(atype, True):
            results.append({"ok": True, "type": atype, "note": "开关未勾选，已跳过", "skipped": True})
            continue
        if atype == "add":
            event_type = str(action.get("event_type", "")).strip()
            value = str(action.get("value", "")).strip()
            if event_type and value:
                existed = bool(redis.conn.sismember("fs3:event:set", FlowScanRedis.fingerprint(event_type, value)))
                # AI 新增事件一律作为根事件运行，不继承任何父事件关系。
                fp = redis.push_event(event_type, value, source_tool="ai_analysis")
                results.append({"ok": True, "type": "add", "event_type": event_type, "value": value, "fp": (fp or "")[:16], "note": "已注入队列" if not existed else "重复事件"})
            else:
                results.append({"ok": False, "type": "add", "event_type": event_type, "value": value, "note": "缺少 event_type 或 value"})
        elif atype == "del":
            event_type = str(action.get("event_type", "")).strip()
            value = str(action.get("value", "")).strip()
            fp = str(action.get("fingerprint", "") or "").strip()
            if not fp and event_type and value:
                fp = FlowScanRedis.fingerprint(event_type, value)
            removed = _remove_event(redis, fp, remove_children=remove_children) if fp else 0
            if removed:
                note = f"已级联移除 {removed} 个事件" if remove_children else "已移除 1 个事件"
            else:
                note = "未找到"
            results.append({"ok": True, "type": "del", "event_type": event_type, "value": value, "removed": removed, "remove_children": remove_children, "note": note})
        elif atype == "blacklist_add":
            bl_et = str(action.get("event_type", "")).strip()
            bl_mm = str(action.get("match_mode", "")).strip()
            bl_val = str(action.get("value", "")).strip()
            bl_comment = str(action.get("comment", "")).strip()
            if not bl_et or not bl_val or bl_mm not in ("contains", "suffix", "prefix", "ip_range"):
                results.append({"ok": False, "type": "blacklist_add", "note": "event_type/value 为空或 match_mode 无效"})
            else:
                fp = add_redis_rule(redis, bl_et, bl_mm, bl_val, bl_comment)
                if fp:
                    results.append({"ok": True, "type": "blacklist_add", "event_type": bl_et, "match_mode": bl_mm, "value": bl_val, "fp": fp[:16], "note": "已添加"})
                else:
                    results.append({"ok": False, "type": "blacklist_add", "event_type": bl_et, "match_mode": bl_mm, "value": bl_val, "note": "规则已存在"})
        elif atype == "blacklist_del":
            bl_et = str(action.get("event_type", "")).strip()
            bl_mm = str(action.get("match_mode", "")).strip()
            bl_val = str(action.get("value", "")).strip()
            if not bl_et or not bl_val:
                results.append({"ok": False, "type": "blacklist_del", "note": "event_type 或 value 为空"})
            else:
                bl_fp = _fingerprint(bl_et, bl_mm, bl_val)
                ok = delete_redis_rule(redis, bl_fp)
                results.append({"ok": ok, "type": "blacklist_del", "event_type": bl_et, "match_mode": bl_mm, "value": bl_val, "deleted": ok, "note": "已删除" if ok else "未找到"})
        elif atype == "log":
            entry = _ai_log_entry(redis, action, source=source, schedule_id=schedule_id)
            results.append({"ok": True, "type": "log", "log_id": entry.get("log_id", ""), "note": "已存储"})
    return results
