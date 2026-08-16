"""LLM OpenAI 兼容 /chat/completions 统一调用核心(含重试与上下文溢出检测)。

被 ai_core(手动分析/定时任务)与 agent(Agent 循环/AI 审批)共用,
消除两处重复的 HTTP 调用与重试逻辑:瞬时网络抖动/429/5xx 自动指数退避重试。
"""

import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

# 思考强度枚举(off=不传思考参数,保持原行为;low/medium/high 对应 reasoning_effort)
_REASONING_EFFORTS = ("off", "low", "medium", "high")


def _apply_reasoning_effort(body: Dict[str, Any], ai_cfg: Dict[str, Any]) -> None:
    """按 reasoning_effort 配置向请求 body 注入思考参数(就地修改)。

    off → 不传任何思考参数(与旧行为完全一致);
    low/medium/high → 传 OpenAI 标准 reasoning_effort + deepseek V3.1+ 的 thinking 开关
    (两者都认识的端点取其一,互相兼容;不认识的端点一般忽略未知字段)。
    """
    effort = str(ai_cfg.get("reasoning_effort") or "off").strip().lower()
    if effort in ("low", "medium", "high"):
        body["reasoning_effort"] = effort
        body["thinking"] = {"type": "enabled"}


def _is_context_overflow_error(msg: str) -> bool:
    """检测 LLM API 的上下文溢出类错误。"""
    if not msg:
        return False
    low = msg.lower()
    markers = ("context length", "maximum context", "max context", "context window", "context overflow",
               "too many tokens", "token limit", "tokens exceed", "exceeds the context",
               "input is too long", "prompt is too long", "request too large")
    return any(m in low for m in markers)


def llm_chat_completions(
    ai_cfg: Dict[str, Any],
    messages: List[Dict[str, Any]],
    tools: Optional[List[Dict[str, Any]]] = None,
    temperature: float = 0.2,
) -> Dict[str, Any]:
    """调用 OpenAI 兼容 /chat/completions,含 429/5xx/网络抖动指数退避重试。

    tools 为 None 时是普通对话(AI 审批/手动分析用),否则带 function calling(Agent 循环用)。

    返回:
      成功: {"ok": True, "answer", "tool_calls", "reasoning", "raw", "model"}
      失败: {"ok": False, "error", "context_overflow": bool}
    """
    base_url = ai_cfg.get("base_url", "")
    api_key = ai_cfg.get("api_key", "")
    model = ai_cfg.get("model", "")
    if not base_url or not api_key or api_key.startswith("YOUR_"):
        return {"ok": False, "error": "AI 配置不完整,请在 config.yaml 的 ai_analysis 中配置 base_url/api_key/model。"}
    url = base_url.rstrip("/") + "/chat/completions"
    body = {"model": model, "messages": messages, "temperature": temperature}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    _apply_reasoning_effort(body, ai_cfg)
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    timeout = int(ai_cfg.get("timeout_seconds", 120))
    retries = 3
    last_err = ""
    for attempt in range(retries):
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
            msg = parsed.get("choices", [{}])[0].get("message", {})
            return {
                "ok": True,
                "answer": msg.get("content") or "",
                "tool_calls": msg.get("tool_calls") or [],
                "reasoning": msg.get("reasoning_content") or "",
                "raw": parsed,
                "model": model,
            }
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
            last_err = f"HTTP {exc.code}: {detail[:2000]}"
            if exc.code in (429, 500, 502, 503, 504):
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
            if _is_context_overflow_error(detail):
                return {"ok": False, "error": last_err, "context_overflow": True}
            return {"ok": False, "error": last_err}
        except Exception as exc:
            last_err = str(exc)
            low = last_err.lower()
            if any(k in low for k in ("timeout", "timed out", "connection", "reset", "refused", "temporarily")):
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
            return {"ok": False, "error": last_err}
    return {"ok": False, "error": last_err}
