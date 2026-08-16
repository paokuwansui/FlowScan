"""AI 日志路由:event-logs(事件日记 + API 模式)与 ai-logs 兼容重定向。

_ai_log_entry 是 AI 日志的落库函数,被 ai_analysis(执行 log 动作)与
agent(log 工具)共享。
"""
import json
import time
import uuid
from datetime import datetime
from typing import Any, Dict

from flask import jsonify, redirect, render_template, request, session as flask_session, url_for

from flowscan.config import load_yaml

from ._common import _json_or_raw
from ._helpers import _children_fps, _event_path, _strip_internal_fields
from .ai_config import _ai_config


def _ai_log_entry(redis: Any, action: Dict[str, Any], source: str = "manual", schedule_id: str = "") -> Dict[str, Any]:
    """存储一条 AI 日志到 Redis。"""
    log_id = uuid.uuid4().hex[:12]
    now = time.time()
    entry = {
        "log_id": log_id,
        "level": str(action.get("level", "info")),
        "message": str(action.get("message", "")),
        "target": str(action.get("target", "")),
        "priority": str(action.get("priority", "medium")),
        "source": source,
        "schedule_id": schedule_id,
        "created_at": now,
        "created_at_iso": datetime.fromtimestamp(now).isoformat(),
    }
    pipe = redis.conn.pipeline()
    pipe.hset(f"fs3:ai:log:{log_id}", mapping={k: json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v for k, v in entry.items()})
    pipe.zadd("fs3:ai:logs", {log_id: now})
    pipe.execute()
    redis.log(f"[AI] log {log_id}: {entry['message'][:120]}")
    return entry


def register(app):
    @app.route("/event-logs")
    def event_logs():
        """事件日记路由:支持浏览器查看(HTML)和 API 密钥访问(JSON)。

        API 参数:
          ?api_key=xxx               → 返回 AI 分析日志 JSON
          ?api_key=xxx&mode=events   → 返回扫描事件列表
          ?api_key=xxx&mode=events&type=DNS_NAME&search=xxx  → 筛选
          ?api_key=xxx&mode=stats    → 返回事件类型统计
        """
        api_key = request.args.get("api_key", "") or request.headers.get("X-API-Key", "")
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        log_api_key = ai_cfg.get("log_api_key", "")
        is_api = bool(api_key and log_api_key and api_key == log_api_key)
        is_web = flask_session.get("logged_in", False)
        if not is_api and not is_web:
            if api_key:
                return jsonify({"error": "unauthorized", "message": "Invalid API key"}), 401
            return redirect(url_for("login"))

        redis = app.config["get_redis"]()
        mode = request.args.get("mode", "")
        fmt = request.args.get("format", "html" if is_web else "json")

        # ── mode=events: 返回扫描事件 ──
        if mode == "events":
            event_type = request.args.get("type", "")
            search_term = request.args.get("search", "").strip().lower()
            fp = request.args.get("fp", "").strip()
            if fp:
                evt = redis.get_event(fp)
                path = _event_path(redis, fp) if evt else []
                children = _children_fps(redis, fp)
                return jsonify({
                    "event": _strip_internal_fields(evt),
                    "path": [_strip_internal_fields(e) for e in path],
                    "children": children,
                })
            # 时间索引分页（硬上限 2000 条），避免全量集合扫描
            key = f"fs3:events:time:{event_type}" if event_type else "fs3:event:time"
            fps = list(redis.conn.zrevrange(key, 0, 1999) or [])
            pipe = redis.conn.pipeline()
            for fp in fps:
                pipe.hgetall(f"fs3:event:{fp}")
            raw_events = [e for e in pipe.execute() if e]
            events = []
            for evt in raw_events:
                if search_term and search_term not in (evt.get("value") or "").lower():
                    continue
                events.append(_strip_internal_fields(evt))
            events.sort(key=lambda e: float(e.get("created_at") or 0), reverse=True)
            return jsonify({"mode": "events", "count": len(events),
                            "truncated": len(fps) >= 2000, "events": events})

        # ── mode=stats: 返回事件统计 ──
        if mode == "stats":
            stats = {}
            for k, v in (redis.conn.hgetall("fs3:stats:event_type") or {}).items():
                stats[k] = int(v or 0)
            return jsonify({"mode": "stats", "stats": stats})

        # ── 默认: AI 分析日志 ──
        log_ids = redis.conn.zrevrange("fs3:ai:logs", 0, 500)
        entries = []
        for lid in log_ids:
            raw = redis.conn.hgetall(f"fs3:ai:log:{lid}")
            if raw:
                entry = {k: _json_or_raw(v) for k, v in raw.items()}
                entries.append(entry)

        if fmt == "json" or is_api:
            return jsonify({"count": len(entries), "logs": entries})

        return render_template("event_logs.html", logs=entries, count=len(entries),
                               log_api_key=ai_cfg.get("log_api_key", ""),
                               log_tab=request.args.get("tab", "ai"))

    @app.route("/ai-logs")
    def ai_logs():
        """兼容旧路由，重定向到 /event-logs"""
        return redirect(url_for("event_logs", **dict(request.args)))
