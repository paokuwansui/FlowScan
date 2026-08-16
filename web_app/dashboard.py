"""仪表盘 + 监控路由:index / nodes / flow / stats / logs / redis-cmd / event-tree / event-query。"""
import re
import time
from math import ceil
from typing import Any, Dict, List

from flask import Response, flash, jsonify, redirect, render_template, request, url_for

from ._common import _json_or_raw, _safe_ping, _to_int, login_required
from ._helpers import (
    _active_nodes,
    _count_events,
    _event_path,
    _event_types,
    _execution_flow_graph,
    _list_events,
    _queue_stats,
    _tool_registry,
)


_LOG_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (.*)$")


def _log_level_class(line: str) -> str:
    """按日志行内容推断级别样式类（供 logs 页着色）。"""
    low = (line or "").lower()
    if any(k in low for k in ("error", "fatal", "traceback", "failed", "失败", "异常")):
        return "log-level-error"
    if any(k in low for k in ("warn", "deprecat", "跳过")):
        return "log-level-warn"
    if "[ai" in low or "[agent" in low:
        return "log-level-ai"
    if any(k in low for k in ("[event]", "[tool]", "[worker]", "[web]", "[blacklist", "[whitelist")):
        return "log-level-info"
    return ""


def register(app):
    @app.route("/")
    @login_required
    def index():
        redis = app.config["get_redis"]()
        redis_ok = _safe_ping(redis)
        queue_stats: List[Dict[str, Any]] = []
        event_count = node_count = tool_count = 0
        if redis_ok:
            event_count = int(redis.conn.scard("fs3:event:all") or 0)
            node_count = len(_active_nodes(redis))
            tools = _tool_registry(redis)
            tool_count = len(tools)
            queue_stats = _queue_stats(redis, app.config["MODULES_DIR"], tools)
        return render_template(
            "index.html",
            redis_ok=redis_ok,
            queue_stats=queue_stats,
            event_count=event_count,
            node_count=node_count,
            tool_count=tool_count,
        )

    @app.route("/logs")
    @login_required
    def logs():
        redis = app.config["get_redis"]()
        raw_limit = str(request.args.get("limit", "200")).strip().lower()
        if raw_limit == "all":
            limit: Any = "all"
            raw_logs = redis.conn.lrange("fs3:logs", 0, -1)
        else:
            limit = _to_int(raw_limit, 200)
            raw_logs = redis.conn.lrange("fs3:logs", 0, int(limit) - 1)
        # 日志行自带 'YYYY-MM-DD HH:MM:SS' 前缀(redis_store.log 写入),拆出作为时间列,
        # 消息正文不再重复携带时间戳
        logs_data = []
        for line in raw_logs:
            m = _LOG_TS_RE.match(line)
            if m:
                logs_data.append({"ts": m.group(1), "msg": m.group(2), "level_class": _log_level_class(line)})
            else:
                logs_data.append({"ts": "", "msg": line, "level_class": _log_level_class(line)})
        return render_template("logs.html", logs=logs_data, limit=limit)

    @app.route("/logs/download")
    @login_required
    def logs_download():
        redis = app.config["get_redis"]()
        raw_limit = str(request.args.get("limit", "10000")).strip().lower()
        if raw_limit == "all":
            raw_logs = redis.conn.lrange("fs3:logs", 0, -1)
        else:
            limit = _to_int(raw_limit, 10000)
            raw_logs = redis.conn.lrange("fs3:logs", 0, limit - 1)
        text = "\n".join(raw_logs)
        from datetime import datetime
        filename = f"flowscan_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        return Response(text, mimetype="text/plain; charset=utf-8", headers={"Content-Disposition": f"attachment; filename={filename}"})

    @app.route("/nodes")
    @login_required
    def nodes():
        redis = app.config["get_redis"]()
        return render_template("nodes.html", nodes=_active_nodes(redis), tools=_tool_registry(redis))

    @app.route("/event-tree")
    @login_required
    def event_tree():
        redis = app.config["get_redis"]()
        # 直接读根事件索引（parent 为空的事件），不再依赖"最近 N 条中过滤无父"
        # ——子事件海量时根事件会沉到时间窗之外导致图谱只剩极少数根。
        fps, _total = redis.recent_root_fps(limit=200, offset=0)
        roots = []
        if fps:
            pipe = redis.conn.pipeline()
            for fp in fps:
                pipe.hgetall(f"fs3:event:{fp}")
            roots = [e for e in pipe.execute() if e]
        roots.sort(key=lambda item: float(item.get("created_at") or 0), reverse=True)
        return render_template("event_tree.html", roots=roots)

    @app.route("/api/event-tree/children/<fingerprint>")
    @login_required
    def event_tree_children(fingerprint: str):
        redis = app.config["get_redis"]()
        children: List[Dict[str, Any]] = []
        for fp in (redis.conn.smembers(f"fs3:children:{fingerprint}") or []):
            event = redis.get_event(fp)
            if event:
                children.append(event)
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for child in children:
            groups.setdefault(child.get("event_type", "?"), []).append(child)
        return jsonify([
            {
                "event_type": event_type,
                "count": len(items),
                "events": [
                    {
                        "value": item.get("value", ""),
                        "fp": item.get("fingerprint", ""),
                        "source": item.get("source_tool", ""),
                        "tool": item.get("source_tool", ""),
                    }
                    for item in sorted(items, key=lambda item: float(item.get("created_at") or 0), reverse=True)
                ],
            }
            for event_type, items in sorted(groups.items())
        ])

    @app.route("/api/event-tree/search")
    @login_required
    def event_tree_search():
        query = request.args.get("value", "").strip().lower()
        if not query:
            return jsonify([])
        redis = app.config["get_redis"]()
        matches = []
        for event in _list_events(redis, limit=1000):   # 硬上限：只搜最近 1000 条
            if query in (event.get("value") or "").lower():
                matches.append({
                    "fp": event.get("fingerprint", ""),
                    "event_type": event.get("event_type", ""),
                    "value": event.get("value", ""),
                    "source_tool": event.get("source_tool", ""),
                    "tool_name": event.get("source_tool", ""),
                })
                if len(matches) >= 50:
                    break
        return jsonify(matches)

    @app.route("/api/events/recursive-children")
    @login_required
    def events_recursive_children():
        redis = app.config["get_redis"]()
        fp = request.args.get("fp", "").strip()
        if not fp:
            return jsonify({"ok": False, "error": "fp 不能为空"})
        if not redis.get_event(fp):
            return jsonify({"ok": False, "error": "事件不存在"})
        data = redis.get_recursive_children(fp)
        return jsonify({"ok": True, **data})

    @app.route("/event-query")
    @login_required
    def event_query():
        redis = app.config["get_redis"]()
        event_types = _event_types(redis)
        selected_type = request.args.get("type", "")
        search_term = request.args.get("search", "").strip()
        path_fp = request.args.get("path", "").strip()
        path_data = _event_path(redis, path_fp) if path_fp else None
        # 游标分页:每页 50,类型浏览与搜索结果共用
        per_page = 50
        page = max(1, _to_int(request.args.get("page"), 1))
        type_values = []
        total_values = 0
        total_pages = 0
        if selected_type and not search_term:
            total_values = _count_events(redis, selected_type)
            total_pages = max(1, ceil(total_values / per_page))
            page = min(page, total_pages)
            type_values = [
                {
                    "value": event.get("value", ""),
                    "fp": event.get("fingerprint", ""),
                    "source": event.get("source_tool", ""),
                    "time": event.get("created_at", 0),
                }
                for event in _list_events(redis, event_type=selected_type, limit=per_page, offset=(page - 1) * per_page)
            ]
        search_results = []
        search_total = 0
        # 搜索窗口:选中类型时放大(单类型时间索引 zrevrange 开销小),
        # 未选类型时保持全类型 1000 条硬上限,避免全量集合扫描。
        # 分页基于窗口内过滤结果,窗口越大搜索结果越完整。
        search_window = 0
        if search_term:
            term = search_term.lower()
            all_results = []
            if selected_type:
                search_window = 5000
                for event in _list_events(redis, event_type=selected_type, limit=search_window):
                    value = event.get("value", "")
                    if term in value.lower():
                        all_results.append({
                            "value": value,
                            "fp": event.get("fingerprint", ""),
                            "type": event.get("event_type", ""),
                            "source": event.get("source_tool", ""),
                            "time": event.get("created_at", 0),
                        })
            else:
                search_window = 1000
                for event in _list_events(redis, limit=search_window):   # 硬上限:只搜最近 1000 条
                    value = event.get("value", "")
                    if term in value.lower():
                        all_results.append({
                            "value": value,
                            "fp": event.get("fingerprint", ""),
                            "type": event.get("event_type", ""),
                            "source": event.get("source_tool", ""),
                            "time": event.get("created_at", 0),
                        })
            search_total = len(all_results)
            total_pages = max(1, ceil(search_total / per_page))
            page = min(page, total_pages)
            search_results = all_results[(page - 1) * per_page: page * per_page]
        # 类型计数(左侧栏徽章):一次 pipeline 批量 zcard,事件类型数量级很小
        type_counts = {}
        if event_types:
            pipe = redis.conn.pipeline()
            for et in event_types:
                pipe.zcard(redis.event_time_index(et))
            for et, count in zip(event_types, pipe.execute()):
                type_counts[et] = int(count or 0)
        return render_template(
            "event_query.html",
            event_types=event_types,
            type_counts=type_counts,
            selected_type=selected_type,
            type_values=type_values,
            total_values=total_values,
            search_term=search_term,
            search_results=search_results,
            search_total=search_total,
            search_window=search_window,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            path_data=path_data,
            path_fp=path_fp,
        )

    @app.route("/flow")
    @login_required
    def flow_view():
        redis = app.config["get_redis"]()
        graph = _execution_flow_graph(redis, app.config["MODULES_DIR"])
        return render_template("flow.html", graph=graph)

    @app.route("/api/flow")
    @login_required
    def flow_api():
        redis = app.config["get_redis"]()
        return jsonify(_execution_flow_graph(redis, app.config["MODULES_DIR"]))

    @app.route("/redis-cmd", methods=["GET", "POST"])
    @login_required
    def redis_cmd():
        result_data = None
        error = None
        if request.method == "POST":
            raw_cmd = request.form.get("command", "").strip()
            if not raw_cmd:
                flash("命令不能为空", "error")
                return redirect(url_for("redis_cmd"))
            redis = app.config["get_redis"]()
            try:
                parts = raw_cmd.split()
                result_data = redis.conn.execute_command(parts[0], *parts[1:])
                flash("命令执行成功", "success")
            except Exception as exc:
                error = str(exc)
                flash(f"执行失败: {exc}", "error")
        return render_template("redis_cmd.html", result=result_data, error=error, last_cmd=request.form.get("command", "") if request.method == "POST" else "")

    @app.route("/api/path/<fingerprint>")
    @login_required
    def path_api(fingerprint: str):
        redis = app.config["get_redis"]()
        return jsonify(_event_path(redis, fingerprint))

    @app.route("/api/stats")
    @login_required
    def api_stats():
        redis = app.config["get_redis"]()
        redis_ok = _safe_ping(redis)
        return jsonify({
            "redis_ok": redis_ok,
            "queue_stats": _queue_stats(redis, app.config["MODULES_DIR"], _tool_registry(redis)) if redis_ok else [],
            "event_count": redis.conn.scard("fs3:event:all") if redis_ok else 0,
            "node_count": len(_active_nodes(redis)) if redis_ok else 0,
            "tool_count": len(_tool_registry(redis)) if redis_ok else 0,
        })

    @app.route("/api/stats/trend")
    @login_required
    def api_stats_trend():
        """仪表盘图表数据:24h 事件趋势(按小时分桶)+ 事件类型分布(Top 8)。

        事件时间索引 zset 的 score 即 created_at(秒),一次 zrangebyscore
        withscores 拿窗口内全部 (fp, ts),按小时归桶,无逐事件查询。
        """
        redis = app.config["get_redis"]()
        redis_ok = _safe_ping(redis)
        if not redis_ok:
            return jsonify({"ok": False, "error": "redis offline"})
        now = time.time()
        window_hours = 24
        start = now - window_hours * 3600
        # ── 24h 趋势:每小时事件数 ──
        raw = redis.conn.zrangebyscore("fs3:event:time", start, now, withscores=True) or []
        buckets = [0] * window_hours
        for _fp, score in raw:
            try:
                idx = int((float(score) - start) // 3600)
            except (TypeError, ValueError):
                continue
            if 0 <= idx < window_hours:
                buckets[idx] += 1
        labels = []
        for i in range(window_hours - 1, -1, -1):
            labels.append(time.strftime("%H:%M", time.localtime(now - i * 3600)))
        # ── 类型分布:统计 hash 取 Top 8,其余并入"其他" ──
        stats = {k: int(v or 0) for k, v in (redis.conn.hgetall("fs3:stats:event_type") or {}).items()}
        sorted_types = sorted(stats.items(), key=lambda kv: kv[1], reverse=True)
        top, rest = sorted_types[:8], sorted_types[8:]
        total = sum(stats.values()) or 1
        dist = [{"type": t, "count": c, "pct": round(c * 100.0 / total, 1)} for t, c in top]
        if rest:
            rest_count = sum(c for _t, c in rest)
            dist.append({"type": "其他", "count": rest_count, "pct": round(rest_count * 100.0 / total, 1)})
        return jsonify({"ok": True, "hours": labels, "counts": buckets, "distribution": dist, "total": total})
