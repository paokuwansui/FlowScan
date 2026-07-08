"""
FlowScan3 Web 控制端。

提供 Redis 事件查看、注入、删除、快照保存、日志、节点和工具状态页面。
"""

import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from functools import wraps
from typing import Any, Dict, Iterable, List, Optional

import yaml

from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session as flask_session,
    url_for,
)

from flowscan3.code_runner import CodeExecutionError, run_input_transform, run_output_parse
from flowscan3.config import load_yaml, render_template as render_command_template
from flowscan3.filter import (
    _fingerprint,
    add_redis_rule,
    delete_redis_rule,
    get_file_rules,
    get_redis_rules,
    reload_file_rules,
    test_file_rules,
    test_redis_rules,
)
from flowscan3.redis_store import FlowScanRedis
from flowscan3.tool_module import ToolModule, load_tools
from flowscan3.utils import run_cmd


DEFAULT_WEB_CONFIG = {
    "username": "admin",
    "password": "admin",
    "secret_key": "flowscan3-secret-change-me",
    "session_ttl": 3600,
    "host": "0.0.0.0",
    "port": 8080,
}


def create_app(config_path: str = "config.yaml", modules_dir: str = "modules") -> Flask:
    app = Flask(__name__)
    cfg = load_yaml(config_path)
    redis_cfg = cfg.get("redis", {}) or {}
    web_cfg = {**DEFAULT_WEB_CONFIG, **(cfg.get("web_config", {}) or {})}

    app.secret_key = web_cfg["secret_key"]
    app.config["CONFIG_PATH"] = config_path
    app.config["MODULES_DIR"] = modules_dir
    app.config["WEB_USERNAME"] = web_cfg["username"]
    app.config["WEB_PASSWORD"] = web_cfg["password"]
    app.config["SESSION_TTL"] = web_cfg["session_ttl"]
    app.config["REDIS"] = {
        "host": redis_cfg.get("remote_host", "127.0.0.1"),
        "port": int(redis_cfg.get("port", 6379)),
        "password": redis_cfg.get("password", ""),
        "db": int(redis_cfg.get("db", 0)),
    }

    def get_redis() -> FlowScanRedis:
        return FlowScanRedis(**app.config["REDIS"])

    app.config["get_redis"] = get_redis
    _register_routes(app)
    _start_loop_thread(app)
    return app


def _register_routes(app: Flask) -> None:
    def login_required(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not flask_session.get("logged_in"):
                return redirect(url_for("login"))
            return func(*args, **kwargs)

        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if username == app.config["WEB_USERNAME"] and password == app.config["WEB_PASSWORD"]:
                flask_session["logged_in"] = True
                flask_session.permanent = True
                app.permanent_session_lifetime = app.config["SESSION_TTL"]
                return redirect(url_for("index"))
            flash("用户名或密码错误", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        flask_session.pop("logged_in", None)
        return redirect(url_for("login"))

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

    @app.route("/events")
    @login_required
    def events():
        redis = app.config["get_redis"]()
        event_type = request.args.get("type", "")
        search_val = request.args.get("search_val", "").strip()
        limit = _to_int(request.args.get("limit"), 100)
        offset = _to_int(request.args.get("offset"), 0)
        tab = request.args.get("tab", "events")
        event_types = _event_types(redis)
        if search_val:
            term = search_val.lower()
            events_list = [
                event for event in _list_events(redis, limit=5000)
                if term in (event.get("value") or "").lower()
            ]
        else:
            events_list = _list_events(redis, event_type=event_type, limit=limit, offset=offset)
        return render_template(
            "events.html",
            events=events_list,
            event_types=event_types,
            current_type=event_type,
            search_val=search_val,
            limit=limit,
            offset=offset,
            tab=tab,
        )

    @app.route("/events/inject", methods=["POST"])
    @login_required
    def events_inject():
        raw = request.form.get("events_batch", "").strip()
        if not raw:
            flash("事件内容不能为空", "error")
            return redirect(url_for("events"))
        redis = app.config["get_redis"]()
        added = skipped = 0
        for line in [item.strip() for item in raw.splitlines() if item.strip()]:
            parsed = _parse_event_line(line)
            if not parsed:
                skipped += 1
                continue
            event_type, value = parsed
            before = redis.conn.sismember("fs3:event:set", FlowScanRedis.fingerprint(event_type, value))
            fp = redis.push_event(event_type, value, source_tool="web_manual")
            if fp and not before:
                added += 1
            else:
                skipped += 1
        message = f"成功注入 {added} 个事件"
        if skipped:
            message += f"，{skipped} 个已存在/无效"
        flash(message, "success" if added else "warning")
        return redirect(url_for("events"))

    @app.route("/events/remove", methods=["POST"])
    @login_required
    def events_remove():
        raw = request.form.get("fingerprints", "").strip()
        if not raw:
            flash("事件内容不能为空", "error")
            return redirect(url_for("events"))
        cascade = request.form.get("cascade", "1") == "1"
        redis = app.config["get_redis"]()
        total = 0
        for line in [item.strip() for item in raw.replace(",", "\n").splitlines() if item.strip()]:
            fp = _line_to_fp(line)
            if fp:
                total += _remove_event(redis, fp, remove_children=cascade)
        suffix = "（含子事件）" if cascade else ""
        flash(f"已移除 {total} 个事件{suffix}", "success")
        return redirect(url_for("events"))

    @app.route("/events/clear", methods=["POST"])
    @login_required
    def events_clear():
        redis = app.config["get_redis"]()
        removed = _clear_all_events(redis)
        flash(f"已清空 {removed} 个事件及相关队列/任务状态", "success")
        return redirect(url_for("events"))

    @app.route("/events/save-state", methods=["POST"])
    @login_required
    def events_save_state():
        redis = app.config["get_redis"]()
        path = _full_export(redis)
        flash(f"全量状态已导出到 {path}", "success")
        return redirect(url_for("events"))

    @app.route("/events/restore-state", methods=["POST"])
    @login_required
    def events_restore_state():
        uploaded = request.files.get("state_file")
        if not uploaded or not uploaded.filename:
            flash("请选择要恢复的 JSON 导出文件", "error")
            return redirect(url_for("events"))
        try:
            raw = uploaded.read().decode("utf-8", errors="replace")
            json_data = json.loads(raw)
        except Exception as exc:
            flash(f"JSON 解析失败: {exc}", "error")
            return redirect(url_for("events"))
        if not isinstance(json_data, dict) or "keys" not in json_data:
            flash("无效的导出文件: 缺少 'keys' 字段，请使用全量导出格式", "error")
            return redirect(url_for("events"))
        redis = app.config["get_redis"]()
        key_count = _full_import(redis, json_data)
        flash(f"状态恢复完成: 清空旧数据后恢复了 {key_count} 个 Redis 键", "success")
        return redirect(url_for("events"))

    # ================================================================
    # 黑名单管理 API
    # ================================================================

    @app.route("/api/blacklist/redis-rules")
    @login_required
    def blacklist_redis_rules():
        redis = app.config["get_redis"]()
        return jsonify(get_redis_rules(redis))

    @app.route("/api/blacklist/file-rules")
    @login_required
    def blacklist_file_rules():
        rules = get_file_rules()
        return jsonify({"rules": rules, "count": len(rules)})

    @app.route("/api/blacklist/add", methods=["POST"])
    @login_required
    def blacklist_add():
        redis = app.config["get_redis"]()
        data = request.get_json(silent=True) or {}
        event_type = str(data.get("event_type", "")).strip()
        match_mode = str(data.get("match_mode", "")).strip()
        value = str(data.get("value", "")).strip()
        comment = str(data.get("comment", "")).strip()
        if not event_type or not value:
            return jsonify({"ok": False, "error": "event_type 和 value 不能为空"})
        if match_mode not in ("contains", "suffix", "prefix", "ip_range"):
            return jsonify({"ok": False, "error": "match_mode 必须是 contains/suffix/prefix/ip_range"})
        fp = add_redis_rule(redis, event_type, match_mode, value, comment)
        if fp:
            return jsonify({"ok": True, "fp": fp})
        return jsonify({"ok": False, "error": "规则已存在或添加失败"})

    @app.route("/api/blacklist/delete", methods=["POST"])
    @login_required
    def blacklist_delete():
        redis = app.config["get_redis"]()
        data = request.get_json(silent=True) or {}
        fp = str(data.get("fp", "")).strip()
        if not fp:
            return jsonify({"ok": False, "error": "fp 不能为空"})
        ok = delete_redis_rule(redis, fp)
        return jsonify({"ok": ok, "deleted": ok})

    @app.route("/api/blacklist/reload-file", methods=["POST"])
    @login_required
    def blacklist_reload_file():
        count = reload_file_rules()
        return jsonify({"ok": True, "count": count})

    @app.route("/api/blacklist/test", methods=["POST"])
    @login_required
    def blacklist_test():
        redis = app.config["get_redis"]()
        data = request.get_json(silent=True) or {}
        event_type = str(data.get("event_type", "DNS_NAME")).strip()
        value = str(data.get("value", "")).strip()
        if not value:
            return jsonify({"ok": False, "error": "value 不能为空"})
        file_matches = test_file_rules(event_type, value)
        redis_matches = test_redis_rules(redis, event_type, value)
        total = len(file_matches) + len(redis_matches)
        return jsonify({
            "ok": True,
            "total": total,
            "blocked": total > 0,
            "file_matches": file_matches,
            "redis_matches": redis_matches,
        })

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
        logs_data = [{"ts": idx, "msg": line} for idx, line in enumerate(raw_logs)]
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
        filename = f"flowscan3_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
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
        roots = [event for event in _list_events(redis, limit=5000) if event.get("root_fp") == event.get("fingerprint")]
        roots.sort(key=lambda item: float(item.get("created_at") or 0), reverse=True)
        return render_template("event_tree.html", roots=roots[:200])

    @app.route("/api/event-tree/children/<fingerprint>")
    @login_required
    def event_tree_children(fingerprint: str):
        redis = app.config["get_redis"]()
        children = [event for event in _list_events(redis, limit=5000) if event.get("parent_fp") == fingerprint]
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
        for event in _list_events(redis, limit=5000):
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

    @app.route("/event-query")
    @login_required
    def event_query():
        redis = app.config["get_redis"]()
        event_types = _event_types(redis)
        selected_type = request.args.get("type", "")
        search_term = request.args.get("search", "").strip()
        path_fp = request.args.get("path", "").strip()
        path_data = _event_path(redis, path_fp) if path_fp else None
        type_values = []
        if selected_type and not search_term:
            type_values = [
                {
                    "value": event.get("value", ""),
                    "fp": event.get("fingerprint", ""),
                    "source": event.get("source_tool", ""),
                    "time": event.get("created_at", 0),
                }
                for event in _list_events(redis, event_type=selected_type, limit=5000)
            ]
        search_results = []
        if search_term:
            term = search_term.lower()
            for event in _list_events(redis, limit=5000):
                value = event.get("value", "")
                if term in value.lower():
                    search_results.append({
                        "value": value,
                        "fp": event.get("fingerprint", ""),
                        "type": event.get("event_type", ""),
                        "source": event.get("source_tool", ""),
                        "time": event.get("created_at", 0),
                    })
        return render_template(
            "event_query.html",
            event_types=event_types,
            selected_type=selected_type,
            type_values=type_values,
            search_term=search_term,
            search_results=search_results,
            path_data=path_data,
            path_fp=path_fp,
        )

    @app.route("/template-lab")
    @login_required
    def template_lab():
        modules_dir = app.config["MODULES_DIR"]
        selected = request.args.get("file", "").strip()
        module_files = _module_yaml_files(modules_dir)
        if not selected and module_files:
            selected = module_files[0]["filename"]
        selected_path = _safe_module_path(modules_dir, selected) if selected else ""
        yaml_text = ""
        if selected_path and os.path.exists(selected_path):
            with open(selected_path, "r", encoding="utf-8") as handle:
                yaml_text = handle.read()
        return render_template(
            "template_lab.html",
            module_files=module_files,
            selected=selected,
            yaml_text=yaml_text,
            default_event_type="DOMAIN",
            default_target="example.com",
        )

    @app.route("/template-lab/save", methods=["POST"])
    @login_required
    def template_lab_save():
        modules_dir = app.config["MODULES_DIR"]
        filename = request.form.get("filename", "").strip()
        yaml_text = request.form.get("yaml_text", "")
        result = _validate_yaml_text(yaml_text)
        if not result["ok"]:
            flash(f"YAML 无效，未保存: {result['error']}", "error")
            return redirect(url_for("template_lab", file=filename))
        path = _safe_module_path(modules_dir, filename)
        if not path:
            flash("文件名无效", "error")
            return redirect(url_for("template_lab"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(yaml_text.rstrip() + "\n")
        flash(f"已保存 {filename}", "success")
        return redirect(url_for("template_lab", file=filename))

    @app.route("/template-lab/api/run", methods=["POST"])
    @login_required
    def template_lab_api_run():
        payload = request.get_json(silent=True) or request.form.to_dict()
        action = (payload.get("action") or "validate").strip()
        yaml_text = payload.get("yaml_text") or ""
        event_type = (payload.get("event_type") or "DOMAIN").strip()
        target = (payload.get("target") or "example.com").strip()
        stdout = payload.get("stdout") or ""
        timeout = _to_int(str(payload.get("timeout", "")), 60)
        install_step = _to_int(str(payload.get("install_step", "")), 0)
        config = load_yaml(app.config["CONFIG_PATH"])
        result = _run_template_lab_action(action, yaml_text, event_type, target, stdout, timeout, install_step, config)
        return jsonify(result)

    @app.route("/ai-analysis", methods=["GET", "POST"])
    @login_required
    def ai_analysis():
        redis = app.config["get_redis"]()
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        event_types = _event_types(redis)
        selected_types = []
        question = ""
        max_events = int(ai_cfg.get("max_events", 200))
        toggles = _default_ai_toggles()
        result = None
        context_events = []
        action_results = []
        parsed_actions = []

        if request.method == "POST":
            selected_types, question, max_events, toggles = _analysis_request_from_form(request.form, ai_cfg)
            if not selected_types:
                flash("至少选择一个事件类型", "error")
            elif not question:
                flash("问题不能为空", "error")
            else:
                run_data = _run_ai_analysis_once(
                    redis=redis,
                    ai_cfg=ai_cfg,
                    selected_types=selected_types,
                    question=question,
                    max_events=max_events,
                    toggles=toggles,
                    run_source="manual",
                )
                result = run_data["result"]
                context_events = run_data["context_events"]
                parsed_actions = run_data["parsed_actions"]
                action_results = run_data["action_results"]

        schedules = _list_ai_schedules(redis)
        return render_template(
            "ai_analysis.html",
            event_types=event_types,
            selected_types=selected_types,
            question=question,
            max_events=max_events,
            ai_cfg=ai_cfg,
            result=result,
            context_events=context_events,
            toggles=toggles,
            action_results=action_results,
            parsed_actions=parsed_actions,
            schedules=schedules,
        )

    @app.route("/ai-logs")
    def ai_logs():
        """AI 日记路由：支持浏览器查看（HTML）和 API 密钥访问（JSON）。"""
        api_key = request.args.get("api_key", "") or request.headers.get("X-API-Key", "")
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        log_api_key = ai_cfg.get("log_api_key", "")
        # 登录用户或 API 密钥均可访问
        is_api = bool(api_key and log_api_key and api_key == log_api_key)
        is_web = flask_session.get("logged_in", False)
        if not is_api and not is_web:
            if api_key:
                return jsonify({"error": "unauthorized", "message": "Invalid API key"}), 401
            return redirect(url_for("login"))

        redis = app.config["get_redis"]()
        fmt = request.args.get("format", "html" if is_web else "json")

        # 读取所有日志
        log_ids = redis.conn.zrevrange("fs3:ai:logs", 0, 500)
        entries = []
        for lid in log_ids:
            raw = redis.conn.hgetall(f"fs3:ai:log:{lid}")
            if raw:
                entry = {k: _json_or_raw(v) for k, v in raw.items()}
                entries.append(entry)

        if fmt == "json" or is_api:
            return jsonify({"count": len(entries), "logs": entries})

        return render_template("ai_logs.html", logs=entries, count=len(entries))

    @app.route("/api/ai-schedule/create", methods=["POST"])
    @login_required
    def ai_schedule_create():
        """按当前页面表单快照新增一个独立的定时 AI 分析任务。"""
        redis = app.config["get_redis"]()
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        selected_types, question, max_events, toggles = _analysis_request_from_form(request.form, ai_cfg)
        interval = _to_int(request.form.get("loop_interval"), 0)
        if interval <= 0:
            flash("定时间隔为 0 表示不开启；请输入大于 0 的分钟数", "error")
            return redirect(url_for("ai_analysis"))
        if not selected_types:
            flash("新增定时任务前至少选择一个事件类型", "error")
            return redirect(url_for("ai_analysis"))
        if not question:
            flash("新增定时任务前问题不能为空", "error")
            return redirect(url_for("ai_analysis"))
        schedule = _create_ai_schedule(redis, {
            "interval_minutes": interval,
            "selected_types": selected_types,
            "question": question,
            "max_events": max_events,
            "toggles": toggles,
            "system_prompt": ai_cfg.get("system_prompt", ""),
            "model": ai_cfg.get("model", ""),
        })
        flash(f"已新增定时 AI 分析任务：{schedule['schedule_id']}，每 {interval} 分钟执行一次", "success")
        return redirect(url_for("ai_analysis"))

    @app.route("/api/ai-schedule/<schedule_id>/delete", methods=["POST"])
    @login_required
    def ai_schedule_delete(schedule_id: str):
        redis = app.config["get_redis"]()
        if _delete_ai_schedule(redis, schedule_id):
            flash(f"已删除定时任务 {schedule_id}", "success")
        else:
            flash(f"未找到定时任务 {schedule_id}", "warning")
        return redirect(url_for("ai_analysis"))

    @app.route("/ai-schedule/<schedule_id>")
    @login_required
    def ai_schedule_detail(schedule_id: str):
        redis = app.config["get_redis"]()
        schedule = _load_ai_schedule(redis, schedule_id)
        if not schedule:
            flash(f"未找到定时任务 {schedule_id}", "error")
            return redirect(url_for("ai_analysis"))
        runs = _list_ai_schedule_runs(redis, schedule_id, limit=50)
        return render_template("ai_schedule_detail.html", schedule=schedule, runs=runs)

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


def _ai_config(config: Dict[str, Any]) -> Dict[str, Any]:
    cfg = config.get("ai_analysis", {}) or {}
    system_prompt = str(cfg.get("system_prompt", "") or "")
    if not system_prompt.strip():
        prompt_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts", "ai_analysis.txt")
        if os.path.exists(prompt_file):
            with open(prompt_file, "r", encoding="utf-8") as handle:
                system_prompt = handle.read().strip()
    return {
        "base_url": str(cfg.get("base_url", "")).rstrip("/"),
        "api_key": str(cfg.get("api_key", "")),
        "model": str(cfg.get("model", "gpt-4o-mini")),
        "timeout_seconds": int(cfg.get("timeout_seconds", 120) or 120),
        "max_events": int(cfg.get("max_events", 5000) or 5000),
        "system_prompt": system_prompt,
        "log_api_key": str(cfg.get("log_api_key", "")),
        "loop_interval_minutes": int(cfg.get("loop_interval_minutes", 0) or 0),
    }


def _default_ai_toggles() -> Dict[str, bool]:
    return {"add": True, "del": True, "del_children": True, "blacklist_add": True, "blacklist_del": True, "log": True}


def _analysis_request_from_form(form: Any, ai_cfg: Dict[str, Any]) -> tuple[List[str], str, int, Dict[str, bool]]:
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
) -> Dict[str, Any]:
    context_events = _events_for_ai(redis, selected_types, max_events)
    result = _call_ai_analysis(ai_cfg, selected_types, context_events, question, redis)
    parsed_actions: List[Dict[str, Any]] = []
    action_results: List[Dict[str, Any]] = []
    if result and result.get("ok") and result.get("answer"):
        parsed_actions = _parse_ai_actions(result["answer"])
        if parsed_actions:
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


def _events_for_ai(redis: FlowScanRedis, event_types: List[str], max_events: int) -> List[Dict[str, Any]]:
    max_events = max(1, min(max_events, 5000))
    events = []
    for event_type in event_types:
        events.extend(_list_events(redis, event_type=event_type, limit=max_events))
    events.sort(key=lambda item: float(item.get("created_at") or 0), reverse=True)
    return events[:max_events]


def _format_context_for_ai(events: List[Dict[str, Any]], redis: Any) -> str:
    lines = []
    for index, event in enumerate(events, 1):
        created = event.get("created_at") or event.get("timestamp") or ""
        lines.append(
            f"{index}. type={event.get('event_type', '')} value={event.get('value', '')} "
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
    url = base_url.rstrip("/") + "/chat/completions"
    user_content = (
        "用户问题：\n"
        f"{question}\n\n"
        "已选择事件类型：\n"
        f"{', '.join(selected_types)}\n\n"
        "事件日志上下文：\n"
        f"{_format_context_for_ai(events, redis)}"
    )
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": ai_cfg.get("system_prompt", "")},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.2,
    }
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=int(ai_cfg.get("timeout_seconds", 120))) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        parsed = json.loads(raw)
        answer = parsed.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {"ok": True, "answer": answer, "raw": parsed, "event_count": len(events), "model": model}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
        return {"ok": False, "error": f"HTTP {exc.code}: {detail[:2000]}", "event_count": len(events), "model": model}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "event_count": len(events), "model": model}


def _parse_ai_actions(text: str) -> List[Dict[str, Any]]:
    """从 AI 回答文本中提取结构化动作。优先读取 ```json 代码块，也兼容纯 JSON。"""
    candidates = re.findall(r"```json\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)
    for block in candidates:
        try:
            parsed = json.loads(block)
            if isinstance(parsed, dict) and isinstance(parsed.get("actions"), list):
                return [action for action in parsed["actions"] if isinstance(action, dict) and action.get("type") in ("add", "del", "blacklist_add", "blacklist_del", "log")]
        except (json.JSONDecodeError, ValueError):
            continue
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


def _validate_yaml_text(yaml_text: str) -> Dict[str, Any]:
    try:
        data = yaml.safe_load(yaml_text) or {}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if not isinstance(data, dict):
        return {"ok": False, "error": "YAML 顶层必须是对象"}
    warnings = []
    for key in ("name", "io_contract", "execution"):
        if key not in data:
            warnings.append(f"缺少字段: {key}")
    io_contract = data.get("io_contract") or {}
    execution = data.get("execution") or {}
    if not io_contract.get("input_events"):
        warnings.append("io_contract.input_events 为空")
    if not execution.get("command"):
        warnings.append("execution.command 为空")
    return {"ok": True, "error": "", "warnings": warnings, "data": data}


def _module_yaml_files(modules_dir: str) -> List[Dict[str, str]]:
    if not os.path.isdir(modules_dir):
        return []
    files = []
    for filename in sorted(os.listdir(modules_dir)):
        if filename.endswith((".yaml", ".yml")):
            files.append({"filename": filename, "path": os.path.join(modules_dir, filename)})
    return files


def _safe_module_path(modules_dir: str, filename: str) -> str:
    if not filename or not filename.endswith((".yaml", ".yml")):
        return ""
    base = os.path.abspath(modules_dir)
    path = os.path.abspath(os.path.join(base, filename))
    if path == base or not path.startswith(base + os.sep):
        return ""
    return path


def _tool_from_yaml_text(yaml_text: str) -> ToolModule:
    validation = _validate_yaml_text(yaml_text)
    if not validation["ok"]:
        raise ValueError(validation["error"])
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", encoding="utf-8", delete=False) as handle:
        handle.write(yaml_text)
        temp_path = handle.name
    try:
        return ToolModule.from_yaml(temp_path)
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def _run_template_lab_action(
    action: str,
    yaml_text: str,
    event_type: str,
    target: str,
    stdout: str,
    timeout: int,
    install_step: int,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    started = time.time()
    validation = _validate_yaml_text(yaml_text)
    if action == "validate":
        return {"ok": validation["ok"], "action": action, "error": validation.get("error", ""), "warnings": validation.get("warnings", []), "elapsed": round(time.time() - started, 3)}
    if not validation["ok"]:
        return {"ok": False, "action": action, "error": validation["error"], "elapsed": round(time.time() - started, 3)}
    try:
        tool = _tool_from_yaml_text(yaml_text)
    except Exception as exc:
        return {"ok": False, "action": action, "error": str(exc), "elapsed": round(time.time() - started, 3)}

    if action == "check":
        command = render_command_template(tool.check_command, {}, config)
        if not command:
            return {"ok": True, "action": action, "message": "未配置 check.command，默认视为可用", "elapsed": round(time.time() - started, 3)}
        ok, output, code = run_cmd(command, timeout=max(1, min(timeout, 300)))
        haystack = output.lower()
        expected = (tool.expect_keyword or "").lower()
        excluded = (tool.exclude_keyword or "").lower()
        keyword_ok = ok and (not expected or expected in haystack) and (not excluded or excluded not in haystack)
        return {"ok": ok and keyword_ok, "action": action, "command": command, "exit_code": code, "stdout": output[-12000:], "keyword_ok": keyword_ok, "expect_keyword": tool.expect_keyword, "exclude_keyword": tool.exclude_keyword, "elapsed": round(time.time() - started, 3)}

    if action == "install":
        steps = list(tool.install_steps or [])
        if not steps:
            return {"ok": True, "action": action, "message": "未配置 install.steps", "steps": [], "elapsed": round(time.time() - started, 3)}
        if install_step > 0:
            indexes = [install_step - 1] if install_step <= len(steps) else []
        else:
            indexes = list(range(len(steps)))
        results = []
        overall_ok = True
        for index in indexes:
            command = render_command_template(steps[index], {}, config)
            ok, output, code = run_cmd(command, timeout=max(1, min(timeout, tool.install_timeout or 900)))
            results.append({"step": index + 1, "command": command, "ok": ok, "exit_code": code, "stdout": output[-12000:]})
            overall_ok = overall_ok and ok
            if not ok:
                break
        return {"ok": overall_ok, "action": action, "results": results, "elapsed": round(time.time() - started, 3)}

    if action in {"transform", "scan"}:
        try:
            params_list = run_input_transform(tool.input_transform_code, {"event_type": event_type, "value": target}, config) if tool.input_transform_code else [{"target": target, "value": target, "event_type": event_type}]
        except CodeExecutionError as exc:
            return {"ok": False, "action": action, "stage": "input_transform", "error": str(exc), "elapsed": round(time.time() - started, 3)}
        commands = [render_command_template(tool.command_template, params, config) for params in params_list]
        if action == "transform":
            return {"ok": True, "action": action, "params": params_list, "commands": commands, "allowed_output_events": tool.allowed_output_events, "elapsed": round(time.time() - started, 3)}
        command_results = []
        parsed_results = []
        overall_ok = True
        for params, command in zip(params_list, commands):
            ok, output, code = run_cmd(command, timeout=max(1, min(timeout, tool.exec_timeout or 600)))
            item = {"params": params, "command": command, "ok": ok, "exit_code": code, "stdout": output[-12000:]}
            command_results.append(item)
            overall_ok = overall_ok and ok
            if ok and tool.output_parse_code:
                try:
                    parsed = run_output_parse(tool.output_parse_code, output, config)
                except CodeExecutionError as exc:
                    parsed = [{"__parse_error__": str(exc)}]
                    overall_ok = False
                parsed_results.extend(parsed)
        return {"ok": overall_ok, "action": action, "params": params_list, "commands": commands, "results": command_results, "parsed": parsed_results, "elapsed": round(time.time() - started, 3)}

    if action == "parse":
        try:
            parsed = run_output_parse(tool.output_parse_code, stdout, config) if tool.output_parse_code else []
            return {"ok": True, "action": action, "parsed": parsed, "elapsed": round(time.time() - started, 3)}
        except CodeExecutionError as exc:
            return {"ok": False, "action": action, "error": str(exc), "elapsed": round(time.time() - started, 3)}

    return {"ok": False, "action": action, "error": f"未知动作: {action}", "elapsed": round(time.time() - started, 3)}


def _safe_ping(redis: FlowScanRedis) -> bool:
    try:
        return redis.ping()
    except Exception:
        return False


def _to_int(value: Optional[str], default: int) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _parse_event_line(line: str) -> Optional[tuple[str, str]]:
    if line.startswith("[") and "]" in line:
        right = line.index("]")
        event_type = line[1:right].strip()
        value = line[right + 1:].strip()
    else:
        # 无 [事件类型] 前缀 → 尝试空格分隔，否则默认 DOMAIN
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] == parts[0].upper() and len(parts[0]) <= 30:
            event_type, value = parts[0].strip(), parts[1].strip()
        elif parts:
            event_type, value = "INPUT", parts[0].strip()
        else:
            return None
    if not event_type or not value:
        return None
    return event_type, value


def _line_to_fp(line: str) -> str:
    parsed = _parse_event_line(line)
    if parsed:
        return FlowScanRedis.fingerprint(parsed[0], parsed[1])
    if len(line) == 64 and all(char in "0123456789abcdef" for char in line.lower()):
        return line
    return ""


def _event_types(redis: FlowScanRedis) -> List[str]:
    return sorted(redis.conn.hkeys("fs3:stats:event_type") or [])


def _list_events(redis: FlowScanRedis, event_type: str = "", limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    if event_type:
        fps = list(redis.conn.smembers(f"fs3:events:type:{event_type}") or [])
    else:
        fps = list(redis.conn.smembers("fs3:event:all") or [])
    events = []
    for fp in fps:
        event = redis.get_event(fp)
        if event:
            event.setdefault("timestamp", event.get("created_at", "0"))
            event.setdefault("tool_name", event.get("source_tool", ""))
            events.append(event)
    events.sort(key=lambda item: float(item.get("created_at") or 0), reverse=True)
    return events[offset:offset + limit]


def _event_path(redis: FlowScanRedis, fp: str) -> List[Dict[str, Any]]:
    path = []
    seen = set()
    current = fp
    while current and current not in seen:
        seen.add(current)
        event = redis.get_event(current)
        if not event:
            break
        event.setdefault("timestamp", event.get("created_at", "0"))
        event.setdefault("tool_name", event.get("source_tool", ""))
        path.append(event)
        current = event.get("parent_fp", "")
    path.reverse()
    return path


def _children_fps(redis: FlowScanRedis, parent_fp: str) -> List[str]:
    return [event["fingerprint"] for event in _list_events(redis, limit=100000) if event.get("parent_fp") == parent_fp]


def _remove_event(redis: FlowScanRedis, fp: str, remove_children: bool = True) -> int:
    event = redis.get_event(fp)
    if not event:
        return 0
    # 先标记取消，再递归删除子树。这样即使有运行中的 worker 正在基于该事件
    # 产出结果，FlowScanRedis.push_event 也会立即丢弃这些新子事件。
    redis.conn.setex(f"fs3:cancelled:{fp}", 86400, "1")
    removed = 0
    if remove_children:
        for child_fp in _children_fps(redis, fp):
            removed += _remove_event(redis, child_fp, remove_children=True)
    event_type = event.get("event_type", "")
    pipe = redis.conn.pipeline()
    pipe.delete(f"fs3:event:{fp}")
    pipe.srem("fs3:event:set", fp)
    pipe.srem("fs3:event:all", fp)
    pipe.srem(f"fs3:events:type:{event_type}", fp)
    pipe.lrem("fs3:event:new", 0, fp)
    # 保留取消标记，阻止运行中的任务产生孤儿子事件（24h TTL）
    pipe.setex(f"fs3:cancelled:{fp}", 86400, "1")
    for key in redis.conn.scan_iter("fs3:pending:*"):
        pipe.zrem(key, fp)
    for key in redis.conn.scan_iter(f"fs3:done:*:{fp}"):
        pipe.delete(key)
    for key in redis.conn.scan_iter(f"fs3:lock:*:{fp}"):
        pipe.delete(key)
    pipe.execute()
    return removed + 1


def _clear_all_events(redis: FlowScanRedis) -> int:
    count = int(redis.conn.scard("fs3:event:all") or 0)
    keys = []
    for pattern in ("fs3:event:*", "fs3:events:type:*", "fs3:done:*", "fs3:lock:*", "fs3:pending:*", "fs3:consumers:*", "fs3:running:*", "fs3:cancelled:*"):
        keys.extend(list(redis.conn.scan_iter(pattern)))
    keys.extend(["fs3:event:set", "fs3:event:all", "fs3:event:new", "fs3:stats:event_type"])
    if keys:
        redis.conn.delete(*set(keys))
    redis.log(f"[WEB] clear all events count={count}")
    return count


def _full_export(redis: FlowScanRedis) -> str:
    """全量导出所有 fs3:* Redis 键到 JSON 文件。
    排除瞬态键: fs3:lock:*, fs3:running:* (带 TTL / 并发计数，恢复无意义)。
    """
    snapshot_dir = os.path.abspath("state_snapshots")
    os.makedirs(snapshot_dir, exist_ok=True)
    path = os.path.join(snapshot_dir, f"flowscan3_full_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    keys_data: Dict[str, Dict[str, Any]] = {}
    key_count = 0
    for key in redis.conn.scan_iter("fs3:*", count=500):
        if key.startswith("fs3:lock:") or key.startswith("fs3:running:") or key.startswith("fs3:cancelled:"):
            continue
        key_type = redis.conn.type(key)
        if key_type == "string":
            keys_data[key] = {"type": "string", "value": redis.conn.get(key)}
        elif key_type == "hash":
            keys_data[key] = {"type": "hash", "value": redis.conn.hgetall(key)}
        elif key_type == "set":
            keys_data[key] = {"type": "set", "value": sorted(redis.conn.smembers(key))}
        elif key_type == "zset":
            raw = redis.conn.zrange(key, 0, -1, withscores=True)
            keys_data[key] = {"type": "zset", "value": [[member, score] for member, score in raw]}
        elif key_type == "list":
            keys_data[key] = {"type": "list", "value": redis.conn.lrange(key, 0, -1)}
        key_count += 1
    data = {
        "version": 1,
        "saved_at": time.time(),
        "saved_at_iso": datetime.now().isoformat(),
        "key_count": key_count,
        "keys": keys_data,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    redis.log(f"[WEB] full export {path} ({key_count} keys)")
    return path


def _full_import(redis: FlowScanRedis, json_data: Dict[str, Any]) -> int:
    """清空所有 fs3:* 键，然后从全量导出 JSON 恢复。
    返回恢复的键数量。
    """
    # 1. 清空所有现有 fs3:* 键
    existing = list(redis.conn.scan_iter("fs3:*", count=1000))
    if existing:
        redis.conn.delete(*existing)
        redis.log(f"[WEB] cleared {len(existing)} existing fs3:* keys")

    # 2. 逐键恢复
    keys = json_data.get("keys", {})
    if not keys:
        redis.log("[WEB] import: no keys in JSON, nothing to restore")
        return 0

    restored = 0
    pipe = redis.conn.pipeline()
    for key, info in keys.items():
        key_type = info["type"]
        value = info["value"]
        try:
            if key_type == "string" and value is not None:
                pipe.set(key, value)
            elif key_type == "hash" and value:
                pipe.delete(key)
                pipe.hset(key, mapping=value)
            elif key_type == "set" and value:
                pipe.delete(key)
                pipe.sadd(key, *value)
            elif key_type == "zset" and value:
                pipe.delete(key)
                pipe.zadd(key, {str(member): float(score) for member, score in value})
            elif key_type == "list" and value:
                pipe.delete(key)
                pipe.rpush(key, *value)
            else:
                continue
            restored += 1
        except Exception as exc:
            redis.log(f"[WEB] import error restoring {key}: {exc}")
        if restored % 500 == 0:
            pipe.execute()
            pipe = redis.conn.pipeline()
    pipe.execute()
    redis.log(f"[WEB] full import done, restored {restored} keys")
    return restored


def _active_nodes(redis: FlowScanRedis) -> List[Dict[str, Any]]:
    nodes = []
    for node_id in sorted(redis.conn.smembers("fs3:nodes") or []):
        raw = redis.conn.hgetall(f"fs3:node:{node_id}")
        if not raw:
            redis.conn.srem("fs3:nodes", node_id)
            continue
        info = {key: _json_or_raw(value) for key, value in raw.items()}
        tools = info.get("tools", [])
        event_types = info.get("event_types", [])
        nodes.append({
            "node_id": node_id,
            "host": info.get("host", ""),
            "pid": info.get("pid", ""),
            "started_at": info.get("time", ""),
            "tools": ",".join(tools) if isinstance(tools, list) else str(tools),
            "event_types": ",".join(event_types) if isinstance(event_types, list) else str(event_types),
        })
    return nodes


def _tool_registry(redis: FlowScanRedis) -> Dict[str, Any]:
    tools = {}
    for name, raw in (redis.conn.hgetall("fs3:tools") or {}).items():
        tools[name] = _json_or_raw(raw)
    return tools


def _queue_stats(redis: FlowScanRedis, modules_dir: str, tools: Dict[str, Any]) -> List[Dict[str, Any]]:
    consumer_map = _consumer_map(modules_dir, tools)
    stats = redis.conn.hgetall("fs3:stats:event_type") or {}
    event_types = sorted(set(stats) | set(consumer_map) | set(_event_types(redis)))
    rows = []
    for event_type in event_types:
        produced = int(stats.get(event_type, 0) or 0)
        consumers = consumer_map.get(event_type, [])
        available = sum(int(redis.conn.zcard(f"fs3:pending:{consumer['tool']}") or 0) for consumer in consumers)
        consumers_with_pending = []
        for consumer in consumers:
            item = dict(consumer)
            item["pending"] = int(redis.conn.zcard(f"fs3:pending:{consumer['tool']}") or 0)
            consumers_with_pending.append(item)
        rows.append({
            "type": event_type,
            "count": available if consumers else 0,
            "total_produced": produced,
            "has_consumer": bool(consumers),
            "consumers": consumers_with_pending,
        })
    rows.sort(key=lambda item: (not item["has_consumer"], item["type"]))
    return rows


def _consumer_map(modules_dir: str, tools: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {}
    try:
        loaded = load_tools(modules_dir)
        for tool in loaded.values():
            for event_type in tool.input_events:
                result.setdefault(event_type, []).append({"tool": tool.name, "produces": tool.allowed_output_events})
    except Exception:
        pass
    if not result:
        for name, info in tools.items():
            input_events = info.get("input_events", []) if isinstance(info, dict) else []
            for event_type in input_events:
                result.setdefault(event_type, []).append({"tool": name, "produces": []})
    return result


def _execution_flow_graph(redis: FlowScanRedis, modules_dir: str) -> Dict[str, Any]:
    tools = _flow_tools(modules_dir, _tool_registry(redis))
    event_counts = {key: int(value or 0) for key, value in (redis.conn.hgetall("fs3:stats:event_type") or {}).items()}
    produced_by: Dict[str, List[str]] = {}
    consumed_by: Dict[str, List[str]] = {}
    visible_tools = dict(tools)
    for tool in visible_tools.values():
        for event_type in tool.get("input_events", []):
            if event_type.startswith("__"):
                continue
            consumed_by.setdefault(event_type, []).append(tool["name"])
        for event_type in tool.get("allowed_output_events", []):
            if event_type.startswith("__"):
                continue
            produced_by.setdefault(event_type, []).append(tool["name"])

    nodes = []
    for tool in sorted(visible_tools.values(), key=lambda item: item["name"]):
        is_enabled = tool.get("enabled", True)
        nodes.append({
            "id": tool["name"],
            "label": _flow_tool_label(tool, redis),
            "title": _flow_tool_title(tool),
            "group": "tool" if is_enabled else "disabled",
            "shape": "box",
        })

    edges = []
    source_events = set()
    sink_events = set()
    all_event_types = sorted((set(event_counts) | set(produced_by) | set(consumed_by)) - {event for event in event_counts if event.startswith("__")})
    edge_index = 1
    for event_type in all_event_types:
        producers = sorted(produced_by.get(event_type, []))
        consumers = sorted(consumed_by.get(event_type, []))
        if not producers and consumers:
            source_events.add(event_type)
        if producers and not consumers:
            sink_events.add(event_type)
            sink_id = f"sink::{event_type}"
            nodes.append({
                "id": sink_id,
                "label": f"{event_type}\n{event_counts.get(event_type, 0)}",
                "title": f"未被消费的事件: {event_type}",
                "group": "event",
                "shape": "dot",
            })
            for producer in producers:
                edges.append(_flow_edge(edge_index, producer, sink_id, event_type, event_counts.get(event_type, 0)))
                edge_index += 1
            continue
        if not producers or not consumers:
            continue

        fanout_cost = len(producers) * len(consumers)
        hub_cost = len(producers) + len(consumers)
        if fanout_cost > hub_cost and fanout_cost >= 6:
            hub_id = f"event::{event_type}"
            nodes.append({
                "id": hub_id,
                "label": f"{event_type}\n{event_counts.get(event_type, 0)}",
                "title": f"事件: {event_type}",
                "group": "event",
                "shape": "dot",
            })
            for producer in producers:
                edges.append(_flow_edge(edge_index, producer, hub_id, event_type, event_counts.get(event_type, 0)))
                edge_index += 1
            for consumer in consumers:
                edges.append(_flow_edge(edge_index, hub_id, consumer, event_type, event_counts.get(event_type, 0)))
                edge_index += 1
            continue

        for producer in producers:
            for consumer in consumers:
                if producer == consumer:
                    continue
                edges.append(_flow_edge(edge_index, producer, consumer, event_type, event_counts.get(event_type, 0)))
                edge_index += 1

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "tool_count": len(visible_tools),
            "event_type_count": len(all_event_types),
            "edge_count": len(edges),
            "event_total": sum(count for event, count in event_counts.items() if not event.startswith("__")),
            "source_events": sorted(source_events),
            "sink_events": sorted(sink_events),
        },
    }


def _flow_tools(modules_dir: str, registered_tools: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    tools: Dict[str, Dict[str, Any]] = {}
    try:
        for tool in load_tools(modules_dir).values():
            tools[tool.name] = {
                "name": tool.name,
                "description": tool.description,
                "yaml_path": tool.yaml_path,
                "input_events": list(tool.input_events),
                "allowed_output_events": list(tool.allowed_output_events),
                "command_template": tool.command_template,
                "max_concurrency": tool.max_concurrency,
                "exec_timeout": tool.exec_timeout,
                "enabled": tool.enabled,
            }
    except Exception:
        pass
    for name, info in registered_tools.items():
        if name in tools:
            continue
        if isinstance(info, dict):
            tools[name] = {
                "name": name,
                "description": "Redis 已注册工具",
                "yaml_path": info.get("yaml_path", ""),
                "input_events": list(info.get("input_events", []) or []),
                "allowed_output_events": [],
                "command_template": "",
                "max_concurrency": 0,
                "exec_timeout": 0,
                "enabled": True,
            }
    return tools


def _flow_edge(index: int, source: str, target: str, event_type: str, count: int) -> Dict[str, Any]:
    return {
        "id": f"tool-flow::{index}",
        "from": source,
        "to": target,
        "label": event_type,
        "title": f"事件: {event_type}<br>累计产生: {count}",
        "arrows": "to",
        "width": max(1, min(5, 1 + count // 50)),
    }


def _flow_tool_label(tool: Dict[str, Any], redis: FlowScanRedis) -> str:
    pending = int(redis.conn.zcard(f"fs3:pending:{tool['name']}") or 0)
    running = _running_count_for_tool(redis, tool["name"])
    if pending or running:
        return f"{tool['name']}\nR:{running} P:{pending}"
    return tool["name"]


def _flow_tool_title(tool: Dict[str, Any]) -> str:
    command = _html_escape(tool.get("command_template") or "-")
    if not tool.get("enabled", True):
        description = _html_escape(tool.get("description", ""))
        return f"状态: disabled / 占位模块<br>{description}<br><br>{command}"
    return command


def _running_count_for_tool(redis: FlowScanRedis, tool_name: str) -> int:
    total = 0
    for key in redis.conn.scan_iter(f"fs3:running:*:{tool_name}", count=100):
        try:
            total += int(redis.conn.get(key) or 0)
        except (TypeError, ValueError):
            continue
    return total


def _html_escape(value: str) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _json_or_raw(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return value


def _ai_schedule_defaults() -> Dict[str, Any]:
    return {
        "schedule_id": "",
        "interval_minutes": 0,
        "selected_types": [],
        "question": "",
        "max_events": 200,
        "toggles": _default_ai_toggles(),
        "system_prompt": "",
        "model": "",
        "enabled": True,
        "created_at": 0.0,
        "created_at_iso": "",
        "last_run": 0.0,
        "last_run_iso": "",
        "next_run": 0.0,
        "next_run_iso": "",
        "run_count": 0,
        "last_status": "pending",
        "last_error": "",
    }


def _normalize_ai_schedule(raw: Dict[str, Any]) -> Dict[str, Any]:
    data = _ai_schedule_defaults()
    data.update(raw or {})
    data["interval_minutes"] = int(data.get("interval_minutes") or 0)
    data["max_events"] = int(data.get("max_events") or 200)
    data["run_count"] = int(data.get("run_count") or 0)
    data["last_run"] = float(data.get("last_run") or 0)
    data["next_run"] = float(data.get("next_run") or 0)
    data["created_at"] = float(data.get("created_at") or 0)
    data["enabled"] = bool(data.get("enabled", True))
    raw_toggles = data.get("toggles")
    toggles: Dict[str, bool] = raw_toggles if isinstance(raw_toggles, dict) else {}
    normalized_toggles = _default_ai_toggles()
    normalized_toggles.update(toggles)
    data["toggles"] = normalized_toggles
    if not isinstance(data.get("selected_types"), list):
        data["selected_types"] = []
    return data


def _create_ai_schedule(redis: Any, cfg: Dict[str, Any]) -> Dict[str, Any]:
    now = time.time()
    schedule_id = uuid.uuid4().hex[:12]
    schedule = _normalize_ai_schedule({
        **cfg,
        "schedule_id": schedule_id,
        "enabled": True,
        "created_at": now,
        "created_at_iso": datetime.fromtimestamp(now).isoformat(),
        "last_run": 0,
        "last_run_iso": "",
        "next_run": now + int(cfg.get("interval_minutes", 0)) * 60,
        "next_run_iso": datetime.fromtimestamp(now + int(cfg.get("interval_minutes", 0)) * 60).isoformat(),
        "run_count": 0,
        "last_status": "pending",
        "last_error": "",
    })
    redis.conn.hset(f"fs3:ai:schedule:{schedule_id}", mapping={k: json.dumps(v, ensure_ascii=False) for k, v in schedule.items()})
    redis.conn.zadd("fs3:ai:schedules", {schedule_id: schedule["created_at"]})
    return schedule


def _load_ai_schedule(redis: Any, schedule_id: str) -> Optional[Dict[str, Any]]:
    raw = redis.conn.hgetall(f"fs3:ai:schedule:{schedule_id}")
    if not raw:
        return None
    return _normalize_ai_schedule({k: _json_or_raw(v) for k, v in raw.items()})


def _save_ai_schedule(redis: Any, schedule: Dict[str, Any]) -> None:
    schedule = _normalize_ai_schedule(schedule)
    redis.conn.hset(f"fs3:ai:schedule:{schedule['schedule_id']}", mapping={k: json.dumps(v, ensure_ascii=False) for k, v in schedule.items()})
    redis.conn.zadd("fs3:ai:schedules", {schedule["schedule_id"]: schedule.get("created_at") or time.time()})


def _list_ai_schedules(redis: Any) -> List[Dict[str, Any]]:
    ids = redis.conn.zrevrange("fs3:ai:schedules", 0, 200)
    schedules = []
    for schedule_id in ids:
        schedule = _load_ai_schedule(redis, schedule_id)
        if schedule:
            schedules.append(schedule)
        else:
            redis.conn.zrem("fs3:ai:schedules", schedule_id)
    schedules.sort(key=lambda item: float(item.get("created_at") or 0), reverse=True)
    return schedules


def _delete_ai_schedule(redis: Any, schedule_id: str) -> bool:
    key = f"fs3:ai:schedule:{schedule_id}"
    existed = bool(redis.conn.exists(key))
    pipe = redis.conn.pipeline()
    pipe.delete(key)
    pipe.zrem("fs3:ai:schedules", schedule_id)
    for run_id in redis.conn.zrange(f"fs3:ai:schedule:{schedule_id}:runs", 0, -1):
        pipe.delete(f"fs3:ai:schedule:{schedule_id}:run:{run_id}")
    pipe.delete(f"fs3:ai:schedule:{schedule_id}:runs")
    pipe.execute()
    return existed


def _save_ai_schedule_run(redis: Any, schedule_id: str, run: Dict[str, Any]) -> Dict[str, Any]:
    run_id = uuid.uuid4().hex[:12]
    now = time.time()
    entry = {
        "run_id": run_id,
        "schedule_id": schedule_id,
        "created_at": now,
        "created_at_iso": datetime.fromtimestamp(now).isoformat(),
        **run,
    }
    pipe = redis.conn.pipeline()
    pipe.hset(f"fs3:ai:schedule:{schedule_id}:run:{run_id}", mapping={k: json.dumps(v, ensure_ascii=False) for k, v in entry.items()})
    pipe.zadd(f"fs3:ai:schedule:{schedule_id}:runs", {run_id: now})
    pipe.zremrangebyrank(f"fs3:ai:schedule:{schedule_id}:runs", 0, -101)
    pipe.execute()
    return entry


def _list_ai_schedule_runs(redis: Any, schedule_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    run_ids = redis.conn.zrevrange(f"fs3:ai:schedule:{schedule_id}:runs", 0, max(0, limit - 1))
    runs = []
    for run_id in run_ids:
        raw = redis.conn.hgetall(f"fs3:ai:schedule:{schedule_id}:run:{run_id}")
        if raw:
            runs.append({k: _json_or_raw(v) for k, v in raw.items()})
    return runs


def _start_loop_thread(app: Flask) -> None:
    """启动后台定时线程，按每个定时任务的配置自动执行 AI 分析。"""
    if app.config.get("AI_SCHEDULE_THREAD_STARTED"):
        return
    app.config["AI_SCHEDULE_THREAD_STARTED"] = True

    def loop_worker():
        while True:
            time.sleep(15)
            try:
                redis = app.config["get_redis"]()
                now = time.time()
                for schedule in _list_ai_schedules(redis):
                    schedule_id = schedule.get("schedule_id", "")
                    interval = int(schedule.get("interval_minutes") or 0)
                    if not schedule_id or not schedule.get("enabled", True) or interval <= 0:
                        continue
                    next_run = float(schedule.get("next_run") or 0)
                    if next_run > now:
                        continue
                    lock_key = f"fs3:ai:schedule:{schedule_id}:lock"
                    if not redis.conn.set(lock_key, str(now), nx=True, ex=max(60, interval * 60)):
                        continue
                    try:
                        config = load_yaml(app.config["CONFIG_PATH"])
                        ai_cfg = _ai_config(config)
                        ai_cfg["system_prompt"] = schedule.get("system_prompt") or ai_cfg.get("system_prompt", "")
                        if schedule.get("model"):
                            ai_cfg["model"] = schedule.get("model")
                        selected_types = list(schedule.get("selected_types") or [])
                        question = str(schedule.get("question", "") or "")
                        if not selected_types or not question:
                            schedule["last_status"] = "skipped"
                            schedule["last_error"] = "事件类型或问题为空"
                        else:
                            run_data = _run_ai_analysis_once(
                                redis=redis,
                                ai_cfg=ai_cfg,
                                selected_types=selected_types,
                                question=question,
                                max_events=int(schedule.get("max_events") or 200),
                                toggles=schedule.get("toggles") or _default_ai_toggles(),
                                run_source="schedule",
                                schedule_id=schedule_id,
                            )
                            result = run_data["result"] or {}
                            ok = bool(result.get("ok"))
                            action_results = run_data["action_results"]
                            _save_ai_schedule_run(redis, schedule_id, {
                                "ok": ok,
                                "error": result.get("error", ""),
                                "answer": result.get("answer", ""),
                                "event_count": result.get("event_count", len(run_data["context_events"])),
                                "parsed_actions": run_data["parsed_actions"],
                                "action_results": action_results,
                            })
                            schedule["last_status"] = "ok" if ok else "error"
                            schedule["last_error"] = "" if ok else str(result.get("error", ""))[:500]
                        finished = time.time()
                        schedule["last_run"] = finished
                        schedule["last_run_iso"] = datetime.fromtimestamp(finished).isoformat()
                        schedule["next_run"] = finished + interval * 60
                        schedule["next_run_iso"] = datetime.fromtimestamp(schedule["next_run"]).isoformat()
                        schedule["run_count"] = int(schedule.get("run_count") or 0) + 1
                        _save_ai_schedule(redis, schedule)
                        redis.log(f"[AI-SCHEDULE] {schedule_id} status={schedule['last_status']} next={schedule['next_run_iso']}")
                    finally:
                        redis.conn.delete(lock_key)
            except Exception as exc:
                try:
                    app.logger.exception("AI schedule loop failed: %s", exc)
                except Exception:
                    pass

    t = threading.Thread(target=loop_worker, daemon=True)
    t.start()


def run_web() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="FlowScan3 Web Control Panel")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--modules-dir", default="modules")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    config = load_yaml(args.config)
    web_cfg = {**DEFAULT_WEB_CONFIG, **(config.get("web_config", {}) or {})}
    host = args.host or web_cfg["host"]
    port = args.port or int(web_cfg["port"])
    app = create_app(args.config, args.modules_dir)
    print(f"[WEB] FlowScan3 Web Panel starting on http://{host}:{port}")
    print(f"[WEB] Login: {web_cfg['username']} / {web_cfg['password']} (configured in {args.config})")
    app.run(host=host, port=port, debug=args.debug)


if __name__ == "__main__":
    run_web()
