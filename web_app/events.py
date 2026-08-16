"""事件管理路由:事件列表 / 注入 / 删除 / 清空 / 快照,以及黑名单 / 白名单 API。"""
import json

from flask import flash, jsonify, redirect, render_template, request, url_for

from flowscan.filter import (
    add_redis_rule,
    add_redis_whitelist_rule,
    delete_redis_rule,
    delete_redis_whitelist_rule,
    get_file_rules,
    get_redis_rules,
    get_redis_whitelist_rules,
    reload_file_rules,
    test_file_rules,
    test_redis_rules,
    test_redis_whitelist,
)
from flowscan.redis_store import FlowScanRedis

from ._common import _to_int, login_required
from ._helpers import (
    _clear_all_events,
    _count_events,
    _event_types,
    _full_export,
    _full_import,
    _list_events,
    _parse_event_line,
    _remove_event,
    _remove_targets,
)


def register(app):
    @app.route("/events")
    @login_required
    def events():
        redis = app.config["get_redis"]()
        search_val = request.args.get("search_val", "").strip()
        tab = request.args.get("tab", "events")
        event_types = _event_types(redis)
        total_events = _count_events(redis)
        events_list = []
        search_window = 1000   # 事件管理页无类型过滤,保持全类型硬上限并明确标注
        if search_val:
            term = search_val.lower()
            # 硬上限：只搜最近 search_window 条（时间索引），避免全量集合扫描。
            # 大数据量搜索建议到事件查询页:先选类型再搜,窗口放大到 5000 且可分页。
            for event in _list_events(redis, limit=search_window):
                if term in (event.get("value") or "").lower():
                    events_list.append(event)
        return render_template(
            "events.html",
            events=events_list,
            event_types=event_types,
            total_events=total_events,
            search_val=search_val,
            search_window=search_window,
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
            # 每行可解析出多个目标:显式 [类型]/大写前缀 → 单条指纹;
            # 纯值(无类型前缀)→ 匹配所有事件类型中值相等的全部事件
            for fp in _remove_targets(redis, line):
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

    # ================================================================
    # 白名单管理 API
    # ================================================================

    @app.route("/api/whitelist/redis-rules")
    @login_required
    def whitelist_redis_rules():
        redis = app.config["get_redis"]()
        return jsonify(get_redis_whitelist_rules(redis))

    @app.route("/api/whitelist/add", methods=["POST"])
    @login_required
    def whitelist_add():
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
        fp = add_redis_whitelist_rule(redis, event_type, match_mode, value, comment)
        if fp:
            return jsonify({"ok": True, "fp": fp})
        return jsonify({"ok": False, "error": "规则已存在或添加失败"})

    @app.route("/api/whitelist/delete", methods=["POST"])
    @login_required
    def whitelist_delete():
        redis = app.config["get_redis"]()
        data = request.get_json(silent=True) or {}
        fp = str(data.get("fp", "")).strip()
        if not fp:
            return jsonify({"ok": False, "error": "fp 不能为空"})
        ok = delete_redis_whitelist_rule(redis, fp)
        return jsonify({"ok": ok, "deleted": ok})

    @app.route("/api/whitelist/test", methods=["POST"])
    @login_required
    def whitelist_test():
        redis = app.config["get_redis"]()
        data = request.get_json(silent=True) or {}
        event_type = str(data.get("event_type", "DNS_NAME")).strip()
        value = str(data.get("value", "")).strip()
        if not value:
            return jsonify({"ok": False, "error": "value 不能为空"})
        matches = test_redis_whitelist(redis, event_type, value)
        has_rules = bool(get_redis_whitelist_rules(redis))
        allowed = (not has_rules) or bool(matches)
        return jsonify({
            "ok": True,
            "total": len(matches),
            "matches": matches,
            "has_rules": has_rules,
            "allowed": allowed,
            "blocked": not allowed,
        })
