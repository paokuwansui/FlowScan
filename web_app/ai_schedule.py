"""定时 AI 分析任务:数据层 + 路由 + 后台调度循环。"""
import json
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import flash, jsonify, redirect, render_template, request, url_for

from flowscan.config import load_yaml

from ._common import _json_or_raw, _to_int, login_required
from .ai_config import _ai_config
from .ai_core import _analysis_request_from_form, _default_ai_toggles, _run_ai_analysis_once


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


def _start_loop_thread(app) -> None:
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
                try:
                    _config = load_yaml(app.config["CONFIG_PATH"])
                    _timeout = int(_ai_config(_config).get("timeout_seconds", 120) or 120)
                except Exception:
                    _config = {}
                    _timeout = 120
                for schedule in _list_ai_schedules(redis):
                    schedule_id = schedule.get("schedule_id", "")
                    interval = int(schedule.get("interval_minutes") or 0)
                    if not schedule_id or not schedule.get("enabled", True) or interval <= 0:
                        continue
                    next_run = float(schedule.get("next_run") or 0)
                    if next_run > now:
                        continue
                    lock_key = f"fs3:ai:schedule:{schedule_id}:lock"
                    # 锁存活时间必须覆盖 LLM 调用超时,否则下一轮轮询会重复执行
                    if not redis.conn.set(lock_key, str(now), nx=True, ex=max(_timeout + 60, interval * 60)):
                        continue
                    try:
                        config = _config
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


def register(app):
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

    @app.route("/api/ai-schedule/<schedule_id>/toggle", methods=["POST"])
    @login_required
    def ai_schedule_toggle(schedule_id: str):
        """切换定时任务的启用/暂停状态（enabled 字段，调度循环据此跳过）。"""
        redis = app.config["get_redis"]()
        schedule = _load_ai_schedule(redis, schedule_id)
        if not schedule:
            return jsonify({"ok": False, "error": "未找到定时任务"}), 404
        schedule["enabled"] = not bool(schedule.get("enabled", True))
        _save_ai_schedule(redis, schedule)
        redis.log(f"[AI-SCHEDULE] {schedule_id} enabled={schedule['enabled']}")
        return jsonify({"ok": True, "enabled": schedule["enabled"]})

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
