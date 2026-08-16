"""AI 分析页面路由:分析启动(后台任务)/ 任务轮询 / 一键执行动作。"""
from flask import jsonify, redirect, render_template, request, url_for

from flowscan.config import load_yaml

from ._common import login_required
from ._helpers import _event_types
from .ai_config import _ai_config
from .ai_core import (
    _AI_TASKS,
    _AI_TASKS_LOCK,
    _analysis_request_from_form,
    _default_ai_toggles,
    _execute_ai_actions,
    _start_ai_task,
)
from .ai_schedule import _list_ai_schedules


def register(app):
    @app.route("/ai-analysis")
    @login_required
    def ai_analysis():
        redis = app.config["get_redis"]()
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        event_types = _event_types(redis)
        max_events = int(ai_cfg.get("max_events", 200))
        toggles = _default_ai_toggles()
        schedules = _list_ai_schedules(redis)
        tab = request.args.get("tab", "agent")
        if tab not in ("schedule", "agent", "logs", "config"):
            tab = "agent"
        # 无 JS 兜底:?new_session=1 直接创建默认名称会话并跳转 Agent tab
        # (按钮是链接,JS 正常时拦截弹窗输入名称;JS 不可用时此路径保证新建会话可用)
        if request.args.get("new_session") == "1":
            from .agent import _create_agent_session  # 延迟 import,避免循环依赖

            sess = _create_agent_session(redis, "新会话", ai_cfg.get("model", ""))
            return redirect(url_for("ai_analysis", tab="agent", session=sess["session_id"]))
        return render_template(
            "ai_analysis.html",
            tab=tab,
            event_types=event_types,
            selected_types=[],
            question="",
            max_events=max_events,
            ai_cfg=ai_cfg,
            result=None,
            context_events=[],
            toggles=toggles,
            action_results=[],
            parsed_actions=[],
            schedules=schedules,
            log_api_key=ai_cfg.get("log_api_key", ""),
        )

    @app.route("/api/ai-analysis/run", methods=["POST"])
    @login_required
    def ai_analysis_run():
        config = load_yaml(app.config["CONFIG_PATH"])
        ai_cfg = _ai_config(config)
        selected_types, question, max_events, toggles = _analysis_request_from_form(request.form, ai_cfg)
        if not selected_types:
            return jsonify({"ok": False, "error": "至少选择一个事件类型"}), 400
        if not question:
            return jsonify({"ok": False, "error": "问题不能为空"}), 400
        redis = app.config["get_redis"]()
        task_id = _start_ai_task(redis, ai_cfg, selected_types, question, max_events, toggles)
        return jsonify({"ok": True, "task_id": task_id})

    @app.route("/api/ai-task/<task_id>")
    @login_required
    def ai_task_status(task_id: str):
        with _AI_TASKS_LOCK:
            task = _AI_TASKS.get(task_id)
        if not task:
            return jsonify({"status": "not_found"}), 404
        return jsonify(task)

    @app.route("/api/ai-actions/execute", methods=["POST"])
    @login_required
    def ai_actions_execute():
        data = request.get_json(silent=True) or {}
        task_id = str(data.get("task_id", "") or request.form.get("task_id", ""))
        with _AI_TASKS_LOCK:
            task = _AI_TASKS.get(task_id)
        if not task:
            return jsonify({"ok": False, "error": "任务不存在"}), 400
        if task.get("status") != "done":
            return jsonify({"ok": False, "error": "任务未完成"}), 400
        if task.get("executed"):
            return jsonify({"ok": True, "executed": True, "action_results": task.get("action_results", [])})
        redis = app.config["get_redis"]()
        parsed_actions = task.get("parsed_actions", [])
        toggles = task.get("toggles", _default_ai_toggles())
        # 预览列表里都是"未勾选自动执行"的剩余动作：一键执行时全部落地，
        # 仅保留 del_children 级联开关（自动执行开关不再过滤预览动作）
        preview_toggles = {**toggles,
                           **{t: True for t in ("add", "del", "blacklist_add", "blacklist_del", "log")}}
        action_results = _execute_ai_actions(parsed_actions, redis, preview_toggles, source="manual")
        with _AI_TASKS_LOCK:
            task["executed"] = True
            task["action_results"] = action_results
        return jsonify({"ok": True, "executed": True, "action_results": action_results})
