"""C2 面板状态接口(代码片段库 + 命令历史)—— 服务端加密落盘, 不落浏览器。

2026-09-28 新增:前端原先用 localStorage 的 fs3_c2_snippets / fs3_c2_history,
现全部改走后端(见 web_app/secure_store.py:ChaCha20+HMAC 加密写文件)。

鉴权与其它模块一致(登录会话);但未登录时返回 **JSON 401** 而不是跳登录页 ——
否则前端 fetch 会拿到一坨 HTML, 报错只能显示"保存失败"看不出原因。
"""
from functools import wraps

from flask import jsonify, request, session

from . import secure_store as store


def _api_login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"ok": False, "message": "未登录或会话已过期"}), 401
        return func(*args, **kwargs)
    return wrapper


def register(app):
    store.set_config_path(app.config.get("CONFIG_PATH", ""))

    @app.route("/api/c2/state")
    @_api_login_required
    def c2_state_get():
        try:
            return jsonify(store.SecureStore().get_state())
        except store.StoreError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 500

    @app.route("/api/c2/history", methods=["POST"])
    @_api_login_required
    def c2_state_history_add():
        body = request.get_json(silent=True) or {}
        try:
            return jsonify(store.SecureStore().add_history(body.get("line", "")))
        except store.StoreError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 500

    @app.route("/api/c2/history/clear", methods=["POST"])
    @_api_login_required
    def c2_state_history_clear():
        try:
            return jsonify(store.SecureStore().clear_history())
        except store.StoreError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 500

    @app.route("/api/c2/snippets", methods=["POST"])
    @_api_login_required
    def c2_state_snippets_save():
        body = request.get_json(silent=True) or {}
        try:
            return jsonify(store.SecureStore().set_snippets(body.get("snippets") or []))
        except store.StoreError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 500
