"""认证路由:登录 / 登出(含登录失败限速)。"""
import threading
import time

from flask import flash, redirect, render_template, request, session as flask_session, url_for

# ── 登录限速（进程内存态） ──
# 同一 IP+用户名:10 分钟窗口内失败 5 次 → 锁定 5 分钟（期间正确密码也拒绝）。
_MAX_FAILS = 5
_WINDOW_SECONDS = 600
_LOCK_SECONDS = 300

_login_records = {}   # key -> {"fails": int, "first": ts, "blocked_at": ts}
_login_lock = threading.Lock()


def _login_key() -> str:
    return f"{request.remote_addr or '?'}:{request.form.get('username', '')}"


def _is_blocked(key: str) -> bool:
    with _login_lock:
        rec = _login_records.get(key)
        if not rec:
            return False
        now = time.time()
        if rec.get("blocked_at") and now - rec["blocked_at"] < _LOCK_SECONDS:
            return True
        if now - rec["first"] > _WINDOW_SECONDS:
            _login_records.pop(key, None)   # 窗口过期，顺带清理陈旧记录
        return False


def _record_failure(key: str) -> None:
    with _login_lock:
        now = time.time()
        rec = _login_records.get(key)
        if not rec or now - rec["first"] > _WINDOW_SECONDS:
            rec = {"fails": 0, "first": now, "blocked_at": 0}
        rec["fails"] += 1
        if rec["fails"] >= _MAX_FAILS:
            rec["blocked_at"] = now
        _login_records[key] = rec


def _reset_login(key: str) -> None:
    with _login_lock:
        _login_records.pop(key, None)


def register(app):
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            key = _login_key()
            if _is_blocked(key):
                flash(f"尝试次数过多，已临时锁定 {_LOCK_SECONDS // 60} 分钟，请稍后再试", "error")
                return render_template("login.html")
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if username == app.config["WEB_USERNAME"] and password == app.config["WEB_PASSWORD"]:
                _reset_login(key)
                flask_session["logged_in"] = True
                flask_session.permanent = True
                app.permanent_session_lifetime = app.config["SESSION_TTL"]
                return redirect(url_for("index"))
            _record_failure(key)
            flash("用户名或密码错误", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        flask_session.pop("logged_in", None)
        return redirect(url_for("login"))
