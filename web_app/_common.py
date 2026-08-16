"""web_app 共享层:登录校验装饰器 + 通用小工具。

被所有子模块(register(app))复用的最小工具集合,不依赖任何业务模块,
避免循环导入。"""
from functools import wraps
from typing import Any, Optional

from flask import redirect, session as flask_session, url_for


def login_required(func):
    """要求已登录,否则跳转登录页。"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not flask_session.get("logged_in"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def _json_or_raw(value: str) -> Any:
    """尝试 JSON 解析,失败原样返回(Redis 存的字段可能是 str 或 JSON)。"""
    import json
    try:
        return json.loads(value)
    except Exception:
        return value


def _to_int(value: Optional[str], default: int) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _safe_ping(redis) -> bool:
    try:
        return redis.ping()
    except Exception:
        return False


def _to_bool(v) -> bool:
    """把 bool / str / int 稳健转 bool(字符串 'false' 不当 True)。"""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    return str(v).strip().lower() in ("1", "true", "on", "yes")


def _html_escape(value: str) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def fmt_ts(value) -> str:
    """Unix 时间戳(秒/毫秒浮点或字符串)→ 'YYYY-MM-DD HH:MM:SS';无效输入返回 '-'。

    供模板以 `{{ ts|fmt_ts }}` 使用,统一人读时间格式,替代散落的 %.2f epoch 浮点。
    """
    from datetime import datetime

    if value is None or value == "":
        return "-"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    if v <= 0:
        return "-"
    if v > 1e11:  # 毫秒量级(1e12)自动转秒
        v /= 1000.0
    try:
        return datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return str(value)
