"""FlowScan Web 控制端(Flask 应用工厂)。

路由按功能域拆分到 web_app/ 下各子模块(auth / dashboard / events /
template_lab / ai_config / ai_logs / ai_analysis / ai_schedule / agent / c2 / views),
每个模块暴露 register(app) 函数,由 create_app 统一注册。端点名保持不变,
模板中的 url_for(...) 引用零改动。
"""
import os
import threading

from flask import Flask

from flowscan import c2_bridge
from flowscan import phishing_bridge
from flowscan.config import load_yaml
from flowscan.redis_store import FlowScanRedis
from flowscan.utils import project_root

from . import (
    agent,
    ai_analysis,
    ai_config,
    ai_logs,
    ai_schedule,
    auth,
    c2,
    dashboard,
    events,
    template_lab,
    views,
)
from ._common import fmt_ts

DEFAULT_WEB_CONFIG = {
    "username": "admin",
    "password": "admin",
    "secret_key": "flowscan-secret-change-me",
    "session_ttl": 3600,
    "host": "0.0.0.0",
    "port": 8080,
}

# 按依赖顺序注册路由(端点名不变;顺序不影响 url_for 运行时解析)
_ROUTE_MODULES = (
    auth,
    dashboard,
    events,
    template_lab,
    ai_config,
    ai_logs,
    ai_analysis,
    ai_schedule,
    agent,
    c2,
    views,
)

# ── 进程级 Redis 连接复用 ──
# 此前每请求新建一条 TCP 连接;改为按连接参数缓存的单例(redis-py 线程安全),
# 高频 API/自动刷新/定时线程共享同一连接,避免连接 churn。
_redis_pool: dict = {}
_redis_pool_lock = threading.Lock()


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
        "host": redis_cfg.get("redis_host", "127.0.0.1"),
        "port": int(redis_cfg.get("redis_port", 6379)),
        "password": redis_cfg.get("password", ""),
        "db": int(redis_cfg.get("db", 0)),
    }

    def get_redis() -> FlowScanRedis:
        key = tuple(sorted(app.config["REDIS"].items()))
        with _redis_pool_lock:
            client = _redis_pool.get(key)
            if client is None:
                client = FlowScanRedis(**app.config["REDIS"])
                _redis_pool[key] = client
            return client

    app.config["get_redis"] = get_redis
    c2_bridge.set_flowscan_config(config_path)
    phishing_bridge.set_flowscan_config(config_path)

    # 公共模板 filter:Unix 时间戳 → 人读时间(模板里 `{{ ts|fmt_ts }}`)
    app.jinja_env.filters["fmt_ts"] = fmt_ts

    for module in _ROUTE_MODULES:
        module.register(app)

    ai_schedule._start_loop_thread(app)

    # 存量事件补建时间索引：此前仅 worker 启动时执行,纯 web 部署(无 worker)
    # 会导致升级前注入的存量事件缺失索引、事件查询页显示 0。
    # 这里在 web 启动时同步补建一次(幂等,SET NX 只执行一次;失败不影响启动)。
    try:
        app.config["get_redis"]().ensure_time_index()
        app.config["get_redis"]().ensure_root_index()
    except Exception:
        pass

    # Agent 孤儿任务检测:web 重启后残留 status=running 的会话没有线程在跑,
    # 标记为 interrupted 避免前端假死(任务线程表是进程内存,已随重启清空)。
    try:
        orphan = agent._recover_orphan_agent_sessions(app.config["get_redis"]())
        if orphan:
            print(f"[WEB] recovered {orphan} orphan agent session(s)")
    except Exception:
        pass

    # Skill 渐进式加载关闭提示(config.yaml 显式 enabled:false 会覆盖代码默认 True,
    # 静默关闭容易误以为功能坏了;启动时打一条 warning)
    try:
        skills_cfg = config.get("skills", {}) or {}
        if not _to_bool(skills_cfg.get("enabled", True)):
            app.logger.warning("skills.enabled=false:Skill 渐进式加载已关闭,Agent 的 load_skill/search_skills 工具不可用")
    except Exception:
        pass

    # 默认技能库目录(项目内 skills/):不存在则创建,保证 AI 管理默认有技能目录可用
    try:
        os.makedirs(os.path.join(project_root(), "skills"), exist_ok=True)
    except Exception:
        pass
    return app


def run_web() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="FlowScan Web Control Panel")
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
    print(f"[WEB] FlowScan Web Panel starting on http://{host}:{port}")
    print(f"[WEB] Login: {web_cfg['username']} (密码见 {args.config} 的 web_config.password)")
    app.run(host=host, port=port, debug=args.debug)


if __name__ == "__main__":
    run_web()
