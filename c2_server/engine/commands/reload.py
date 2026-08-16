"""reload — 重新加载配置文件 + 热加载植入模块

流程: 重新读取 config.json → 原地更新运行中的 ServerConfig（后续新连接/
新任务读取即用新值）→ 同步已创建组件（模块目录/大小、任务上限、结果条数）
→ 重扫植入模块。

启动期基础设施（端口、密钥、event_file、log_file）变更需重启 server。
"""

import os

from server.core.config import load_config, ServerConfig


def run(disp, args):
    cfg = disp.config
    cfg_path = getattr(cfg, "config_path", "") or os.path.join(
        cfg.base_dir, "config.json")
    try:
        new = load_config(cfg_path)
    except Exception as e:
        return f"[!] 配置重载失败: {e}"
    if not isinstance(new, ServerConfig):
        return f"[!] 配置重载失败: {cfg_path} 不是 server 配置"

    changed = [f.name for f in ServerConfig.__dataclass_fields__.values()
               if f.name != "config_path"
               and getattr(new, f.name) != getattr(cfg, f.name)]

    # 原地更新运行中 config（base_dir/config_path 保留原值）
    for f in ServerConfig.__dataclass_fields__.values():
        if f.name not in ("config_path", "base_dir"):
            setattr(cfg, f.name, getattr(new, f.name))

    # 同步已创建组件
    disp.modules.reconfigure(modules_dir=cfg.modules_dir,
                             max_task_code_size=cfg.max_task_code_size)
    disp.smods.reconfigure(modules_dir=cfg.server_modules_dir)
    disp.tq.set_max_tasks(cfg.max_tasks_per_client)
    disp.mgr.set_max_results(cfg.max_results_per_beacon)
    disp.modules.reload()

    lines = ["[+] 配置已重载，模块已重扫"]
    if changed:
        lines.append("    变更: " + ", ".join(sorted(changed)))
    lines.append("    注意: server_port/client_port/密钥/event_file/log_file"
                 " 变更需重启生效，其余已热生效")
    return "\n".join(lines)
