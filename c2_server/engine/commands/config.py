"""config — 显示当前配置"""


def run(disp, args):
    cfg = disp.config
    lines = [
        f"Server: {cfg.server_host}:{cfg.server_port} (implant) / "
        f"client_port: {cfg.client_port}",
        f"Modules: {cfg.modules_dir}",
        f"Event file: {cfg.event_file}",
        f"Max frame: {cfg.max_frame_size // 1024}KB",
        f"Max tasks/beacon: {cfg.max_tasks_per_client}",
        f"exec 超时: {cfg.exec_timeout}s",
        f"client TLS: {'开' if cfg.client_tls else '关'}",
    ]
    if cfg.auto_commands:
        lines.append(f"自动命令: {', '.join(cfg.auto_commands)}")
    return "\n".join(lines)
