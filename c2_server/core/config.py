"""
core/config.py — 配置加载 (ServerConfig / ClientConfig)

服务端配置 (server/config.json):
  server_host, server_port (implant 端口), client_port (client 端口),
  implant_key (beacon↔server), client_key (client↔server),
  socket_timeout, modules_dir, event_file, log_file,
  max_frame_size, max_result_size, max_task_code_size,
  max_tasks_per_client, max_results_per_beacon, max_connections,
  client_timeout, auto_commands

  客户端配置 (client/config.json):
  server_host, client_port, client_key

约定 (T1.3):
  - 未知 key 告警而非静默丢弃 (E4)
  - 相对路径基于配置文件所在目录解析，不 chdir (E6)
  - validate() 返回问题列表（空列表 = 合法）
  - 空 key 不视为错误（server 启动兜底自动生成，见 10.1）
"""

import json
import os
import warnings
from dataclasses import dataclass, field


def _is_hex64(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdefABCDEF" for c in value)
    )


@dataclass
class ServerConfig:
    """Server 配置。JSON 缺失字段用默认值。"""

    server_host: str = "0.0.0.0"
    server_port: int = 9001          # implant 监听端口
    client_port: int = 9002          # client 监听端口（10.1 端口分离）
    socket_timeout: int = 30
    implant_key: str = ""            # beacon ↔ server 密钥（原 xor_key）
    client_key: str = ""             # client ↔ server 密钥
    modules_dir: str = "modules"
    server_modules_dir: str = "s_modules"
    event_file: str = "events.jsonl"
    log_file: str = "server.log"
    max_frame_size: int = 524288     # 512 KB
    max_result_size: int = 1048576   # 1 MB
    max_task_code_size: int = 262144 # 256 KB
    max_tasks_per_client: int = 100
    max_results_per_beacon: int = 200
    max_connections: int = 256
    client_timeout: int = 300
    beacon_expire_seconds: int = 86400  # beacon 过期清理时限（秒，默认 1 天；超时未回连即移除）
    client_tls: bool = False         # client 远程通道启用 TLS（防嗅探）
    auto_commands: list = field(default_factory=list)
    stage_code: str = ""           # 分段载荷第二段代码(stage 命令设定;新 beacon 首次上线下发, 引导代码 exec)
    base_dir: str = ""               # 配置文件所在目录（load_config 设置）
    config_path: str = ""            # 配置文件绝对路径（load_config 设置，reload 用）

    def validate(self) -> list:
        """返回配置问题列表；空列表 = 合法。"""
        problems = []
        for name, port in (("server_port", self.server_port),
                           ("client_port", self.client_port)):
            # 0 = 该通道关闭(web 通道配置「填 0 关闭」语义,2026-09-04);
            # 其余必须落在合法端口区间
            if not isinstance(port, int) or port < 0 or port > 65535:
                problems.append(f"{name}: invalid port {port!r}")
        for name, val in (
            ("socket_timeout", self.socket_timeout),
            ("max_frame_size", self.max_frame_size),
            ("max_result_size", self.max_result_size),
            ("max_task_code_size", self.max_task_code_size),
            ("max_tasks_per_client", self.max_tasks_per_client),
            ("max_results_per_beacon", self.max_results_per_beacon),
            ("max_connections", self.max_connections),
            ("client_timeout", self.client_timeout),
            ("beacon_expire_seconds", self.beacon_expire_seconds),
        ):
            if not isinstance(val, int) or val <= 0:
                problems.append(f"{name}: must be positive int, got {val!r}")
        if self.implant_key and not _is_hex64(self.implant_key):
            problems.append(
                f"implant_key: invalid hex "
                f"(got {len(self.implant_key)} chars, need 64)")
        if self.client_key and not _is_hex64(self.client_key):
            problems.append(
                f"client_key: invalid hex "
                f"(got {len(self.client_key)} chars, need 64)")
        return problems

    def resolve_path(self, rel: str) -> str:
        """相对路径基于 base_dir 解析；绝对路径原样返回。"""
        if not rel or os.path.isabs(rel) or not self.base_dir:
            return rel
        return os.path.join(self.base_dir, rel)


@dataclass
class ClientConfig:
    """Client 配置（操作员端）。"""

    server_host: str = "127.0.0.1"
    client_port: int = 9002
    client_key: str = ""
    client_tls: bool = False         # 与 server client_tls 保持一致

    def validate(self) -> list:
        problems = []
        if not isinstance(self.client_port, int) or \
                not (1 <= self.client_port <= 65535):
            problems.append(f"client_port: invalid port {self.client_port!r}")
        if self.client_key and not _is_hex64(self.client_key):
            problems.append(
                f"client_key: invalid hex "
                f"(got {len(self.client_key)} chars, need 64)")
        return problems


def _filter_fields(cls, raw: dict) -> dict:
    """按 dataclass 字段过滤；未知 key 告警。"""
    valid = {f.name for f in cls.__dataclass_fields__.values()}
    kwargs = {}
    for k, v in raw.items():
        if k in valid:
            kwargs[k] = v
        else:
            warnings.warn(f"config: unknown key '{k}' ignored",
                          UserWarning, stacklevel=2)
    return kwargs


def _looks_like_client(raw: dict, path: str = "") -> bool:
    """推断配置类型：显式 type > 目录名 > 启发式（S9）。

    - "type": "client"/"server" 显式指定优先
    - 目录名含 client → ClientConfig；含 server → ServerConfig
      （极简 server 配置不会被误判为 client）
    - 兜底启发式：含 client_key 且无 server 特有字段 → client
    """
    if "type" in raw:
        return str(raw["type"]).lower() == "client"
    if path:
        base = os.path.basename(os.path.dirname(os.path.abspath(path))).lower()
        if "client" in base:
            return True
        if "server" in base:
            return False
    server_only = ("implant_key", "modules_dir", "event_file",
                   "max_connections", "auto_commands")
    # server_port（implant 端口）是 ServerConfig 独有字段
    # （ClientConfig 只有 client_port）→ 极简 server 配置不误判
    if "client_key" in raw and "server_port" in raw:
        return False
    return "client_key" in raw and not any(k in raw for k in server_only)


def load_config(path: str):
    """从 JSON 文件加载配置（自动推断 ServerConfig / ClientConfig）。

    Args:
        path: JSON 配置文件路径

    Returns:
        ServerConfig 或 ClientConfig 实例

    Raises:
        FileNotFoundError: 文件不存在
        json.JSONDecodeError: JSON 语法错误
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    base_dir = os.path.dirname(os.path.abspath(path))

    if _looks_like_client(raw, path):
        cfg = ClientConfig(**_filter_fields(ClientConfig, raw))
        cfg.base_dir = base_dir
        return cfg

    cfg = ServerConfig(**_filter_fields(ServerConfig, raw))
    cfg.base_dir = base_dir
    cfg.config_path = os.path.abspath(path)
    # 相对路径统一解析到配置文件目录（E6）
    cfg.modules_dir = cfg.resolve_path(cfg.modules_dir)
    cfg.server_modules_dir = cfg.resolve_path(cfg.server_modules_dir)
    cfg.event_file = cfg.resolve_path(cfg.event_file)
    cfg.log_file = cfg.resolve_path(cfg.log_file)
    return cfg
