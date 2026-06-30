import os
import re
from typing import Any, Dict

import yaml


def load_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data if isinstance(data, dict) else {}


def get_config_value(config: Dict[str, Any], dotted_path: str, default: Any = "") -> Any:
    current: Any = config
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


def render_template(template: str, context: Dict[str, Any], config: Dict[str, Any] | None = None) -> str:
    if not isinstance(template, str):
        return str(template)
    config = config or {}

    def replace(match: re.Match[str]) -> str:
        expr = match.group(1).strip()
        if expr.startswith("config."):
            return str(get_config_value(config, expr[len("config."):], ""))
        return str(context.get(expr, ""))

    return _PLACEHOLDER_RE.sub(replace, template)
