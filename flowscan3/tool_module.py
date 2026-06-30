import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

import yaml


@dataclass
class ToolModule:
    name: str
    yaml_path: str
    description: str = ""
    input_events: List[str] = field(default_factory=list)
    allowed_output_events: List[str] = field(default_factory=list)
    input_transform_code: str = ""
    command_template: str = ""
    output_parse_code: str = ""
    max_concurrency: int = 1
    exec_timeout: int = 600
    check_command: str = ""
    expect_keyword: str = ""
    exclude_keyword: str = ""
    install_steps: List[str] = field(default_factory=list)
    install_timeout: int = 900
    enabled: bool = True

    @classmethod
    def from_yaml(cls, path: str) -> "ToolModule":
        with open(path, "r", encoding="utf-8") as handle:
            cfg = yaml.safe_load(handle) or {}
        if not isinstance(cfg, dict):
            raise ValueError(f"invalid YAML object: {path}")
        name = cfg.get("name") or os.path.splitext(os.path.basename(path))[0]
        runtime = cfg.get("runtime", {}) or {}
        io_contract = cfg.get("io_contract", {}) or {}
        execution = cfg.get("execution", {}) or {}
        check = cfg.get("check", {}) or {}
        install = cfg.get("install", {}) or {}
        return cls(
            name=name,
            yaml_path=os.path.abspath(path),
            description=cfg.get("description", ""),
            input_events=list(io_contract.get("input_events", []) or []),
            allowed_output_events=list(cfg.get("allowed_output_events", []) or []),
            input_transform_code=io_contract.get("input_transform_code", ""),
            command_template=execution.get("command", ""),
            output_parse_code=execution.get("output_parse_code", ""),
            max_concurrency=max(1, int(runtime.get("max_concurrency", 1))),
            exec_timeout=int(runtime.get("exec_timeout_seconds", 600)),
            check_command=check.get("command", ""),
            expect_keyword=check.get("expect_keyword", ""),
            exclude_keyword=check.get("exclude_keyword", ""),
            install_steps=list(install.get("steps", []) or []),
            install_timeout=int(install.get("install_timeout_seconds", 900)),
            enabled=bool(cfg.get("enabled", True)),
        )

    def can_consume(self, event_type: str) -> bool:
        return self.enabled and event_type in self.input_events


def load_tools(modules_dir: str) -> Dict[str, ToolModule]:
    tools: Dict[str, ToolModule] = {}
    if not os.path.isdir(modules_dir):
        return tools
    for filename in sorted(os.listdir(modules_dir)):
        if not filename.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(modules_dir, filename)
        try:
            tool = ToolModule.from_yaml(path)
            if not tool.input_events or not tool.command_template:
                print(f"[TOOL] skip invalid module {filename}: missing input_events or command")
                continue
            tools[tool.name] = tool
            print(f"[TOOL] loaded {tool.name}: inputs={tool.input_events} concurrency={tool.max_concurrency}")
        except Exception as exc:
            print(f"[TOOL] failed to load {filename}: {exc}")
    return tools


def event_map_for(tools: Dict[str, ToolModule]) -> Dict[str, List[ToolModule]]:
    mapping: Dict[str, List[ToolModule]] = {}
    for tool in tools.values():
        if not tool.enabled:
            continue
        for event_type in tool.input_events:
            mapping.setdefault(event_type, []).append(tool)
    return mapping
