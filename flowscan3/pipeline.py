from typing import Any, Dict, List

from .code_runner import CodeExecutionError, run_input_transform, run_output_parse
from .config import render_template
from .tool_module import ToolModule
from .utils import run_cmd


class EventPipeline:
    def __init__(self, node_id: str, config: Dict[str, Any], debug: bool = False):
        self.node_id = node_id
        self.config = config
        self.debug = debug

    def process(self, event: Dict[str, Any], tool: ToolModule, redis_client: Any) -> int:
        event_type = event.get("event_type", "")
        event_value = event.get("value", "")
        parent_fp = event.get("fingerprint", "")
        root_fp = event.get("root_fp", "") or parent_fp
        redis_client.log(f"[{self.node_id}] [{tool.name}] processing {event_type}={event_value[:100]}")
        params_list = self._transform(event_type, event_value, tool, redis_client)
        published = 0
        for params in params_list:
            command = render_template(tool.command_template, params, self.config)
            redis_client.log(f"[{self.node_id}] [{tool.name}] exec {command[:240]}")
            ok, output, code = run_cmd(command, timeout=tool.exec_timeout)
            if self.debug:
                redis_client.log(f"[{self.node_id}] [{tool.name}] stdout: {output}")
            if not ok:
                redis_client.log(f"[{self.node_id}] [{tool.name}] exit={code} {output[:300]}")
                continue
            parsed = self._parse(output, tool, redis_client)
            for item in parsed:
                for out_type, out_value in item.items():
                    if not out_type or out_value in (None, ""):
                        continue
                    if tool.allowed_output_events and out_type not in tool.allowed_output_events:
                        redis_client.log(f"[{self.node_id}] [{tool.name}] drop output {out_type}, not allowed")
                        continue
                    fp = redis_client.push_event(
                        out_type,
                        str(out_value),
                        source_tool=tool.name,
                        parent_fp=parent_fp,
                        root_fp=root_fp,
                    )
                    if fp:
                        published += 1
        redis_client.log(f"[{self.node_id}] [{tool.name}] done published={published}")
        return published

    def _transform(self, event_type: str, event_value: str, tool: ToolModule, redis_client: Any) -> List[Dict[str, Any]]:
        if not tool.input_transform_code:
            return [{"target": event_value, "value": event_value, "event_type": event_type}]
        try:
            params = run_input_transform(tool.input_transform_code, {"event_type": event_type, "value": event_value}, self.config)
            for param in params:
                param.setdefault("value", event_value)
                param.setdefault("target", event_value)
                param.setdefault("event_type", event_type)
            return params
        except CodeExecutionError as exc:
            redis_client.log(f"[{self.node_id}] [{tool.name}] transform error: {exc}")
            return []

    def _parse(self, output: str, tool: ToolModule, redis_client: Any) -> List[Dict[str, Any]]:
        if not tool.output_parse_code:
            return []
        try:
            return run_output_parse(tool.output_parse_code, output, self.config)
        except CodeExecutionError as exc:
            redis_client.log(f"[{self.node_id}] [{tool.name}] parse error: {exc}")
            return []
