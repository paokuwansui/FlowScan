from typing import Any, Dict, List, Tuple

from .code_runner import CodeExecutionError, run_input_transform, run_output_parse
from .config import render_template
from .tool_module import ToolModule
from .utils import run_cmd


class EventPipeline:
    def __init__(self, node_id: str, config: Dict[str, Any], debug: bool = False):
        self.node_id = node_id
        self.config = config
        self.debug = debug

    def process(self, event: Dict[str, Any], tool: ToolModule, redis_client: Any) -> Tuple[int, bool, str]:
        """执行工具命令并发布子事件。

        返回 (published, failed, reason):
          published=发布子事件数;failed=True 表示本次执行未成功(调用方应释放锁、
          pending 保留,而非标记 done);reason 说明失败环节:
          "exit"(命令 exit≠0)/ "transform"(输入变换代码异常)/ "parse"(输出解析
          代码异常),空串=成功。

        2026-09-15: transform/parse 的沙箱异常此前只返回 [] 且 failed=False →
        事件被标记 done 并从 pending 摘掉,链路静默断头(模块 YAML 用了沙箱不
        支持的名字/语法就永不重试)。现统一按失败处理,交给 worker 的本地
        指数退避重试。
        """
        event_type = event.get("event_type", "")
        event_value = event.get("value", "")
        parent_fp = event.get("fingerprint", "")
        root_fp = event.get("root_fp", "") or parent_fp
        redis_client.log(f"[{self.node_id}] [{tool.name}] processing {event_type}={event_value[:100]}")
        params_list, transform_ok = self._transform(event_type, event_value, tool, redis_client)
        published = 0
        failed = False
        reason = ""
        if not transform_ok:
            failed, reason = True, "transform"
        for params in params_list:
            command = render_template(tool.command_template, params, self.config)
            redis_client.log(f"[{self.node_id}] [{tool.name}] exec {command[:240]}")
            ok, output, code = run_cmd(command)
            if self.debug:
                redis_client.log(f"[{self.node_id}] [{tool.name}] stdout: {output}")
            if not ok:
                redis_client.log(f"[{self.node_id}] [{tool.name}] exit={code} {output[:300]}")
                failed = True
                reason = reason or "exit"
                continue
            parsed, parse_ok = self._parse(output, tool, redis_client)
            if not parse_ok:
                failed = True
                reason = reason or "parse"
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
        redis_client.log(f"[{self.node_id}] [{tool.name}] done published={published} failed={failed}")
        return published, failed, reason

    def _transform(self, event_type: str, event_value: str, tool: ToolModule, redis_client: Any) -> Tuple[List[Dict[str, Any]], bool]:
        """返回 (参数列表, ok)。ok=False 表示变换代码异常(调用方按失败处理)。"""
        if not tool.input_transform_code:
            return [{"target": event_value, "value": event_value, "event_type": event_type}], True
        try:
            params = run_input_transform(tool.input_transform_code, {"event_type": event_type, "value": event_value}, self.config)
            for param in params:
                param.setdefault("value", event_value)
                param.setdefault("target", event_value)
                param.setdefault("event_type", event_type)
            return params, True
        except CodeExecutionError as exc:
            redis_client.log(f"[{self.node_id}] [{tool.name}] transform error: {exc}")
            return [], False

    def _parse(self, output: str, tool: ToolModule, redis_client: Any) -> Tuple[List[Dict[str, Any]], bool]:
        """返回 (解析结果, ok)。ok=False 表示解析代码异常(调用方按失败处理)。"""
        if not tool.output_parse_code:
            return [], True
        try:
            return run_output_parse(tool.output_parse_code, output, self.config), True
        except CodeExecutionError as exc:
            redis_client.log(f"[{self.node_id}] [{tool.name}] parse error: {exc}")
            return [], False
