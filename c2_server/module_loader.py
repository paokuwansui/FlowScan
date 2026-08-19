"""
server/module_loader.py — 植入模块加载器 v2 (D1/D4)

模块格式 v2 (5.1):
  - 元数据: 顶层 MODULE dict（module_meta.parse_meta，AST 解析，替换 docstring 正则）
  - 入口: run() 或 run_<platform>()（可选，无 pass 占位，消灭 _is_pass_body 启发式）
  - 结果处理器: MODULE["result_processor"]（Q7，Task 携带标记）

加载失败显式化: 语法错误 / MODULE 非法 / JSON 引用缺失 → logging 告警并跳过
（不再静默跳过整个模块，M2/M6 解决）。

JSON 序列模块: steps 串联 python 模块；加载后统一校验引用存在性，
嵌套 JSON 引用直接拒绝。
"""

import io
import json
import logging
import os
import tokenize
from dataclasses import dataclass, field
from typing import Optional

# 下发载荷的 Python 注释剥离器(tokenize 安全,保留字符串字面量与 docstring):
# 仅移除 # 注释,不影响代码语义、MODULE dict、docstring 与普通字符串。
def strip_py_comments(source: str) -> str:
    """移除源码中全部 # 注释,保留 docstring,返回紧凑代码(保持可编译)。"""
    if not source.strip():
        return source
    lines = source.split("\n")
    # tokenize 精确删除 COMMENT token(仅挖掉注释文本,不删整行,行尾注释安全)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return source
    cuts = [(t.start[0], t.start[1], t.end[1])
            for t in tokens if t.type == tokenize.COMMENT]
    for lineno, c0, c1 in sorted(cuts, reverse=True):
        ln = lines[lineno - 1]
        lines[lineno - 1] = ln[:c0] + ln[c1:]
    return "\n".join(lines).rstrip() + "\n"

from server.core.log import get_logger
from . import module_meta

logger = get_logger("module_loader")


@dataclass
class ModuleInfo:
    """单个模块的解析结果。"""

    name: str
    path: str
    type: str                        # "python" | "json"
    desc: str = ""
    params: list = field(default_factory=list)   # [(name, hint), ...]
    result_processor: str = ""       # Q7：结果处理 server 模块名
    code: str = ""                   # 去 __main__ 的完整模块代码
    funcs: set = field(default_factory=set)      # 顶层函数名集合
    steps: list = field(default_factory=list)    # JSON 步骤
    errors: list = field(default_factory=list)   # 加载期问题（JSON 校验）


class ModuleLoader:
    """植入模块加载器。扫描 modules/ 目录，解析 .py 与 .json 模块。"""

    def __init__(self, modules_dir: str = "modules",
                 max_task_code_size: int = 262144):
        self._modules_dir = modules_dir
        self._max_task_code_size = max_task_code_size
        self._modules: dict[str, ModuleInfo] = {}

    # ── 公开接口 ──

    def load(self) -> None:
        """扫描并加载全部模块。"""
        self._modules.clear()
        if not os.path.isdir(self._modules_dir):
            logger.warning("modules dir not found: %s", self._modules_dir)
            return
        for filename in sorted(os.listdir(self._modules_dir)):
            path = os.path.join(self._modules_dir, filename)
            if not os.path.isfile(path):
                continue
            if filename.endswith(".py"):
                self._load_py_module(filename, path)
            elif filename.endswith(".json"):
                self._load_json_module(filename, path)
        self._validate_json_steps()

    def list_modules(self) -> list:
        """列出模块摘要: [{name, desc, type, params?/steps?}]"""
        result = []
        for mod in self._modules.values():
            item = {"name": mod.name, "desc": mod.desc, "type": mod.type}
            if mod.type == "python":
                item["params"] = mod.params
            else:
                item["steps"] = len(mod.steps)
            result.append(item)
        return result

    def get_module(self, name: str) -> Optional[dict]:
        """获取模块完整元数据；不存在返回 None。"""
        mod = self._modules.get(name)
        if not mod:
            return None
        result = {"name": mod.name, "type": mod.type, "desc": mod.desc}
        if mod.type == "python":
            result["params"] = mod.params
            result["result_processor"] = mod.result_processor
            result["code"] = mod.code
            result["funcs"] = sorted(mod.funcs)
        else:
            result["steps"] = mod.steps
        return result

    def param_names(self, name: str) -> list:
        """模块声明的参数名列表（结构化，替代字符串解析 S3②）。"""
        mod = self._modules.get(name)
        if not mod:
            return []
        return [p[0] for p in mod.params
                if isinstance(p, (list, tuple)) and p and isinstance(p[0], str)]

    def build_task(self, name: str, platform: str = "", **kwargs) -> str:
        """构建下发给执行端的 Python 代码。

        Args:
            name: 模块名称
            platform: "" / "linux" / "windows" / "macos"
            **kwargs: 模块参数（键必须在 MODULE.params 声明内）

        Returns:
            可 exec() 的代码字符串

        Raises:
            ValueError: 模块不存在 / 无适用平台实现 / 未知参数 / 代码超限
        """
        mod = self._modules.get(name)
        if not mod:
            raise ValueError(f"module '{name}' not found")
        if mod.type == "python":
            return self._build_py_task(mod, kwargs, platform)
        if mod.type == "json":
            return self._build_json_task(mod, platform)
        raise ValueError(f"unknown module type: {mod.type}")

    def reload(self) -> None:
        """热加载：重新扫描目录。"""
        self.load()

    def reconfigure(self, modules_dir: str = None,
                    max_task_code_size: int = None) -> None:
        """更新加载参数（reload 命令热重载配置用），随后 reload() 生效。"""
        if modules_dir is not None:
            self._modules_dir = modules_dir
        if max_task_code_size is not None:
            self._max_task_code_size = max_task_code_size

    # ── .py 模块 ──

    def _load_py_module(self, filename: str, path: str) -> None:
        name = filename[:-3]
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            logger.warning("module %s: read failed: %s", name, e)
            return
        if not content.strip():
            logger.warning("module %s: empty file, skipped", name)
            return
        try:
            compile(content, path, "exec")
        except SyntaxError as e:
            logger.warning("module %s: syntax error, skipped: %s", name, e)
            return

        meta = module_meta.parse_meta(content)
        params = meta.get("params", [])
        if not isinstance(params, list):
            logger.warning("module %s: MODULE['params'] must be a list, "
                           "skipped", name)
            return
        norm = []
        for p in params:
            if (isinstance(p, (list, tuple)) and len(p) >= 1
                    and isinstance(p[0], str)):
                hint = p[1] if len(p) > 1 and isinstance(p[1], str) else ""
                norm.append((p[0], hint))
            else:
                logger.warning("module %s: bad params entry %r ignored", name, p)

        rp = meta.get("result_processor", "")
        if not isinstance(rp, str):
            rp = ""

        funcs = module_meta.list_funcs(content)
        if not funcs:
            logger.warning("module %s: no functions defined, skipped", name)
            return

        self._modules[name] = ModuleInfo(
            name=name, path=path, type="python",
            desc=str(meta.get("desc", "")), params=norm,
            result_processor=rp,
            code=module_meta.extract_code(content), funcs=funcs,
        )

    def _build_py_task(self, mod: ModuleInfo, kwargs: dict,
                       platform: str = "") -> str:
        func_name = module_meta.select_entry(mod.funcs, platform)
        if func_name is None:
            plat = platform or "unknown"
            raise ValueError(
                f"module '{mod.name}' has no implementation "
                f"for platform '{plat}'")
        declared = [p[0] for p in mod.params
                    if isinstance(p, (list, tuple)) and p]
        unknown = set(kwargs) - set(declared)
        if unknown:
            raise ValueError(
                f"module '{mod.name}': unknown args {sorted(unknown)}")

        call_args = ",".join(f"{k}={v!r}" for k, v in sorted(kwargs.items()))
        call = (f"result = {func_name}({call_args})" if call_args
                else f"result = {func_name}()")
        code = (
            f"# --- module: {mod.name} ({func_name}) ---\n"
            f"{strip_py_comments(mod.code)}\n\n"
            f"{call}\n"
            f"print(result)\n"
        )
        self._check_size(code)
        return code

    # ── .json 模块 ──

    def _load_json_module(self, filename: str, path: str) -> None:
        name = filename[:-5]
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("json module %s: load failed: %s", name, e)
            return
        if not isinstance(data, dict):
            logger.warning("json module %s: root must be an object", name)
            return
        steps = data.get("steps", [])
        if not isinstance(steps, list):
            logger.warning("json module %s: 'steps' must be a list", name)
            return
        self._modules[name] = ModuleInfo(
            name=str(data.get("name", name)), path=path, type="json",
            desc=str(data.get("desc", "")), steps=steps,
        )

    def _validate_json_steps(self) -> None:
        """JSON 步骤显式校验：引用必须存在且为 python 类型（M6）。"""
        for mod in self._modules.values():
            if mod.type != "json":
                continue
            for i, step in enumerate(mod.steps):
                if not isinstance(step, dict):
                    mod.errors.append(f"step {i + 1}: not an object")
                    continue
                ref = step.get("module", "")
                target = self._modules.get(ref)
                if target is None:
                    mod.errors.append(f"step {i + 1}: module '{ref}' not found")
                elif target.type != "python":
                    mod.errors.append(
                        f"step {i + 1}: module '{ref}' is {target.type}, "
                        f"nested json sequences not allowed")
            if mod.errors:
                logger.warning("json module %s has %d problem(s): %s",
                               mod.name, len(mod.errors),
                               "; ".join(mod.errors))

    def _build_json_task(self, mod: ModuleInfo, platform: str = "") -> str:
        """JSON 序列模块：去重内联 python 模块代码，串行调用。"""
        lines = [f"# --- json sequence: {mod.name} ---"]
        seen = set()
        for step in mod.steps:
            if not isinstance(step, dict):
                continue
            module_name = step.get("module", "")
            if module_name in seen:
                continue
            step_mod = self._modules.get(module_name)
            if step_mod and step_mod.type == "python" and step_mod.code:
                seen.add(module_name)
                lines.append(f"\n# --- module: {module_name} ---")
                lines.append(step_mod.code)

        lines.append("\nresults = []\n")

        for i, step in enumerate(mod.steps):
            if not isinstance(step, dict):
                continue
            module_name = step.get("module", "")
            step_mod = self._modules.get(module_name)
            args = step.get("args", {})
            if not isinstance(args, dict):
                args = {}
            if step_mod and step_mod.type == "python":
                func_name = module_meta.select_entry(step_mod.funcs, platform)
                if func_name is None:
                    lines.append(
                        f"results.append('[module {module_name}: "
                        f"no implementation for {platform or 'unknown'}]')")
                    continue
                declared = [p[0] for p in step_mod.params
                            if isinstance(p, (list, tuple)) and p]
                unknown = set(args) - set(declared)
                if unknown:
                    lines.append(
                        f"results.append('[module {module_name}: "
                        f"unknown args {sorted(unknown)}]')")
                    continue
                call_args = ",".join(
                    f"{k}={v!r}" for k, v in sorted(args.items()))
                call = (f"result = {func_name}({call_args})" if call_args
                        else f"result = {func_name}()")
                lines.append(f"# step {i + 1}: {module_name} → {func_name}")
                lines.append(call)
                lines.append("results.append(str(result))")
                lines.append("")
            else:
                lines.append(f"results.append('[module {module_name} not found]')")

        lines.append("output = '\\n'.join(results)")
        lines.append("print(output)")
        code = "\n".join(lines)
        self._check_size(code)
        return code

    # ── 公共工具 ──

    def _check_size(self, code: str) -> None:
        """生成代码长度上限（5.3 / 10.5）。"""
        if len(code) > self._max_task_code_size:
            raise ValueError(
                f"task code {len(code)} bytes exceeds max_task_code_size "
                f"{self._max_task_code_size}")
