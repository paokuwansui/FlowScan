import textwrap
from typing import Any, Dict, List


class CodeExecutionError(RuntimeError):
    pass


# 沙箱内允许 import 的模块白名单(顶层模块或完整子模块路径)。
# 模块 YAML 的 input_transform_code / output_parse_code 只应依赖标准库的
# 纯数据/文本处理模块。os/subprocess/sys 等能执行系统操作的模块一律拒绝,
# 防止模块代码经 __import__ 逃逸沙箱执行任意命令。
# 注意 `from urllib.parse import urlparse` 这类语句传给 __import__ 的 name
# 是完整路径(如 "urllib.parse"), 故白名单按完整路径精确匹配。
_SANDBOX_ALLOWED_IMPORTS = {
    "json",
    "re",
    "shlex",
    "ipaddress",
    "hashlib",
    "base64",
    "string",
    "math",
    "itertools",
    "functools",
    "collections",
    "textwrap",
    "urllib.parse",
    "xml.etree.ElementTree",
    "datetime",
    "time",
    "random",
    "statistics",
}


def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    """沙箱内替代 __import__ 的受限导入,只放行白名单模块。"""
    if name not in _SANDBOX_ALLOWED_IMPORTS:
        raise ImportError(f"module '{name}' is not allowed in FlowScan sandbox")
    return __import__(name, globals, locals, fromlist, level)


SAFE_BUILTINS = {
    "__import__": _safe_import,
    "len": len,
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "list": list,
    "dict": dict,
    "set": set,
    "tuple": tuple,
    "range": range,
    "enumerate": enumerate,
    "min": min,
    "max": max,
    "sum": sum,
    "sorted": sorted,
    "any": any,
    "all": all,
    "isinstance": isinstance,
    "type": type,
}


def _run_returning_code(code: str, data: Dict[str, Any], config: Dict[str, Any]) -> Any:
    if not code:
        return []
    source = "def __flowscan_user_fn__(data, config):\n" + textwrap.indent(code.strip() + "\n", "    ")
    namespace: Dict[str, Any] = {"__builtins__": SAFE_BUILTINS}
    try:
        exec(source, namespace, namespace)
        return namespace["__flowscan_user_fn__"](data, config)
    except Exception as exc:
        raise CodeExecutionError(str(exc)) from exc


def run_input_transform(code: str, data: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = _run_returning_code(code, data, config)
    if result is None:
        return []
    if isinstance(result, dict):
        return [result]
    if isinstance(result, list):
        return [item for item in result if isinstance(item, dict)]
    raise CodeExecutionError("input_transform_code must return dict/list[dict]/None")


def run_output_parse(code: str, stdout: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = _run_returning_code(code, {"stdout": stdout}, config)
    if result is None:
        return []
    if isinstance(result, dict):
        return [result]
    if isinstance(result, list):
        return [item for item in result if isinstance(item, dict)]
    raise CodeExecutionError("output_parse_code must return dict/list[dict]/None")
