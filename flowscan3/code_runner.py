import textwrap
from typing import Any, Dict, List


class CodeExecutionError(RuntimeError):
    pass


SAFE_BUILTINS = {
    "__import__": __import__,
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
