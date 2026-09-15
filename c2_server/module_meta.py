"""
server/module_meta.py — 模块元数据共享解析层 (D4)

用 AST 解析模块文件，替换 docstring 正则 (M1/M3 解决)。
纯函数、无 I/O、可单测。module_loader 与 server_module_loader 共用。

模块 v2 格式 (5.1):
    MODULE = {
        "desc": str,
        "params": [(name, hint), ...],   # 参数声明
        "result_processor": str,          # 可选：结果处理 server 模块名 (Q7)
    }
    入口函数: run() 或 run_<platform>()（全部可选，无 pass 占位）
"""

import ast
import warnings

_ALLOWED_KEYS = {"desc", "params", "result_processor", "cross_platform", "platforms"}
_PLATFORM_ALIASES = {"macos": "mac"}  # 控制台用 macos，变体名用 mac (M7 归一)


def parse_meta(source: str) -> dict:
    """解析顶层 MODULE 字面量 dict。

    Returns:
        MODULE dict；无 MODULE / 非法时返回 {}（告警）。

    注: 语法错误由调用方在 compile 阶段处理；此处仅防御。
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        warnings.warn("module_meta: source has syntax errors", UserWarning)
        return {}

    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "MODULE"):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                warnings.warn("module_meta: MODULE must be a literal dict",
                              UserWarning)
                return {}
            if not isinstance(value, dict):
                warnings.warn("module_meta: MODULE must be a dict",
                              UserWarning)
                return {}
            unknown = set(value) - _ALLOWED_KEYS
            if unknown:
                warnings.warn(
                    f"module_meta: unknown MODULE keys {sorted(unknown)}",
                    UserWarning)
            return value
    return {}


def extract_code(source: str) -> str:
    """返回去掉 `if __name__` 块之后的模块代码。

    约定: if __name__ 块位于文件末尾（模块开发规范）。
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source.rstrip()

    for node in tree.body:
        if (isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"):
            lines = source.split("\n")
            return "\n".join(lines[:node.lineno - 1]).rstrip()
    return source.rstrip()


def list_funcs(source: str) -> set:
    """返回顶层函数定义名集合。"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    return {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}


def platform_allowed(platforms, platform: str) -> bool:
    """模块用 MODULE["platforms"] 声明平台白名单时,目标平台必须命中。

    2026-09-15(R13):给「run() 内部自带平台分支、但某平台其实没实现」的模块
    一个硬禁用手段 —— 例如 shell(termios/pty)标 `"platforms": ["linux"]` 后,
    对 windows beacon 下发会被当场拒绝而不是运行期报错。
    平台未知/空、或模块未声明 platforms 时一律放行(保持旧行为)。
    """
    if not platforms:
        return True
    plat = _PLATFORM_ALIASES.get(platform, platform)
    if not plat:
        return True
    allowed = {_PLATFORM_ALIASES.get(str(p).lower(), str(p).lower()) for p in platforms}
    return plat in allowed


def select_entry(funcs, platform: str, cross_platform: bool = False):
    """平台入口选择: run_<platform> > run()。

    Args:
        funcs: list_funcs() 的结果
        platform: "linux" | "windows" | "macos" | ""
        cross_platform: 模块显式声明跨平台(MODULE["cross_platform"]=True)

    Returns:
        选中的函数名；无可用实现返回 None。

    2026-09-15(R13):此前只要没有 `run_<platform>` 就无条件回退 `run()`,于是
    只写了 POSIX 实现的模块(priv_esc/netinfo/ls/proc_kill 等)会照发给 windows
    beacon,植入物运行时才抛异常、操作者只看到「任务失败无原因」(第二/三批修复
    后还会白走 12 次退避重试)。现规则:
      - 已知平台(linux/windows/mac)且模块声明了别的平台专用实现 → 认为该模块
        有平台差异,不匹配即返回 None(调用方抛错,面板即时提示);
      - 模块只写通用 `run()`(无任何 `run_<plat>`)→ 视为天然跨平台,行为不变;
      - 模块显式 `cross_platform: true` → 任何已知平台都放行 `run()`;
      - 平台未知/空 → 仍回退 `run()` 兜底。
    """
    plat = _PLATFORM_ALIASES.get(platform, platform)
    known = plat in ("linux", "windows", "mac")
    if known and f"run_{plat}" in funcs:
        return f"run_{plat}"
    if "run" in funcs:
        has_platform_specific = any(str(n).startswith("run_") for n in funcs)
        if known and has_platform_specific and not cross_platform:
            return None
        return "run"
    return None
