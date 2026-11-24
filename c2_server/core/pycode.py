"""pycode — 下发到植入物端执行的 Python 源码处理。

单一职责：把要下发的 Python 代码里的 `#` 注释剥掉（docstring 保留）。
所有下发路径（模块 / raw / record_exec / stage / uplevel / 续传 / 快照恢复）
都经 Task 构造，Task 统一调用这里 → 不在各处重复处理。
"""

import ast
import functools
import io
import tokenize


@functools.lru_cache(maxsize=512)
def strip_py_comments(source: str) -> str:
    """移除源码中全部 # 注释，保留 docstring，返回紧凑代码（保持可编译）。

    按 token 精确删除 COMMENT token（仅挖掉注释文本，行尾注释安全）。
    非法/不可 tokenize 的输入原样返回：本函数也用于非 Python 的任务文本
    （如 shell 透传），不能因为解析失败就把内容弄丢或改写。
    """
    if not source.strip():
        return source
    lines = source.split("\n")
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


def strip_py_docstrings(source: str) -> str:
    """去掉模块/类/函数的 docstring（仅正文首条字符串语句），返回等效源码。

    只用于**植入物载荷**：载荷里的 docstring 全是开发笔记（为什么这么写、
    修过什么 bug、日期），运行时一个都用不到，不下发（省体积 + 不留线索）。
    普通字符串表达式语句不会被误删——只处理 body 的首条字符串常量。
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    changed = False
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            body.pop(0)
            if not body:
                body.append(ast.Pass())
            changed = True
    if not changed:
        return source
    return ast.unparse(tree) + "\n"
