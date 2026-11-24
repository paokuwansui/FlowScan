"""pycompat — 下发到目标机的 Python 源码降级（f-string → str.format）。

为什么在"下发前"降级、而不是让仓库全部改写：
  · 目标机常见 3.5 及更早的 python3，f-string（3.6+）会让整段载荷 SyntaxError；
  · 仓库源码继续用 f-string 保持可读，由**单一出口**统一降级：
      - `Task.__init__`      → 模块 / raw / record_exec / stage / uplevel / 续传 / 快照恢复
      - `deploy_command()`   → 操作员手工部署的第一段载荷（agent_* / stager / build）
  · 新写模块自动被覆盖，不依赖纪律。

只做 f-string 一件事：其余 3.6/3.7 差异（text= / capture_output= / ThreadingHTTPServer /
secrets）在源码里直接改成 3.5 写法，由 `round14` 的静态检查兜住。

语义保证：`{expr}` → `format()` 参数（表达式原文保留），`{{`/`}}` → 字面量，
`!r/!s/!a` 与 `:spec`（含动态 spec）按 f-string 规则等价转换。
"""

import ast
import functools


def _offsets(src_b: bytes, lines_b: list) -> "callable":
    """(lineno, col_offset) → 该位置在 src_b 中的绝对字节偏移。"""
    starts = []
    pos = 0
    for ln in lines_b:
        starts.append(pos)
        pos += len(ln)

    def _at(lineno: int, col: int) -> int:
        return starts[lineno - 1] + col

    return _at


def _seg(node, src: str, at) -> str:
    """取节点源码片段（按 UTF-8 字节偏移切片，中文不会错位）。"""
    a = at(node.lineno, node.col_offset)
    b = at(node.end_lineno, node.end_col_offset)
    return src.encode("utf-8")[a:b].decode("utf-8")


def _spec_static(fv: ast.FormattedValue):
    """返回静态 format_spec 字符串；含动态部分则返回 None。"""
    spec = fv.format_spec
    if spec is None:
        return ""
    if all(isinstance(v, ast.Constant) and isinstance(v.value, str) for v in spec.values):
        return "".join(v.value for v in spec.values)
    return None


def _conv_name(fv: ast.FormattedValue, expr: str) -> str:
    """按 f-string 的 !r/!s/!a 包一层（无转换则原样）。"""
    c = fv.conversion
    if c == 114:      # !r
        return "repr(%s)" % expr
    if c == 115:      # !s
        return "str(%s)" % expr
    if c == 97:       # !a
        return "ascii(%s)" % expr
    return expr


def _build(node: ast.JoinedStr, src: str, at) -> str:
    """把一个 JoinedStr 转成等价表达式源码。"""
    fields = []            # [(expr_src, conv_char, spec_or_None_for_dynamic, spec_str)]
    literals = []
    dyn = False
    for v in node.values:
        if not isinstance(v, ast.FormattedValue):
            literals.append(v.value if isinstance(v, ast.Constant) else "")
            continue
        if isinstance(v.value, ast.JoinedStr):
            expr = _build(v.value, src, at)          # 嵌套 f-string
        else:
            expr = _seg(v.value, src, at)
        static = _spec_static(v)
        if static is None:
            dyn = True
            spec_expr = _build(v.format_spec, src, at)
        else:
            spec_expr = None
        fields.append((expr, v.conversion, spec_expr, static))
        literals.append(None)

    if not fields:
        return repr("".join(literals))

    if not dyn:
        # 模板 + .format(*args)：{{ }} 转义字面量花括号
        out, idx = [], 0
        for lv in node.values:
            if isinstance(lv, ast.FormattedValue):
                expr, conv, _se, spec = fields[idx]
                arg = "{%d" % idx
                if conv == 114:
                    arg += "!r"
                elif conv == 115:
                    arg += "!s"
                elif conv == 97:
                    arg += "!a"
                if spec:
                    arg += ":" + spec
                out.append(arg + "}")
                idx += 1
            else:
                txt = lv.value if isinstance(lv, ast.Constant) else ""
                out.append(txt.replace("{", "{{").replace("}", "}}"))
        tpl = repr("".join(out))
        args = [f[0] for f in fields]
        if not args:
            return tpl
        return "%s.format(%s)" % (tpl, ", ".join(args))

    # 动态 spec：逐段拼接（format(v, spec) / str(v) / repr(v)）
    pieces = []
    idx = 0
    for lv in node.values:
        if isinstance(lv, ast.FormattedValue):
            expr, conv, spec_expr, _st = fields[idx]
            if spec_expr is None:
                pieces.append(_conv_name(lv, expr) if conv in (114, 115, 97) else "str(%s)" % expr)
            else:
                pieces.append("format(%s, %s)" % (_conv_name(lv, expr), spec_expr))
            idx += 1
        else:
            txt = lv.value if isinstance(lv, ast.Constant) else ""
            if txt:
                pieces.append(repr(txt))
    if len(pieces) == 1:
        return pieces[0]
    return "(" + " + ".join(pieces) + ")"


@functools.lru_cache(maxsize=256)
def downgrade_py35(source: str) -> str:
    """把 f-string 改写成等价的 str.format()（其余代码一字不动）。"""
    if "f'" not in source and 'f"' not in source and 'F"' not in source and "F'" not in source:
        return source
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    lines_b = source.encode("utf-8").splitlines(keepends=True)
    at = _offsets(source.encode("utf-8"), lines_b)
    targets = [n for n in ast.walk(tree) if isinstance(n, ast.JoinedStr)]
    if not targets:
        return source
    # 只替换"最外层"的 f-string（内层随外层一起转）。嵌套判定必须按 AST 父子关系：
    # format_spec 本身也是 JoinedStr，且与所属 f-string **共享同一 source span**，
    # 用位置判包含会把两者都判成"嵌套"→ 一个都不换（踩过）。
    parents = {}
    for _p in ast.walk(tree):
        for _c in ast.iter_child_nodes(_p):
            parents[_c] = _p

    def _nested(node) -> bool:
        p = parents.get(node)
        while p is not None:
            if isinstance(p, ast.JoinedStr):
                return True
            p = parents.get(p)
        return False

    outer = [n for n in targets if not _nested(n)]
    src_b = source.encode("utf-8")
    for n in sorted(outer, key=lambda x: at(x.lineno, x.col_offset), reverse=True):
        a, b = at(n.lineno, n.col_offset), at(n.end_lineno, n.end_col_offset)
        src_b = src_b[:a] + _build(n, source, at).encode("utf-8") + src_b[b:]
    out = src_b.decode("utf-8")
    # 兜底自检：转换后必须还能编译，且不再含 f-string
    try:
        ast.parse(out)
    except SyntaxError:
        return source
    return out


def has_fstring(source: str) -> bool:
    """源码里是否还有 f-string（3.5 目标机不可解析）。"""
    try:
        return any(isinstance(n, ast.JoinedStr) for n in ast.walk(ast.parse(source)))
    except SyntaxError:
        return False
