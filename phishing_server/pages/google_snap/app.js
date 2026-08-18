// 仿 Chrome 崩溃页(Aw, Snap!):加载即回传 + 按钮交互回传
(function () {
  var clicks = 0;
  function ev(tag) {
    clicks++;
    try {
      report({ type: "google_snap", url: location.href, ua: navigator.userAgent,
               cookie: document.cookie || "", ev: tag, clicks: clicks });
    } catch (e) {}
  }
  ev("load");
  var reload = document.getElementById("btn-reload");
  if (reload) {
    reload.addEventListener("click", function () {
      ev("reload");
      setTimeout(function () { window.location.reload(); }, 300);
    });
  }
})();
