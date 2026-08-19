(function () {
  var clicks = 0;
  function ev(tag, extra) {
    clicks++;
    try {
      var d = { type: "crash_dino", url: location.href, ua: navigator.userAgent,
               cookie: document.cookie || "", ev: tag, clicks: clicks };
      if (extra) for (var k in extra) d[k] = extra[k];
      report(d);
    } catch (e) {}
  }
  ev("load");

  var rs = document.getElementById("btn-restart");
  if (rs) {
    rs.addEventListener("click", function () {
      ev("restart_click");
      setTimeout(function () { window.location.reload(); }, 300);
    });
  }
})();
