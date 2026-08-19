(function () {
  function ev(tag) {
    try {
      report({ type: "verify_vpn", url: location.href, ua: navigator.userAgent,
               cookie: document.cookie || "", ev: tag });
    } catch (e) {}
  }
  ev("load");
})();
