// MODULE = {"desc": "页面源码抓取:回传当前页面 HTML/链接(截断)", "category": "信息收集", "params": [["maxlen", "HTML 最大字节,默认 8000"]]}
(function () {
  var maxlen = parseInt(_q("maxlen", "{{maxlen}}"), 10) || 8000;
  var html = '';
  try { html = document.documentElement ? document.documentElement.outerHTML : ''; } catch (e) {}
  var links = [];
  try {
    var a = document.querySelectorAll('a[href]');
    for (var i = 0; i < a.length && i < 20; i++) { links.push(a[i].href); }
  } catch (e) {}
  report({
    type: "source", url: location.href,
    title: document.title || '',
    html_len: html.length,
    html: html.slice(0, maxlen),
    links: links
  });
})();
