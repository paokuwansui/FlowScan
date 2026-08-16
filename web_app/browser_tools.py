"""Agent 浏览器工具:web 搜索 + 完整浏览器自动化(browser-use 无头 chromium + CDP)。

架构:
- 全局单例 Browser + 后台 asyncio 事件循环(线程安全提交)——跨 agent 调用保持页面状态
- 交互走 CDP 底层:DOM.focus + Input.insertText 输入、Input.dispatchMouseEvent 点击
  (highlight_coordinate_click 实测不触发 click 事件,弃用)
- web_search/web_browse 优先 httpx 直取(快、无浏览器开销),JS 渲染页面 fallback 浏览器

docker 打包:主节点 Dockerfile 需 apt 装 chromium + pip 装 browser-use(见 Dockerfile 注释)。
"""

import asyncio
import json
import threading
import time
from typing import Any, Callable
from urllib.parse import quote

import httpx
from bs4 import BeautifulSoup

try:
    from browser_use import Browser
    _BROWSER_AVAILABLE = True
except Exception:  # pragma: no cover - 依赖缺失时工具返回明确错误
    Browser = None
    _BROWSER_AVAILABLE = False

# ── 全局浏览器单例(后台 asyncio loop) ──
_loop: Any = None
_loop_thread: threading.Thread | None = None
_browser: Any = None
_browser_lock = threading.Lock()

_CHROMIUM = "/usr/bin/chromium"
_START_TIMEOUT = 90
_OP_TIMEOUT = 90
_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")


def _ensure_loop() -> Any:
    global _loop, _loop_thread
    if _loop is None:
        _loop = asyncio.new_event_loop()
        _loop_thread = threading.Thread(target=_loop.run_forever, daemon=True, name="fs3-browser-loop")
        _loop_thread.start()
    return _loop


def _submit(coro_factory: Callable[[], Any], timeout: float = _OP_TIMEOUT) -> Any:
    """在全局 loop 上执行异步浏览器操作(线程安全,跨调用保持浏览器状态)。"""
    loop = _ensure_loop()
    fut = asyncio.run_coroutine_threadsafe(coro_factory(), loop)
    return fut.result(timeout=timeout)


async def _get_browser() -> Any:
    global _browser
    if _browser is None or not _browser.is_cdp_connected:
        _browser = Browser(
            executable_path=_CHROMIUM,
            headless=True,
            chromium_sandbox=False,       # 容器/root 下必须禁沙箱
            enable_default_extensions=False,   # 跳过 uBlock 扩展下载
            minimum_wait_page_load_time=0.3,
        )
        await _browser.start()
    return _browser


def browser_available() -> bool:
    return _BROWSER_AVAILABLE


# ══════════════════════ 完整浏览器自动化(CDP) ══════════════════════

def browser_navigate(url: str) -> str:
    """导航到 URL。返回 {ok, url}。"""
    def err(e: Exception) -> str:
        return json.dumps({"ok": False, "error": f"browser_navigate: {e}"}, ensure_ascii=False)

    async def f() -> str:
        try:
            b = await _get_browser()
            await b.navigate_to(url)
            await asyncio.sleep(1.0)
            return json.dumps({"ok": True, "url": await b.get_current_page_url()}, ensure_ascii=False)
        except Exception as e:
            return err(e)
    try:
        return _submit(f)
    except Exception as e:
        return err(e)


def browser_state() -> str:
    """读取当前页面:URL/标题 + 带索引的 DOM 元素文本(供后续 click/type 使用)。"""
    def err(e: Exception) -> str:
        return json.dumps({"ok": False, "error": f"browser_state: {e}"}, ensure_ascii=False)

    async def f() -> str:
        try:
            b = await _get_browser()
            await b.get_browser_state_summary(include_screenshot=False)   # 构建 selector map
            text = await b.get_state_as_text()
            return json.dumps({
                "ok": True,
                "url": await b.get_current_page_url(),
                "title": await b.get_current_page_title(),
                "dom": text[:6000],
            }, ensure_ascii=False)
        except Exception as e:
            return err(e)
    try:
        return _submit(f)
    except Exception as e:
        return err(e)


def browser_click(index: int) -> str:
    """按索引点击元素(索引来自 browser_state 的 dom)。CDP 原生鼠标事件。"""
    def err(e: Exception) -> str:
        return json.dumps({"ok": False, "error": f"browser_click: {e}"}, ensure_ascii=False)

    async def f() -> str:
        try:
            b = await _get_browser()
            node = await b.get_element_by_index(index)
            if node is None:
                return json.dumps({"ok": False, "error": f"index {index} 不存在(先 browser_state 获取最新索引)"}, ensure_ascii=False)
            cdp = await b.get_or_create_cdp_session(node.target_id, focus=True)
            rect = await b.get_element_coordinates(node.backend_node_id, cdp)
            if rect is None:
                return json.dumps({"ok": False, "error": f"index {index} 坐标不可用(元素可能不可见)"}, ensure_ascii=False)
            x, y = int(rect.x + rect.width / 2), int(rect.y + rect.height / 2)
            for ev_type in ("mousePressed", "mouseReleased"):
                await cdp.cdp_client.send.Input.dispatchMouseEvent(
                    params={"type": ev_type, "x": x, "y": y, "button": "left", "clickCount": 1},
                    session_id=cdp.session_id)
            await asyncio.sleep(0.4)
            return json.dumps({"ok": True, "clicked_index": index, "x": x, "y": y}, ensure_ascii=False)
        except Exception as e:
            return err(e)
    try:
        return _submit(f)
    except Exception as e:
        return err(e)


def browser_type(index: int, text: str) -> str:
    """按索引聚焦元素并输入文本(DOM.focus + Input.insertText,对 input/textarea 可靠)。"""
    def err(e: Exception) -> str:
        return json.dumps({"ok": False, "error": f"browser_type: {e}"}, ensure_ascii=False)

    async def f() -> str:
        try:
            b = await _get_browser()
            node = await b.get_element_by_index(index)
            if node is None:
                return json.dumps({"ok": False, "error": f"index {index} 不存在(先 browser_state 获取最新索引)"}, ensure_ascii=False)
            cdp = await b.get_or_create_cdp_session(node.target_id, focus=True)
            await cdp.cdp_client.send.DOM.focus(params={"backendNodeId": node.backend_node_id}, session_id=cdp.session_id)
            await asyncio.sleep(0.15)
            await cdp.cdp_client.send.Input.insertText(params={"text": text}, session_id=cdp.session_id)
            await asyncio.sleep(0.2)
            return json.dumps({"ok": True, "typed_index": index}, ensure_ascii=False)
        except Exception as e:
            return err(e)
    try:
        return _submit(f)
    except Exception as e:
        return err(e)


def browser_screenshot(path: str = "") -> str:
    """截图。path 留空则存到 /tmp/fs3-browser-<ts>.png;返回文件路径(用户可在 Web 端查看)。"""
    def err(e: Exception) -> str:
        return json.dumps({"ok": False, "error": f"browser_screenshot: {e}"}, ensure_ascii=False)

    async def f() -> str:
        try:
            b = await _get_browser()
            p = path or f"/tmp/fs3-browser-{int(time.time())}.png"
            png = await b.take_screenshot(path=p, full_page=False)
            return json.dumps({"ok": True, "path": p, "bytes": len(png) if png else 0}, ensure_ascii=False)
        except Exception as e:
            return err(e)
    try:
        return _submit(f)
    except Exception as e:
        return err(e)


def browser_close() -> str:
    """关闭浏览器实例(释放 chromium;下次调用自动重启)。"""
    def err(e: Exception) -> str:
        return json.dumps({"ok": False, "error": f"browser_close: {e}"}, ensure_ascii=False)

    async def f() -> str:
        global _browser
        try:
            if _browser is not None:
                await _browser.close()
                _browser = None
            return json.dumps({"ok": True}, ensure_ascii=False)
        except Exception as e:
            _browser = None
            return err(e)
    try:
        return _submit(f)
    except Exception as e:
        return err(e)


# ══════════════════════ 搜索 + 浏览(httpx 优先,浏览器兜底) ══════════════════════

def web_search(query: str, limit: int = 8) -> str:
    """搜索引擎搜索,返回 [{title, url, snippet}]。DuckDuckGo HTML 为主,Bing 兜底,无需 API key。"""
    results: list[dict] = []
    errors: list[str] = []
    for name, fn in (("duckduckgo", _search_ddg), ("bing", _search_bing)):
        try:
            results = fn(query, limit)
            if results:
                break
        except Exception as e:
            errors.append(f"{name}: {e}")
    if not results:
        return json.dumps({"ok": False, "error": "搜索失败: " + "; ".join(errors) or "无结果"}, ensure_ascii=False)
    return json.dumps({"ok": True, "query": query, "count": len(results), "results": results}, ensure_ascii=False)


def _search_ddg(query: str, limit: int) -> list[dict]:
    r = httpx.get(f"https://html.duckduckgo.com/html/?q={quote(query)}",
                  headers={"User-Agent": _UA}, timeout=15, follow_redirects=True)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    out = []
    for a in soup.select("a.result__a")[:limit]:
        title = a.get_text(strip=True)
        href = a.get("href") or ""
        # DDG 结果链接是重定向包装:解析 uddg 参数
        if "uddg=" in href:
            from urllib.parse import unquote, urlparse, parse_qs
            try:
                href = parse_qs(urlparse(href).query).get("uddg", [href])[0]
            except Exception:
                pass
        snip_el = a.find_next("a", class_="result__snippet")
        snippet = snip_el.get_text(strip=True) if snip_el else ""
        if title and href.startswith("http"):
            out.append({"title": title, "url": href, "snippet": snippet[:300]})
    return out


def _search_bing(query: str, limit: int) -> list[dict]:
    r = httpx.get(f"https://www.bing.com/search?q={quote(query)}",
                  headers={"User-Agent": _UA}, timeout=15, follow_redirects=True)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    out = []
    for li in soup.select("li.b_algo")[:limit]:
        a = li.select_one("h2 a")
        if not a:
            continue
        title = a.get_text(strip=True)
        href = a.get("href") or ""
        cap = li.select_one(".b_caption p, .b_caption")
        snippet = cap.get_text(strip=True) if cap else ""
        if title and href.startswith("http"):
            out.append({"title": title, "url": href, "snippet": snippet[:300]})
    return out


def web_browse(url: str) -> str:
    """浏览网页:httpx 直取转文本(快);JS 渲染页面内容不足时用无头浏览器渲染兜底。"""
    # 1) httpx 直取
    try:
        r = httpx.get(url, headers={"User-Agent": _UA}, timeout=15, follow_redirects=True, verify=False)
        if r.status_code == 200 and r.text:
            text = _html_to_text(r.text)
            if len(text.strip()) > 30:
                return json.dumps({"ok": True, "url": url, "mode": "http", "text": text[:8000]}, ensure_ascii=False)
    except Exception:
        pass
    # 2) 浏览器渲染兜底(JS 页面)
    if not _BROWSER_AVAILABLE:
        return json.dumps({"ok": False, "error": "页面内容为空且浏览器不可用(browser-use 未安装)"}, ensure_ascii=False)
    async def f() -> str:
        try:
            b = await _get_browser()
            await b.navigate_to(url)
            await asyncio.sleep(2.0)
            await b.get_browser_state_summary(include_screenshot=False)
            text = await b.get_state_as_text()
            return json.dumps({"ok": True, "url": url, "mode": "browser", "text": text[:8000]}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"ok": False, "error": f"web_browse 浏览器模式失败: {e}"}, ensure_ascii=False)
    try:
        return _submit(f)
    except Exception as e:
        return json.dumps({"ok": False, "error": f"web_browse: {e}"}, ensure_ascii=False)


def _html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "iframe", "header", "footer", "nav"]):
        tag.decompose()
    text = soup.get_text(separator="\n", strip=True)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return "\n".join(lines)
