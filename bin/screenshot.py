#!/usr/bin/env python3
"""网页截图:URL → SCREENSHOT 事件(附带截图地址 + base64 图片编码)。

用 chromium/chrome headless 对 URL 截图,存 reports/screenshots/{hash}.png,
读取 PNG 转 base64,产出 SCREENSHOT 事件。value 为 JSON 字符串:
  {"url": "https://example.com", "path": "reports/screenshots/abc.png", "b64": "<base64>"}

用法:
  python ./bin/screenshot.py https://example.com
"""

import base64
import hashlib
import json
import os
import subprocess
import sys

# 项目根目录(脚本在 bin/ 下)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_chrome() -> str:
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        try:
            p = subprocess.run(["which", name], capture_output=True, text=True).stdout.strip()
        except Exception:
            p = ""
        if p:
            return p
    return ""


def main() -> int:
    url = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if not url.startswith(("http://", "https://")):
        print(f"[screenshot] invalid url: {url!r}", file=sys.stderr)
        return 1

    chrome = find_chrome()
    if not chrome:
        print("[screenshot] no chromium/chrome found", file=sys.stderr)
        return 1

    h = hashlib.sha256(url.encode()).hexdigest()[:16]
    out_dir = os.path.join(BASE, "reports", "screenshots")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, f"{h}.png")

    cmd = [
        chrome, "--headless", "--disable-gpu", "--no-sandbox",
        "--disable-dev-shm-usage", "--hide-scrollbars",
        "--window-size=800,500", f"--screenshot={out_file}",
        "--virtual-time-budget=8000", url,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        print("[screenshot] timeout", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[screenshot] failed: {exc}", file=sys.stderr)
        return 1

    if r.returncode != 0 or not os.path.isfile(out_file):
        print(f"[screenshot] screenshot failed: {(r.stderr or '')[:200]}", file=sys.stderr)
        return 1

    try:
        with open(out_file, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
    except Exception as exc:
        print(f"[screenshot] read failed: {exc}", file=sys.stderr)
        return 1

    rel_path = os.path.join("reports", "screenshots", f"{h}.png")
    payload = json.dumps({"url": url, "path": rel_path, "b64": b64}, ensure_ascii=False)
    print(json.dumps({"SCREENSHOT": payload}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
