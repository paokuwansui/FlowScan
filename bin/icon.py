#!/usr/bin/env python3
"""图标(favicon)解析:ICON_PATH → ICON 事件(附带图标地址 + base64 编码)。

下载 favicon 图标存 reports/icons/{hash}.{ext},读取转 base64,产出 ICON 事件。
value 为 JSON 字符串:
  {"url": "https://example.com/favicon.ico", "path": "reports/icons/abc.ico", "b64": "<base64>", "mime": "image/x-icon"}

用法:
  python ./bin/icon.py https://example.com/favicon.ico
"""

import base64
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request

# 项目根目录(脚本在 bin/ 下)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MIME_MAP = {
    "ico": "image/x-icon",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "svg": "image/svg+xml",
    "webp": "image/webp",
}


def main() -> int:
    url = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    if not url.startswith(("http://", "https://")):
        print(f"[icon] invalid url: {url!r}", file=sys.stderr)
        return 1

    # 下载 favicon
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
    except Exception as exc:
        print(f"[icon] download failed: {exc}", file=sys.stderr)
        return 1

    if not data or len(data) > 2 * 1024 * 1024:  # 空或 >2MB 跳过
        print("[icon] empty or too large", file=sys.stderr)
        return 1

    # 从 URL 路径推断扩展名
    path = urllib.parse.urlparse(url).path.lower()
    ext = "ico"
    for e in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"):
        if path.endswith(e):
            ext = e.lstrip(".")
            break

    h = hashlib.sha256(url.encode()).hexdigest()[:16]
    out_dir = os.path.join(BASE, "reports", "icons")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, f"{h}.{ext}")
    try:
        with open(out_file, "wb") as f:
            f.write(data)
    except Exception as exc:
        print(f"[icon] write failed: {exc}", file=sys.stderr)
        return 1

    b64 = base64.b64encode(data).decode("ascii")
    rel_path = os.path.join("reports", "icons", f"{h}.{ext}")
    mime = MIME_MAP.get(ext, "image/x-icon")
    payload = json.dumps(
        {"url": url, "path": rel_path, "b64": b64, "mime": mime}, ensure_ascii=False
    )
    print(json.dumps({"ICON": payload}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
