import hashlib
import json
import re
import socket
import ssl
import sys
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


def get_cert_hash_by_url():
    # 1. 校验命令行参数
    if len(sys.argv) < 2:
        sys.exit(1)

    url_arg = sys.argv[1]

    # 2. 解析 URL
    parsed_url = urlparse(url_arg)
    hostname = parsed_url.hostname

    if not hostname:
        sys.exit(1)

    port = parsed_url.port if parsed_url.port else 443

    # 3. 配置 SSL 上下文（忽略证书验证错误）
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # 初始化存储变量
    sha256_hash = ""
    site_title = ""
    favicon_url = ""

    # 4. 步骤一：通过 Socket 获取 SSL 证书指纹 (SHA-256)
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(
                sock, server_hostname=hostname
            ) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                sha256_hash = format_hash_colon(
                    hashlib.sha256(cert_der).hexdigest()
                )
    except Exception:
        pass

    # 5. 步骤二：通过 HTTP 请求获取网页源码，解析 Title 和 Favicon
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
        }
        req = Request(url_arg, headers=headers)

        with urlopen(req, context=context, timeout=6) as response:
            html_bytes = response.read()

            try:
                html_text = html_bytes.decode("utf-8", errors="replace")
            except Exception:
                html_text = html_bytes.decode("gbk", errors="replace")

            # 正则匹配提取 <title>
            title_match = re.search(
                r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.S
            )
            if title_match:
                site_title = title_match.group(1).strip()

            # 正则匹配提取 <link rel="*icon" href="...">
            icon_match = re.search(
                (
                    r'<link[^>]+rel=["\'](?:shortcut\s+)?icon["\'][^>]+href=["\']([^"\']+)["\']'
                ),
                html_text,
                re.IGNORECASE,
            )
            if not icon_match:
                icon_match = re.search(
                    (
                        r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut\s+)?icon["\']'
                    ),
                    html_text,
                    re.IGNORECASE,
                )

            if icon_match:
                raw_icon_path = icon_match.group(1).strip()
                favicon_url = urljoin(url_arg, raw_icon_path)
            else:
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                favicon_url = urljoin(base_url, "favicon.ico")

    except Exception:
        pass

    # 6. 按要求的格式输出结果（使用 json.dumps 确保特殊字符被正确转义）
    print(json.dumps({"type": "TITLE", "value": site_title}, ensure_ascii=False))
    print(json.dumps({"type": "ICON", "value": favicon_url}, ensure_ascii=False))
    print(json.dumps({"type": "CERT_HASH", "value": sha256_hash}, ensure_ascii=False))


def format_hash_colon(hash_str):
    return ":".join(
        hash_str[i : i + 2].upper() for i in range(0, len(hash_str), 2)
    )


if __name__ == "__main__":
    get_cert_hash_by_url()
