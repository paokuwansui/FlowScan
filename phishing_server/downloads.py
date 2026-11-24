"""下载物配置管理 — 多下载物(name ↔ path/url + UA 匹配),存 downloads.json。

格式:
    [
      {"name": "vpn_client", "path": "/download/vpn.exe",  "ua": ""},
      {"name": "vpn_client", "path": "https://cdn.x/vpn-c.exe", "ua": "chrome"},
      {"name": "vpn_client", "path": "https://cdn.x/vpn-f.exe", "ua": "firefox"}
    ]

- name: 下载物名称,页面 <a data-download="名称"> 引用
- path: 真实地址(本服务器文件用 /download/<file>;外部 URL 直接 http/https)
- ua:   浏览器匹配(chrome/firefox/edge/safari;空 = 通用兜底)
同 name 多条 = 按访客 UA 动态选择。
"""

import ipaddress
import json
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# 允许的 UA 匹配值(空串 = 通用)
_ALLOWED_UA = {"", "chrome", "firefox", "edge", "safari"}

# 页面里的 <a data-download> 会直接使用 path 作为跳转地址 —— 不限制协议/主机
# 等于给访客一个任意外站跳板(还能指向内网/本机做探测)。只允许:
#   1) /download/<文件>  本站共享下载目录
#   2) 公网 http(s) URL
_BLOCKED_HOST_SUFFIX = (".localhost", ".local", ".internal", ".home.arpa")


def _path_error(path: str) -> Optional[str]:
    """校验下载地址。合法返回 None,否则返回原因。"""
    if path.startswith("/download/"):
        fname = path[len("/download/"):]
        if not fname or "/" in fname or "\\" in fname or ".." in fname:
            return f"本机下载路径非法: {path}"
        return None
    parts = urlsplit(path)
    if parts.scheme not in ("http", "https"):
        return f"只允许 http/https 或 /download/<文件>: {path}"
    host = (parts.hostname or "").lower()
    if not host:
        return f"URL 缺少主机名: {path}"
    if host == "localhost" or host.endswith(_BLOCKED_HOST_SUFFIX):
        return f"禁止指向本机/内网地址: {path}"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified):
        return f"禁止指向本机/内网地址: {path}"
    return None


def downloads_path(config) -> str:
    """downloads.json 绝对路径(与 config.json 同目录)。"""
    base = getattr(config, "base_dir", "") or "."
    return os.path.join(base, "downloads.json")


def load_downloads(config) -> List[Dict[str, str]]:
    """读取下载物列表;文件缺失/损坏返回 []。"""
    try:
        with open(downloads_path(config), "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(raw, list):
        return []
    out = []
    for x in raw:
        if not isinstance(x, dict):
            continue
        name = str(x.get("name") or "").strip()
        path = str(x.get("path") or "").strip()
        if not name or not path:
            continue
        if _path_error(path):
            continue               # 存量非法地址直接不加载(不跳外站/内网)
        ua = str(x.get("ua") or "").strip().lower()
        if ua not in _ALLOWED_UA:
            ua = ""
        out.append({"name": name, "path": path, "ua": ua})
    return out


def save_downloads(config, downloads: List[Dict[str, Any]]) -> Tuple[bool, str]:
    """校验并写回 downloads.json。返回 (ok, message)。"""
    out = []
    errors = []
    for x in (downloads or []):
        if not isinstance(x, dict):
            continue
        name = str(x.get("name") or "").strip()
        path = str(x.get("path") or "").strip()
        if not name or not path:
            continue
        err = _path_error(path)
        if err:
            errors.append(f"{name}: {err}")
            continue
        ua = str(x.get("ua") or "").strip().lower()
        if ua not in _ALLOWED_UA:
            ua = ""
        out.append({"name": name, "path": path, "ua": ua})
    if errors:
        return False, "以下下载地址非法,已拒绝保存 —— " + "；".join(errors)
    try:
        with open(downloads_path(config), "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        return True, f"已保存 {len(out)} 个下载物"
    except OSError as e:
        return False, f"保存失败: {e}"
