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

import json
import os
from typing import Any, Dict, List, Tuple

# 允许的 UA 匹配值(空串 = 通用)
_ALLOWED_UA = {"", "chrome", "firefox", "edge", "safari"}


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
        ua = str(x.get("ua") or "").strip().lower()
        if ua not in _ALLOWED_UA:
            ua = ""
        out.append({"name": name, "path": path, "ua": ua})
    return out


def save_downloads(config, downloads: List[Dict[str, Any]]) -> Tuple[bool, str]:
    """校验并写回 downloads.json。返回 (ok, message)。"""
    out = []
    for x in (downloads or []):
        if not isinstance(x, dict):
            continue
        name = str(x.get("name") or "").strip()
        path = str(x.get("path") or "").strip()
        if not name or not path:
            continue
        ua = str(x.get("ua") or "").strip().lower()
        if ua not in _ALLOWED_UA:
            ua = ""
        out.append({"name": name, "path": path, "ua": ua})
    try:
        with open(downloads_path(config), "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        return True, f"已保存 {len(out)} 个下载物"
    except OSError as e:
        return False, f"保存失败: {e}"
