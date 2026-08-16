"""
@module: sysinfo_parse
@desc: 解析 sysinfo 结果，返回注册表回填字段
"""
import json

MODULE = {
    "desc": "解析 sysinfo 结果，返回注册表回填字段",
    "params": [],
}


def run(output, error="", *extra):
    """处理器形态: run(output, error, *extra) -> dict（Q7 约定）。

    extra 为扩展参数（proc_arg / disp / bid），sysinfo 不需要；
    download_parse 等处理器按需声明使用。

    Returns:
        {"sys_user": ..., "sys_os": ..., "sys_platform": ...} 的过滤子集。
        无法解析时返回 {}（框架按白名单回填，未知键丢弃）。
    """
    try:
        data = json.loads(output.strip() or "{}")
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}

    fields = {}
    user = data.get("user", "")
    os_str = data.get("os", "")
    if isinstance(user, str) and user:
        fields["sys_user"] = user
    if isinstance(os_str, str) and os_str:
        fields["sys_os"] = os_str
        fields["sys_platform"] = detect_platform(os_str)
    return fields


def detect_platform(os_str: str) -> str:
    """平台判定（从 client_manager.set_sysinfo 迁入，10.1 边界清单）。"""
    low = os_str.lower()
    if "windows" in low:
        return "windows"
    if "linux" in low:
        return "linux"
    if "darwin" in low or "macos" in low or "mac os" in low:
        return "macos"
    return ""


if __name__ == "__main__":
    print(run('{"user": "alice", "os": "Linux-5.15.0-x86_64"}'))
