"""
@module: priv_esc_parse
@desc: 解析 priv_esc 提权检测结果,回填注册表字段
"""
import json

MODULE = {
    "desc": "解析 priv_esc 提权检测结果,回填注册表字段",
    "params": [],
}


def run(output, error="", *extra):
    """处理器形态: run(output, error, *extra) -> dict(Q7 约定)。

    提取:可提权 SUID 数、命中 CVE 列表、内核版本、发行版。
    输出为空/无法解析返回 {}（框架按白名单回填,未知键丢弃;空输出不覆盖旧值）。
    """
    if not (output or "").strip():
        return {}
    try:
        data = json.loads(output.strip() or "{}")
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}

    fields = {}
    suid = data.get("suid") or []
    cve = data.get("cve") or []
    gtfobins_n = sum(1 for s in suid if s.get("gtfobins"))
    if isinstance(suid, list):
        fields["priv_suid_n"] = len(suid)
        fields["priv_suid_gtfobins_n"] = gtfobins_n
    if isinstance(cve, list):
        fields["priv_cve_list"] = ",".join(
            f"{c.get('cve', '?')}({c.get('name', '')})" for c in cve[:5]) or ""
    kern = data.get("kernel", "")
    if isinstance(kern, str) and kern:
        fields["kernel_version"] = kern
    distro = data.get("distro", "")
    if isinstance(distro, str) and distro:
        fields["sys_distro"] = distro
    return fields
