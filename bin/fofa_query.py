#!/usr/bin/env python3
"""FlowScan FOFA wrapper implemented on top of FoFaX.

The wrapper keeps the historical fofa-flowscan JSONL output contract:
{"type": "URL|IP|SUBDOMAIN|DOMAIN", "value": "..."}

Input semantics:
- DOMAIN/SUBDOMAIN-like value -> fofax -q 'domain="value"' -ffi
- LIVE_URL-like value          -> fofax -uc value -ffi
- ICON_PATH-like favicon URL   -> fofax -iu value -ffi
- FOFA expression / fx query   -> fofax -q value [-fe] -ffi

Output policy semantics:
- mode="truncate": output at most policy["limit"] unique parsed results.
- mode="drop_all": if unique parsed results exceed policy["limit"], output nothing.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

# 查询策略配置：按“接收到的查询事件类型”控制最多输出数量和超量处理方式。
# mode 支持：
# - truncate：截断输出，最多输出 limit 条。
# - drop_all：只要去重后的有效结果数量大于 limit，则本次查询结果全部丢弃，一条也不返回。
QUERY_POLICIES = {
    "DOMAIN": {"limit": 1000, "mode": "truncate"},     # 域名或子域名查询事件
    "URL": {"limit": 500, "mode": "truncate"},         # URL 存活查询事件
    "ICON": {"limit": 300, "mode": "drop_all"},        # 图标 Hash / favicon 匹配事件
    "ADVANCED": {"limit": 1000, "mode": "truncate"},   # 高级 FOFA 语法/表达式查询事件
}

DEFAULT_QUERY_POLICY = {"limit": 1000, "mode": "truncate"}
VALID_POLICY_MODES = {"truncate", "drop_all"}

IP_RE = re.compile(r"^(?P<ip>(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))(?:[:/].*)?$")
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
LOG_RE = re.compile(r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[[A-Z]+\]")

# 常见的多级公共后缀，用于准确判定 DOMAIN / SUBDOMAIN
COMMON_PUBLIC_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "org.top",
    "co.uk", "me.uk", "org.uk", "ltd.uk", "plc.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.tw", "org.tw", "edu.tw", "com.hk", "org.hk"
}

# 过滤黑名单：防止工具自身的 Banner、主页或文档地址被误识别为资产
IGNORE_DOMAINS = {"fofax.xiecat.fun", "xiecat.fun"}


def sanitize_error_message(err) -> str:
    text = str(err)
    text = re.sub(r"(?i)(key|fofakey)=([^&\s)]+)", r"\1=[REDACTED]", text)
    text = re.sub(r"(?i)(-key|-fofakey)\s+\S+", r"\1 [REDACTED]", text)
    return text


def is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def looks_like_icon_url(value: str) -> bool:
    if not is_url(value):
        return False
    parsed = urlparse(value)
    path = parsed.path.lower()
    return any(token in path for token in ("favicon", "icon")) or path.endswith((".ico", ".png", ".jpg", ".jpeg", ".svg", ".webp"))


def strip_port(host: str) -> str:
    host = host.strip().strip("[]")
    if ":" in host and host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host


def parse_domain_type(host: str) -> str:
    """精准识别是根域名还是子域名，考虑多级后缀"""
    parts = host.split(".")
    if len(parts) <= 2:
        return "DOMAIN"

    # 检查最后两级是否属于常见双字后缀（如 com.cn）
    last_two = ".".join(parts[-2:])
    if last_two in COMMON_PUBLIC_SUFFIXES:
        return "DOMAIN" if len(parts) == 3 else "SUBDOMAIN"

    return "SUBDOMAIN"


def get_query_mode(query: str) -> str:
    """根据接收到的原始查询值识别查询事件类型，用于选择 QUERY_POLICIES。"""
    value = query.strip()
    if looks_like_icon_url(value):
        return "ICON"
    if is_url(value):
        return "URL"
    if is_advanced_fofa_query(value):
        return "ADVANCED"
    return "DOMAIN"


def is_advanced_fofa_query(value: str) -> bool:
    """识别 FOFA 高级语法/表达式查询。"""
    if value.startswith(('fx=', 'fx="', "fx='")):
        return True
    return any(op in value for op in ('="', "='", " && ", " || ", "title=", "body=", "host=", "ip=", "app="))


def get_query_policy(query_mode: str) -> dict[str, int | str]:
    """读取并校验查询策略；配置错误时回退到安全的默认截断策略。"""
    raw_policy = QUERY_POLICIES.get(query_mode, DEFAULT_QUERY_POLICY)

    try:
        limit = int(raw_policy.get("limit", DEFAULT_QUERY_POLICY["limit"]))
    except (TypeError, ValueError):
        limit = int(DEFAULT_QUERY_POLICY["limit"])
    if limit < 0:
        limit = 0

    mode = str(raw_policy.get("mode", DEFAULT_QUERY_POLICY["mode"])).strip()
    if mode not in VALID_POLICY_MODES:
        mode = str(DEFAULT_QUERY_POLICY["mode"])

    return {"limit": limit, "mode": mode}


def classify_fofax_value(value: str) -> dict[str, str] | None:
    item = value.strip().strip("'").strip('"')
    if not item or LOG_RE.match(item):
        return None
    if item.startswith(("[", "-", "Usage:", "Flags:", "CONFIGS:", "FILTERS:", "SINGLE ", "MULTIPLE ", "FX ", "OTHER ")):
        return None
    if item.startswith(("┌", "├", "└", "│")):
        return None
    if " " in item and not item.startswith(("http://", "https://")):
        return None

    # 检查是否为 URL
    if is_url(item):
        parsed = urlparse(item)
        # 拦截黑名单域名（支持带端口的情况）
        host_netloc = parsed.netloc.split(":")[0]
        if host_netloc in IGNORE_DOMAINS:
            return None
        return {"type": "URL", "value": item}

    host = strip_port(item)

    # 拦截独立出现的黑名单域名
    if host in IGNORE_DOMAINS:
        return None

    ip_match = IP_RE.match(item)
    if ip_match:
        return {"type": "IP", "value": ip_match.group("ip")}

    if DOMAIN_RE.match(host):
        dtype = parse_domain_type(host)
        return {"type": dtype, "value": host}

    return None


def build_fofax_args(query: str, fetch_size: int = 1000) -> list[str]:
    value = query.strip()
    fetch = ["-fs", str(fetch_size), "-ffi"]
    if looks_like_icon_url(value):
        return ["-iu", value, *fetch]
    if is_url(value):
        return ["-uc", value, *fetch]
    if value.startswith('fx=') or value.startswith('fx="') or value.startswith("fx='"):
        return ["-q", value, "-fe", *fetch]
    if is_advanced_fofa_query(value):
        return ["-q", value, *fetch]
    return ["-q", f'domain="{value}"', *fetch]


def emit_with_policy(parsed: dict[str, str], policy: dict[str, int | str], state: dict) -> None:
    """按策略处理一条去重后的有效结果。drop_all 模式会延迟到查询结束后再输出。"""
    limit = int(policy["limit"])
    mode = str(policy["mode"])

    state["count"] += 1

    if mode == "truncate":
        if state["count"] <= limit:
            print(json.dumps(parsed, ensure_ascii=False), flush=True)
        return

    if mode == "drop_all":
        if state["count"] <= limit:
            state["buffer"].append(parsed)
        else:
            state["dropped"] = True
            state["buffer"].clear()


def flush_drop_all_buffer(policy: dict[str, int | str], state: dict) -> None:
    """drop_all 模式下，如果最终未超过 limit，则统一输出缓存结果。"""
    if policy["mode"] != "drop_all" or state.get("dropped"):
        return
    for parsed in state.get("buffer", []):
        print(json.dumps(parsed, ensure_ascii=False), flush=True)


def run_fofax(fofax_bin: str, query: str, fetch_size: int) -> int:
    query_mode = get_query_mode(query)
    policy = get_query_policy(query_mode)

    cmd = [fofax_bin]
    api_key = os.environ.get("FOFA_KEY", "")
    if api_key:
        cmd.extend(["-key", api_key])
    cmd.extend(build_fofax_args(query, fetch_size=fetch_size))

    try:
        # 改用 Popen 流式读取，防止大文本输出导致缓冲区满而死锁
        proc = subprocess.Popen(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
    except FileNotFoundError:
        print(f"[-] 未找到 fofax 二进制: {fofax_bin}", file=sys.stderr)
        return 127
    except Exception as exc:
        print(f"[-] fofax 启动失败: {sanitize_error_message(exc)}", file=sys.stderr)
        return 2

    seen = set()
    state = {"count": 0, "buffer": [], "dropped": False}

    try:
        # 流式按行解析，优化内存并杜绝卡死
        for line in proc.stdout:
            parsed = classify_fofax_value(line)
            if not parsed:
                continue
            key = (parsed["type"], parsed["value"])
            if key in seen:
                continue
            seen.add(key)
            emit_with_policy(parsed, policy, state)

        proc.wait(timeout=120)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        print(f"[-] fofax 执行超时: {sanitize_error_message(exc)}", file=sys.stderr)
        return 124
    except Exception as exc:
        proc.kill()
        print(f"[-] 运行运行时异常: {sanitize_error_message(exc)}", file=sys.stderr)
        return 2

    flush_drop_all_buffer(policy, state)
    return proc.returncode


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="FlowScan FoFaX JSONL wrapper")
    parser.add_argument("query", help="DOMAIN / LIVE_URL / ICON_PATH / FOFA 查询语句")
    parser.add_argument("--fofax-bin", default=os.path.expandvars("$HOME/.local/bin/fofax"), help="fofax 二进制路径")
    parser.add_argument("--fetch-size", "-fs", type=int, default=1000, help="FoFaX fetch size")
    args = parser.parse_args(argv)
    return run_fofax(args.fofax_bin, args.query, args.fetch_size)


if __name__ == "__main__":
    raise SystemExit(main())
