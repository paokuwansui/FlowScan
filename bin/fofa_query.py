#!/usr/bin/env python3
"""FlowScan FOFA wrapper implemented on top of FoFaX.

The wrapper keeps the historical fofa-flowscan JSONL output contract:
{"type": "URL|IP|SUBDOMAIN|DOMAIN", "value": "..."}

Input semantics:
- DOMAIN/SUBDOMAIN-like value -> fofax -q 'domain="value"' -ffi
- LIVE_URL-like value          -> fofax -uc value -ffi
- ICON_PATH-like favicon URL   -> fofax -iu value -ffi
"""

import argparse
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

IP_RE = re.compile(r"^(?P<ip>(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))(?:[:/].*)?$")
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
LOG_RE = re.compile(r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[[A-Z]+\]")


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

    if is_url(item):
        return {"type": "URL", "value": item}

    host = strip_port(item)
    ip_match = IP_RE.match(item)
    if ip_match:
        return {"type": "IP", "value": ip_match.group("ip")}

    if DOMAIN_RE.match(host):
        if len(host.split(".")) > 2:
            return {"type": "SUBDOMAIN", "value": host}
        return {"type": "DOMAIN", "value": host}

    return None


def parse_fofax_output_lines(lines):
    seen = set()
    for line in lines:
        parsed = classify_fofax_value(line)
        if not parsed:
            continue
        key = (parsed["type"], parsed["value"])
        if key in seen:
            continue
        seen.add(key)
        yield parsed


def build_fofax_args(query: str, fetch_size: int = 1000) -> list[str]:
    value = query.strip()
    fetch = ["-fs", str(fetch_size), "-ffi"]
    if looks_like_icon_url(value):
        return ["-iu", value, *fetch]
    if is_url(value):
        return ["-uc", value, *fetch]
    if value.startswith('fx=') or value.startswith('fx="') or value.startswith("fx='"):
        return ["-q", value, "-fe", *fetch]
    if any(op in value for op in ('="', "='", " && ", " || ", "title=", "body=", "host=", "ip=", "app=")):
        return ["-q", value, *fetch]
    return ["-q", f'domain="{value}"', *fetch]


def run_fofax(fofax_bin: str, query: str, fetch_size: int) -> int:
    cmd = [fofax_bin]
    api_key = os.environ.get("FOFA_KEY", "")
    if api_key:
        cmd.extend(["-key", api_key])
    cmd.extend(build_fofax_args(query, fetch_size=fetch_size))

    try:
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120, check=False)
    except FileNotFoundError:
        print(f"[-] 未找到 fofax 二进制: {fofax_bin}", file=sys.stderr)
        return 127
    except subprocess.TimeoutExpired as exc:
        print(f"[-] fofax 执行超时: {sanitize_error_message(exc)}", file=sys.stderr)
        return 124
    except Exception as exc:
        print(f"[-] fofax 执行失败: {sanitize_error_message(exc)}", file=sys.stderr)
        return 2

    for record in parse_fofax_output_lines(proc.stdout.splitlines()):
        print(json.dumps(record, ensure_ascii=False))

    if proc.returncode != 0:
        print(sanitize_error_message(proc.stdout), file=sys.stderr)
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
