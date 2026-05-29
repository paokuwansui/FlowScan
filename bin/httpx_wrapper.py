#!/usr/bin/env python3
"""ProjectDiscovery httpx wrapper for FlowScan.

This wrapper keeps httpx.yaml simple by converting raw httpx JSONL into a
FlowScan-friendly JSONL contract. It does not invent fields: favicon/icon fields
are emitted only when httpx reports them.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse, urlunparse

import tldextract


def _unique(values: Iterable[Any]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def registered_domain(hostname: str) -> str | None:
    """Return eTLD+1 using the Public Suffix List via tldextract."""
    host = (hostname or "").strip().strip(".").lower()
    if not host:
        return None
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def _normalize_icon_path(value: Any, raw: dict[str, Any]) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith(("http://", "https://")):
        return text

    parsed_url = urlparse(str(raw.get("url") or ""))
    scheme = str(raw.get("scheme") or parsed_url.scheme or "https").strip() or "https"
    host = str(raw.get("host") or parsed_url.netloc or "").strip()

    if text.startswith("//"):
        return f"{scheme}:{text}"
    if text.startswith("/") and host:
        return urlunparse((scheme, host, text, "", "", ""))
    return text


def normalize_httpx_record(raw: dict[str, Any]) -> dict[str, Any]:
    tls = raw.get("tls") if isinstance(raw.get("tls"), dict) else {}
    fingerprint_hash = tls.get("fingerprint_hash") if isinstance(tls.get("fingerprint_hash"), dict) else {}

    san_hosts = _unique(tls.get("subject_an") or [])
    domain_candidates = san_hosts or _unique([raw.get("host"), tls.get("host"), raw.get("input")])
    domains = _unique(registered_domain(host) for host in domain_candidates)

    output: dict[str, Any] = {}

    url = raw.get("url")
    if url:
        output["LIVE_URL"] = str(url).strip()

    if domains:
        output["DOMAIN"] = domains

    if san_hosts:
        output["SUBDOMAIN"] = san_hosts

    ips = _unique([raw.get("host_ip"), *(_ensure_list(raw.get("a")))])
    if ips:
        output["IP"] = ips

    cert_org = _unique(tls.get("subject_org") or [])
    if cert_org:
        output["CERT_ORG"] = cert_org

    cert_fingerprint = fingerprint_hash.get("sha256")
    if cert_fingerprint:
        output["CERT_FINGERPRINT"] = str(cert_fingerprint).strip()

    # Do not guess /favicon.ico. Only forward icon data that httpx actually reports.
    # Prefer URL fields because httpx path fields may be relative (/favicon.ico) or
    # protocol-relative (//cdn.example/favicon.ico). Normalize path-only fields to a
    # complete URL when scheme+host are available.
    for key in ("favicon_url", "icon_url", "favicon_path", "icon_path"):
        normalized_icon_path = _normalize_icon_path(raw.get(key), raw)
        if normalized_icon_path:
            output["ICON_PATH"] = normalized_icon_path
            break

    if raw.get("favicon") is not None:
        output["ICON_HASH"] = str(raw["favicon"]).strip()
    elif isinstance(raw.get("knowledgebase"), dict) and raw["knowledgebase"].get("pHash") not in (None, 0, "0", ""):
        output["ICON_HASH"] = str(raw["knowledgebase"]["pHash"]).strip()

    return output


def normalize_jsonl_stream(lines: Iterable[str]) -> int:
    emitted = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"[httpx-wrapper] skip non-json line: {exc}: {line}", file=sys.stderr)
            continue
        if not isinstance(raw, dict):
            continue
        normalized = normalize_httpx_record(raw)
        if normalized:
            print(json.dumps(normalized, ensure_ascii=False, separators=(",", ":")), flush=True)
            emitted += 1
    return emitted


def run_httpx(args: argparse.Namespace) -> int:
    httpx_bin = args.httpx_bin or shutil.which("httpx")
    if not httpx_bin:
        print("[httpx-wrapper] httpx binary not found in PATH", file=sys.stderr)
        return 127

    cmd = [
        httpx_bin,
        "-title",
        "-favicon",
        "-tls-probe",
        "-status-code",
        "-json",
        "-silent",
    ]
    if args.extra:
        cmd.extend(args.extra)

    proc = subprocess.Popen(
        cmd,
        stdin=sys.stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    normalize_jsonl_stream(proc.stdout)
    _, stderr = proc.communicate()
    if stderr:
        print(stderr, file=sys.stderr, end="")
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run httpx and normalize JSONL output for FlowScan")
    parser.add_argument("--httpx-bin", default="", help="path to projectdiscovery httpx binary; default: PATH lookup")
    parser.add_argument("--normalize-only", action="store_true", help="read raw httpx JSONL from stdin and normalize it without running httpx")
    parser.add_argument("extra", nargs=argparse.REMAINDER, help="extra arguments appended to httpx")
    args = parser.parse_args(argv)

    if args.normalize_only:
        normalize_jsonl_stream(sys.stdin)
        return 0
    return run_httpx(args)


if __name__ == "__main__":
    raise SystemExit(main())
