#!/usr/bin/env python3
"""Lightweight JavaScript secret finder for FlowScan.

Fetches a URL (usually a .js file) or reads a local file and emits JSONL secrets.
"""
import json
import re
import sys
import urllib.request

PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{12,20}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z_]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Bearer Token", re.compile(r"Bearer\s+([A-Za-z0-9._\-]{20,})", re.I)),
    ("Private Key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Password Assignment", re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]([^'\"]{6,})['\"]")),
]


def read_target(target: str) -> str:
    if target.startswith(("http://", "https://")):
        req = urllib.request.Request(target, headers={"User-Agent": "FlowScan-secretfinder/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read(2_000_000)
        return raw.decode("utf-8", errors="ignore")
    with open(target, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def line_context(text: str, start: int, end: int) -> str:
    left = text.rfind("\n", 0, start) + 1
    right = text.find("\n", end)
    if right == -1:
        right = len(text)
    return text[left:right].strip()[:500]


def main():
    if len(sys.argv) != 2:
        print("usage: secretfinder.py <url-or-file>", file=sys.stderr)
        return 2
    target = sys.argv[1]
    try:
        text = read_target(target)
    except Exception as exc:
        print(json.dumps({"url": target, "type": "FETCH_ERROR", "secret": str(exc), "context": ""}, ensure_ascii=False))
        return 0

    seen = set()
    for typ, pattern in PATTERNS:
        for m in pattern.finditer(text):
            secret = m.group(0)
            if typ == "Password Assignment" and m.lastindex and m.lastindex >= 2:
                secret = f"{m.group(1)}={m.group(2)}"
            elif typ == "Bearer Token" and m.lastindex:
                secret = m.group(1)
            key = (typ, secret)
            if key in seen:
                continue
            seen.add(key)
            print(json.dumps({
                "url": target,
                "type": typ,
                "secret": secret,
                "context": line_context(text, m.start(), m.end()),
            }, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
