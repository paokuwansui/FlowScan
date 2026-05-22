#!/usr/bin/env python3
"""Run nmap -sV for a single host:port and emit one JSON object per open port."""
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


def split_target(value: str):
    value = value.strip()
    if not value:
        raise ValueError("empty target")
    if value.startswith("[") and "]:" in value:
        host, port = value.rsplit(":", 1)
        return host.strip("[]"), port
    if ":" not in value:
        raise ValueError("expected host:port")
    host, port = value.rsplit(":", 1)
    if not re.fullmatch(r"\d{1,5}", port):
        raise ValueError("expected numeric port in host:port")
    return host, port


def service_fp(service):
    parts = []
    for key in ("product", "version", "extrainfo"):
        value = service.get(key, "")
        if value:
            parts.append(value)
    return " ".join(parts).strip()


def main():
    if len(sys.argv) != 2:
        print("usage: nmap_service.py host:port", file=sys.stderr)
        return 2
    try:
        host, port = split_target(sys.argv[1])
    except ValueError as exc:
        print(json.dumps({"error": str(exc), "input": sys.argv[1]}, ensure_ascii=False))
        return 0

    cmd = ["nmap", "-sV", "-Pn", "-p", port, "-oX", "-", host]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="ignore", timeout=180)
    text = proc.stdout
    start = text.find("<?xml")
    if start == -1:
        start = text.find("<nmaprun")
    if start > 0:
        text = text[start:]
    try:
        root = ET.fromstring(text)
    except Exception as exc:
        print(json.dumps({"host": host, "port": port, "error": f"xml_parse_failed: {exc}"}, ensure_ascii=False))
        return 0

    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port_node.find("service")
        svc = service.attrib if service is not None else {}
        name = svc.get("name", "unknown")
        product = svc.get("product", "")
        version = svc.get("version", "")
        fp = service_fp(svc)
        proto = port_node.get("protocol", "tcp")
        out = {
            "host": host,
            "port": port_node.get("portid", port),
            "protocol": proto,
            "state": "open",
            "service": name,
            "product": product,
            "version": version,
            "service_fp": fp,
        }
        print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
