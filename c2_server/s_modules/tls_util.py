"""
server/s_modules/tls_util.py — TLS 证书工具（U3）

零第三方依赖：自签证书经系统 openssl 生成（server 侧工具）。
返回 cert/key PEM + sha256 指纹（指纹烧进 implant 与 proxy 代码做 pin）。
"""

import hashlib
import os
import subprocess


def generate_self_signed(host: str, out_dir: str) -> dict:
    """用 openssl 生成自签证书（10 年有效期）。

    Returns:
        {"cert_pem": str, "key_pem": str, "fingerprint": sha256 hex,
         "cert_file": path, "key_file": path}

    Raises:
        RuntimeError: openssl 不可用或生成失败
    """
    os.makedirs(out_dir, exist_ok=True)
    key_file = os.path.join(out_dir, "proxy.key")
    cert_file = os.path.join(out_dir, "proxy.crt")

    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", key_file, "-out", cert_file,
         "-days", "3650", "-nodes", "-subj", f"/CN={host}"],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"openssl failed: {r.stderr[:300]}")

    with open(cert_file, "r", encoding="utf-8") as f:
        cert_pem = f.read()
    with open(key_file, "r", encoding="utf-8") as f:
        key_pem = f.read()

    der = subprocess.run(
        ["openssl", "x509", "-in", cert_file, "-outform", "DER"],
        capture_output=True, timeout=30)
    if der.returncode != 0:
        raise RuntimeError("openssl x509 DER conversion failed")
    fingerprint = hashlib.sha256(der.stdout).hexdigest()

    return {
        "cert_pem": cert_pem, "key_pem": key_pem,
        "fingerprint": fingerprint,
        "cert_file": cert_file, "key_file": key_file,
    }
