"""
server/s_modules/tls_util.py — TLS 证书工具（U3 / Agent mTLS）

零第三方依赖：自签证书/CA/受签证书经系统 openssl 生成（server 侧工具）。
返回 cert/key PEM + sha256 指纹（指纹烧进 implant 与 agent 代码做 pin）。
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


def generate_ca(out_dir: str, cn: str = "pyexec-c2-ca") -> dict:
    """生成自签 CA（10 年）。返回 {ca_pem, ca_key_pem, ca_fingerprint, ca_file, ca_key_file}。"""
    os.makedirs(out_dir, exist_ok=True)
    ca_key_file = os.path.join(out_dir, "mtls_ca.key")
    ca_file = os.path.join(out_dir, "mtls_ca.crt")

    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", ca_key_file, "-out", ca_file,
         "-days", "3650", "-nodes", "-subj", f"/CN={cn}"],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"openssl CA failed: {r.stderr[:300]}")

    with open(ca_file, "r", encoding="utf-8") as f:
        ca_pem = f.read()
    with open(ca_key_file, "r", encoding="utf-8") as f:
        ca_key_pem = f.read()

    der = subprocess.run(
        ["openssl", "x509", "-in", ca_file, "-outform", "DER"],
        capture_output=True, timeout=30)
    if der.returncode != 0:
        raise RuntimeError("openssl x509 DER conversion failed")
    fingerprint = hashlib.sha256(der.stdout).hexdigest()

    return {
        "ca_pem": ca_pem, "ca_key_pem": ca_key_pem,
        "ca_fingerprint": fingerprint,
        "ca_file": ca_file, "ca_key_file": ca_key_file,
    }


def issue_cert(ca: dict, cn: str, out_dir: str, name: str) -> dict:
    """用 CA 签发服务器/客户端证书。返回 {cert_pem, key_pem, cert_file, key_file}。"""
    os.makedirs(out_dir, exist_ok=True)
    key_file = os.path.join(out_dir, f"{name}.key")
    csr_file = os.path.join(out_dir, f"{name}.csr")
    cert_file = os.path.join(out_dir, f"{name}.crt")

    r = subprocess.run(["openssl", "genrsa", "-out", key_file, "2048"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"openssl genrsa failed: {r.stderr[:300]}")

    r = subprocess.run(["openssl", "req", "-new", "-key", key_file,
                        "-out", csr_file, "-subj", f"/CN={cn}"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"openssl req failed: {r.stderr[:300]}")

    r = subprocess.run(
        ["openssl", "x509", "-req", "-in", csr_file,
         "-CA", ca["ca_file"], "-CAkey", ca["ca_key_file"], "-CAcreateserial",
         "-out", cert_file, "-days", "3650"],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"openssl x509 -req failed: {r.stderr[:300]}")

    for f in (csr_file, os.path.join(out_dir, "mtls_ca.srl")):
        try:
            os.remove(f)
        except OSError:
            pass

    with open(cert_file, "r", encoding="utf-8") as f:
        cert_pem = f.read()
    with open(key_file, "r", encoding="utf-8") as f:
        key_pem = f.read()

    return {
        "cert_pem": cert_pem, "key_pem": key_pem,
        "cert_file": cert_file, "key_file": key_file,
    }
