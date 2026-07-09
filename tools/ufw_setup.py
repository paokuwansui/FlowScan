#!/usr/bin/env python3
"""
Quick UFW firewall setup.

Usage:
    python3 ufw_setup.py                                # ensure SSH open + enable UFW
    python3 ufw_setup.py -i 10.0.0.5 -p 6379             # allow 10.0.0.5 to port 6379 tcp+udp
    python3 ufw_setup.py -p 6379,8080                    # allow any IP to ports 6379 and 8080
    python3 ufw_setup.py -i 10.0.0.5,10.0.0.6 -p 6379    # allow two IPs to port 6379
    python3 ufw_setup.py status                          # show current rules
"""

import argparse
import subprocess
import sys


def run(cmd, check=True):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip()
        if check and r.returncode != 0 and out:
            print(f"  [!] {out}")
        return r.returncode == 0, out
    except Exception as e:
        return False, str(e)


def ufw_installed():
    _, out = run("which ufw", check=False)
    return bool(out and "ufw" in out)


def ufw_enabled():
    _, out = run("sudo ufw status", check=False)
    return "Status: active" in out


def ssh_open_to_any():
    """Check if port 22/tcp is allowed from anywhere."""
    _, out = run("sudo ufw status numbered", check=False)
    # Look for "22/tcp" with "ALLOW" and "Anywhere"
    for line in out.splitlines():
        if "22/tcp" in line and "ALLOW" in line and ("Anywhere" in line or "0.0.0.0" in line):
            return True
    return False


def ensure_ssh():
    if ssh_open_to_any():
        print("  SSH (22/tcp) already open to anywhere — skip")
        return
    print("  Adding SSH (22/tcp) allow from anywhere...")
    run("sudo ufw allow 22/tcp")


def allow_port(port, ip=None):
    """Allow tcp+udp on port, optionally restricted to ip."""
    for proto in ("tcp", "udp"):
        if ip:
            rule = f"sudo ufw allow from {ip} to any port {port} proto {proto}"
            print(f"  Allow {ip} -> :{port}/{proto}")
        else:
            rule = f"sudo ufw allow {port}/{proto}"
            print(f"  Allow any -> :{port}/{proto}")
        run(rule)


def enable_ufw():
    if ufw_enabled():
        print("  UFW already enabled — skip")
        return
    print("  Enabling UFW...")
    # Use --force to avoid interactive prompt
    run("sudo ufw --force enable")


def show_status():
    _, out = run("sudo ufw status verbose", check=False)
    print(out)


def main():
    parser = argparse.ArgumentParser(description="UFW firewall quick setup")
    parser.add_argument("-i", "--ip",   default=None, help="来源 IP，逗号分隔多个，如: 10.0.0.1,10.0.0.2")
    parser.add_argument("-p", "--port", default=None, help="开放端口，逗号分隔多个，如: 6379,8080")
    parser.add_argument("command", nargs="?", default="setup",
                        choices=["setup", "status"],
                        help="Action: setup (default) or status")
    args = parser.parse_args()

    if args.command == "status":
        show_status()
        return

    if not ufw_installed():
        print("UFW not installed. Run: sudo apt install ufw -y")
        sys.exit(1)

    ips   = [x.strip() for x in args.ip.split(",") if x.strip()]   if args.ip   else []
    ports = [x.strip() for x in args.port.split(",") if x.strip()] if args.port else []

    print("=== UFW Setup ===")

    ensure_ssh()

    if ports:
        for port in ports:
            if ips:
                for ip in ips:
                    allow_port(port, ip)
            else:
                allow_port(port)

    enable_ufw()

    print()
    show_status()
    print("\nDone.")


if __name__ == "__main__":
    main()
