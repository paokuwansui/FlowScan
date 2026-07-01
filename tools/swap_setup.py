#!/usr/bin/env python3
"""
Quick swap space setup / resize.

Usage:
    python3 swap_setup.py <size_gb>
    python3 swap_setup.py 4        # 4 GB swap
    python3 swap_setup.py 16       # 16 GB swap
    python3 swap_setup.py status   # show current swap

Actions:
    1. Disable existing swap on /swapfile (if any)
    2. Create or resize /swapfile to <size_gb> GB
    3. mkswap + swapon
    4. Update /etc/fstab for persistence
"""

import os
import subprocess
import sys


SWAP_PATH = "/swapfile"


def run(cmd, check=True):
    """Run a shell command, return (ok, stdout, returncode)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = (r.stdout + r.stderr).strip()
        if check and r.returncode != 0:
            print(f"  [!] {cmd}\n  -> {output}")
        return r.returncode == 0, output, r.returncode
    except Exception as e:
        return False, str(e), 1


def show_status():
    print("=== Current Swap ===")
    _, out, _ = run("swapon --show 2>/dev/null || echo 'no swap active'", check=False)
    print(out or "(none)")
    print()
    _, out, _ = run("free -h | grep -i swap", check=False)
    print(out)


def disable_existing():
    """Turn off existing /swapfile if mounted."""
    _, out, _ = run(f"swapon --show | grep -q '{SWAP_PATH}'", check=False)
    if out:
        return
    # Check if it's actually mounted
    _, out, _ = run("swapon --show --noheadings", check=False)
    if SWAP_PATH in out:
        print(f"  Disabling existing swap at {SWAP_PATH}...")
        run(f"sudo swapoff {SWAP_PATH}", check=False)
        run(f"sudo sed -i '\\|^{SWAP_PATH} .*swap.*$|d' /etc/fstab", check=False)


def setup_swap(size_gb):
    if size_gb <= 0:
        print(f"ERROR: invalid size {size_gb} GB (must be > 0)")
        sys.exit(1)

    # Check free disk space
    _, out, _ = run(f"df -BG / | tail -1", check=False)
    try:
        avail = int(out.split()[3].replace("G", ""))
    except Exception:
        avail = 0
    if avail < size_gb + 1:
        print(f"WARNING: only {avail}G free on /, need {size_gb}G for swap")
        if input("Continue? [y/N] ").strip().lower() != "y":
            sys.exit(1)

    print(f"=== Setting up {size_gb} GB swap at {SWAP_PATH} ===")

    disable_existing()

    # Create swap file
    print(f"  Creating {size_gb}G swapfile...")
    ok, out, rc = run(f"sudo fallocate -l {size_gb}G {SWAP_PATH}", check=False)
    if not ok and "fallocate" in out and "not supported" in out:
        print("  fallocate not supported, using dd...")
        run(f"sudo dd if=/dev/zero of={SWAP_PATH} bs=1M count={size_gb * 1024} status=progress")

    run(f"sudo chmod 600 {SWAP_PATH}")

    # mkswap
    print("  Running mkswap...")
    ok, out, _ = run(f"sudo mkswap {SWAP_PATH}")
    if not ok and "existing swap signature" in out:
        print("  Overwriting existing swap signature...")
        run(f"sudo mkswap -f {SWAP_PATH}")

    # swapon
    print("  Enabling swap...")
    run(f"sudo swapon {SWAP_PATH}")

    # fstab
    print("  Adding to /etc/fstab...")
    run(f"sudo sed -i '\\|^{SWAP_PATH} .*swap.*$|d' /etc/fstab", check=False)
    run(f"echo '{SWAP_PATH} none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null")

    print()
    show_status()
    print("Done.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    arg = sys.argv[1].strip().lower()

    if arg in ("status", "show", "-s", "--status"):
        show_status()
        return

    try:
        size_gb = int(arg)
    except ValueError:
        print(f"ERROR: '{arg}' is not a valid size (use a number like 4, 8, 16)")
        sys.exit(1)

    setup_swap(size_gb)


if __name__ == "__main__":
    main()
