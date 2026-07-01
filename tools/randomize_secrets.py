#!/usr/bin/env python3
"""
Randomize sensitive values in config.yaml.

Replaces:
  - redis.password
  - web_config.password
  - web_config.secret_key
  - ai_analysis.log_api_key

Usage: python3 randomize_secrets.py [config.yaml]
"""

import secrets
import string
import sys
from pathlib import Path

import yaml


def random_password(length: int = 24):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))


def random_secret_key():
    return secrets.token_hex(32)


def random_log_api_key():
    return "fs3-log-" + secrets.token_hex(16)


def main():
    config_path = Path(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")

    if not config_path.exists():
        print(f"ERROR: {config_path} not found")
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as handle:
        cfg = yaml.safe_load(handle) or {}

    # redis
    redis_cfg = cfg.setdefault("redis", {})
    redis_cfg["password"] = random_password()
    print(f"  redis.password        → {redis_cfg['password']}")

    # web
    web_cfg = cfg.setdefault("web_config", {})
    web_cfg["password"] = random_password(16)
    web_cfg["secret_key"] = random_secret_key()
    print(f"  web_config.password   → {web_cfg['password']}")
    print(f"  web_config.secret_key → {web_cfg['secret_key']}")

    # ai
    ai_cfg = cfg.setdefault("ai_analysis", {})
    ai_cfg["log_api_key"] = random_log_api_key()
    print(f"  ai_analysis.log_api_key → {ai_cfg['log_api_key']}")

    with open(config_path, "w", encoding="utf-8") as handle:
        yaml.dump(cfg, handle, allow_unicode=True, default_flow_style=False, sort_keys=False)

    print(f"\nDone. Updated {config_path}")


if __name__ == "__main__":
    main()
