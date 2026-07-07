#!/usr/bin/env python3
"""
FlowScan3 黑名单过滤器。

两套独立规则：
  1. 文件规则（black_list.cfg）— 模块级缓存，手动 reload
  2. Redis 规则（fs3:blacklist:rules）— 实时查询

格式: event_type:match_mode:value
  event_type = * | DNS_NAME | URL | IP_ADDRESS | ...
  match_mode = contains | suffix | prefix | ip_range
  contains 模式为正则，其余为字面量；所有匹配忽略大小写。

检测流程（在 push_event 中）：
  1. check_file_rules(event_type, value) → 命中则丢弃
  2. check_redis_rules(redis, event_type, value) → 命中则丢弃
  3. 均未命中 → 正常入队
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "black_list.cfg",
)


# ============================================================
# 数据模型
# ============================================================


@dataclass
class BlacklistRule:
    event_type: str    # "*" 表示匹配所有
    match_mode: str    # contains | suffix | prefix | ip_range
    value: str         # 匹配值
    source: str = "file"  # "file" | "redis"
    fp: str = ""       # sha256 指纹（Redis 规则用）
    comment: str = ""

    def __post_init__(self) -> None:
        if not self.fp:
            self.fp = _fingerprint(self.event_type, self.match_mode, self.value)


# ============================================================
# 配置文件加载（文件规则）
# ============================================================


def load_file_rules(config_path: str = CONFIG_PATH) -> List[BlacklistRule]:
    """解析 black_list.cfg，返回规则列表。"""
    rules: List[BlacklistRule] = []
    if not os.path.exists(config_path):
        return rules

    with open(config_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # 跳过空行和注释
            if not line or line.startswith("#"):
                continue
            rule = _parse_line(line)
            if rule:
                rules.append(rule)
    return rules


def _parse_line(line: str) -> Optional[BlacklistRule]:
    """解析一行规则: event_type:match_mode:value"""
    parts = line.split(":", 2)
    if len(parts) != 3:
        return None
    event_type, match_mode, value = parts[0].strip(), parts[1].strip(), parts[2].strip()
    if not value:
        return None
    if match_mode not in ("contains", "suffix", "prefix", "ip_range"):
        return None
    if not event_type:
        return None
    # 清理不必要的 regex 转义：\- → - （- 仅在字符类内部需要转义）
    if match_mode == "contains":
        value = value.replace("\\-", "-")
    return BlacklistRule(
        event_type=event_type,
        match_mode=match_mode,
        value=value,
        source="file",
    )


# ============================================================
# 匹配引擎
# ============================================================


def rule_matches(rule: BlacklistRule, event_type: str, value: str) -> bool:
    """检查单条规则是否匹配给定事件。

    event_type 为 "*" 时匹配所有事件类型。
    所有字符串匹配忽略大小写。
    """
    if rule.event_type != "*" and rule.event_type != event_type:
        return False

    mode = rule.match_mode
    pattern = rule.value
    target = value if mode == "ip_range" else value.lower()
    pattern_lower = pattern.lower() if mode != "ip_range" else pattern

    if mode == "suffix":
        return target.endswith(pattern_lower)
    if mode == "prefix":
        return target.startswith(pattern_lower)
    if mode == "contains":
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FutureWarning)
                return bool(re.search(pattern_lower, target, re.IGNORECASE))
        except re.error:
            # 正则非法 → 回退为字面量包含
            return pattern_lower in target.lower()
    if mode == "ip_range":
        try:
            return ipaddress.ip_address(value.strip()) in ipaddress.ip_network(
                pattern, strict=False
            )
        except ValueError:
            return False
    return False


def _fingerprint(event_type: str, match_mode: str, value: str) -> str:
    return hashlib.sha256(
        f"{event_type}\0{match_mode}\0{value}".encode("utf-8")
    ).hexdigest()


# ============================================================
# 文件规则 API（模块级缓存）
# ============================================================


_FILE_RULES: List[BlacklistRule] = load_file_rules()


def reload_file_rules(config_path: str = CONFIG_PATH) -> int:
    """重新加载 black_list.cfg 文件规则。返回加载的规则数。"""
    global _FILE_RULES
    _FILE_RULES = load_file_rules(config_path)
    return len(_FILE_RULES)


def get_file_rules() -> List[Dict[str, Any]]:
    """返回文件规则的序列化列表（供 Web 展示）。"""
    return [_rule_to_dict(rule) for rule in _FILE_RULES]


def check_file_rules(event_type: str, value: str) -> bool:
    """检查文件规则。返回 True 表示应拦截。"""
    for rule in _FILE_RULES:
        if rule_matches(rule, event_type, value):
            return True
    return False


def test_file_rules(event_type: str, value: str) -> List[Dict[str, Any]]:
    """测试给定值会命中哪些文件规则（供预览）。"""
    return [
        _rule_to_dict(rule)
        for rule in _FILE_RULES
        if rule_matches(rule, event_type, value)
    ]


# ============================================================
# Redis 规则 API（动态规则，不缓存，每次实时查询）
# ============================================================


def check_redis_rules(redis_client: Any, event_type: str, value: str) -> bool:
    """检查 Redis 中的动态规则。返回 True 表示应拦截。"""
    try:
        for raw_fp in redis_client.conn.zrange("fs3:blacklist:rules", 0, -1):
            raw = redis_client.conn.hgetall(f"fs3:blacklist:rule:{raw_fp}")
            if not raw:
                continue
            rule = BlacklistRule(
                event_type=raw.get("event_type", "*"),
                match_mode=raw.get("match_mode", ""),
                value=raw.get("value", ""),
                source="redis",
                fp=raw_fp,
                comment=raw.get("comment", ""),
            )
            if rule_matches(rule, event_type, value):
                return True
    except Exception:
        pass
    return False


def get_redis_rules(redis_client: Any) -> List[Dict[str, Any]]:
    """获取 Redis 中所有动态规则。"""
    rules: List[Dict[str, Any]] = []
    try:
        for raw_fp in redis_client.conn.zrange("fs3:blacklist:rules", 0, -1):
            raw = redis_client.conn.hgetall(f"fs3:blacklist:rule:{raw_fp}")
            if raw:
                rules.append({
                    "fp": raw_fp,
                    "event_type": raw.get("event_type", "*"),
                    "match_mode": raw.get("match_mode", ""),
                    "value": raw.get("value", ""),
                    "comment": raw.get("comment", ""),
                    "created_at": raw.get("created_at", ""),
                    "source": "redis",
                })
    except Exception:
        pass
    return rules


def add_redis_rule(
    redis_client: Any,
    event_type: str,
    match_mode: str,
    value: str,
    comment: str = "",
) -> Optional[str]:
    """向 Redis 中添加一条动态规则。返回规则 fp，已存在返回 None。"""
    if match_mode not in ("contains", "suffix", "prefix", "ip_range"):
        return None
    if not value or not event_type:
        return None
    fp = _fingerprint(event_type, match_mode, value)
    import time

    key = f"fs3:blacklist:rule:{fp}"
    if redis_client.conn.exists(key):
        return None
    redis_client.conn.hset(
        key,
        mapping={
            "event_type": event_type,
            "match_mode": match_mode,
            "value": value,
            "comment": comment,
            "created_at": str(time.time()),
        },
    )
    redis_client.conn.zadd("fs3:blacklist:rules", {fp: time.time()})
    redis_client.log(f"[BLACKLIST-REDIS-ADD] {event_type}:{match_mode}:{value}")
    return fp


def delete_redis_rule(redis_client: Any, fp: str) -> bool:
    """删除 Redis 中的一条动态规则。"""
    key = f"fs3:blacklist:rule:{fp}"
    if not redis_client.conn.exists(key):
        return False
    redis_client.conn.delete(key)
    redis_client.conn.zrem("fs3:blacklist:rules", fp)
    redis_client.log(f"[BLACKLIST-REDIS-DEL] fp={fp[:16]}")
    return True


def test_redis_rules(
    redis_client: Any, event_type: str, value: str
) -> List[Dict[str, Any]]:
    """测试给定值会命中哪些 Redis 规则（供预览）。"""
    matches: List[Dict[str, Any]] = []
    try:
        for raw_fp in redis_client.conn.zrange("fs3:blacklist:rules", 0, -1):
            raw = redis_client.conn.hgetall(f"fs3:blacklist:rule:{raw_fp}")
            if not raw:
                continue
            rule = BlacklistRule(
                event_type=raw.get("event_type", "*"),
                match_mode=raw.get("match_mode", ""),
                value=raw.get("value", ""),
                source="redis",
                fp=raw_fp,
                comment=raw.get("comment", ""),
            )
            if rule_matches(rule, event_type, value):
                matches.append(_rule_to_dict(rule))
    except Exception:
        pass
    return matches


# ============================================================
# 兼容层（旧 API）
# ============================================================


def is_blacklisted(target: str) -> bool:
    """兼容旧调用：仅检查文件规则，不指定事件类型时用 DNS_NAME。

    推荐新代码使用 check_file_rules(event_type, value)。
    """
    target = target.strip().strip("[]").lower()
    if not target:
        return False
    # 尝试判断事件类型
    try:
        ipaddress.ip_address(target)
        return check_file_rules("IP_ADDRESS", target)
    except ValueError:
        return check_file_rules("DNS_NAME", target)


# ============================================================
# 辅助函数
# ============================================================


def _rule_to_dict(rule: BlacklistRule) -> Dict[str, Any]:
    return {
        "fp": rule.fp,
        "event_type": rule.event_type,
        "match_mode": rule.match_mode,
        "value": rule.value,
        "comment": rule.comment,
        "source": rule.source,
    }


# ============================================================
# CLI 入口（兼容旧用法）
# ============================================================


def main() -> int:
    import subprocess
    import sys

    if len(sys.argv) < 2:
        return 0

    raw_target = sys.argv[1].strip()
    if not raw_target:
        return 0

    target = raw_target.strip("[]").lower()

    # ── 1. 文件规则 ──
    if check_file_rules("DNS_NAME", target) or check_file_rules(
        "IP_ADDRESS", target
    ):
        print(f"[filter] BLOCK (file): {raw_target}", file=sys.stderr)
        return 1

    # ── 2. cdncheck 验证 ──
    try:
        r = subprocess.run(
            ["cdncheck", "-i", target, "-cdn", "-resp", "-silent"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.stdout.strip():
            print(
                f"[filter] BLOCK (cdncheck): {raw_target} -> {r.stdout.strip()}",
                file=sys.stderr,
            )
            return 1
    except Exception as exc:
        print(f"[filter] cdncheck error, allowing: {exc}", file=sys.stderr)

    print(f"[filter] PASS: {raw_target}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main())
