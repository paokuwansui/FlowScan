#!/usr/bin/env python3
"""
FlowScan 黑名单过滤器。

两套独立规则：
  1. 文件规则（black_list.cfg）— 模块级缓存，手动 reload
  2. Redis 规则（fs3:blacklist:rules）— 实时查询

格式: event_type:match_mode:value
  event_type = * | DNS_NAME | URL | IP_ADDRESS | ...
  match_mode = contains | suffix | prefix | ip_range
  contains 模式为正则，其余为字面量；所有匹配忽略大小写。

检测流程（在 push_event 中）：
  1. check_file_rules(event_type, value) → 命中则丢弃
  2. check_redis_rules_cached(redis, event_type, value) → 命中则丢弃
  3. 均未命中 → 正常入队
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import time
import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

_logger = logging.getLogger("flowscan.filter")

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


_FILE_RULES: List[BlacklistRule] = []
_FILE_RULES_PATH: str = CONFIG_PATH  # 上次加载用的规则文件路径(自动刷新盯它)
_FILE_RULES_MTIME: float = 0.0      # 上次加载时规则文件的 mtime
_FILE_RULES_STAT_AT: float = 0.0    # 上次 stat 的时间(节流)
_FILE_RULES_STAT_INTERVAL = 2.0     # 最多每 2 秒检查一次文件是否变过


def _load_and_stamp(config_path: str = CONFIG_PATH) -> int:
    """加载文件规则并记下源文件路径/mtime(供自动刷新比对)。"""
    global _FILE_RULES, _FILE_RULES_PATH, _FILE_RULES_MTIME
    _FILE_RULES_PATH = config_path
    _FILE_RULES = load_file_rules(config_path)
    try:
        _FILE_RULES_MTIME = os.path.getmtime(config_path)
    except OSError:
        _FILE_RULES_MTIME = 0.0
    return len(_FILE_RULES)


def reload_file_rules(config_path: str = CONFIG_PATH) -> int:
    """重新加载 black_list.cfg 文件规则。返回加载的规则数。"""
    return _load_and_stamp(config_path)


def _auto_reload_file_rules() -> None:
    """规则文件被改动后自动刷新(2026-09-15 B)。

    此前「重载文件黑名单」只在**调用它的那个进程**里生效:web 点了重载,
    worker 仍用启动时读进的旧规则(点了等于没点)。这里按源文件 mtime 自动
    感知变化(节流 2s,单次 os.stat 开销可忽略),web/worker 都能生效,
    也不依赖 Redis 广播;直接编辑规则文件同样会被感知。
    """
    global _FILE_RULES_STAT_AT
    now = time.monotonic()
    if now - _FILE_RULES_STAT_AT < _FILE_RULES_STAT_INTERVAL:
        return
    _FILE_RULES_STAT_AT = now
    try:
        mtime = os.path.getmtime(_FILE_RULES_PATH)
    except OSError:
        return
    if mtime > _FILE_RULES_MTIME:
        _load_and_stamp(_FILE_RULES_PATH)   # 必须带路径,否则会退回默认文件(实测踩到)


def get_file_rules() -> List[Dict[str, Any]]:
    """返回文件规则的序列化列表（供 Web 展示）。"""
    return [_rule_to_dict(rule) for rule in _FILE_RULES]


def check_file_rules(event_type: str, value: str) -> bool:
    """检查文件规则。返回 True 表示应拦截。"""
    _auto_reload_file_rules()
    for rule in _FILE_RULES:
        if rule_matches(rule, event_type, value):
            return True
    return False


_load_and_stamp()   # 模块导入时载入一次


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
    redis_client.conn.incr("fs3:ver:blacklist")  # 版本+1:各进程规则缓存据此刷新
    redis_client.log(f"[BLACKLIST-REDIS-ADD] {event_type}:{match_mode}:{value}")
    return fp


def delete_redis_rule(redis_client: Any, fp: str) -> bool:
    """删除 Redis 中的一条动态规则。"""
    key = f"fs3:blacklist:rule:{fp}"
    if not redis_client.conn.exists(key):
        return False
    redis_client.conn.delete(key)
    redis_client.conn.zrem("fs3:blacklist:rules", fp)
    redis_client.conn.incr("fs3:ver:blacklist")
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
# Redis 白名单 API（动态规则，实时查询；非空则只放行匹配事件）
# ============================================================

def get_redis_whitelist_rules(redis_client: Any) -> List[Dict[str, Any]]:
    """获取 Redis 白名单所有规则。"""
    rules: List[Dict[str, Any]] = []
    try:
        for raw_fp in redis_client.conn.zrange("fs3:whitelist:rules", 0, -1):
            raw = redis_client.conn.hgetall(f"fs3:whitelist:rule:{raw_fp}")
            if raw:
                rules.append({
                    "fp": raw_fp,
                    "event_type": raw.get("event_type", "*"),
                    "match_mode": raw.get("match_mode", ""),
                    "value": raw.get("value", ""),
                    "comment": raw.get("comment", ""),
                    "created_at": raw.get("created_at", ""),
                    "source": "whitelist",
                })
    except Exception:
        pass
    return rules


def add_redis_whitelist_rule(
    redis_client: Any,
    event_type: str,
    match_mode: str,
    value: str,
    comment: str = "",
) -> Optional[str]:
    """向 Redis 白名单添加一条规则。返回规则 fp,已存在返回 None。"""
    if match_mode not in ("contains", "suffix", "prefix", "ip_range"):
        return None
    if not value or not event_type:
        return None
    fp = _fingerprint(event_type, match_mode, value)
    import time

    key = f"fs3:whitelist:rule:{fp}"
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
    redis_client.conn.zadd("fs3:whitelist:rules", {fp: time.time()})
    redis_client.conn.incr("fs3:ver:whitelist")
    redis_client.log(f"[WHITELIST-ADD] {event_type}:{match_mode}:{value}")
    return fp


def delete_redis_whitelist_rule(redis_client: Any, fp: str) -> bool:
    """删除 Redis 白名单规则。"""
    key = f"fs3:whitelist:rule:{fp}"
    if not redis_client.conn.exists(key):
        return False
    redis_client.conn.delete(key)
    redis_client.conn.zrem("fs3:whitelist:rules", fp)
    redis_client.conn.incr("fs3:ver:whitelist")
    redis_client.log(f"[WHITELIST-DEL] fp={fp[:16]}")
    return True


def test_redis_whitelist(
    redis_client: Any, event_type: str, value: str
) -> List[Dict[str, Any]]:
    """测试给定值会命中哪些白名单规则（供预览）。"""
    matches: List[Dict[str, Any]] = []
    try:
        for raw_fp in redis_client.conn.zrange("fs3:whitelist:rules", 0, -1):
            raw = redis_client.conn.hgetall(f"fs3:whitelist:rule:{raw_fp}")
            if not raw:
                continue
            rule = BlacklistRule(
                event_type=raw.get("event_type", "*"),
                match_mode=raw.get("match_mode", ""),
                value=raw.get("value", ""),
                source="whitelist",
                fp=raw_fp,
                comment=raw.get("comment", ""),
            )
            if rule_matches(rule, event_type, value):
                matches.append(_rule_to_dict(rule))
    except Exception:
        pass
    return matches


# ============================================================
# 规则缓存 API（push_event 热路径用，版本号驱动失效）
# ============================================================
#
# 每条事件入队都要查黑/白名单，若每次实时拉全量规则会 O(规则数) 次往返。
# 这里把规则解析结果缓存在 redis_client 实例上，用 fs3:ver:<kind> 版本键驱动
# 失效：add/delete 规则时版本+1，各进程（web/worker）下次检查自动刷新。


def _mark_degraded(redis_client: Any, kind: str, flag: bool) -> None:
    """记录/清除“规则读取降级”标记(供后续观测;失败不影响主流程)。"""
    try:
        state = getattr(redis_client, "_fs3_rules_degraded", None)
        if not isinstance(state, dict):
            state = {}
            setattr(redis_client, "_fs3_rules_degraded", state)
        state[kind] = bool(flag)
    except Exception:
        pass


def _rules_warn(redis_client: Any, kind: str, message: str) -> None:
    """规则读取失败告警(限流:同 kind 每 60s 最多一条,防故障期刷爆日志)。

    注意:不能用 redis_client.log()——写 Redis 正是失败源;走 logging,
    worker 的 stdout / web 的日志都能看到。
    """
    attr = f"_fs3_rules_warn_at_{kind}"
    now = time.time()
    try:
        last = float(getattr(redis_client, attr, 0.0) or 0.0)
    except (TypeError, ValueError):
        last = 0.0
    if now - last < 60.0:
        return
    try:
        setattr(redis_client, attr, now)
    except Exception:
        pass
    _logger.warning("[FILTER] %s 规则读取失败,过滤降级(沿用上次规则;"
                    "白名单将按上次名单继续拦截): %s", kind, message)


def _cached_rules(redis_client: Any, kind: str) -> List[BlacklistRule]:
    """kind: "blacklist" | "whitelist"。返回缓存的规则对象列表。

    2026-09-15(R8 fail-open 修复):此前版本号读失败兜底成 "0"、规则拉取失败
    `except: pass` 后**仍无条件写缓存** —— zrange/逐条 hgetall 抖动一次,就会把
    「空规则表」(或半截规则表)当成当前版本的有效结果缓存下来并长期命中:
    白名单语义是「空 = 全放行」→ 过滤整体失效且无声。现在:
      - 任何失败都不写缓存(下次调用自然重试,Redis 恢复即自愈);
      - 失败时沿用上一次的规则(策略保持 = fail-closed,而不是清空);
      - 限流告警 + `_fs3_rules_degraded` 降级标记,避免「错了不知道」。
    """
    ver_key = f"fs3:ver:{kind}"
    cache_attr = f"_fs3_rules_cache_{kind}"
    cached = getattr(redis_client, cache_attr, None)
    old_rules: List[BlacklistRule] = list(cached[1]) if cached else []

    try:
        ver = redis_client.conn.get(ver_key) or "0"
    except Exception as exc:
        # 版本号读不到 → 无法判断新旧,不能走「版本相同即命中」短路
        _mark_degraded(redis_client, kind, True)
        _rules_warn(redis_client, kind, f"版本号读取失败: {exc}")
        return old_rules

    if cached and cached[0] == ver:
        _mark_degraded(redis_client, kind, False)
        return cached[1]

    rules: List[BlacklistRule] = []
    try:
        for raw_fp in redis_client.conn.zrange(f"fs3:{kind}:rules", 0, -1):
            raw = redis_client.conn.hgetall(f"fs3:{kind}:rule:{raw_fp}")
            if not raw:
                continue
            rules.append(BlacklistRule(
                event_type=raw.get("event_type", "*"),
                match_mode=raw.get("match_mode", ""),
                value=raw.get("value", ""),
                source=kind,
                fp=raw_fp,
                comment=raw.get("comment", ""),
            ))
    except Exception as exc:
        # 关键:不写缓存——否则「空表/半截表 + 当前版本号」会被长期命中
        _mark_degraded(redis_client, kind, True)
        _rules_warn(redis_client, kind, f"规则拉取失败: {exc}")
        return old_rules

    _mark_degraded(redis_client, kind, False)
    setattr(redis_client, cache_attr, (ver, rules))
    return rules


def check_redis_rules_cached(redis_client: Any, event_type: str, value: str) -> bool:
    """缓存版黑名单检查。返回 True 表示应拦截。"""
    return any(rule_matches(r, event_type, value)
               for r in _cached_rules(redis_client, "blacklist"))


def check_redis_whitelist_cached(redis_client: Any, event_type: str, value: str) -> bool:
    """缓存版白名单检查。返回 True 表示应拦截。"""
    rules = _cached_rules(redis_client, "whitelist")
    if not rules:
        return False
    return not any(rule_matches(r, event_type, value) for r in rules)


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
    raise SystemExit(main())
