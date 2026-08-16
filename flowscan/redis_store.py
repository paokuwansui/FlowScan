import hashlib
import json
import time
from typing import Any, Dict, Iterable, List, Optional, Set

import redis as redis_py

from .filter import check_file_rules, check_redis_rules_cached, check_redis_whitelist_cached


CLAIM_TASK_LUA = """
local done_key = KEYS[1]
local lock_key = KEYS[2]
local node_id = ARGV[1]
local now = tonumber(ARGV[2])
local stale_after = tonumber(ARGV[3])

if redis.call('EXISTS', done_key) == 1 then
  return 0
end
if redis.call('EXISTS', lock_key) == 1 then
  local hb = redis.call('HGET', lock_key, 'heartbeat_at')
  if hb and tonumber(hb) > 0 and (now - tonumber(hb)) > stale_after then
    redis.call('DEL', lock_key)
  else
    return 0
  end
end
redis.call('HSET', lock_key, 'node_id', node_id, 'started_at', now, 'heartbeat_at', now)
return 1
"""

RELEASE_TASK_LUA = """
local done_key = KEYS[1]
local lock_key = KEYS[2]
local mark_done = ARGV[1]
local node_id = ARGV[2]
local now = ARGV[3]
local status = ARGV[4]

if mark_done == '1' then
  redis.call('HSET', done_key, 'node_id', node_id, 'finished_at', now, 'status', status)
end
redis.call('DEL', lock_key)
return 1
"""

# push_event 原子入队：一次调用完成「父事件取消检查 → 去重 → 落库 →
# 时间索引 → 根事件索引 → 统计 → 子事件索引 → 各消费工具 pending 入队」。
# 返回: 1=新增 0=重复 -1=父事件已取消
PUSH_EVENT_LUA = """
local fp = ARGV[1]
local parent = ARGV[2]
if parent ~= '' and redis.call('EXISTS', KEYS[10]) == 1 then
  return -1
end
if redis.call('SISMEMBER', KEYS[1], fp) == 1 then
  return 0
end
redis.call('SADD', KEYS[1], fp)
redis.call('SADD', KEYS[2], fp)
redis.call('SADD', KEYS[3], fp)
redis.call('HSET', KEYS[5],
  'fingerprint', fp, 'event_type', ARGV[3], 'value', ARGV[4],
  'source_tool', ARGV[5], 'parent_fp', parent, 'root_fp', ARGV[6],
  'created_at', ARGV[7])
redis.call('ZADD', KEYS[6], ARGV[7], fp)
redis.call('ZADD', KEYS[7], ARGV[7], fp)
if parent == '' then
  redis.call('ZADD', KEYS[8], ARGV[7], fp)
end
redis.call('HINCRBY', KEYS[4], ARGV[3], 1)
if parent ~= '' then
  redis.call('SADD', KEYS[9], fp)
end
for i = 8, #ARGV do
  redis.call('ZADD', KEYS[11 + (i - 8)], ARGV[7], fp)
end
return 1
"""

# 事件时间索引 / 根事件索引 / 游标 / 版本键前缀（见各方法注释）
_TIME_INDEX_KEY = "fs3:event:time"
_TYPE_TIME_INDEX_KEY = "fs3:events:time:{}"
_ROOTS_INDEX_KEY = "fs3:event:roots"
_ENQ_CURSOR_KEY = "fs3:enq:cursor:{}"
_TIME_INDEX_FLAG = "fs3:index:time:v1"
_ROOTS_INDEX_FLAG = "fs3:index:roots:v1"
_CONSUMERS_CLEANUP_FLAG = "fs3:upgrade:consumers:v1"


class FlowScanRedis:
    def __init__(self, host: str = "127.0.0.1", port: int = 6379, password: str = "", db: int = 0):
        self.conn = redis_py.Redis(
            host=host,
            port=port,
            password=password or None,
            db=db,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=10,
            socket_keepalive=True,
        )
        self._claim_script = self.conn.register_script(CLAIM_TASK_LUA)
        self._release_script = self.conn.register_script(RELEASE_TASK_LUA)
        self._push_script = self.conn.register_script(PUSH_EVENT_LUA)
        self._tools_cache: Optional[tuple] = None   # (version, {name: info})
        self._rule_cache: Dict[str, tuple] = {}     # kind -> (version, rules)

    @staticmethod
    def fingerprint(event_type: str, value: str) -> str:
        return hashlib.sha256(f"{event_type}\0{value}".encode("utf-8")).hexdigest()

    def ping(self) -> bool:
        return bool(self.conn.ping())

    def _redis_time(self) -> float:
        """Redis 服务器时间（统一各节点时钟，避免机器时间漂移影响失联判定）。"""
        try:
            t = self.conn.time()
            return float(t[0]) + float(t[1]) / 1e6
        except Exception:
            return time.time()

    def push_event(self, event_type: str, value: str, source_tool: str = "manual", parent_fp: str = "", root_fp: str = "") -> Optional[str]:
        event_type = str(event_type).strip()
        value = str(value).strip()
        if not event_type or not value:
            return None
        # 1. 文件黑名单检查
        if check_file_rules(event_type, value):
            self.log(f"[BLACKLIST-FILE] {event_type}={value[:120]} discarded")
            return None
        # 2. Redis 动态黑名单检查（版本号缓存，规则变更时自动刷新）
        if check_redis_rules_cached(self, event_type, value):
            self.log(f"[BLACKLIST-REDIS] {event_type}={value[:120]} discarded")
            return None
        # 3. Redis 白名单检查(白名单非空则只放行匹配事件；同样走版本缓存)
        if check_redis_whitelist_cached(self, event_type, value):
            self.log(f"[WHITELIST] {event_type}={value[:120]} discarded (not in whitelist)")
            return None

        fp = self.fingerprint(event_type, value)
        now = str(time.time())
        root = root_fp or parent_fp or fp
        consumers = sorted(self.consumers_for_event_type(event_type))
        # 原子入队（Lua）：父取消检查 → 去重 → 落库 → 时间索引 → 统计 → 子索引 → pending
        keys = [
            "fs3:event:set",
            "fs3:event:all",
            f"fs3:events:type:{event_type}",
            "fs3:stats:event_type",
            f"fs3:event:{fp}",
            _TIME_INDEX_KEY,
            _TYPE_TIME_INDEX_KEY.format(event_type),
            _ROOTS_INDEX_KEY,
            f"fs3:children:{parent_fp}",
            f"fs3:cancelled:{parent_fp}",
        ]
        keys.extend(f"fs3:pending:{tool}" for tool in consumers)
        args = [fp, parent_fp, event_type, value, source_tool, root, now]
        args.extend(consumers)
        rc = self._push_script(keys=keys, args=args)
        if rc == -1:
            self.log(f"[CANCELLED] {event_type}={value[:120]} parent deleted, discarding")
            return None
        if rc == 0:
            return fp
        self.log(f"[EVENT] {event_type}={value[:120]} fp={fp[:10]} source={source_tool}")
        return fp

    def get_event(self, fp: str) -> Optional[Dict[str, Any]]:
        data = self.conn.hgetall(f"fs3:event:{fp}")
        return data or None

    # ── 工具表缓存（消费者推导的唯一数据源；不再依赖 fs3:consumers:* 集合） ──

    def _tools(self) -> Dict[str, Dict[str, Any]]:
        """工具注册表缓存（fs3:tools hash），版本号变化时自动刷新。"""
        ver = self.conn.get("fs3:ver:tools") or "0"
        cached = self._tools_cache
        if cached and cached[0] == ver:
            return cached[1]
        info: Dict[str, Dict[str, Any]] = {}
        for name, raw in (self.conn.hgetall("fs3:tools") or {}).items():
            try:
                info[name] = json.loads(raw)
            except Exception:
                continue
        self._tools_cache = (ver, info)
        return info

    def consumers_for_event_type(self, event_type: str) -> Set[str]:
        """该事件类型的所有消费工具（来自工具注册表）。"""
        return {name for name, info in self._tools().items()
                if event_type in (info.get("input_events") or [])}

    # ── 时间索引（#8/#9/#10：分页、游标增量、AI 增量查询共用） ──

    def event_time_index(self, event_type: str = "") -> str:
        return _TYPE_TIME_INDEX_KEY.format(event_type) if event_type else _TIME_INDEX_KEY

    def recent_event_fps(self, event_type: str = "", limit: int = 100, offset: int = 0) -> tuple:
        """按创建时间倒序取一页事件指纹。返回 (fps, total)。"""
        key = self.event_time_index(event_type)
        total = int(self.conn.zcard(key) or 0)
        fps = list(self.conn.zrevrange(key, offset, offset + max(0, limit - 1)) or [])
        return fps, total

    def events_since(self, ts: float, limit: int = 500) -> List[Dict[str, Any]]:
        """创建时间 > ts 的最近事件（增量查询，供 Agent 注入后拉取新增）。"""
        fps = list(self.conn.zrangebyscore(_TIME_INDEX_KEY, f"({ts}", "+inf",
                                           start=0, num=max(1, limit)) or [])
        if not fps:
            return []
        pipe = self.conn.pipeline()
        for fp in fps:
            pipe.hgetall(f"fs3:event:{fp}")
        events = [ev for ev in pipe.execute() if ev]
        events.sort(key=lambda e: float(e.get("created_at") or 0))
        return events

    def ensure_time_index(self) -> int:
        """把存量事件补进时间索引(幂等:zadd nx 只补缺失,可安全重复执行)。

        每次调用都会扫描 event:all 补齐缺失条目;不依赖 flag 早退,
        这样「有事件但时间索引缺失」的历史数据(旧版写入/迁移遗漏)在启动时自动自愈。
        flag 仅用于多节点并发时避免同一时刻重复全量扫描。
        """
        self.conn.set(_TIME_INDEX_FLAG, "1", nx=True)  # 占位防并发,不用于早退
        try:
            n = 0
            pipe = self.conn.pipeline()
            for fp in self.conn.sscan_iter("fs3:event:all", count=500):
                ev = self.conn.hgetall(f"fs3:event:{fp}")
                if not ev:
                    continue
                score = float(ev.get("created_at") or time.time())
                pipe.zadd(_TIME_INDEX_KEY, {fp: score}, nx=True)
                pipe.zadd(_TYPE_TIME_INDEX_KEY.format(ev.get("event_type", "")), {fp: score}, nx=True)
                n += 1
                if n % 500 == 0:
                    pipe.execute()
                    pipe = self.conn.pipeline()
            pipe.execute()
            self.log(f"[INDEX] time index ensured: {n} events")
            return n
        except Exception:
            raise

    def recent_root_fps(self, limit: int = 200, offset: int = 0) -> tuple:
        """按创建时间倒序取一页根事件指纹（parent 为空的事件，事件图谱用）。"""
        total = int(self.conn.zcard(_ROOTS_INDEX_KEY) or 0)
        fps = list(self.conn.zrevrange(_ROOTS_INDEX_KEY, offset,
                                       offset + max(0, limit - 1)) or [])
        return fps, total

    def ensure_root_index(self) -> int:
        """一次性把存量根事件补进根事件索引（多节点并发由 SET NX 保证只跑一次）。"""
        if self.conn.exists(_ROOTS_INDEX_FLAG):
            return 0
        if not self.conn.set(_ROOTS_INDEX_FLAG, "1", nx=True):
            return 0
        try:
            n = 0
            pipe = self.conn.pipeline()
            for fp in self.conn.sscan_iter("fs3:event:all", count=500):
                ev = self.conn.hgetall(f"fs3:event:{fp}")
                if not ev or ev.get("parent_fp"):
                    continue
                score = float(ev.get("created_at") or time.time())
                pipe.zadd(_ROOTS_INDEX_KEY, {fp: score}, nx=True)
                n += 1
                if n % 500 == 0:
                    pipe.execute()
                    pipe = self.conn.pipeline()
            pipe.execute()
            self.log(f"[INDEX] root index backfilled: {n} events")
            return n
        except Exception:
            self.conn.delete(_ROOTS_INDEX_FLAG)  # 失败允许下次重试
            raise

    def cleanup_legacy_consumers(self) -> int:
        """一次性删除废弃的 fs3:consumers:* 集合（消费关系以 fs3:tools 为准）。"""
        if not self.conn.set(_CONSUMERS_CLEANUP_FLAG, "1", nx=True):
            return 0
        keys = list(self.conn.scan_iter("fs3:consumers:*", count=500))
        if keys:
            self.conn.delete(*keys)
        return len(keys)

    def get_recursive_children(self, fp: str, max_depth: int = 50, max_nodes: int = 10000) -> Dict[str, Any]:
        """递归查询某事件的所有后代子事件(子/孙/曾孙...)。

        沿 fs3:children:{fp} 反向索引做 DFS,返回结构化结果:
          - root: 根事件(不含 children 字段)
          - tree: 完整树形(children 逐层嵌套)
          - flat: 扁平列表(每个节点带 depth / parent_fp,便于表格展示)
          - total_descendants: 后代总数(不含根)
        """
        visited: Set[str] = set()

        def build(node_fp: str, depth: int) -> Optional[Dict[str, Any]]:
            if node_fp in visited or depth > max_depth or len(visited) >= max_nodes:
                return None
            visited.add(node_fp)
            event = self.get_event(node_fp)
            if not event:
                return None
            node: Dict[str, Any] = {
                "event_type": event.get("event_type", ""),
                "value": event.get("value", ""),
                "source_tool": event.get("source_tool", ""),
                "created_at": event.get("created_at", ""),
                "depth": depth,
                "children": [],
            }
            for child_fp in sorted(self.conn.smembers(f"fs3:children:{node_fp}") or []):
                child_node = build(child_fp, depth + 1)
                if child_node:
                    node["children"].append(child_node)
            return node

        tree = build(fp, 0)

        flat: List[Dict[str, Any]] = []

        def flatten(node: Dict[str, Any]) -> None:
            flat.append({k: v for k, v in node.items() if k != "children"})
            for child in node.get("children", []):
                flatten(child)

        if tree:
            flatten(tree)

        return {
            "root": {k: v for k, v in tree.items() if k != "children"} if tree else None,
            "tree": tree,
            "flat": flat,
            "total_descendants": max(0, len(flat) - 1),
        }

    def is_event_cancelled(self, fp: str) -> bool:
        """Return True if an event was explicitly deleted/cancelled.

        Deleted events are marked with fs3:cancelled:<fp> so workers that already
        claimed the event can still notice the deletion before publishing output.
        """
        return bool(fp and self.conn.exists(f"fs3:cancelled:{fp}"))

    def iter_event_fps(self, event_types: Iterable[str], limit_per_type: int = 200) -> List[str]:
        """按时间倒序取多类型最近事件（替代全量集合扫描）。"""
        fps: List[str] = []
        seen: Set[str] = set()
        for event_type in event_types:
            key = _TYPE_TIME_INDEX_KEY.format(event_type)
            for fp in self.conn.zrevrange(key, 0, max(0, limit_per_type - 1)):
                if fp in seen:
                    continue
                seen.add(fp)
                fps.append(fp)
                if len(fps) >= limit_per_type:
                    return fps
        return fps

    def pending_for_tool(self, tool_name: str, event_types: Iterable[str], limit: int = 200) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        queue_key = f"fs3:pending:{tool_name}"
        stale_fps: List[str] = []
        skip_fps: List[tuple] = []   # (fp, event_type) 类型不匹配:可能是异构同名工具消费,不轻易删除
        for fp in self.conn.zrange(queue_key, 0, max(limit * 5, limit) - 1):
            if self.conn.exists(f"fs3:done:{tool_name}:{fp}"):
                stale_fps.append(fp)
                continue
            if self.is_event_cancelled(fp):
                stale_fps.append(fp)
                continue
            event = self.get_event(fp)
            if not event:
                stale_fps.append(fp)
                continue
            if event.get("event_type") not in event_types:
                skip_fps.append((fp, event.get("event_type", "")))
                continue
            events.append(event)
            if len(events) >= limit:
                break
        if stale_fps:
            self.conn.zrem(queue_key, *stale_fps)
        # 类型不匹配的条目仅在该类型已无任何注册工具消费时才清理
        # （保护同名工具异构 worker 的共享队列，不被对方误删）
        if skip_fps:
            removable = [fp for fp, et in skip_fps if not self.consumers_for_event_type(et)]
            if removable:
                self.conn.zrem(queue_key, *removable)
        return events

    def claim_task(self, tool_name: str, fp: str, node_id: str, stale_after: int = 120) -> bool:
        # lock 不设 TTL,靠看门狗释放:持有者每 heartbeat_interval_seconds 刷新
        # heartbeat_at,若超过 stale_after 秒无心跳(持有者已死)则释放锁允许抢占。
        return bool(self._claim_script(
            keys=[f"fs3:done:{tool_name}:{fp}", f"fs3:lock:{tool_name}:{fp}"],
            args=[node_id, str(time.time()), str(stale_after)],
        ))

    def heartbeat_lock(self, tool_name: str, fp: str, now: float) -> None:
        """看门狗心跳:刷新 lock 的 heartbeat_at,证明持有者仍存活。"""
        key = f"fs3:lock:{tool_name}:{fp}"
        if self.conn.exists(key):
            self.conn.hset(key, "heartbeat_at", str(now))

    def release_task(self, tool_name: str, fp: str, node_id: str, mark_done: bool = True, status: str = "done") -> None:
        self._release_script(
            keys=[f"fs3:done:{tool_name}:{fp}", f"fs3:lock:{tool_name}:{fp}"],
            args=["1" if mark_done else "0", node_id, str(time.time()), status],
        )
        if mark_done:
            self.conn.zrem(f"fs3:pending:{tool_name}", fp)

    def register_node(self, node_id: str, info: Dict[str, Any], ttl: int = 45) -> None:
        pipe = self.conn.pipeline()
        pipe.sadd("fs3:nodes", node_id)
        pipe.hset(f"fs3:node:{node_id}", mapping={k: json.dumps(v, ensure_ascii=False) for k, v in info.items()})
        pipe.expire(f"fs3:node:{node_id}", ttl)
        pipe.execute()

    def register_tool(self, tool_name: str, yaml_path: str, input_events: List[str]) -> None:
        """注册工具（幂等 + 冲突检测 + 存活时间戳）。

        幂等: 配置内容与已注册值一致时不重复写、不 bump 版本号（避免各进程
        缓存反复失效与无谓重扫）。
        冲突: 同名工具被不同配置覆盖时记录 [TOOL-CONFLICT] 日志（多 worker
        异构或模块定义漂移的信号），最后写入者生效（hash 字段唯一，不产生重复条目）。
        存活: 同时写入 fs3:tools:seen 时间戳（Redis 服务器时间），供失联清理用。
        """
        value = json.dumps({"yaml_path": yaml_path, "input_events": input_events}, ensure_ascii=False)
        existing = self.conn.hget("fs3:tools", tool_name)
        if existing is not None and existing != value:
            self.log(f"[TOOL-CONFLICT] {tool_name} 配置被覆盖: {existing[:160]} → {value[:160]}")
        now = self._redis_time()
        pipe = self.conn.pipeline()
        if existing != value:
            pipe.hset("fs3:tools", tool_name, value)
            pipe.incr("fs3:ver:tools")
        pipe.hset("fs3:tools:seen", tool_name, str(now))
        pipe.execute()
        self.enqueue_existing_events_for_tool(tool_name, input_events)

    def touch_tools(self, tool_names: Iterable[str]) -> None:
        """心跳刷新本 worker 持有工具的存活时间戳（fs3:tools:seen）。"""
        if not tool_names:
            return
        now = self._redis_time()
        pipe = self.conn.pipeline()
        for name in tool_names:
            pipe.hset("fs3:tools:seen", name, str(now))
        pipe.execute()

    def sweep_stale_tools(self, stale_seconds: int = 90) -> int:
        """清理失联工具（持有 worker 已死/下线，seen 超过 stale_seconds）。

        任意节点均可触发，SET NX 锁保证同一时刻只有一个执行者；移除后
        工具表版本 +1，各进程消费者缓存自动刷新，不再为幽灵工具建 pending 队列。
        """
        lock_key = "fs3:lock:tools:sweep"
        if not self.conn.set(lock_key, "1", nx=True, ex=60):
            return 0
        try:
            now = self._redis_time()
            seen = self.conn.hgetall("fs3:tools:seen") or {}
            removed = []
            for name in (self.conn.hkeys("fs3:tools") or []):
                try:
                    ts = float(seen.get(name) or 0)
                except (TypeError, ValueError):
                    ts = 0
                if now - ts > stale_seconds:
                    removed.append(name)
            if removed:
                pipe = self.conn.pipeline()
                pipe.hdel("fs3:tools", *removed)
                pipe.hdel("fs3:tools:seen", *removed)
                pipe.incr("fs3:ver:tools")
                pipe.execute()
                for name in removed:
                    self.log(f"[TOOL-SWEEP] 移除失联工具 {name}")
            return len(removed)
        finally:
            pass  # 锁带 TTL 自动释放

    def enqueue_existing_events_for_tool(self, tool_name: str, event_types: Iterable[str],
                                         window_days: int = 7) -> int:
        """把该工具未处理过的近期事件重入队（#9：游标 + 时间窗口，不再全量重扫）。

        只处理创建时间 > max(上次游标, 现在-window_days) 的事件：
        - 首次注册最多扫最近 window_days 的增量（可配置）
        - 重启后从游标继续，只有重启期间产生的新事件会被重扫
        """
        now = time.time()
        cutoff = now - window_days * 86400
        cursor_key = _ENQ_CURSOR_KEY.format(tool_name)
        try:
            start = max(float(self.conn.get(cursor_key) or 0), cutoff)
        except (TypeError, ValueError):
            start = cutoff
        queued = 0
        pipe = self.conn.pipeline()
        queue_key = f"fs3:pending:{tool_name}"
        for event_type in event_types:
            key = _TYPE_TIME_INDEX_KEY.format(event_type)
            for fp in self.conn.zrangebyscore(key, f"({start}", "+inf"):
                if self.conn.exists(f"fs3:done:{tool_name}:{fp}"):
                    continue
                event = self.get_event(fp)
                if not event:
                    continue
                score = float(event.get("created_at") or now)
                pipe.zadd(queue_key, {fp: score}, nx=True)
                queued += 1
                if queued % 500 == 0:
                    pipe.execute()
                    pipe = self.conn.pipeline()
        pipe.execute()
        self.conn.set(cursor_key, str(now))
        return queued

    def log(self, message: str, max_items: int = 2000) -> None:
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}"
        pipe = self.conn.pipeline()
        pipe.lpush("fs3:logs", line)
        pipe.ltrim("fs3:logs", 0, max_items - 1)
        pipe.execute()
        print(line)
