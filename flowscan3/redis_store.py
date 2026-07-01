import hashlib
import json
import time
from typing import Any, Dict, Iterable, List, Optional, Set

import redis as redis_py


CLAIM_TASK_LUA = """
local done_key = KEYS[1]
local lock_key = KEYS[2]
local running_key = KEYS[3]
local max_conc = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local node_id = ARGV[3]
local now = ARGV[4]

if redis.call('EXISTS', done_key) == 1 then
  return 0
end
if redis.call('EXISTS', lock_key) == 1 then
  return 0
end
redis.call('SETNX', running_key, 0)
local running = redis.call('INCR', running_key)
if running > max_conc then
  redis.call('DECR', running_key)
  return 0
end
redis.call('HSET', lock_key, 'node_id', node_id, 'started_at', now)
redis.call('EXPIRE', lock_key, ttl)
return 1
"""

RELEASE_TASK_LUA = """
local done_key = KEYS[1]
local lock_key = KEYS[2]
local running_key = KEYS[3]
local mark_done = ARGV[1]
local node_id = ARGV[2]
local now = ARGV[3]
local status = ARGV[4]

if mark_done == '1' then
  redis.call('HSET', done_key, 'node_id', node_id, 'finished_at', now, 'status', status)
end
redis.call('DEL', lock_key)
local running = redis.call('GET', running_key)
if running and tonumber(running) > 0 then
  redis.call('DECR', running_key)
end
return 1
"""


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

    @staticmethod
    def fingerprint(event_type: str, value: str) -> str:
        return hashlib.sha256(f"{event_type}\0{value}".encode("utf-8")).hexdigest()

    def ping(self) -> bool:
        return bool(self.conn.ping())

    def push_event(self, event_type: str, value: str, source_tool: str = "manual", parent_fp: str = "", root_fp: str = "") -> Optional[str]:
        event_type = str(event_type).strip()
        value = str(value).strip()
        if not event_type or not value:
            return None
        # 检查父事件是否已被取消（删除）——阻止孤儿事件入队
        if parent_fp and self.conn.exists(f"fs3:cancelled:{parent_fp}"):
            self.log(f"[CANCELLED] {event_type}={value[:120]} parent deleted, discarding")
            return None
        fp = self.fingerprint(event_type, value)
        added = self.conn.sadd("fs3:event:set", fp)
        if not added:
            return fp
        now = str(time.time())
        root = root_fp or parent_fp or fp
        meta = {
            "fingerprint": fp,
            "event_type": event_type,
            "value": value,
            "source_tool": source_tool,
            "parent_fp": parent_fp,
            "root_fp": root,
            "created_at": now,
        }
        pipe = self.conn.pipeline()
        pipe.hset(f"fs3:event:{fp}", mapping=meta)
        pipe.sadd("fs3:event:all", fp)
        pipe.sadd(f"fs3:events:type:{event_type}", fp)
        pipe.lpush("fs3:event:new", fp)
        pipe.hincrby("fs3:stats:event_type", event_type, 1)
        for tool_name in self.consumers_for_event_type(event_type):
            pipe.zadd(f"fs3:pending:{tool_name}", {fp: float(now)})
        pipe.execute()
        self.log(f"[EVENT] {event_type}={value[:120]} fp={fp[:10]} source={source_tool}")
        return fp

    def get_event(self, fp: str) -> Optional[Dict[str, Any]]:
        data = self.conn.hgetall(f"fs3:event:{fp}")
        return data or None

    def is_event_cancelled(self, fp: str) -> bool:
        """Return True if an event was explicitly deleted/cancelled.

        Deleted events are marked with fs3:cancelled:<fp> so workers that already
        claimed the event can still notice the deletion before publishing output.
        """
        return bool(fp and self.conn.exists(f"fs3:cancelled:{fp}"))

    def consumers_for_event_type(self, event_type: str) -> Set[str]:
        consumers: Set[str] = set(self.conn.smembers(f"fs3:consumers:{event_type}") or [])
        for name, raw in (self.conn.hgetall("fs3:tools") or {}).items():
            try:
                info = json.loads(raw)
            except Exception:
                continue
            if event_type in (info.get("input_events") or []):
                consumers.add(name)
        return consumers

    def iter_event_fps(self, event_types: Iterable[str], limit_per_type: int = 200) -> List[str]:
        fps: List[str] = []
        seen: Set[str] = set()
        for event_type in event_types:
            key = f"fs3:events:type:{event_type}"
            for fp in self.conn.sscan_iter(key, count=max(100, limit_per_type)):
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
                stale_fps.append(fp)
                continue
            events.append(event)
            if len(events) >= limit:
                break
        if stale_fps:
            self.conn.zrem(queue_key, *stale_fps)
        return events

    def claim_task(self, tool_name: str, fp: str, node_id: str, max_concurrency: int, lock_ttl: int) -> bool:
        return bool(self._claim_script(
            keys=[f"fs3:done:{tool_name}:{fp}", f"fs3:lock:{tool_name}:{fp}", f"fs3:running:{node_id}:{tool_name}"],
            args=[str(max_concurrency), str(lock_ttl), node_id, str(time.time())],
        ))

    def release_task(self, tool_name: str, fp: str, node_id: str, mark_done: bool = True, status: str = "done") -> None:
        self._release_script(
            keys=[f"fs3:done:{tool_name}:{fp}", f"fs3:lock:{tool_name}:{fp}", f"fs3:running:{node_id}:{tool_name}"],
            args=["1" if mark_done else "0", node_id, str(time.time()), status],
        )
        if mark_done:
            self.conn.zrem(f"fs3:pending:{tool_name}", fp)

    def mark_command_executed(self, cmd: str) -> None:
        self.conn.sadd("fs3:install:commands", hashlib.sha256(cmd.encode()).hexdigest())

    def is_command_executed(self, cmd: str) -> bool:
        return bool(self.conn.sismember("fs3:install:commands", hashlib.sha256(cmd.encode()).hexdigest()))

    def register_node(self, node_id: str, info: Dict[str, Any], ttl: int = 45) -> None:
        pipe = self.conn.pipeline()
        pipe.sadd("fs3:nodes", node_id)
        pipe.hset(f"fs3:node:{node_id}", mapping={k: json.dumps(v, ensure_ascii=False) for k, v in info.items()})
        pipe.expire(f"fs3:node:{node_id}", ttl)
        pipe.execute()

    def register_tool(self, tool_name: str, yaml_path: str, input_events: List[str]) -> None:
        pipe = self.conn.pipeline()
        pipe.hset("fs3:tools", tool_name, json.dumps({"yaml_path": yaml_path, "input_events": input_events}, ensure_ascii=False))
        for event_type in input_events:
            pipe.sadd(f"fs3:consumers:{event_type}", tool_name)
        pipe.execute()
        self.enqueue_existing_events_for_tool(tool_name, input_events)

    def enqueue_existing_events_for_tool(self, tool_name: str, event_types: Iterable[str]) -> int:
        queued = 0
        pipe = self.conn.pipeline()
        queue_key = f"fs3:pending:{tool_name}"
        for event_type in event_types:
            for fp in self.conn.sscan_iter(f"fs3:events:type:{event_type}", count=500):
                if self.conn.exists(f"fs3:done:{tool_name}:{fp}"):
                    continue
                event = self.get_event(fp)
                if not event:
                    continue
                score = float(event.get("created_at") or time.time())
                pipe.zadd(queue_key, {fp: score}, nx=True)
                queued += 1
                if queued % 500 == 0:
                    pipe.execute()
                    pipe = self.conn.pipeline()
        pipe.execute()
        return queued

    def log(self, message: str, max_items: int = 2000) -> None:
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}"
        pipe = self.conn.pipeline()
        pipe.lpush("fs3:logs", line)
        pipe.ltrim("fs3:logs", 0, max_items - 1)
        pipe.execute()
        print(line)
