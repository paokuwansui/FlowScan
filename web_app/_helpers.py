"""web_app 数据访问层:Redis 事件 / 节点 / 工具 / 队列 / 流程图的查询与变更。

被 dashboard / events / ai_* / agent 等子模块共享的"数据层"辅助函数。
只依赖 flowscan 核心库与 _common,不依赖任何路由模块,避免循环导入。
"""
import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from flowscan.redis_store import FlowScanRedis
from flowscan.tool_module import load_tools
from flowscan.utils import project_root

from ._common import _html_escape, _json_or_raw


def _parse_event_line(line: str) -> Optional[tuple]:
    if line.startswith("[") and "]" in line:
        right = line.index("]")
        event_type = line[1:right].strip()
        value = line[right + 1:].strip()
    else:
        # 无 [事件类型] 前缀 → 尝试空格分隔，否则默认 DOMAIN
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] == parts[0].upper() and len(parts[0]) <= 30:
            event_type, value = parts[0].strip(), parts[1].strip()
        elif parts:
            event_type, value = "INPUT", parts[0].strip()
        else:
            return None
    if not event_type or not value:
        return None
    return event_type, value


def _find_fps_by_value(redis: FlowScanRedis, value: str) -> List[str]:
    """查找所有事件类型中值完全等于 value 的事件指纹（精确匹配，批量移除用）。

    遍历 fs3:event:all 权威全集（sscan_iter 分批 + pipeline 批量取事件），
    内存占用与 Redis 往返数可控，不依赖事件类型统计键的完整性。
    """
    value = str(value).strip()
    if not value:
        return []
    fps: List[str] = []
    batch: List[str] = []
    for fp in redis.conn.sscan_iter("fs3:event:all", count=500):
        batch.append(fp)
        if len(batch) >= 500:
            _collect_fps_by_value(redis, batch, value, fps)
            batch = []
    if batch:
        _collect_fps_by_value(redis, batch, value, fps)
    return fps


def _collect_fps_by_value(redis: FlowScanRedis, fps: List[str], value: str, out: List[str]) -> None:
    """批量比对一批事件的值，命中者追加到 out。"""
    pipe = redis.conn.pipeline()
    for fp in fps:
        pipe.hgetall(f"fs3:event:{fp}")
    for fp, event in zip(fps, pipe.execute()):
        if event and event.get("value") == value:
            out.append(fp)


def _remove_targets(redis: FlowScanRedis, line: str) -> List[str]:
    """解析批量移除输入行 → 目标事件指纹列表。

    - SHA256 指纹（64 位 hex）        → 该指纹
    - [事件类型]事件值                 → 单条指纹
    - 事件类型 事件值（全大写前缀）      → 单条指纹
    - 纯值（无类型前缀）               → 所有事件类型中值完全相等的全部指纹
    """
    line = (line or "").strip()
    if not line:
        return []
    if len(line) == 64 and all(char in "0123456789abcdef" for char in line.lower()):
        return [line]
    if line.startswith("[") and "]" in line:
        parsed = _parse_event_line(line)
        if parsed:
            return [FlowScanRedis.fingerprint(parsed[0], parsed[1])]
        return []
    parts = line.split(None, 1)
    if len(parts) == 2 and parts[0] == parts[0].upper() and len(parts[0]) <= 30:
        return [FlowScanRedis.fingerprint(parts[0], parts[1].strip())]
    return _find_fps_by_value(redis, line)


def _event_types(redis: FlowScanRedis) -> List[str]:
    return sorted(redis.conn.hkeys("fs3:stats:event_type") or [])


def _strip_internal_fields(event: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """去掉事件里的内部字段(fingerprint/parent_fp/root_fp),供对外 API 返回。"""
    if not isinstance(event, dict):
        return event or {}
    return {k: v for k, v in event.items() if k not in ("fingerprint", "parent_fp", "root_fp")}


def _list_events(redis: FlowScanRedis, event_type: str = "", limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """按创建时间倒序取一页事件（基于时间索引 zset，不再全量 SMEMBERS）。"""
    fps, _total = redis.recent_event_fps(event_type=event_type, limit=max(1, limit), offset=offset)
    events = []
    if fps:
        pipe = redis.conn.pipeline()
        for fp in fps:
            pipe.hgetall(f"fs3:event:{fp}")
        for event in pipe.execute():
            if event:
                event.setdefault("timestamp", event.get("created_at", "0"))
                event.setdefault("tool_name", event.get("source_tool", ""))
                events.append(event)
    return events


def _count_events(redis: FlowScanRedis, event_type: str = "") -> int:
    """事件总数（时间索引 zcard，O(1)）。"""
    return int(redis.conn.zcard(redis.event_time_index(event_type)) or 0)


def _event_path(redis: FlowScanRedis, fp: str) -> List[Dict[str, Any]]:
    path = []
    seen = set()
    current = fp
    while current and current not in seen:
        seen.add(current)
        event = redis.get_event(current)
        if not event:
            break
        event.setdefault("timestamp", event.get("created_at", "0"))
        event.setdefault("tool_name", event.get("source_tool", ""))
        path.append(event)
        current = event.get("parent_fp", "")
    path.reverse()
    return path


def _children_fps(redis: FlowScanRedis, parent_fp: str) -> List[str]:
    return list(redis.conn.smembers(f"fs3:children:{parent_fp}") or [])


def _remove_event(redis: FlowScanRedis, fp: str, remove_children: bool = True) -> int:
    event = redis.get_event(fp)
    if not event:
        return 0
    # 先标记取消，再递归删除子树。这样即使有运行中的 worker 正在基于该事件
    # 产出结果，FlowScanRedis.push_event 也会立即丢弃这些新子事件。
    redis.conn.setex(f"fs3:cancelled:{fp}", 86400, "1")
    removed = 0
    if remove_children:
        for child_fp in _children_fps(redis, fp):
            removed += _remove_event(redis, child_fp, remove_children=True)
    event_type = event.get("event_type", "")
    pipe = redis.conn.pipeline()
    pipe.delete(f"fs3:event:{fp}")
    pipe.delete(f"fs3:children:{fp}")
    pipe.srem("fs3:event:set", fp)
    pipe.srem("fs3:event:all", fp)
    pipe.srem(f"fs3:events:type:{event_type}", fp)
    pipe.lrem("fs3:event:new", 0, fp)
    # 时间索引同步移除
    pipe.zrem("fs3:event:time", fp)
    pipe.zrem(f"fs3:events:time:{event_type}", fp)
    pipe.zrem("fs3:event:roots", fp)
    # 保留取消标记，阻止运行中的任务产生孤儿子事件（24h TTL）
    pipe.setex(f"fs3:cancelled:{fp}", 86400, "1")
    # 递减事件类型统计（不低于 0，保持与 push_event 的 hincrby +1 对称）
    if event_type and int(redis.conn.hget("fs3:stats:event_type", event_type) or 0) > 0:
        pipe.hincrby("fs3:stats:event_type", event_type, -1)
    # 从所有工具的 pending/done/lock 中移除（用已知工具名直接构造 key，避免 scan_iter）
    for tool_name in (redis.conn.hkeys("fs3:tools") or []):
        pipe.zrem(f"fs3:pending:{tool_name}", fp)
        pipe.delete(f"fs3:done:{tool_name}:{fp}")
        pipe.delete(f"fs3:lock:{tool_name}:{fp}")
    pipe.execute()
    return removed + 1


def _clear_all_events(redis: FlowScanRedis) -> int:
    count = int(redis.conn.scard("fs3:event:all") or 0)
    keys = []
    for pattern in ("fs3:event:*", "fs3:events:type:*", "fs3:events:time:*", "fs3:children:*",
                    "fs3:done:*", "fs3:lock:*", "fs3:pending:*", "fs3:consumers:*",
                    "fs3:running:*", "fs3:cancelled:*", "fs3:ver:*", "fs3:enq:cursor:*"):
        keys.extend(list(redis.conn.scan_iter(pattern)))
    keys.extend(["fs3:event:set", "fs3:event:all", "fs3:event:new", "fs3:stats:event_type",
                 "fs3:event:time", "fs3:index:time:v1", "fs3:upgrade:consumers:v1"])
    if keys:
        redis.conn.delete(*set(keys))
    redis.log(f"[WEB] clear all events count={count}")
    return count


def _full_export(redis: FlowScanRedis) -> str:
    """全量导出所有 fs3:* Redis 键到 JSON 文件。
    排除瞬态键: fs3:lock:*, fs3:running:* (带 TTL / 并发计数，恢复无意义)。
    """
    snapshot_dir = os.path.abspath("state_snapshots")
    os.makedirs(snapshot_dir, exist_ok=True)
    path = os.path.join(snapshot_dir, f"flowscan_full_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    keys_data: Dict[str, Dict[str, Any]] = {}
    key_count = 0
    for key in redis.conn.scan_iter("fs3:*", count=500):
        if key.startswith("fs3:lock:") or key.startswith("fs3:running:") or key.startswith("fs3:cancelled:"):
            continue
        key_type = redis.conn.type(key)
        if key_type == "string":
            keys_data[key] = {"type": "string", "value": redis.conn.get(key)}
        elif key_type == "hash":
            keys_data[key] = {"type": "hash", "value": redis.conn.hgetall(key)}
        elif key_type == "set":
            keys_data[key] = {"type": "set", "value": sorted(redis.conn.smembers(key))}
        elif key_type == "zset":
            raw = redis.conn.zrange(key, 0, -1, withscores=True)
            keys_data[key] = {"type": "zset", "value": [[member, score] for member, score in raw]}
        elif key_type == "list":
            keys_data[key] = {"type": "list", "value": redis.conn.lrange(key, 0, -1)}
        key_count += 1
    data = {
        "version": 1,
        "saved_at": time.time(),
        "saved_at_iso": datetime.now().isoformat(),
        "key_count": key_count,
        "keys": keys_data,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    redis.log(f"[WEB] full export {path} ({key_count} keys)")
    return path


def _full_import(redis: FlowScanRedis, json_data: Dict[str, Any]) -> int:
    """清空所有 fs3:* 键，然后从全量导出 JSON 恢复。返回恢复的键数量。"""
    existing = list(redis.conn.scan_iter("fs3:*", count=1000))
    if existing:
        redis.conn.delete(*existing)
        redis.log(f"[WEB] cleared {len(existing)} existing fs3:* keys")

    keys = json_data.get("keys", {})
    if not keys:
        redis.log("[WEB] import: no keys in JSON, nothing to restore")
        return 0

    restored = 0
    pipe = redis.conn.pipeline()
    for key, info in keys.items():
        key_type = info["type"]
        value = info["value"]
        try:
            if key_type == "string" and value is not None:
                pipe.set(key, value)
            elif key_type == "hash" and value:
                pipe.delete(key)
                pipe.hset(key, mapping=value)
            elif key_type == "set" and value:
                pipe.delete(key)
                pipe.sadd(key, *value)
            elif key_type == "zset" and value:
                pipe.delete(key)
                pipe.zadd(key, {str(member): float(score) for member, score in value})
            elif key_type == "list" and value:
                pipe.delete(key)
                pipe.rpush(key, *value)
            else:
                continue
            restored += 1
        except Exception as exc:
            redis.log(f"[WEB] import error restoring {key}: {exc}")
        if restored % 500 == 0:
            pipe.execute()
            pipe = redis.conn.pipeline()
    pipe.execute()
    redis.log(f"[WEB] full import done, restored {restored} keys")
    return restored


def _active_nodes(redis: FlowScanRedis) -> List[Dict[str, Any]]:
    nodes = []
    for node_id in sorted(redis.conn.smembers("fs3:nodes") or []):
        raw = redis.conn.hgetall(f"fs3:node:{node_id}")
        if not raw:
            redis.conn.srem("fs3:nodes", node_id)
            continue
        info = {key: _json_or_raw(value) for key, value in raw.items()}
        tools = info.get("tools", [])
        event_types = info.get("event_types", [])
        nodes.append({
            "node_id": node_id,
            "host": info.get("host", ""),
            "pid": info.get("pid", ""),
            "started_at": info.get("time", ""),
            "tools": ",".join(tools) if isinstance(tools, list) else str(tools),
            "event_types": ",".join(event_types) if isinstance(event_types, list) else str(event_types),
        })
    return nodes


def _tool_registry(redis: FlowScanRedis) -> Dict[str, Any]:
    tools = {}
    for name, raw in (redis.conn.hgetall("fs3:tools") or {}).items():
        tools[name] = _json_or_raw(raw)
    return tools


def _queue_stats(redis: FlowScanRedis, modules_dir: str, tools: Dict[str, Any]) -> List[Dict[str, Any]]:
    consumer_map = _consumer_map(modules_dir, tools)
    stats = redis.conn.hgetall("fs3:stats:event_type") or {}
    event_types = sorted(set(stats) | set(consumer_map) | set(_event_types(redis)))
    rows = []
    for event_type in event_types:
        produced = int(stats.get(event_type, 0) or 0)
        consumers = consumer_map.get(event_type, [])
        available = sum(int(redis.conn.zcard(f"fs3:pending:{consumer['tool']}") or 0) for consumer in consumers)
        consumers_with_pending = []
        for consumer in consumers:
            item = dict(consumer)
            item["pending"] = int(redis.conn.zcard(f"fs3:pending:{consumer['tool']}") or 0)
            consumers_with_pending.append(item)
        rows.append({
            "type": event_type,
            "count": available if consumers else 0,
            "total_produced": produced,
            "has_consumer": bool(consumers),
            "consumers": consumers_with_pending,
        })
    rows.sort(key=lambda item: (not item["has_consumer"], item["type"]))
    return rows


def _consumer_map(modules_dir: str, tools: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {}
    try:
        loaded = load_tools(modules_dir)
        for tool in loaded.values():
            for event_type in tool.input_events:
                result.setdefault(event_type, []).append({"tool": tool.name, "produces": tool.allowed_output_events})
    except Exception:
        pass
    if not result:
        for name, info in tools.items():
            input_events = info.get("input_events", []) if isinstance(info, dict) else []
            for event_type in input_events:
                result.setdefault(event_type, []).append({"tool": name, "produces": []})
    return result


def _execution_flow_graph(redis: FlowScanRedis, modules_dir: str) -> Dict[str, Any]:
    tools = _flow_tools(modules_dir, _tool_registry(redis))
    event_counts = {key: int(value or 0) for key, value in (redis.conn.hgetall("fs3:stats:event_type") or {}).items()}
    produced_by: Dict[str, List[str]] = {}
    consumed_by: Dict[str, List[str]] = {}
    visible_tools = dict(tools)
    for tool in visible_tools.values():
        for event_type in tool.get("input_events", []):
            if event_type.startswith("__"):
                continue
            consumed_by.setdefault(event_type, []).append(tool["name"])
        for event_type in tool.get("allowed_output_events", []):
            if event_type.startswith("__"):
                continue
            produced_by.setdefault(event_type, []).append(tool["name"])

    nodes = []
    for tool in sorted(visible_tools.values(), key=lambda item: item["name"]):
        is_enabled = tool.get("enabled", True)
        nodes.append({
            "id": tool["name"],
            "label": _flow_tool_label(tool, redis),
            "title": _flow_tool_title(tool),
            "group": "tool" if is_enabled else "disabled",
            "shape": "box",
        })

    edges = []
    source_events = set()
    sink_events = set()
    all_event_types = sorted((set(event_counts) | set(produced_by) | set(consumed_by)) - {event for event in event_counts if event.startswith("__")})
    edge_index = 1
    for event_type in all_event_types:
        producers = sorted(produced_by.get(event_type, []))
        consumers = sorted(consumed_by.get(event_type, []))
        if not producers and consumers:
            source_events.add(event_type)
        if producers and not consumers:
            sink_events.add(event_type)
            sink_id = f"sink::{event_type}"
            nodes.append({
                "id": sink_id,
                "label": f"{event_type}\n{event_counts.get(event_type, 0)}",
                "title": f"未被消费的事件: {event_type}",
                "group": "event",
                "shape": "dot",
            })
            for producer in producers:
                edges.append(_flow_edge(edge_index, producer, sink_id, event_type, event_counts.get(event_type, 0)))
                edge_index += 1
            continue
        if not producers or not consumers:
            continue

        fanout_cost = len(producers) * len(consumers)
        hub_cost = len(producers) + len(consumers)
        if fanout_cost > hub_cost and fanout_cost >= 6:
            hub_id = f"event::{event_type}"
            nodes.append({
                "id": hub_id,
                "label": f"{event_type}\n{event_counts.get(event_type, 0)}",
                "title": f"事件: {event_type}",
                "group": "event",
                "shape": "dot",
            })
            for producer in producers:
                edges.append(_flow_edge(edge_index, producer, hub_id, event_type, event_counts.get(event_type, 0)))
                edge_index += 1
            for consumer in consumers:
                edges.append(_flow_edge(edge_index, hub_id, consumer, event_type, event_counts.get(event_type, 0)))
                edge_index += 1
            continue

        for producer in producers:
            for consumer in consumers:
                if producer == consumer:
                    continue
                edges.append(_flow_edge(edge_index, producer, consumer, event_type, event_counts.get(event_type, 0)))
                edge_index += 1

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "tool_count": len(visible_tools),
            "event_type_count": len(all_event_types),
            "edge_count": len(edges),
            "event_total": sum(count for event, count in event_counts.items() if not event.startswith("__")),
            "source_events": sorted(source_events),
            "sink_events": sorted(sink_events),
        },
    }


def _flow_tools(modules_dir: str, registered_tools: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    tools: Dict[str, Dict[str, Any]] = {}
    try:
        for tool in load_tools(modules_dir).values():
            tools[tool.name] = {
                "name": tool.name,
                "description": tool.description,
                "yaml_path": tool.yaml_path,
                "input_events": list(tool.input_events),
                "allowed_output_events": list(tool.allowed_output_events),
                "command_template": tool.command_template,
                "max_concurrency": tool.max_concurrency,
                "exec_timeout": 0,
                "enabled": tool.enabled,
            }
    except Exception:
        pass
    for name, info in registered_tools.items():
        if name in tools:
            continue
        if isinstance(info, dict):
            tools[name] = {
                "name": name,
                "description": "Redis 已注册工具",
                "yaml_path": info.get("yaml_path", ""),
                "input_events": list(info.get("input_events", []) or []),
                "allowed_output_events": [],
                "command_template": "",
                "max_concurrency": 0,
                "exec_timeout": 0,
                "enabled": True,
            }
    return tools


def _flow_edge(index: int, source: str, target: str, event_type: str, count: int) -> Dict[str, Any]:
    return {
        "id": f"tool-flow::{index}",
        "from": source,
        "to": target,
        "label": event_type,
        "title": f"事件: {event_type}<br>累计产生: {count}",
        "arrows": "to",
        "width": max(1, min(5, 1 + count // 50)),
    }


def _flow_tool_label(tool: Dict[str, Any], redis: FlowScanRedis) -> str:
    pending = int(redis.conn.zcard(f"fs3:pending:{tool['name']}") or 0)
    running = _running_count_for_tool(redis, tool["name"])
    if pending or running:
        return f"{tool['name']}\nR:{running} P:{pending}"
    return tool["name"]


def _flow_tool_title(tool: Dict[str, Any]) -> str:
    command = _html_escape(tool.get("command_template") or "-")
    if not tool.get("enabled", True):
        description = _html_escape(tool.get("description", ""))
        return f"状态: disabled / 占位模块<br>{description}<br><br>{command}"
    return command


def _running_count_for_tool(redis: FlowScanRedis, tool_name: str) -> int:
    """汇总所有 worker 节点上报的 per-tool 运行计数(来自心跳 running_by_tool)。"""
    total = 0
    for node_id in (redis.conn.smembers("fs3:nodes") or []):
        raw = redis.conn.hgetall(f"fs3:node:{node_id}")
        if not raw:
            continue
        running_by_tool = _json_or_raw(raw.get("running_by_tool", "{}"))
        if isinstance(running_by_tool, dict):
            try:
                total += int(running_by_tool.get(tool_name, 0) or 0)
            except (TypeError, ValueError):
                continue
    return total


# ── xray 报告 JSON ─────────────────────────────────────────────

def xray_json_paths() -> List[str]:
    """候选 xray JSON 报告路径(主报告目录 + xray 进程工作目录回退)。"""
    root = project_root()
    return [
        os.path.join(root, "reports", "xray_out.json"),
        os.path.join(root, "bin", "xray", "reports", "xray_out.json"),
    ]


_SEV_HINTS = {
    "critical": ["rce", "command-injection", "upload", "sql-injection", "sqli",
                 "ssrf", "path-traversal", "file-read", "deserialization", "xxe", "ssti"],
    "high": ["xss", "crlf", "open-redirect", "redirect", "idor", "jsonp", "cors",
             "weak-password", "brute", "unauthorized", "log4j", "shiro"],
    "medium": ["info-leak", "leak", "backup", "sourcecode", "config", "baseline"],
}


def xray_severity(plugin: str = "", vuln_class: str = "") -> str:
    """按插件名/漏洞类别粗估严重等级:critical/high/medium/low/info。"""
    s = f"{plugin} {vuln_class}".lower()
    for sev, kws in _SEV_HINTS.items():
        if any(k in s for k in kws):
            return sev
    return "low" if s.strip() else "info"


def _parse_xray_stream(raw: str) -> List[Dict[str, Any]]:
    """xray 被动模式(webscan --listen)流式写 JSON:以 `[` 开头、逐行对象、永不闭合 `]`。
    兼容解析:跳过首尾括号行,逐行 json.loads(容忍行尾逗号)。"""
    items = []
    for line in raw.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            items.append(obj)
    return items


def xray_load_findings() -> List[Dict[str, Any]]:
    """读取 xray JSON 报告,标准化为发现列表;无文件/解析失败返回空列表。"""
    for path in xray_json_paths():
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            break
    else:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # xray 被动模式流式输出(未闭合数组),逐行兼容解析
            data = _parse_xray_stream(raw)
    except Exception:
        return []
    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("vulnerabilities", "results", "data"):
            v = data.get(key)
            if isinstance(v, list):
                items = v
                break
    elif isinstance(data, (list,)) or data is None:
        items = []
    findings = []
    for it in items:
        if not isinstance(it, dict):
            continue
        detail = it.get("detail") or {}
        if not isinstance(detail, dict):
            detail = {}
        target = it.get("target") or {}
        if not isinstance(target, dict):
            target = {}
        plugin = str(it.get("plugin") or "")
        vuln_class = str(it.get("vuln_class") or "")
        created = it.get("create_time") or 0
        try:
            created_iso = datetime.fromtimestamp(int(created)).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OSError):
            created_iso = ""
        findings.append({
            "plugin": plugin,
            "vuln_class": vuln_class,
            "severity": xray_severity(plugin, vuln_class),
            "url": str(detail.get("url") or target.get("url") or ""),
            "host": str(detail.get("host") or ""),
            "port": detail.get("port", ""),
            "payload": str(detail.get("payload") or ""),
            "create_time": created,
            "create_time_iso": created_iso,
            "addr": str(detail.get("addr") or ""),
        })
    findings.sort(key=lambda f: f.get("create_time") or 0, reverse=True)
    return findings
