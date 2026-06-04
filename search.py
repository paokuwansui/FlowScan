#!/usr/bin/env python3
"""Search FlowScan outputs/RUN_LOG and reconstruct event provenance chains.

RUN_LOG is JSONL, one event per line, for example:
{"target":"127.0.0.1","module_name":"fscan_module","event_name":"PORT_OPEN","value":"127.0.0.1:80"}

Usage:
  python search.py 127.0.0.1:80
  python search.py 80 --contains
  python search.py 127.0.0.1:80 --json

Text output uses the compact hop format requested by the project:
  <target> <module>_<EVENT> <value>
For example:
  127.0.0.1 fscan_PORT_OPEN 127.0.0.1:80
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


DEFAULT_RUN_LOG = Path("./outputs/RUN_LOG")


def normalize_module_name(module_name: str) -> str:
    """Make output concise: fscan_module -> fscan, ENGINE_START/ROOT unchanged."""
    module_name = str(module_name or "UNKNOWN").strip() or "UNKNOWN"
    if module_name.endswith("_module"):
        return module_name[: -len("_module")]
    return module_name


def load_run_log(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"RUN_LOG 不存在: {path}")

    records: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[WARN] 跳过非法 JSON 行 {line_no}: {exc}", file=sys.stderr)
                continue
            if not isinstance(item, dict):
                print(f"[WARN] 跳过非对象 JSON 行 {line_no}", file=sys.stderr)
                continue

            target = str(item.get("target", "")).strip()
            module_name = str(item.get("module_name", "")).strip()
            event_name = str(item.get("event_name", "")).strip()
            value = str(item.get("value", "")).strip()
            if not value:
                print(f"[WARN] 跳过缺少 value 的 RUN_LOG 行 {line_no}", file=sys.stderr)
                continue

            records.append(
                {
                    "target": target,
                    "module_name": module_name,
                    "event_name": event_name,
                    "value": value,
                    "line_no": str(line_no),
                }
            )
    return records


def build_indexes(records: list[dict[str, str]]):
    by_value: dict[str, list[dict[str, str]]] = defaultdict(list)
    for record in records:
        by_value[record["value"]].append(record)
    return by_value


def compact_hop(record: dict[str, str]) -> str:
    module = normalize_module_name(record.get("module_name", "UNKNOWN"))
    event = record.get("event_name", "UNKNOWN") or "UNKNOWN"
    target = record.get("target", "")
    value = record.get("value", "")
    return f"{target} {module}_{event} {value}".strip()


def record_for_json(record: dict[str, str]) -> dict[str, Any]:
    return {
        "target": record.get("target", ""),
        "module_name": record.get("module_name", ""),
        "event_name": record.get("event_name", ""),
        "value": record.get("value", ""),
        "line_no": int(record.get("line_no", "0") or 0),
    }


def find_start_records(records: list[dict[str, str]], query: str, contains: bool) -> list[dict[str, str]]:
    if contains:
        return [record for record in records if query in record.get("value", "")]
    return [record for record in records if record.get("value") == query]


def trace_record(
    record: dict[str, str],
    by_value: dict[str, list[dict[str, str]]],
    max_depth: int,
) -> list[list[dict[str, str]]]:
    """Return root -> leaf chains for one leaf record.

    Parent lookup rule:
      current.target is the previous event's value.

    This matches RUN_LOG semantics:
      target = module input value
      value  = module output event value

    If current.target has no producer in RUN_LOG, current is treated as the first
    produced event after the original user/root input.
    """

    def walk(current: dict[str, str], seen_keys: set[tuple[str, str, str]], depth: int):
        current_key = (
            current.get("target", ""),
            current.get("event_name", ""),
            current.get("value", ""),
        )
        if current_key in seen_keys:
            return [[current]]
        if depth >= max_depth:
            return [[current]]

        parent_value = current.get("target", "")
        parent_records = by_value.get(parent_value, []) if parent_value else []
        if not parent_records:
            return [[current]]

        chains: list[list[dict[str, str]]] = []
        next_seen = set(seen_keys)
        next_seen.add(current_key)
        for parent in parent_records:
            for parent_chain in walk(parent, next_seen, depth + 1):
                chains.append(parent_chain + [current])
        return chains

    return walk(record, set(), 0)


def print_text_result(query: str, chains: list[list[dict[str, str]]]) -> None:
    if not chains:
        print(f"未找到 value={query!r} 对应的 RUN_LOG 记录")
        return

    print(f"查询值: {query}")
    print(f"匹配链条数: {len(chains)}")
    for idx, chain in enumerate(chains, 1):
        print(f"\n[{idx}] 溯源链条 root -> leaf")
        for hop_index, record in enumerate(chain, 1):
            print(f"  {hop_index}. {compact_hop(record)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="从 FlowScan outputs/RUN_LOG 反向梳理事件溯源链条")
    parser.add_argument("value", help="要查询的事件值，例如 127.0.0.1:80")
    parser.add_argument("--run-log", default=str(DEFAULT_RUN_LOG), help="RUN_LOG 路径，默认 ./outputs/RUN_LOG")
    parser.add_argument("--contains", action="store_true", help="按 value 包含关系搜索，而不是精确匹配")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式")
    parser.add_argument("--max-depth", type=int, default=50, help="最大回溯深度，默认 50")
    args = parser.parse_args(argv)

    run_log_path = Path(args.run_log)
    max_depth = max(1, args.max_depth)

    try:
        records = load_run_log(run_log_path)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    by_value = build_indexes(records)
    matched_records = find_start_records(records, args.value, args.contains)

    all_chains: list[list[dict[str, str]]] = []
    for record in matched_records:
        all_chains.extend(trace_record(record, by_value, max_depth=max_depth))

    if args.json:
        payload = {
            "query": args.value,
            "run_log": str(run_log_path),
            "match_mode": "contains" if args.contains else "exact",
            "chain_count": len(all_chains),
            "chains": [[record_for_json(record) for record in chain] for chain in all_chains],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_text_result(args.value, all_chains)

    return 0 if all_chains else 1


if __name__ == "__main__":
    raise SystemExit(main())
