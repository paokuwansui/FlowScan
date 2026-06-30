import os
import signal
import socket
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Dict, List, Optional, Set

from .pipeline import EventPipeline
from .redis_store import FlowScanRedis
from .tool_module import ToolModule, event_map_for, load_tools
from .utils import check_tool_installed


class Worker:
    def __init__(self, config: dict, modules_dir: str, redis_client: FlowScanRedis, node_id: Optional[str] = None, pool_size: int = 20, debug: bool = False):
        self.config = config
        self.modules_dir = os.path.abspath(modules_dir)
        self.redis = redis_client
        self.node_id = node_id or f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
        self.pool_size = pool_size
        self.tools: Dict[str, ToolModule] = {}
        self.event_map: Dict[str, List[ToolModule]] = {}
        self.running = False
        self.executor: Optional[ThreadPoolExecutor] = None
        self.futures: Set[Future] = set()
        self.lock = threading.Lock()
        self.pipeline = EventPipeline(self.node_id, config, debug=debug)
        self._tool_cursor = 0

    def load(self) -> None:
        all_tools = load_tools(self.modules_dir)
        self.tools = {}
        for name, tool in all_tools.items():
            if not check_tool_installed(tool.check_command, tool.expect_keyword, tool.exclude_keyword, timeout=10):
                print(f"[{self.node_id}] skip unavailable tool {name}; run init on this node")
                continue
            self.tools[name] = tool
            self.redis.register_tool(name, tool.yaml_path, tool.input_events)
        self.event_map = event_map_for(self.tools)
        print(f"[{self.node_id}] active tools={list(self.tools)} event_types={list(self.event_map)}")

    def inject(self, event_type: str, value: str) -> None:
        self.redis.push_event(event_type, value, source_tool="manual")

    def start(self) -> None:
        self.redis.ping()
        self.load()
        if not self.tools:
            print(f"[{self.node_id}] no runnable tools")
            return
        self.running = True
        self.executor = ThreadPoolExecutor(max_workers=self.pool_size, thread_name_prefix=f"fs3-{self.node_id}")
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        print(f"[{self.node_id}] worker started pool={self.pool_size}")
        while self.running:
            self._reap_done_futures()
            submitted = self._scan_and_submit_once()
            if submitted == 0:
                time.sleep(float(self.config.get("worker", {}).get("idle_sleep_seconds", 1.0)))

    def stop(self) -> None:
        self.running = False
        if self.executor:
            self.executor.shutdown(wait=True)
        print(f"[{self.node_id}] stopped")

    def _scan_and_submit_once(self) -> int:
        if not self.executor:
            return 0
        submitted = 0
        max_pending = int(self.config.get("worker", {}).get("max_local_pending", self.pool_size * 2))
        scan_batch_size = int(self.config.get("worker", {}).get("scan_batch_size", 200))
        with self.lock:
            available_slots = max_pending - len(self.futures)
        if available_slots <= 0:
            return 0
        tools = list(self.tools.values())
        if not tools:
            return 0
        start = self._tool_cursor % len(tools)
        ordered_tools = tools[start:] + tools[:start]
        self._tool_cursor = (start + 1) % len(tools)
        per_tool_limit = max(1, min(scan_batch_size, max(1, available_slots // len(tools) or 1)))
        for tool in ordered_tools:
            if not self.running:
                break
            with self.lock:
                available_slots = max_pending - len(self.futures)
            if available_slots <= 0:
                break
            pending = self.redis.pending_for_tool(tool.name, tool.input_events, limit=min(per_tool_limit, available_slots))
            for event in pending:
                with self.lock:
                    if len(self.futures) >= max_pending:
                        return submitted
                fp = event.get("fingerprint", "")
                if not fp:
                    continue
                ttl = max(int(tool.exec_timeout or 600) + 120, 180)
                if not self.redis.claim_task(tool.name, fp, self.node_id, tool.max_concurrency, ttl):
                    continue
                future = self.executor.submit(self._run_task, event, tool)
                with self.lock:
                    self.futures.add(future)
                submitted += 1
        return submitted

    def _run_task(self, event: dict, tool: ToolModule) -> None:
        fp = event.get("fingerprint", "")
        status = "done"
        try:
            self.pipeline.process(event, tool, self.redis)
        except Exception as exc:
            status = f"error:{exc}"
            self.redis.log(f"[{self.node_id}] [{tool.name}] fatal: {exc}")
        finally:
            self.redis.release_task(tool.name, fp, self.node_id, mark_done=True, status=status)

    def _reap_done_futures(self) -> None:
        with self.lock:
            self.futures = {future for future in self.futures if not future.done()}

    def _heartbeat_loop(self) -> None:
        while self.running:
            info = {
                "pid": os.getpid(),
                "host": socket.gethostname(),
                "tools": sorted(self.tools),
                "event_types": sorted(self.event_map),
                "pending_local": len(self.futures),
                "time": time.time(),
            }
            try:
                self.redis.register_node(self.node_id, info)
            except Exception:
                pass
            time.sleep(15)


def run_forever(worker: Worker) -> None:
    def handle(sig, frame):
        print(f"signal {sig}, stopping")
        worker.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)
    worker.start()
