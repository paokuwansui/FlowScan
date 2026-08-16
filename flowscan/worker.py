import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Dict, List, Optional, Set, Tuple

from .pipeline import EventPipeline
from .redis_store import FlowScanRedis
from .tool_module import ToolModule, event_map_for, load_tools
from .utils import check_tool_installed, project_root


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
        # 进程内 per-tool 并发计数(每个 worker 节点独立计算,不再用 Redis 全局 running 计数)
        self._running_by_tool: Dict[str, int] = {}
        # 模块安装脚本目录:install/<模块名>.sh(按 modules/*.yaml 文件名对应)
        self.install_dir = os.path.join(project_root(), "install")
        # 看门狗:当前持有锁的 (tool_name, fp) 集合,心跳时刷新其 heartbeat_at
        self._active_locks: Set[Tuple[str, str]] = set()
        # 看门狗阈值:lock 超过该秒数无心跳视为持有者已死,允许被抢占
        self._lock_stale_seconds = int(config.get("worker", {}).get("lock_stale_seconds", 120))
        # 失败退避(每节点本地):(tool_name, fp) -> 失败次数 / 退避到期时间。
        # 计数与到期时间均不落 redis——单节点网络问题不应拖住整个集群,
        # 其他节点可立即抢占该事件;本节点退避期内跳过,到期后经 claim 确认未被抢占再抢。
        self._retry_counts: Dict[Tuple[str, str], int] = {}
        self._cooldowns: Dict[Tuple[str, str], float] = {}
        self._retry_base = int(config.get("worker", {}).get("retry_base_seconds", 5))
        self._retry_cap = int(config.get("worker", {}).get("retry_cap_seconds", 21600))   # 上限 6 小时

    def install_tools(self) -> None:
        """安装所有工具 + 检查可用性(不依赖 redis),填充 self.tools。

        启动顺序:先装工具 → 再探测/连接主节点,故本方法在连 redis 之前调用。
        """
        all_tools = load_tools(self.modules_dir)
        self.tools = {}
        for name, tool in all_tools.items():
            # 按模块 YAML 文件名找对应安装脚本,存在则执行(幂等:已装则跳过)
            base = os.path.splitext(os.path.basename(tool.yaml_path))[0]
            install_script = os.path.join(self.install_dir, f"{base}.sh")
            if os.path.isfile(install_script):
                if not self._run_module_install(install_script, name):
                    print(f"[{self.node_id}] skip {name} (install failed)")
                    continue
            if not check_tool_installed(tool.check_command, tool.expect_keyword, tool.exclude_keyword, timeout=10):
                print(f"[{self.node_id}] skip unavailable tool {name} (missing binary)")
                continue
            self.tools[name] = tool
        self.event_map = event_map_for(self.tools)
        print(f"[{self.node_id}] tools installed={list(self.tools)} event_types={list(self.event_map)}")

    def register_tools(self) -> None:
        """向 redis 注册可用工具(需要 redis 已连接)。"""
        for name, tool in self.tools.items():
            self.redis.register_tool(name, tool.yaml_path, tool.input_events)

    def _run_module_install(self, script: str, tool_name: str) -> bool:
        """执行模块安装脚本(bash install/<模块>.sh),幂等:工具已装则脚本自行跳过。"""
        print(f"[{self.node_id}] installing {tool_name} via {os.path.basename(script)} ...")
        ok = False
        try:
            proc = subprocess.run(["bash", script])
            ok = proc.returncode == 0
        except Exception as exc:
            print(f"[{self.node_id}] install error for {tool_name}: {exc}")
        if ok:
            print(f"[{self.node_id}] {tool_name} ready")
        else:
            print(f"[{self.node_id}] {tool_name} install FAILED")
        return ok

    def inject(self, event_type: str, value: str) -> None:
        self.redis.push_event(event_type, value, source_tool="manual")

    def start(self) -> None:
        self.redis.ping()
        # 一次性升级动作（多节点由 SET NX 保证只执行一次）：
        #  1) 存量事件补建时间索引（#8/#9/#10 依赖）
        #  2) 存量事件补建根事件索引（事件图谱）
        #  3) 清理废弃的 fs3:consumers:* 集合（#12，消费关系以 fs3:tools 为准）
        self.redis.ensure_time_index()
        self.redis.ensure_root_index()
        self.redis.cleanup_legacy_consumers()
        self.register_tools()
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
            # 进程内 per-tool 并发限制:达到该工具的 max_concurrency 则本轮跳过该工具
            with self.lock:
                running_for_tool = self._running_by_tool.get(tool.name, 0)
            if running_for_tool >= tool.max_concurrency:
                continue
            pending = self.redis.pending_for_tool(tool.name, tool.input_events, limit=min(per_tool_limit, available_slots))
            for event in pending:
                with self.lock:
                    if len(self.futures) >= max_pending:
                        return submitted
                    running_for_tool = self._running_by_tool.get(tool.name, 0)
                if running_for_tool >= tool.max_concurrency:
                    break
                fp = event.get("fingerprint", "")
                if not fp:
                    continue
                # 本地退避:本节点对该 (tool, fp) 还在冷却中 → 跳过(不 claim)。
                # 其他节点不受影响;到期后走正常 claim(被抢占/已 done 则 claim 返回 0)。
                with self.lock:
                    cd_until = self._cooldowns.get((tool.name, fp), 0.0)
                if cd_until > time.time():
                    continue
                if not self.redis.claim_task(tool.name, fp, self.node_id, self._lock_stale_seconds):
                    # claim 失败:事件已被处理(done)或锁被持有。若锁正被**本节点**持有
                    # (该事件处理中,_active_locks 含此 key),绝不能清理退避状态——
                    # 否则处理失败后计数丢失,退避永远从 retry=1 开始。
                    # 仅当事件确实被其他节点/已 done,且本地退避已到期,才惰性清理。
                    with self.lock:
                        key = (tool.name, fp)
                        if key not in self._active_locks and self._cooldowns.get(key, 0.0) <= time.time():
                            self._cooldowns.pop(key, None)
                            self._retry_counts.pop(key, None)
                    continue
                future = self.executor.submit(self._run_task, event, tool)
                with self.lock:
                    self.futures.add(future)
                    self._running_by_tool[tool.name] = self._running_by_tool.get(tool.name, 0) + 1
                    self._active_locks.add((tool.name, fp))
                submitted += 1
        return submitted

    def _run_task(self, event: dict, tool: ToolModule) -> None:
        fp = event.get("fingerprint", "")
        status = "done"
        mark_done = True
        try:
            if fp and self.redis.is_event_cancelled(fp):
                status = "cancelled"
                self.redis.log(f"[{self.node_id}] [{tool.name}] skip cancelled event fp={fp[:10]}")
                return
            published, failed = self.pipeline.process(event, tool, self.redis)
            if failed:
                # 命令报错退出:不标记完成,释放锁(pending 保留)让其他节点抢占。
                # 本节点对该 (tool, fp) 指数退避(base×2^(n-1),cap 封顶),退避期内
                # 不再抢占该事件;其他节点不受影响,可立即抢占(网络可达时成功)。
                mark_done = False
                key = (tool.name, fp)
                with self.lock:
                    n = self._retry_counts.get(key, 0) + 1
                    self._retry_counts[key] = n
                backoff = min(self._retry_base * (2 ** (n - 1)), self._retry_cap)
                with self.lock:
                    self._cooldowns[key] = time.time() + backoff
                status = f"error:exit(retry={n},backoff={backoff}s)"
                self.redis.log(f"[{self.node_id}] [{tool.name}] {status} fp={fp[:10]}")
        except Exception as exc:
            status = f"error:{exc}"
            mark_done = False
            self.redis.log(f"[{self.node_id}] [{tool.name}] fatal: {exc}")
        finally:
            with self.lock:
                self._running_by_tool[tool.name] = max(0, self._running_by_tool.get(tool.name, 0) - 1)
                self._active_locks.discard((tool.name, fp))
            self.redis.release_task(tool.name, fp, self.node_id, mark_done=mark_done, status=status)
            if mark_done and fp:
                # 成功/取消:清除该事件的本地退避状态(下次失败从 base 重新开始)
                key = (tool.name, fp)
                with self.lock:
                    self._retry_counts.pop(key, None)
                    self._cooldowns.pop(key, None)

    def _reap_done_futures(self) -> None:
        with self.lock:
            self.futures = {future for future in self.futures if not future.done()}

    def _heartbeat_loop(self) -> None:
        interval = int(self.config.get("worker", {}).get("heartbeat_interval_seconds", 10))
        while self.running:
            with self.lock:
                running_by_tool = dict(self._running_by_tool)
                active_locks = list(self._active_locks)
            info = {
                "pid": os.getpid(),
                "host": socket.gethostname(),
                "tools": sorted(self.tools),
                "event_types": sorted(self.event_map),
                "pending_local": len(self.futures),
                "running_by_tool": running_by_tool,
                "active_locks": [[tool, fp] for tool, fp in active_locks],
                "time": time.time(),
            }
            try:
                self.redis.register_node(self.node_id, info)
                # 工具注册自愈:注册表(fs3:tools)被误删/清空时,心跳周期自动重建。
                # register_tool 幂等(配置一致时不写、不 bump 版本),每轮开销仅 16 次 hget。
                self.register_tools()
                # 看门狗:刷新每个持有锁的 heartbeat_at,证明本节点仍存活
                now = time.time()
                for tool_name, fp in active_locks:
                    self.redis.heartbeat_lock(tool_name, fp, now)
                # 工具存活刷新 + 失联工具清理(多节点由 SET NX 锁保证单执行者)
                self.redis.touch_tools(sorted(self.tools))
                self.redis.sweep_stale_tools(
                    int(self.config.get("worker", {}).get("tool_stale_seconds", 90)))
            except Exception:
                pass
            time.sleep(interval)


def run_forever(worker: Worker) -> None:
    def handle(sig, frame):
        print(f"signal {sig}, stopping")
        worker.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)
    worker.start()
