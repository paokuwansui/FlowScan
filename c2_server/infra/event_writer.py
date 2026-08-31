"""
server/infra/event_writer.py — 事件文件（Q6 / 10.3）

JSONL 一行一事件；文件既是事件总线又是审计日志（console 后台线程、
未来 API/Web 各自 tail/增量读取同一文件）。

- 写入: RotatingFileHandler（10MB × 5 份，线程安全内置锁）
- 读端: tail(n) 最近 N 行；read_from(offset) 增量游标（供转发线程）

事件行格式: {"ts": ISO时间, "event": EVENT_*, "beacon": id, ...detail}
"""

import json
import logging
import os
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler

from server.core.events import ALL_EVENTS


class EventWriter:
    """事件文件写入端 + 读端。"""

    def __init__(self, path: str,
                 max_bytes: int = 10 * 1024 * 1024,
                 backup_count: int = 5):
        self._path = path
        # logger 名唯一化: logging 是全局注册表,"events" 单例会被多实例
        # (双 server/测试环境)互相覆盖 handler, 导致事件串写(2026-08-29 修复)
        self._logger = logging.getLogger(
            f"events.{os.path.basename(path)}.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        for h in list(self._logger.handlers):
            self._logger.removeHandler(h)
        dirname = os.path.dirname(path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        handler = RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backup_count,
            encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)
        self._lock = threading.Lock()  # 读端游标互斥（写端由 handler 自带锁）

    @property
    def path(self) -> str:
        return self._path

    # ── 写端 ──

    def emit(self, event: str, beacon: str = "-", **detail) -> None:
        """写入一条事件。

        Args:
            event: core.events 中的事件类型
            beacon: 关联 beacon id（无则 "-"）
            **detail: 附加字段（将序列化为 JSON）
        """
        record = {"ts": datetime.now().isoformat(),
                  "event": event, "beacon": beacon}
        record.update(detail)
        self._logger.info(json.dumps(record, ensure_ascii=False))

    # ── 读端 ──

    def tail(self, n: int = 100) -> list:
        """读取最后 N 行（最新在最后）。"""
        if not os.path.isfile(self._path):
            return []
        with self._lock:
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                return []  # M10：写端 rotate 竞态，返回空
        return lines[-n:]

    def read_from(self, offset: int) -> tuple:
        """从文件偏移增量读取。

        Returns:
            (lines, new_offset)。轮换后 offset 失效时从 0 重新读。
        """
        if not os.path.isfile(self._path):
            return [], 0
        with self._lock:
            try:
                size = os.path.getsize(self._path)
                if offset > size:
                    offset = 0  # 轮换后旧 offset 失效，从头重读
                with open(self._path, "r", encoding="utf-8") as f:
                    f.seek(offset)
                    lines = [line.strip() for line in f if line.strip()]
                    new_offset = f.tell()
            except FileNotFoundError:
                return [], 0  # M10：写端 rotate 竞态
        return lines, new_offset

    @staticmethod
    def parse_line(line: str) -> dict:
        """解析一行事件为 dict（读端消费用）。"""
        try:
            return json.loads(line)
        except ValueError:
            return {"event": "bad_line", "raw": line}
