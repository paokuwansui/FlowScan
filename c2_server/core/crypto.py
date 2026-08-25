"""
core/crypto.py — 加密/解密管道 (ChaCha20 + HMAC-SHA256 + zlib + 帧混淆)

编码管道:
  原始数据 (bytes)
    → zlib.compress()
    → ChaCha20 加密 (每帧派生密钥)
    → HMAC-SHA256 完整性标签 (encrypt-then-MAC)
    → 帧尾随机 padding (0-255 字节 + 1 字节 pad_len)   ← 流量混淆: 打乱长度分布

解码管道 (逆向):
  剥除帧尾 padding → 验 HMAC → ChaCha20 解密 → zlib.decompress()

每帧派生密钥: 主密钥 K 经 sha256(domain_separation || K) 派生出
enc_key / mac_key；每帧随机 12 字节 nonce，杜绝流密码 nonce 复用。

ChaCha20 为 RFC 8439 变体（96-bit nonce + 32-bit counter），公有领域。
MAC 用 hmac.compare_digest 常数时间比较，防时序侧信道。

2026-08-25 混淆改造: 移除 base64(字符集指纹),新增帧尾随机 padding。
"""

import hashlib
import hmac
import secrets
import struct
import zlib

# ── ChaCha20 (RFC 8439) ──

_NONCE_SIZE = 12
_TAG_SIZE = 32


def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xffffffff
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xffffffff
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xffffffff
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xffffffff


def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """ChaCha20 单块（64 字节密钥流）。key=32B, nonce=12B。"""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state = (constants
             + list(struct.unpack("<8I", key))
             + [counter]
             + list(struct.unpack("<3I", nonce)))
    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return struct.pack(
        "<16I", *[(working[i] + state[i]) & 0xffffffff for i in range(16)])


def chacha20_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
    out = bytearray()
    counter = 0
    for i in range(0, len(data), 64):
        block = chacha20_block(key, nonce, counter)
        out.extend(a ^ b for a, b in zip(data[i:i + 64], block))
        counter += 1
    return bytes(out)


# ── 密钥派生（domain separation）──
#
# 标签字节必须与 server/implant/implant_template.py 与
# server/s_modules/proxy.py 中的 b"e"/b"m" 完全一致（三处共享同一密码格式）。

_ENC_LABEL = b"e"
_MAC_LABEL = b"m"


def derive_keys(master: bytes) -> tuple:
    """主密钥 → (enc_key, mac_key)。两个 32 字节子密钥。"""
    enc = hashlib.sha256(_ENC_LABEL + master).digest()
    mac = hashlib.sha256(_MAC_LABEL + master).digest()
    return enc, mac


# ── 封/解封（encrypt-then-MAC）──

def seal(data: bytes, master: bytes) -> bytes:
    """data → nonce(12) || ciphertext || tag(32)。"""
    enc, mac_key = derive_keys(master)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    ciphertext = chacha20_xor(data, enc, nonce)
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def open_sealed(sealed: bytes, master: bytes) -> bytes:
    """seal() 的逆；MAC 不匹配抛 ValueError。"""
    if len(sealed) < _NONCE_SIZE + _TAG_SIZE:
        raise ValueError("bad MAC")
    enc, mac_key = derive_keys(master)
    nonce = sealed[:_NONCE_SIZE]
    ciphertext = sealed[_NONCE_SIZE:-_TAG_SIZE]
    tag = sealed[-_TAG_SIZE:]
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("bad MAC")
    return chacha20_xor(ciphertext, enc, nonce)


# ── 帧管道（对外接口不变；2026-08-25 混淆: 去 base64 + 帧尾 padding）──

_MAX_PAD = 255


def encode_frame(data: bytes, key: bytes) -> bytes:
    """data → 混淆帧: seal(...) + 随机 padding(0-255) + 1B pad_len。

    pad_len 放帧尾最后 1 字节,decode 时先剥除,再走 MAC 校验。
    padding 让帧长度分布带上 0-255 随机偏移,打掉包大小指纹。
    """
    compressed = zlib.compress(data)
    sealed = seal(compressed, key)
    pad_len = secrets.randbelow(_MAX_PAD + 1)
    return sealed + secrets.token_bytes(pad_len) + bytes([pad_len])


def decode_frame(data: bytes, key: bytes) -> bytes:
    if not data:
        raise ValueError("decode_frame: data must not be empty")
    pad_len = data[-1]
    if len(data) < _NONCE_SIZE + _TAG_SIZE + 1 + pad_len:
        raise ValueError("decode_frame: frame too short")
    sealed = data[: -1 - pad_len]
    try:
        plaintext = open_sealed(sealed, key)
    except ValueError as e:
        raise ValueError(f"decode_frame: {e}") from e
    try:
        return zlib.decompress(plaintext)
    except zlib.error as e:
        raise ValueError(f"decode_frame: decompression failed: {e}") from e


# 保留 XOR 原语（测试/通用用途；帧管道已改用 ChaCha20+HMAC）
def xor_crypt(data: bytes, key: bytes) -> bytes:
    """逐字节循环异或（历史原语，非帧管道）。"""
    if not key:
        raise ValueError("xor_crypt: key must not be empty")
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))
