"""
@module: keygen
@desc: 随机生成 implant_key 与 client_key 并自动写回 config.json
@params: [client_config]
"""
import json
import os
import secrets

MODULE = {
    "desc": "随机生成 implant_key/client_key 并自动写入 config.json",
    "params": [("client_config", "可选：同时写入 client 侧 config 文件路径")],
}

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_PATH = os.path.join(_SERVER_DIR, "config.json")


def run(client_config=None):
    """生成两把密钥写回 server/config.json（保留其余配置）。

    Returns:
        dict: 状态 + 密钥 + 写回路径；可选同时写 client 配置。
    """
    implant_key = secrets.token_hex(32)
    client_key = secrets.token_hex(32)

    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {"status": "error", "message": f"read config failed: {e}"}

    raw["implant_key"] = implant_key
    raw["client_key"] = client_key
    with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2)

    result = {
        "status": "ok",
        "config": _CONFIG_PATH,
        "implant_key": implant_key,
        "client_key": client_key,
        "note": ("client_key 需同步到操作员机器的 client/config.json；"
                 "密钥变更后需重启 server 生效（运行中的 server 仍用旧 key）"),
    }

    if client_config:
        try:
            with open(client_config, "r", encoding="utf-8") as f:
                craw = json.load(f)
            craw["client_key"] = client_key
            with open(client_config, "w", encoding="utf-8") as f:
                json.dump(craw, f, indent=2)
            result["client_config"] = client_config
        except (OSError, json.JSONDecodeError) as e:
            result["client_config_error"] = str(e)

    return result


if __name__ == "__main__":
    print("usage: s_exec keygen [client_config_path]")
