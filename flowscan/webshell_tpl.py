"""WebShell 一句话木马模板加载器 — 扫描 webshell_templates/*,解析文件头元数据。

模板格式(目录即模块,参考 c2/phishing 的模块体系):
    文件首行附近包含 MODULE 元数据头(注释语法按语言不同,loader 按行提取后删除该行):
        php  :  // MODULE = {...}
        jsp  :  <%-- MODULE = {...} --%>
        aspx :  <%-- MODULE = {...} --%>
        asp  :  ' MODULE = {...}
    模板体用 {{param}} 占位符,render 时按参数替换。

加载失败显式化:无 MODULE 头 / JSON 非法 / 结构错误 → 告警跳过(不静默)。
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("webshell.template_loader")

# 行内含 MODULE = {json}(兼容 //、'、<%-- --%>、<!-- --> 注释前缀/后缀)
_MODULE_HEAD_RE = re.compile(
    r"^\s*(?://|'|<!--|<%--)?\s*MODULE\s*=\s*(\{.*\})\s*(?:--\s*%>|-->\s*)?$", re.M
)

# 支持扫描的模板扩展名
_TEMPLATE_EXTS = (".php", ".jsp", ".aspx", ".asp", ".tpl")


@dataclass
class TemplateInfo:
    name: str
    path: str
    desc: str = ""
    category: str = "php"          # 按语言分类:php / jsp / aspx / asp
    params: list = field(default_factory=list)   # [(name, hint), ...]
    body: str = ""                               # 去 MODULE 头行后的模板体


class TemplateLoader:
    """WebShell 模板加载器。扫描目录,解析 .php/.jsp/.aspx/.asp 模板。"""

    def __init__(self, templates_dir: str = "webshell_templates"):
        self._dir = templates_dir
        self._templates: dict = {}

    # ── 公开接口 ──

    def load(self) -> None:
        self._templates.clear()
        if not os.path.isdir(self._dir):
            logger.warning("webshell templates dir not found: %s", self._dir)
            return
        for filename in sorted(os.listdir(self._dir)):
            path = os.path.join(self._dir, filename)
            if not os.path.isfile(path) or not filename.endswith(_TEMPLATE_EXTS):
                continue
            self._load_template(filename, path)

    def list_templates(self) -> list:
        """列出模板摘要: [{name, desc, category, params}]"""
        return [
            {"name": t.name, "desc": t.desc, "category": t.category, "params": list(t.params)}
            for t in self._templates.values()
        ]

    def get_template(self, name: str) -> Optional[dict]:
        tpl = self._templates.get(name)
        if not tpl:
            return None
        return {"name": tpl.name, "desc": tpl.desc, "category": tpl.category,
                "params": list(tpl.params), "body": tpl.body}

    def render(self, name: str, params: Optional[Dict[str, str]] = None) -> Optional[str]:
        """渲染模板:{{param}} 按 params 替换;未提供参数保留原占位符。"""
        tpl = self._templates.get(name)
        if not tpl:
            return None
        text = tpl.body
        for k, v in (params or {}).items():
            text = text.replace("{{" + k + "}}", str(v))
        return text

    def reload(self) -> None:
        self.load()

    # ── 内部 ──

    def _load_template(self, filename: str, path: str) -> None:
        name = os.path.splitext(filename)[0]
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            logger.warning("ws template %s: read failed: %s", name, e)
            return
        if not content.strip():
            logger.warning("ws template %s: empty file, skipped", name)
            return
        m = _MODULE_HEAD_RE.search(content)
        if not m:
            logger.warning("ws template %s: 缺少 MODULE 元数据头, skipped", name)
            return
        try:
            meta = json.loads(m.group(1))
        except json.JSONDecodeError as e:
            logger.warning("ws template %s: MODULE 元数据 JSON 非法: %s, skipped", name, e)
            return
        if not isinstance(meta, dict):
            logger.warning("ws template %s: MODULE 必须是对象, skipped", name)
            return
        desc = str(meta.get("desc", ""))
        category = str(meta.get("category", "") or "php").lower()
        params = meta.get("params", [])
        norm = []
        if isinstance(params, list):
            for p in params:
                if isinstance(p, (list, tuple)) and len(p) >= 1 and isinstance(p[0], str):
                    hint = p[1] if len(p) > 1 and isinstance(p[1], str) else ""
                    norm.append((p[0], hint))
        # 去 MODULE 头行(保留其他内容)
        body = _MODULE_HEAD_RE.sub("", content, count=1).strip()
        if not body:
            logger.warning("ws template %s: 无模板体, skipped", name)
            return
        self._templates[name] = TemplateInfo(
            name=name, path=path, desc=desc, category=category, params=norm, body=body,
        )
        logger.info("ws template loaded: %s (category=%s, params=%s)",
                    name, category, [p[0] for p in norm])
