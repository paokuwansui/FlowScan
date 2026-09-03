"""
server/server_module_loader.py — Server 端模块加载器 v2 (5.6)

从 s_modules/ 扫描 .py，按文件路径动态加载（spec_from_file_location，
不走 sys.path 包解析，避免与真实 s_modules 包缓存冲突）。
每次执行重新加载 —— 改代码立即生效（热加载）。

元数据统一用 module_meta 读顶层 MODULE dict（与植入模块一致，替换 docstring 解析）。
结果处理器为第一等公民 (Q7): run(output, error) -> dict —— 调用约定与普通
server 模块相同（run(*args)），处理器约定前两个位置参数为 output/error。
执行异常记录运行日志。
"""

import importlib.util
import sys
from pathlib import Path
from typing import Optional

from server.core.log import get_logger
from . import module_meta

logger = get_logger("server_module_loader")


class ServerModuleLoader:
    """Server 端模块加载器。扫描 s_modules/ 目录。"""

    def __init__(self, modules_dir: str = "s_modules"):
        self._dir = Path(modules_dir)

    # ── 公开接口 ──

    def list_modules(self) -> list:
        """列出模块摘要: [{name, desc, params}]"""
        result = []
        for f in sorted(self._dir.glob("*.py")):
            if f.stem == "__init__":
                continue
            meta = self._read_meta(f)
            result.append({
                "name": f.stem,
                "desc": meta.get("desc", ""),
                "params": meta.get("params", []),
            })
        return result

    def get_module(self, name: str) -> Optional[dict]:
        """获取模块元信息；不存在返回 None。"""
        path = self._dir / f"{name}.py"
        if not path.is_file():
            return None
        meta = self._read_meta(path)
        return {"name": name, "desc": meta.get("desc", ""),
                "params": meta.get("params", [])}

    def reconfigure(self, modules_dir: str = None) -> None:
        """更新模块目录（reload 命令热重载配置用）。"""
        if modules_dir is not None:
            self._dir = Path(modules_dir)

    def run(self, name: str, args: list) -> str:
        """执行模块的 run(*args)。

        处理器形态 (Q7): 调用 run(output, error) —— args = [output, error]，
        返回 dict 时自动 JSON 序列化。

        Raises:
            ValueError: 模块不存在
            ImportError: 模块加载失败
        """
        result = self._run_module(name, args)
        if isinstance(result, str):
            return result  # 模块自身已返回文本(错误/usage)

        if isinstance(result, dict):
            import json
            # deploy 字段是 shell 部署命令,JSON 转义（\"）后无法直接复制
            # 使用——移出 JSON 结构,原样追加在末尾供复制。
            deploy = result.get("deploy")
            if deploy is None and isinstance(result.get("command"), str):
                # socks_server / file_server / protfwd_server 等用顶层 command
                # 承载部署命令:同样移出并在末尾追加可复制段落(与 beacon 生成一致)
                deploy = result.pop("command")
            body = {k: v for k, v in result.items() if k != "deploy"}
            text = json.dumps(body, indent=2, ensure_ascii=False)
            if deploy is not None:
                text += "\n\n部署命令（可直接复制）:\n" + str(deploy)
            return text
        return str(result) if result is not None else ""

    def run_structured(self, name: str, args: list):
        """执行模块 run(*args) 并原样返回结果（dict 不序列化）。

        供桥接层(c2_bridge.build_deploy 等)结构化消费 dict 结果——
        run() 会把 dict JSON 序列化成文本,结构化调用方无法还原字段。

        Raises:
            ValueError: 模块不存在
            ImportError: 模块加载失败
        """
        result = self._run_module(name, args)
        if isinstance(result, str):
            return {"status": "error", "message": result}
        return result

    def _run_module(self, name: str, args: list):
        """加载并执行模块 run(*args)，返回原始结果（run/run_structured 共用）。"""
        path = self._dir / f"{name}.py"
        if not path.is_file():
            raise ValueError(f"server module not found: {name}")

        try:
            mod = self._load_module(name, path)
        except Exception as e:
            logger.error("server module %s import failed: %s", name, e)
            raise ImportError(f"failed to import {name}: {e}") from e

        if not hasattr(mod, "run"):
            return f"[!] module '{name}' has no run() function"

        try:
            return mod.run(*args)
        except TypeError as e:
            logger.warning("server module %s run TypeError: %s", name, e)
            return f"[!] {name}: {e}"
        except Exception:
            import traceback
            tb = traceback.format_exc()
            logger.error("server module %s run failed:\n%s", name, tb)
            return tb

    # ── 内部 ──

    @staticmethod
    def _load_module(name: str, path: Path):
        """按文件路径加载模块（每次执行重新加载 = 热加载）。

        不使用 importlib.import_module：避免 sys.path 包名解析与
        真实 s_modules 包的缓存冲突；spec 方式天然支持任意目录。
        """
        mod_name = f"s_modules.{name}"
        spec = importlib.util.spec_from_file_location(mod_name, str(path))
        if spec is None or spec.loader is None:
            raise ImportError(f"failed to create module spec for {name}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception:
            sys.modules.pop(mod_name, None)
            raise
        return mod

    def _read_meta(self, path: Path) -> dict:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return {}
        return module_meta.parse_meta(content)
