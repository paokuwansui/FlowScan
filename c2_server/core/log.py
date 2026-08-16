"""
core/log.py — 统一运行日志 (10.3)

与事件文件职责分离:
  - 运行日志 (本模块): 排障用——连接、帧错误、模块加载失败、异常 traceback
  - 事件文件 (server/infra/event_writer.py): 业务审计 + 多 UI 事件流

交互模式输出 stderr；headless 输出文件。
"""

import logging
import sys

_FMT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"


def setup_logging(level=logging.INFO, file=None):
    """初始化根日志。

    Args:
        level: logging 级别（DEBUG/INFO/WARNING/ERROR）
        file: 输出文件路径；None 时输出到 stderr

    Returns:
        root logger
    """
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = (logging.FileHandler(file, encoding="utf-8")
               if file else logging.StreamHandler(sys.stderr))
    handler.setFormatter(logging.Formatter(_FMT))
    root.addHandler(handler)
    return root


def get_logger(name: str) -> logging.Logger:
    """获取模块级 logger（配合 setup_logging 使用）。"""
    return logging.getLogger(name)
