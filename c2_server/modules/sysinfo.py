"""
@module: sysinfo
@desc: 收集用户与系统信息
@result: sysinfo_parse 处理器回填注册表 (Q7)
"""
import getpass
import json
import platform

MODULE = {
    "desc": "收集用户与系统信息",
    "params": [],
    "result_processor": "sysinfo_parse",
}


def run():
    """输出 JSON: {"user": ..., "os": ...}，由 sysinfo_parse 处理器解析回填。"""
    return json.dumps({"user": getpass.getuser(),
                       "os": platform.platform()})


if __name__ == "__main__":
    print(run())
