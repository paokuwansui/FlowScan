"""
@module: download_parse
@desc: download 结果处理器：写本地分块文件 + 自动下发下一块

处理器形态: run(output, error, arg="", disp=None, bid="")
  - arg: 本地落盘路径（Task.proc_arg）
  - disp/bid: 自动续传下一块所需（beacon.py 传入）
"""
import base64
import json
import os

MODULE = {
    "desc": "download 结果处理器（写块+自动续传）",
    "params": [],
}


def run(output, error="", arg="", disp=None, bid=""):
    """写块到 arg，未完成则下发下一块任务。返回 {}（无元数据回填）。"""
    try:
        data = json.loads(output)
    except (ValueError, TypeError):
        return "{}"
    if not isinstance(data, dict):
        return "{}"
    if "error" in data:
        return json.dumps({"dl_error": data["error"]})

    chunk = data.get("chunk", 0)
    total = data.get("total", 1)
    path = data.get("path", "")
    local = arg
    try:
        if data.get("data"):
            raw = base64.b64decode(data["data"])
            mode = "ab" if chunk > 0 else "wb"
            with open(local, mode) as f:
                f.write(raw)
    except Exception as e:
        return json.dumps({"dl_error": str(e)})

    if chunk + 1 < total and disp is not None and bid:
        try:
            task = disp.build_task("download", [path, str(chunk + 1)])
            if task is not None:
                task.result_processor = "download_parse"
                task.proc_arg = local
                disp.push_task(bid, task)
        except Exception:
            pass
    return "{}"


if __name__ == "__main__":
    print(run('{"chunk": 0, "total": 1, "data": "aGk=", "path": "/x"}'))
