"""
@module: upload_parse
@desc: upload 结果处理器:上一块写完后再下发下一块(串行,防同批并发 append 写坏文件)

处理器形态: run(output, error="", arg="", disp=None, bid="")
  - arg: JSON 串 {"bid","local","remote","chunk","total"}(本地文件路径 + 进度)
  - disp/bid: 续传下一块所需(beacon.py 传入)
"""
import base64
import json

MODULE = {
    "desc": "upload 结果处理器(串行续传)",
    "params": [],
}

_CHUNK = 180 * 1024  # 与 engine/commands/upload.py 保持一致


def run(output, error="", arg="", disp=None, bid=""):
    try:
        st = json.loads(arg or "{}")
    except (ValueError, TypeError):
        return "{}"
    if not isinstance(st, dict):
        return "{}"
    local = str(st.get("local") or "")
    remote = str(st.get("remote") or "")
    total = int(st.get("total") or 0)
    idx = int(st.get("chunk") or 0)
    bid2 = str(st.get("bid") or bid or "")

    # 失败判定:error 通道,或植入物 upload 模块返回的 "(error: ...)" 文本
    fail = error or (output.strip() if output.strip().startswith("(error") else "")
    if fail:
        return json.dumps({"ul_error": f"第 {idx + 1}/{total} 块写入失败: {fail[:200]}"})
    if disp is None or not bid2 or not local:
        return "{}"

    nxt = idx + 1
    try:
        with open(local, "rb") as f:
            f.seek(nxt * _CHUNK)
            data = f.read(_CHUNK)
    except OSError as e:
        return json.dumps({"ul_error": f"续传读取本地文件失败: {e}"})
    if not data:
        # 已读完(或文件长度与块数不一致)→ 视为完成,清掉上一次的失败原因
        return json.dumps({"ul_error": ""})

    try:
        task = disp.build_task("upload",
                               [remote, base64.b64encode(data).decode("ascii"), "1"])
    except ValueError as e:
        return json.dumps({"ul_error": f"续传构建失败: {e}"})
    if task is None:
        return json.dumps({"ul_error": "续传失败: upload 模块缺失"})
    task.result_processor = "upload_parse"
    task.proc_arg = json.dumps(
        {"bid": bid2, "local": local, "remote": remote,
         "chunk": nxt, "total": total}, ensure_ascii=False)
    msg = disp.push_task(bid2, task)
    if isinstance(msg, str) and msg.startswith("[!]"):
        return json.dumps({"ul_error": f"队列已满,上传中断于第 {nxt + 1}/{total} 块"})
    return "{}"
