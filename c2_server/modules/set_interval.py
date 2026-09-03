"""
@module: set_interval
@desc: 修改 Beacon 回连间隔和抖动
@contract: 用 globals() 字符串键 _I/_J 读写——minify 后模块与模板独立池化,
直接 global _I 写入的是模块短名键, 模板 sleep_jitter 读不到(多线程 exec
在同一共享全局 dict, 但键名已不一致); 字符串键不受压缩影响(D2)
"""
MODULE = {
    "desc": "修改 Beacon 回连间隔和抖动",
    "params": [("interval", "必填，秒"), ("jitter", "默认 0.2")],
}


def run(interval, jitter=0.2):
    globals()["_I"] = int(interval)
    globals()["_J"] = float(jitter)
    return "interval=%ds, jitter=%s" % (globals().get("_I", 0),
                                        globals().get("_J", 0))


if __name__ == "__main__":
    print("usage: set_interval <seconds> [jitter]")
