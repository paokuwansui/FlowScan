#!/usr/bin/env python3
import argparse
import os
import sys
import time

from flowscan.config import load_yaml
from flowscan.redis_store import FlowScanRedis
from flowscan.worker import Worker, run_forever


def make_redis_client(config: dict, args) -> FlowScanRedis:
    """创建 redis 客户端(redis-py 懒连接,此处不真正连接;连接由 ping 触发)。"""
    redis_cfg = config.get("redis", {}) or {}
    host = args.redis_host or redis_cfg.get("redis_host", "127.0.0.1")
    port = args.redis_port or int(redis_cfg.get("redis_port", 6379))
    password = args.redis_password or redis_cfg.get("password", "")
    db = int(redis_cfg.get("db", 0))
    return FlowScanRedis(host=host, port=port, password=password, db=db)


def connect_redis_with_retry(config_path: str, args, delay: int = 10) -> FlowScanRedis:
    """连接主节点 redis,失败每 delay 秒重读 config 重建连接重试直到连上。

    重读 config 是为了拿到可能被 randomize_secrets 更新过的密码;
    CLI 参数优先级高于 config,但空值回退 config(见 make_redis_client)。
    """
    while True:
        cfg = load_yaml(config_path)
        client = make_redis_client(cfg, args)
        try:
            client.ping()
            print("[WORKER] redis connected")
            return client
        except Exception as exc:
            print(f"[WORKER] redis not reachable ({exc}), re-reading config in {delay}s...")
            time.sleep(delay)


def main() -> int:
    parser = argparse.ArgumentParser(description="FlowScan Redis event driven scanner")
    parser.add_argument("mode", choices=["worker", "status", "web"], help="运行模式")
    parser.add_argument("--config", default="config.yaml", help="主配置文件")
    parser.add_argument("--modules-dir", default="modules", help="模块目录")
    parser.add_argument("--redis-host", default=None)
    parser.add_argument("--redis-port", type=int, default=None)
    parser.add_argument("--redis-password", default=None)
    parser.add_argument("--node-id", default=None)
    parser.add_argument("--pool-size", type=int, default=20)
    parser.add_argument("--event-type", default="DOMAIN", help="worker 模式启动时注入的事件类型")
    parser.add_argument("--value", default="", help="worker 模式启动时注入的事件值")
    parser.add_argument("--host", default=None, help="web 模式监听地址")
    parser.add_argument("--port", type=int, default=None, help="web 模式监听端口")
    parser.add_argument("--debug", action="store_true", help="web 模式开启 Flask debug / worker 模式记录完整命令输出到日志")
    args = parser.parse_args()

    project_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_dir)
    config = load_yaml(args.config)

    if args.mode == "web":
        from web_app import DEFAULT_WEB_CONFIG, create_app

        web_cfg = {**DEFAULT_WEB_CONFIG, **(config.get("web_config", {}) or {})}
        host = args.host or web_cfg["host"]
        port = args.port or int(web_cfg["port"])
        app = create_app(args.config, args.modules_dir)
        print(f"[WEB] FlowScan Web Panel starting on http://{host}:{port}")
        print(f"[WEB] Login: {web_cfg['username']} (密码见 {args.config} 的 web_config.password)")
        app.run(host=host, port=port, debug=args.debug)
        return 0

    if args.mode == "status":
        redis_client = make_redis_client(config, args)
        redis_client.ping()
        print("[STATUS] events:", redis_client.conn.scard("fs3:event:all"))
        print("[STATUS] tools:", redis_client.conn.hlen("fs3:tools"))
        print("[STATUS] nodes:", redis_client.conn.smembers("fs3:nodes"))
        for line in redis_client.conn.lrange("fs3:logs", 0, 20):
            print(line)
        return 0

    if args.mode == "worker":
        # 1. 创建 redis 客户端(懒连接,尚未探测)
        redis_client = make_redis_client(config, args)
        # 2. 创建 Worker + 先装工具(不依赖 redis 连接)
        worker = Worker(config, args.modules_dir, redis_client, node_id=args.node_id, pool_size=args.pool_size, debug=args.debug)
        worker.install_tools()
        if not worker.tools:
            print(f"[{worker.node_id}] no runnable tools, exiting")
            return 1
        # 3. 探测主节点存活 + 连接(重读 config 重试直到连上)
        worker.redis = connect_redis_with_retry(args.config, args)
        if args.value:
            worker.inject(args.event_type, args.value)
        # 4. 注册工具 + 领活循环
        run_forever(worker)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
