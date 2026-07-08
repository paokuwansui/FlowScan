#!/usr/bin/env python3
import argparse
import os
import sys

from flowscan3.config import load_yaml
from flowscan3.installer import init_all
from flowscan3.redis_store import FlowScanRedis
from flowscan3.worker import Worker, run_forever


def connect_redis(config: dict, args) -> FlowScanRedis:
    redis_cfg = config.get("redis", {}) or {}
    host = args.redis_host or redis_cfg.get("remote_host", "127.0.0.1")
    port = args.redis_port or int(redis_cfg.get("port", 6379))
    password = args.redis_password if args.redis_password is not None else redis_cfg.get("password", "")
    db = int(redis_cfg.get("db", 0))
    client = FlowScanRedis(host=host, port=port, password=password, db=db)
    client.ping()
    return client


def main() -> int:
    parser = argparse.ArgumentParser(description="FlowScan3 Redis event driven scanner")
    parser.add_argument("mode", choices=["init", "worker", "inject", "status", "web"], help="运行模式")
    parser.add_argument("--config", default="config.yaml", help="主配置文件")
    parser.add_argument("--modules-dir", default="modules", help="模块目录")
    parser.add_argument("--redis-host", default=None)
    parser.add_argument("--redis-port", type=int, default=None)
    parser.add_argument("--redis-password", default=None)
    parser.add_argument("--node-id", default=None)
    parser.add_argument("--pool-size", type=int, default=20)
    parser.add_argument("--event-type", default="DOMAIN", help="inject 模式事件类型")
    parser.add_argument("--value", default="", help="inject 模式事件值")
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
        print(f"[WEB] FlowScan3 Web Panel starting on http://{host}:{port}")
        print(f"[WEB] Login: {web_cfg['username']} / {web_cfg['password']} (configured in {args.config})")
        app.run(host=host, port=port, debug=args.debug)
        return 0

    if args.mode == "init":
        result = init_all(args.modules_dir, config, None)
        ready = sum(1 for ok in result.values() if ok)
        print(f"[INIT] ready {ready}/{len(result)}")
        for name, ok in result.items():
            print(f"  {name}: {'READY' if ok else 'NOT_READY'}")
        return 0 if ready == len(result) else 1

    redis_client = connect_redis(config, args)

    if args.mode == "inject":
        if not args.value:
            print("inject requires --value")
            return 2
        fp = redis_client.push_event(args.event_type, args.value, source_tool="manual")
        print(f"[INJECT] {args.event_type}={args.value} fp={fp}")
        return 0

    if args.mode == "status":
        print("[STATUS] events:", redis_client.conn.scard("fs3:event:all"))
        print("[STATUS] tools:", redis_client.conn.hlen("fs3:tools"))
        print("[STATUS] nodes:", redis_client.conn.smembers("fs3:nodes"))
        for line in redis_client.conn.lrange("fs3:logs", 0, 20):
            print(line)
        return 0

    if args.mode == "worker":
        worker = Worker(config, args.modules_dir, redis_client, node_id=args.node_id, pool_size=args.pool_size, debug=args.debug)
        if args.value:
            worker.inject(args.event_type, args.value)
        run_forever(worker)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
