#!/usr/bin/env python3
"""
Quick UFW firewall setup + Docker 发布端口 IP 限制。

背景:Docker 发布端口(-p 8080:8080)的流量走 iptables FORWARD/DOCKER 链,
不经过 UFW 管理的 INPUT 链——ufw allow from <ip> 对 docker 端口无效。
正确解法:Docker 官方保留的 DOCKER-USER 链(FORWARD 链最前、专供用户自定义、
docker 不会清理),对它插入"仅允许指定 IP + 其余拒绝"的规则。

Usage:
    python3 ufw_setup.py                                # ensure SSH open + enable UFW
    python3 ufw_setup.py -p 6379,8080                   # allow any IP to ports(仅 ufw,不限制 docker)
    python3 ufw_setup.py -p 8080 -i 1.2.3.4,5.6.7.8     # 只允许这些 IP 访问 8080
                                                        #   → ufw INPUT 规则 + Docker DOCKER-USER 链限制
    python3 ufw_setup.py status                         # UFW 状态 + Docker 限制规则
    python3 ufw_setup.py docker-status                  # 查看 DOCKER-USER 链规则
    python3 ufw_setup.py docker-clear                   # 清空全部 DOCKER-USER 限制(恢复 docker 默认开放)
    python3 ufw_setup.py docker-save                    # 持久化 iptables 规则(rules.v4,重启保留)
"""

import argparse
import subprocess
import sys


def run(cmd, check=True):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip()
        if check and r.returncode != 0 and out:
            print(f"  [!] {out}")
        return r.returncode == 0, out
    except Exception as e:
        return False, str(e)


# ══════════════════════════ UFW 部分 ══════════════════════════

def ufw_installed():
    _, out = run("which ufw", check=False)
    return bool(out and "ufw" in out)


def ufw_enabled():
    _, out = run("sudo ufw status", check=False)
    return "Status: active" in out


def ssh_open_to_any():
    """Check if port 22/tcp is allowed from anywhere."""
    _, out = run("sudo ufw status numbered", check=False)
    for line in out.splitlines():
        if "22/tcp" in line and "ALLOW" in line and ("Anywhere" in line or "0.0.0.0" in line):
            return True
    return False


def ensure_ssh():
    if ssh_open_to_any():
        print("  SSH (22/tcp) already open to anywhere — skip")
        return
    print("  Adding SSH (22/tcp) allow from anywhere...")
    run("sudo ufw allow 22/tcp")


def allow_port(port, ip=None):
    """Allow tcp+udp on port, optionally restricted to ip(UFW INPUT 链,本地/常规进程用)。"""
    for proto in ("tcp", "udp"):
        if ip:
            rule = f"sudo ufw allow from {ip} to any port {port} proto {proto}"
            print(f"  Allow {ip} -> :{port}/{proto}")
        else:
            rule = f"sudo ufw allow {port}/{proto}"
            print(f"  Allow any -> :{port}/{proto}")
        run(rule)


def enable_ufw():
    if ufw_enabled():
        print("  UFW already enabled — skip")
    else:
        print("  Enabling UFW...")
        # Use --force to avoid interactive prompt
        run("sudo ufw --force enable")
    # ⚠️ Docker 关键:UFW 默认 FORWARD 策略是 DROP,启用后会掐断 docker 容器网络
    # (docker 发布的端口流量走 FORWARD 链)。必须放行路由流量,再靠 DOCKER-USER 链做限制。
    ok, out = run("sudo ufw default allow routed", check=False)
    if not ok:
        print("  [!] 'ufw default allow routed' 失败,容器网络可能被 ufw 掐断: " + out[:200])
    else:
        print("  UFW routed 策略: allow(docker 容器流量放行,限制交给 DOCKER-USER 链)")


def show_status():
    _, out = run("sudo ufw status verbose", check=False)
    print(out)


# ══════════════════════════ Docker DOCKER-USER 部分 ══════════════════════════

def docker_chain_exists():
    """DOCKER-USER 链存在 = docker daemon 运行中(该链由 docker 创建)。"""
    ok, out = run("sudo iptables -L DOCKER-USER -n", check=False)
    return ok and "DOCKER-USER" in out


def docker_limit_port(port, ips, proto="tcp"):
    """只允许 ips 访问 docker 发布的 port,其余 IP 一律拒绝。

    规则写在 DOCKER-USER 链(FORWARD 最前,先于 DOCKER 链评估):
      - 先清掉该端口的旧规则(幂等)
      - 按序插入:先插 DROP,再逐个插 ACCEPT(-I 插链首,ACCEPT 最终排在 DROP 之前)
    顺序结果:ACCEPT(允许IP)... ACCEPT DROP → 指定 IP 放行,其余落到 DROP。
    """
    if not docker_chain_exists():
        print(f"  [!] DOCKER-USER 链不存在(docker 未运行?),跳过 docker 端口 {port} 限制")
        return False
    # 清理旧规则(忽略不存在)
    run(f"sudo iptables -D DOCKER-USER -p {proto} --dport {port} -j DROP", check=False)
    for ip in ips:
        run(f"sudo iptables -D DOCKER-USER -p {proto} --dport {port} -s {ip} -j ACCEPT", check=False)
    # 先 DROP 后 ACCEPT(-I 插链首,后插的 ACCEPT 排在前面)
    run(f"sudo iptables -I DOCKER-USER -p {proto} --dport {port} -j DROP")
    for ip in ips:
        run(f"sudo iptables -I DOCKER-USER -p {proto} --dport {port} -s {ip} -j ACCEPT")
    print(f"  [docker] 端口 {port}/{proto}: 仅允许 {' '.join(ips)} 访问,其余拒绝(DOCKER-USER 链)")
    return True


def docker_clear():
    """清空 DOCKER-USER 链(恢复 docker 默认开放行为)。"""
    if not docker_chain_exists():
        print("  DOCKER-USER 链不存在(docker 未运行?)")
        return
    run("sudo iptables -F DOCKER-USER")
    print("  DOCKER-USER 链已清空(docker 端口恢复默认开放)")


def docker_status():
    if not docker_chain_exists():
        print("DOCKER-USER 链不存在(docker 未运行)")
        return
    ok, out = run("sudo iptables -L DOCKER-USER -n --line-numbers", check=False)
    print(out if ok else "(读取失败)")


def docker_save():
    """持久化 iptables 规则(DOCKER-USER 限制在重启后保留)。"""
    ok, out = run("sudo mkdir -p /etc/iptables && sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null", check=False)
    if ok:
        print("  iptables 规则已保存到 /etc/iptables/rules.v4")
        print("  提示:安装 iptables-persistent 可开机自动恢复(sudo apt install -y iptables-persistent)")
    else:
        print("  [!] 保存失败: " + out[:200])


def main():
    parser = argparse.ArgumentParser(description="UFW firewall + Docker 端口 IP 限制 setup")
    parser.add_argument("-i", "--ip",   default=None, help="来源 IP,逗号分隔多个,如: 10.0.0.1,10.0.0.2")
    parser.add_argument("-p", "--port", default=None, help="开放端口,逗号分隔多个,如: 6379,8080")
    parser.add_argument("--proto", default="tcp", choices=["tcp", "udp"],
                        help="docker 限制的协议,默认 tcp")
    parser.add_argument("command", nargs="?", default="setup",
                        choices=["setup", "status", "docker-status", "docker-clear", "docker-save"],
                        help="Action: setup (default) / status / docker-status / docker-clear / docker-save")
    args = parser.parse_args()

    if args.command == "status":
        show_status()
        print()
        print("=== Docker DOCKER-USER 限制规则 ===")
        docker_status()
        return

    if args.command == "docker-status":
        docker_status()
        return
    if args.command == "docker-clear":
        docker_clear()
        return
    if args.command == "docker-save":
        docker_save()
        return

    # ── setup ──
    if not ufw_installed():
        print("UFW not installed. Run: sudo apt install ufw -y")
        sys.exit(1)

    ips   = [x.strip() for x in args.ip.split(",") if x.strip()]   if args.ip   else []
    ports = [x.strip() for x in args.port.split(",") if x.strip()] if args.port else []

    print("=== UFW Setup ===")

    ensure_ssh()

    if ports:
        for port in ports:
            if ips:
                for ip in ips:
                    allow_port(port, ip)
            else:
                allow_port(port)

    enable_ufw()

    # Docker 发布端口限制:有 -i 时,受限端口同时写 DOCKER-USER 链(否则 ufw 规则管不到 docker 流量)
    if ports and ips and docker_chain_exists():
        print()
        print("=== Docker 端口限制(DOCKER-USER 链)===")
        for port in ports:
            docker_limit_port(port, ips, proto=args.proto)
    elif ports and ips:
        print("\n  [!] DOCKER-USER 链不存在(docker 未运行):docker 发布的端口暂不受本规则限制")
        print("      docker 启动后重跑本命令即可")

    print()
    show_status()
    print("\nDone.")
    print("提示:docker 发布端口的外部流量限制在 DOCKER-USER 链生效;")
    print("      docker-status 查看 / docker-clear 清空 / docker-save 持久化")


if __name__ == "__main__":
    main()
