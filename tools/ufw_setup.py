#!/usr/bin/env python3
"""
FlowScan 防火墙管理 —— init 封死 + 累加白名单(宿主机 + docker 双链同步,仅 TCP)

用法:
    python3 ufw_setup.py init                                    # 仅 22/tcp 任意 IP 可达,其余端口全部封死
    python3 ufw_setup.py -p 65500,65501                          # 放行这些端口(全来源;不写 -i = 全网)
    python3 ufw_setup.py -i 192.168.0.5 -p 65500,65501           # 仅该 IP 可访问(可多次执行,累加不失效)
    python3 ufw_setup.py -i 192.168.0.1-10 -p 65530-65535        # IP 段 / 端口范围
    python3 ufw_setup.py -i 192.168.0.0/24 -p 65500              # CIDR
    python3 ufw_setup.py -i 192.168.0.1,192.168.0.2 -p 65535,65534  # 多 IP / 多端口
    python3 ufw_setup.py status                                  # 查看双链规则

规则说明:
- 只放行 TCP(udp 不放行)
- 宿主机进程流量走 UFW INPUT 链;docker 发布端口流量走 iptables DOCKER-USER 链,两条链同步
- 规则状态保存在 <项目>/tools/flowscan-firewall.json,重复执行累加,init 重置
- 所有命令需要 root(sudo 前缀)
"""

import argparse
import ipaddress
import json
import os
import subprocess

# 状态文件默认写项目 tools 目录(与脚本同目录)
STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flowscan-firewall.json")


def run(cmd, check=True):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip()
        if check and r.returncode != 0 and out:
            print(f"  [!] {out}")
        return r.returncode == 0, out
    except Exception as e:
        return False, str(e)


# ══════════════════════════ 解析器 ══════════════════════════

def parse_ips(raw):
    """-i 解析:单 IP / 逗号多 IP / a.b.c.d-m 段 / CIDR。段压缩为 CIDR 集合返回。"""
    out = []
    for part in str(raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            ipaddress.ip_network(part, strict=False)   # 校验
            out.append(part)
        elif "-" in part:
            base, _, end = part.rpartition("-")
            if not base or not end:
                raise ValueError(f"非法 IP 段: {part}")
            start = ipaddress.ip_address(base)
            if "." not in end:
                end_ip = ipaddress.ip_address(base.rsplit(".", 1)[0] + "." + end)
            else:
                end_ip = ipaddress.ip_address(end)
            if int(end_ip) < int(start):
                raise ValueError(f"段起点大于终点: {part}")
            for net in ipaddress.summarize_address_range(start, end_ip):
                out.append(str(net))
        else:
            ipaddress.ip_address(part)                 # 校验
            out.append(part)
    return out


def parse_ports(raw):
    """-p 解析:单端口 / 逗号多端口 / a-b 范围 → ['a'] 或 ['a:b']。"""
    out = []
    for part in str(raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            lo, hi = int(a), int(b)
            if not (0 < lo <= hi <= 65535):
                raise ValueError(f"非法端口范围: {part}")
            out.append(f"{lo}:{hi}")
        else:
            p = int(part)
            if not (0 < p <= 65535):
                raise ValueError(f"非法端口: {part}")
            out.append(str(p))
    return out


# ══════════════════════════ 状态文件 ══════════════════════════

def load_state():
    if not os.path.exists(STATE_PATH):
        return {"rules": []}
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"rules": []}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def merge_rules(state, ips, ports):
    """ips×ports 笛卡尔积去重合并;ips=None 表示全来源(规则 ip='any')。"""
    existing = {(r["ip"], r["port"]) for r in state["rules"]}
    for port in ports:
        if ips is None:
            key = ("any", port)
            if key not in existing:
                state["rules"].append({"ip": "any", "port": port})
                existing.add(key)
        else:
            for ip in ips:
                key = (ip, port)
                if key not in existing:
                    state["rules"].append({"ip": ip, "port": port})
                    existing.add(key)
    return state


# ══════════════════════════ UFW 侧(宿主机入站)══════════════════════════

def ufw_available():
    ok, out = run("which ufw", check=False)
    return ok and out.strip()


def ufw_clear_all_except_ssh():
    """删除 ufw 全部应用规则,仅保留 22/tcp(IPv4+IPv6)。

    枚举 `ufw status numbered` 解析规则行,非 22/tcp 的一律删除(编号从大到小,
    避免删除后编号移位)。default deny incoming 兜底,删除间隙不暴露端口。
    """
    _, out = run("sudo ufw status numbered", check=False)
    to_delete = []
    for line in out.splitlines():
        line = line.strip()
        # 形如: [ 1] 22/tcp ALLOW IN Anywhere
        if not line.startswith("["):
            continue
        try:
            num = int(line.split("]")[0].strip("[").strip())
            spec = line.split("]", 1)[1].strip()
        except (ValueError, IndexError):
            continue
        # 22/tcp 及其 v6 形式保留,其余全部删除
        if spec.startswith("22/tcp"):
            continue
        to_delete.append((num, spec))
    for num, spec in sorted(to_delete, reverse=True):
        run(f"sudo ufw --force delete {num}", check=False)
        print(f"  [ufw] 删除残留规则 #{num}: {spec}")


def ufw_init():
    """封死:默认拒绝入站 + 只放行 22;清空其余全部规则(含历史残留)。

    顺序关键:先 allow 22 再 enable(启用瞬间规则文件已含 22,SSH 不断);
    再删非 22 规则 + default deny incoming 兜底。
    """
    run("sudo ufw allow 22/tcp")                 # 先写规则(未启用时仅改配置文件)
    run("sudo ufw --force enable")               # 启用时加载规则,22 已在白名单
    run("sudo ufw default deny incoming")
    run("sudo ufw default allow routed")         # 容器网络必须;限制交给 DOCKER-USER
    ufw_clear_all_except_ssh()                   # 删干净(含状态文件之外的历史残留)
    for rule in load_state()["rules"]:
        ip, port = rule["ip"], rule["port"]
        if ip == "any":
            run(f"sudo ufw delete allow {port}/tcp", check=False)
        else:
            run(f"sudo ufw delete allow from {ip} to any port {port} proto tcp", check=False)


def ufw_allow_rule(ip, port):
    """增量放行(TCP)。ip='any' 表示全来源;port 为 'a' 或 'a:b'。"""
    if ip == "any":
        run(f"sudo ufw allow {port}/tcp")
    else:
        run(f"sudo ufw allow from {ip} to any port {port} proto tcp")


# ══════════════════════════ DOCKER-USER 侧(容器入站)══════════════════════════

def docker_chain_exists():
    ok, out = run("sudo iptables -L DOCKER-USER -n", check=False)
    return ok and "DOCKER-USER" in out


def docker_init():
    """清空 DOCKER-USER 并加兜底:容器流量默认全拒(仅新连接)。

    关键:DROP 兜底只匹配 NEW(新连接),ESTABLISHED/RELATED 一律放行——
    否则容器回程包(SYN-ACK,源=容器 IP)不匹配入站白名单,会被 DROP all
    双向掐死,表现为"SYN 能进、应答出不来"(2026-08 云端实测 timeout)。
    顺序:ESTABLISHED ACCEPT → NEW DROP 兜底(白名单 ACCEPT 由 docker_allow 插在最前)。
    """
    if not docker_chain_exists():
        print("  [!] DOCKER-USER 链不存在(docker 未运行),跳过 docker 侧封死")
        return
    run("sudo iptables -F DOCKER-USER")
    run("sudo iptables -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    run("sudo iptables -A DOCKER-USER -m conntrack --ctstate NEW -j DROP")


def docker_allow(ip, port):
    """单条白名单 TCP:ACCEPT 插在 DROP 兜底之前。ip='any' 不带 -s。

    port 表示:单值 'a' → --dport a;范围 'a:b' → --dport a:b;
    多值用逗号(调用方先按逗号拆成单值逐条添加,避免 --dports 兼容性问题)。
    """
    if not docker_chain_exists():
        print(f"  [!] DOCKER-USER 链不存在,跳过 docker 端口 {port} 放行")
        return
    port_opt = f"--dport {port}"
    src = f"-s {ip} " if ip != "any" else ""
    run(f"sudo iptables -I DOCKER-USER -p tcp {src}{port_opt} -j ACCEPT")


def docker_replay(state):
    """全量重建:flush → 兜底 DROP → 按状态文件插 ACCEPT(ACCEPT 排在 DROP 前)。"""
    docker_init()
    for rule in state["rules"]:
        docker_allow(rule["ip"], rule["port"])


# ══════════════════════════ 展示 ══════════════════════════

def show_status():
    print("=== UFW(宿主机入站)===")
    _, out = run("sudo ufw status verbose", check=False)
    print(out)
    print("=== Docker DOCKER-USER(容器入站)===")
    if docker_chain_exists():
        _, out = run("sudo iptables -L DOCKER-USER -n --line-numbers", check=False)
        print(out)
    else:
        print("(DOCKER-USER 链不存在,docker 未运行)")
    state = load_state()
    if state["rules"]:
        print(f"=== 状态文件 {STATE_PATH}({len(state['rules'])} 条)===")
        for r in state["rules"]:
            print(f"  {r['ip']} -> :{r['port']}/tcp")


# ══════════════════════════ 主流程 ══════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="FlowScan 防火墙:init 封死 + 累加白名单(宿主机+docker 双链,仅 TCP)")
    parser.add_argument("action", nargs="?", default="",
                        choices=["", "init", "status"],
                        help="init=仅 22 可达其余封死 / status=查看规则(默认空=提示用法)")
    parser.add_argument("-i", "--ip", default=None,
                        help="来源 IP:单IP/逗号多IP/CIDR/段(如 192.168.0.1-10);省略=全来源")
    parser.add_argument("-p", "--port", default=None,
                        help="端口:单端口/逗号多端口/范围(如 65530-65535)")
    args = parser.parse_args()

    if not args.action and not args.port:
        parser.print_help()
        return 0
    if not ufw_available():
        print("UFW 未安装: sudo apt install ufw -y")
        return 1

    if args.action == "status":
        show_status()
        return 0

    if args.action == "init":
        save_state({"rules": []})
        print("=== init:仅 22/tcp 任意 IP 可达,其余端口全部封死(宿主+docker)===")
        ufw_init()
        docker_init()
        show_status()
        return 0

    # -p(可带 -i):累加添加
    ports = parse_ports(args.port)
    ips = parse_ips(args.ip) if args.ip else None     # None = 全来源
    state = load_state()
    before = len(state["rules"])
    state = merge_rules(state, ips, ports)
    added = len(state["rules"]) - before
    save_state(state)
    scope = "全来源" if ips is None else ", ".join(ips)
    print(f"=== 添加 {added} 条规则(现有 {len(state['rules'])} 条,来源: {scope})===")
    for rule in state["rules"]:
        print(f"  {rule['ip']} -> :{rule['port']}/tcp")
    for rule in state["rules"]:
        ufw_allow_rule(rule["ip"], rule["port"])
    docker_replay(state)
    show_status()
    return 0


if __name__ == "__main__":
    main()
