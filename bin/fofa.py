#!/usr/bin/env python3
import argparse
import subprocess
import re
import sys
import json
from urllib.parse import urlparse
import tldextract
# 扫描策略配置
QUERY_POLICIES = {
    "DNS_NAME": {"limit": 1000, "mode": "truncate"},    # 域名或子域名查询事件
    "URL_UNVERIFIED": {"limit": 500, "mode": "truncate"},          # URL 查询事件
    "IP_RANGE": {"limit": 500, "mode": "truncate"},     # IP 段查询事件
    "ICON_PATH": {"limit": 300, "mode": "drop_all"},    # 图标 Hash / favicon 匹配事件
    "IP_ADDRESS": {"limit": 300, "mode": "drop_all"},   # 单个 IP 查询事件
    "CERT": {"limit": 300, "mode": "drop_all"}          # 证书查询事件
}

# 默认回退策略
DEFAULT_POLICY = {"limit": 100, "mode": "truncate"}

# 基础正则定义
IP_BASE_PATTERN = r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
IP_ADDRESS_RE = re.compile(r"^" + IP_BASE_PATTERN + r"$")
IP_RANGE_RE = re.compile(r"^" + IP_BASE_PATTERN + r"/(?:3[0-2]|[1-2]?\d)$")
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")

# 用于从任意文本中挖出纯 IP
IP_GLOBAL_EXTRACT_RE = re.compile(IP_BASE_PATTERN)

def is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

def looks_like_icon_url(value: str) -> bool:
    if not is_url(value):
        return False
    parsed = urlparse(value)
    path = parsed.path.lower()
    return any(token in path for token in ("favicon", "icon")) or path.endswith((".ico", ".png", ".jpg", ".jpeg", ".svg", ".webp"))

def strip_port(host: str) -> str:
    host = host.strip().strip("[]")
    if ":" in host and host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host

def generate_url_climb_steps(url_str: str) -> list[str]:
    """将单个 URL 逐级爬升生成目录序列"""
    if not is_url(url_str):
        return [url_str]
    parsed = urlparse(url_str)
    base_scheme_netloc = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.split("/") if p]
    
    steps = []
    steps.append(url_str)
    while path_parts:
        path_parts.pop()
        sub_path = "/".join(path_parts)
        if sub_path:
            steps.append(f"{base_scheme_netloc}/{sub_path}/")
        else:
            steps.append(f"{base_scheme_netloc}/")
            
    unique_steps = []
    for step in steps:
        if step not in unique_steps:
            unique_steps.append(step)
    return unique_steps

def generate_domain_climb_steps(domain_str: str) -> list[str]:
    """
    使用 tldextract 支持复杂双后缀的域名逐级向右爬升。
    例如: www.abc.baidu.com.cn -> ['www.abc.baidu.com.cn', 'abc.baidu.com.cn', 'baidu.com.cn']
    """
    if not DOMAIN_RE.match(domain_str):
        return [domain_str]
        
    ext = tldextract.extract(domain_str)
    
    main_domain = ext.domain
    suffix = ext.suffix
    
    # 如果无法有效解析出核心域名或后缀，则不进行爬升
    if not main_domain or not suffix:
        return [domain_str]
        
    # 锁定根域名 (如 baidu.com.cn)
    root_domain = f"{main_domain}.{suffix}"
    
    steps = []
    # 仅对 subdomain (子域名) 部分进行分割和逐级剥离
    if ext.subdomain:
        sub_parts = ext.subdomain.split(".")
        while sub_parts:
            current_sub = ".".join(sub_parts)
            steps.append(f"{current_sub}.{root_domain}")
            sub_parts.pop(0)
            
    steps.append(root_domain)
    return steps

def extract_assets_by_policy(text: str) -> dict[str, list[str]]:
    """
    输入一串字符串，将逗号替换为换行，按行切分。
    支持 URL 逐级爬升爆破，并对每个片段进行多维度独立抽取。
    """
    result = {
        "DNS_NAME": [],
        "URL_UNVERIFIED": [],
        "ICON_PATH": [],
        "IP_ADDRESS": [],
        "IP_RANGE": []
    }
    seen = {k: set() for k in result.keys()}
    
    normalized_text = text.replace(",", "\n")
    raw_lines = [line.strip().strip("'").strip('"') for line in normalized_text.split("\n")]
    
    all_items = []
    for line in raw_lines:
        if not line:
            continue
        if is_url(line):
            all_items.extend(generate_url_climb_steps(line))
        else:
            all_items.append(line)
            
    for item in all_items:
        # --- 1. URL 判定 ---
        if is_url(item):
            if item not in seen["URL_UNVERIFIED"]:
                seen["URL_UNVERIFIED"].add(item)
                result["URL_UNVERIFIED"].append(item)
                
        # --- 2. ICON_PATH 判定 ---
        if looks_like_icon_url(item):
            if item not in seen["ICON_PATH"]:
                seen["ICON_PATH"].add(item)
                result["ICON_PATH"].append(item)
                
        # --- 3. IP_RANGE 判定 ---
        if IP_RANGE_RE.match(item):
            if item not in seen["IP_RANGE"]:
                seen["IP_RANGE"].add(item)
                result["IP_RANGE"].append(item)
                
        # --- 4. IP_ADDRESS 判定 ---
        if IP_ADDRESS_RE.match(item):
            if item not in seen["IP_ADDRESS"]:
                seen["IP_ADDRESS"].add(item)
                result["IP_ADDRESS"].append(item)
        else:
            ip_matches = IP_GLOBAL_EXTRACT_RE.findall(item)
            for extracted_ip in ip_matches:
                if extracted_ip not in seen["IP_ADDRESS"]:
                    seen["IP_ADDRESS"].add(extracted_ip)
                    result["IP_ADDRESS"].append(extracted_ip)
                    
        # --- 5. DNS_NAME 判定 (包含域名爬升) ---
        target_hosts = []
        host = strip_port(item)
        
        if DOMAIN_RE.match(host):
            target_hosts.append(host)
        elif is_url(item):
            parsed_url = urlparse(item)
            url_host = strip_port(parsed_url.netloc)
            if DOMAIN_RE.match(url_host):
                target_hosts.append(url_host)
                
        # 对识别出的域名进行逐级爬升并去重写入
        for th in target_hosts:
            clived_domains = generate_domain_climb_steps(th)
            for d in clived_domains:
                if d not in seen["DNS_NAME"]:
                    seen["DNS_NAME"].add(d)
                    result["DNS_NAME"].append(d)
                    
    return result

def build_fofax_cmd(fofax_bin: str, event_type: str, value: str, fetch_size: int, fofakey: str = "") -> list[str]:
    """根据不同的事件类型，拼装 fofax 的执行命令选项，显式包含传入的 fofakey"""
    cmd = [fofax_bin]
    
    # 显式使用从函数参数传入的 fofakey
    if fofakey and fofakey.strip():
        cmd.extend(["-key", fofakey.strip()])
        
    # 通用过滤器参数：URL_UNVERIFIED 提取、带 scheme 端口信息
    common_filters = ["-fs", str(fetch_size), "-ffi"]
    
    if event_type == "ICON_PATH":
        # 对应 -iu: 输入 icon 的 URL_UNVERIFIED 自动计算 hash 并查询
        cmd.extend(["-iu", value] + common_filters)
        
    elif event_type == "URL_UNVERIFIED":
        # 【根据FOFA官方API文档修正】：全面废弃 link= 改为合法的原生搜索核心 host= 语法
        # 通过简单清洗剥离协议和尾部路径，保留最高效的主机资产段
        cleaned_host = value.strip()
        cleaned_host = re.sub(r"^https?://", "", cleaned_host, flags=re.IGNORECASE)
        cleaned_host = cleaned_host.split("/")[0]
        cmd.extend(["-q", f'host="{cleaned_host}"'] + common_filters)
            
    elif event_type == "DNS_NAME":
        # 语法查询: domain="xxx"
        cmd.extend(["-q", f'domain="{value}" || cert="{value}"'] + common_filters)
    elif event_type in ("IP_ADDRESS", "IP_RANGE"):
        # 语法查询: ip="xxx" 或 ip="xxx/24"
        cmd.extend(["-q", f'ip="{value}"'] + common_filters)
    elif event_type == "CERT":
        # 独立证书事件联动查询：对应 -uc 参数获取证书关联资产
        cmd.extend(["-uc", value] + common_filters)
    return cmd


def run_fofax_queries(asset_list: list[dict[str, str]], fofakey: str, fofax_bin: str = "fofax") -> list[dict]:
    """
    接收资产列表，显式通过 fofakey 参数传入密钥，循环调用 fofax 工具查询。
    """
    total_results = ""

    # 1. 预处理阶段：遍历 asset_list，把里面的 URL_UNVERIFIED 事件拿出来
    # 如果是 https 开头，就在任务队列后面新加一个 {"CERT": "xxxx"} 事件
    processed_asset_list = []
    cert_events = []
    
    for asset_dict in asset_list:
        if not asset_dict:
            continue
        # 先把常规事件加进去
        processed_asset_list.append(asset_dict)
        
        # 拆解当前事件的键值
        event_type, value = list(asset_dict.items())[0]
        
        # 判定是否满足追加 CERT 的条件
        if event_type == "URL_UNVERIFIED" and str(value).strip().lower().startswith("https://"):
            cert_events.append({"CERT": value})
            
    # 将裂变出来的 CERT 事件按顺序拼接到主任务列表末尾（确保在处理完所有常规事件后运行）
    processed_asset_list.extend(cert_events)

    # 2. 核心循环查询阶段（此时 processed_asset_list 中已包含裂变出来的 CERT 事件）
    for asset_dict in processed_asset_list:
        if not asset_dict:
            continue  
            
        # 提取当前资产的类型和具体值
        event_type, value = list(asset_dict.items())[0]
        
        # 获取对应的策略
        policy = QUERY_POLICIES.get(event_type, DEFAULT_POLICY)
        limit = policy["limit"]
        mode = policy["mode"]
        
        # 根据设计：如果是 drop_all，最大抓取量设为 limit + 1
        if mode == "drop_all":
            fetch_size = limit + 1
        else:
            fetch_size = limit
            
        # 拼装对应的 fofax 命令行，直接传递 fofakey 参数
        cmd = build_fofax_cmd(fofax_bin, event_type, value, fetch_size, fofakey=fofakey)
        
        try:
            # 使用 Popen 流式读取结果，防止进程死锁
            proc = subprocess.Popen(
                cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
        except FileNotFoundError:
            print(f"[-] 未找到 fofax 二进制程序，请确认路径: {fofax_bin}", file=sys.stderr)
            continue
        except Exception as exc:
            print(f"[-] fofax 启动失败: {exc}", file=sys.stderr)
            continue

        current_asset_results = []
        seen_lines = set()
        is_over_limit = False

        # 流式读取输出结果
        for line in proc.stdout:
            cleaned_line = line.strip()
            if not cleaned_line:
                continue
                
            # 2. 完美的静默拦截器：如果一行不是以字母(a-z)或数字(0-9)开头，绝对是垃圾 Banner 或日志，直接扔掉
            if not (cleaned_line[0].isalnum()) or "fofax.xiecat.fun" in cleaned_line:
                continue
                
            # 3. 过滤可能以字母开头但属于日志的行（如 [INFO] 等，防止漏网）
            if re.match(r"^(Usage:|Flags:)", cleaned_line):
                continue
                
            if cleaned_line in seen_lines:
                continue
            seen_lines.add(cleaned_line)
            
            # 如果是 drop_all 模式，且查出的有效结果行数已经达到了配置数额 + 1
            if mode == "drop_all" and len(current_asset_results) >= limit:
                is_over_limit = True
                break
                
            current_asset_results.append(cleaned_line)

        # 确保释放子进程
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

        # 针对 drop_all 的超额边界处理
        if mode == "drop_all" and is_over_limit:
            print(f"[!] 资产 [{event_type}] {value} 结果数超过限额 {limit}，触发 drop_all 机制，清空结果。", file=sys.stderr)
            current_asset_results = []
        total_results = total_results + ','+','.join(current_asset_results) + ','

    return total_results
def main() -> int:
    data = []
    # 设置命令行工具的描述信息
    parser = argparse.ArgumentParser(description="Asset Extractor with URL Climb Support")
    parser.add_argument("-k", "--key", required=True, help="FoFa API Key 认证密钥")
    parser.add_argument("--fofax-bin", default="fofax", help="fofax 二进制文件的执行路径 (默认: fofax)")
    parser.add_argument("input_string", help="需要提取资产的输入字符串 (支持逗号、换行分隔)")
    args = parser.parse_args()
    extracted_data = extract_assets_by_policy(args.input_string)
    for event_type, asset_list in extracted_data.items():
        for asset in asset_list:
            data.append({event_type: asset})
    fofax_outputs = run_fofax_queries(data, fofakey=args.key, fofax_bin=args.fofax_bin)
    for event_type, asset_list in extract_assets_by_policy(fofax_outputs).items():
        for asset in asset_list:
            if asset == "8.8.8.8":
                continue
            # 组装格式为：{"事件类型": "抽取结果"}
            output_line = {event_type: asset}
            # 一行一个，实时刷新标准输出
            print(json.dumps(output_line, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    sys.exit(main())
