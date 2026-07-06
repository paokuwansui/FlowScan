#!/usr/bin/env python3
import argparse
import json
import re
import sys
from urllib.parse import urlparse
import tldextract

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
    例如: ://baidu.com.cn -> ['://baidu.com.cn', '://baidu.com.cn', 'baidu.com.cn']
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
    输入一串字符串，通过多重分隔符切分并清洗，
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
    
    # 将 逗号、单双引号、大括号、方括号 统一替换为换行，打碎混合字符串
    normalized_text = text
    for char in [",", '"', "'", "{", "}", "[", "]"]:
        normalized_text = normalized_text.replace(char, "\n")
        
    # 按行切分并剥离两端空格，同时移除前后残留的冒号（洗掉类似 JSON 键值对中间的 : 干扰）
    raw_lines = []
    for line in normalized_text.split("\n"):
        clean_line = line.strip().strip(":")
        if clean_line:
            raw_lines.append(clean_line)
    
    all_items = []
    for line in raw_lines:
        if is_url(line):
            all_items.extend(generate_url_climb_steps(line))
        else:
            all_items.append(line)
            
    for item in all_items:
        # --- 1. ICON_PATH 与 URL_UNVERIFIED 判定 (互斥分流) ---
        if looks_like_icon_url(item):
            # 如果是图标后缀结尾，仅记录为 ICON_PATH，不再记录为 URL_UNVERIFIED
            if item not in seen["ICON_PATH"]:
                seen["ICON_PATH"].add(item)
                result["ICON_PATH"].append(item)
        elif is_url(item):
            # 只有不是图标的普通 URL 才会进入 URL_UNVERIFIED
            if item not in seen["URL_UNVERIFIED"]:
                seen["URL_UNVERIFIED"].add(item)
                result["URL_UNVERIFIED"].append(item)
                
        # --- 2. IP_RANGE 判定 ---
        if IP_RANGE_RE.match(item):
            if item not in seen["IP_RANGE"]:
                seen["IP_RANGE"].add(item)
                result["IP_RANGE"].append(item)
                
        # --- 3. IP_ADDRESS 判定 ---
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
                    
        # --- 4. DNS_NAME 判定 (包含域名爬升) ---
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

def main() -> int:
    parser = argparse.ArgumentParser(description="Asset Extractor with URL and Domain Climb Support")
    parser.add_argument("input_string", help="需要提取资产的输入字符串 (支持逗号、换行、引号分隔)")
    args = parser.parse_args()
    
    extracted_data = extract_assets_by_policy(args.input_string.replace("*.",""))
    
    for event_type, asset_list in extracted_data.items():
        for asset in asset_list:
            output_line = {event_type: asset}
            print(json.dumps(output_line, ensure_ascii=False), flush=True)
            
    return 0

if __name__ == "__main__":
    sys.exit(main())

