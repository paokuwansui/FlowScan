import argparse
import base64
import requests
import re
import json
api_key = ""  # 替换为您的真实 FOFA Key
if api_key == "":
    print("请完善API_key")
    exit()

def parse_fofa_set(input_set):
    result_list = []

    # 正则表达式：用于匹配标准 IPv4 地址
    ip_pattern = re.compile(
        r"^(((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d))))$"
    )

    for item in input_set:
        item = item.strip()
        if not item:
            continue  # 跳过空字符串

        # 1. 判断是否为 URL（URL 保留端口）
        if item.startswith("http://") or item.startswith("https://"):
            item_dict = {"URL": item}

        # 2. 判断是否为 IP 地址
        elif ip_pattern.match(item.split(":")[0]):
            item_dict = {"IP": item}

        # 3. 处理域名部分（去掉端口号）
        else:
            domain_clean = item.split(":")[0]
            domain_parts = domain_clean.split(".")

            if len(domain_parts) > 2:
                item_dict = {"SUBDOMAIN": domain_clean}
            else:
                item_dict = {"DOMAIN": domain_clean}

        # 【去重逻辑】：如果这个字典不在结果列表中，才添加进去
        if item_dict not in result_list:
            result_list.append(item_dict)

    return result_list


    # 1. 设置命令行参数解析
parser = argparse.ArgumentParser(description="FOFA API 查询工具")

# 必填参数：查询目标（如 baidu.com）
parser.add_argument("query", help="FOFA 查询语句或域名")

# 可选参数：自定义返回字段
default_fields = "host,title,ip,domain,port,protocol,server,link,certs.subject.org,certs.subject.cn,cert.sn"
parser.add_argument(
    "--type", default=default_fields, help="自定义返回的 fields 字段"
)

args = parser.parse_args()

# 2. 将查询语句进行 Base64 编码
query_bytes = args.query.encode("utf-8")
base64_bytes = base64.b64encode(query_bytes)
qbase64_str = base64_bytes.decode("utf-8")

# 3. 构造请求 URL

url = "https://fofa.info/api/v1/search/all"

params = {
    "key": api_key,
    "size": 1000,
    "fields": args.type,
    "qbase64": qbase64_str,
}

# 4. 发送 GET 请求并按行打印结果
try:
    response = requests.get(url, params=params, timeout=10)

    if response.status_code == 200:
        # 解析成 JSON 字典
        res_json = response.json()

        # 提取 results 并判断是否存在
        results = res_json.get("results", [])

        if results:
            # 遍历列表，按行打印
            data_set = set()
            for item in results:
                data_set.add(item[0])
                data_set.add(item[2])
                data_set.add(item[3])
                data_set.add(item[7])
                data_set.add(item[9])
            for i in parse_fofa_set(data_set):
                # i 的结构如：{'URL': 'https://teoem.vip'}
                # 使用 next(iter(...)) 动态获取字典的第一个键和值
                for key, value in i.items():
                    output_dict = {
                        "type": key,
                        "value": value
                    }
                    print(json.dumps(output_dict))
        else:
            print("[-] 未查询到任何结果或请求报错。")
            print(response.text)
    else:
        print(response.text)

except requests.exceptions.RequestException as e:
    print(f"[-] 请求发生错误: {e}")
