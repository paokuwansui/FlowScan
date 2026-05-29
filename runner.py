import asyncio
import os
import yaml
import re
import json
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

class Event:
    def __init__(self, data_type: str, value: str, source: str = "ROOT", root_target: str = None):
        self.type = data_type      
        self.value = value        
        self.source = source
        self.root_target = root_target or value  # 根事件的root_target就是自己，子事件会继承
        self.cancel_token = None

    def __repr__(self):
        return f"[{self.source}] ({self.type}) -> {self.value}"

class PipelineModule:
    def __init__(self, yaml_path: str):
        with open(yaml_path, 'r', encoding='utf-8') as f:
            self.cfg = yaml.safe_load(f)
        
        self.name = self.cfg['name']
        self.inputs = self.cfg['execute']['inputs']
        self.outputs = self.cfg['execute']['outputs']
        self.cmd_template = self.cfg['execute']['command']
        self.parser_cfg = self.cfg.get('parser', {})
        self.save_cfg = self.cfg.get('save', {})
        
        # 🌟 新增：读取模块级并发控制和超时配置
        execute_cfg = self.cfg.get('execute', {})
        self.timeout = execute_cfg.get('timeout', 900)
        self.max_parallel_num = execute_cfg.get('max_parallel_num', 1)
        # YAML 驱动的事件值正则抽取/过滤配置。
        # 空字符串/未配置表示原样输出；非空正则匹配失败则丢弃该事件并 warning。
        self.event_extractors = self.cfg.get('event_extractors') or execute_cfg.get('event_extractors', {}) or {}


    def _match_json_field_condition(self, data: dict, match_cfg: dict) -> bool:
        """匹配 JSON 字段条件，支持点路径、equals 和 regex。"""
        field_name = match_cfg.get('field')
        if not field_name:
            return False
        value = self._get_json_path(data, f"$.{field_name}") if '.' in field_name else data.get(field_name)
        if not self._has_value(value):
            return False
        expected_value = match_cfg.get('equals')
        if expected_value is not None and value != expected_value:
            return False
        regex_pattern = match_cfg.get('regex')
        if regex_pattern and not re.search(regex_pattern, str(value)):
            return False
        return True

    def _parse_line(self, line: str) -> tuple[dict, list[Event]]:
        """
        🌟 声明式规则解析引擎
        
        :param line: 外部工具控制台输出的单行文本内容
        :return: (结构化数据字典, 生成的衍生资产/漏洞事件列表)
        
        工作原理：
        1. 遍历rules中的每条规则，找到第一条匹配的规则
        2. 根据match配置提取context变量
        3. 使用extract模板生成结果字典
        4. 自动将结果转换为Event对象
        """
        rules = self.parser_cfg.get('rules', [])
        if not rules:
            return {}, []
        
        line_stripped = line.strip()
        if not line_stripped:
            return {}, []
        
        # 尝试每条规则，找到第一条匹配的
        for rule in rules:
            match_cfg = rule.get('match', {})
            extract_cfg = rule.get('extract', {})
            match_type = match_cfg.get('type')
            
            matched = False
            context = {}
            
            # 1. 前缀匹配 - 适用于命令行标准输出
            if match_type == 'prefix':
                prefix_value = match_cfg.get('value', '')
                if line_stripped.startswith(prefix_value):
                    matched = True
                    context['rest'] = line_stripped[len(prefix_value):].strip()
                    context['full_line'] = line_stripped
            
            # 2. JSON字段条件匹配 - 适用于JSON格式输出
            elif match_type == 'json_field':
                if line_stripped.startswith('{'):
                    try:
                        data = json.loads(line_stripped)
                        if self._match_json_field_condition(data, match_cfg):
                            matched = True
                            context.update(data)  # 整个JSON对象都放入context
                    except Exception:
                        pass
            
            # 3. 正则表达式匹配 - 适用于复杂文本模式
            elif match_type == 'regex':
                pattern = match_cfg.get('pattern')
                match = re.search(pattern, line_stripped)
                if match:
                    matched = True
                    context.update(match.groupdict())
                    context['full_match'] = match.group(0)
            
            # 4. 多条件AND匹配 - 需要同时满足多个条件
            elif match_type == 'multi_match':
                conditions = match_cfg.get('conditions', [])
                all_matched = True
                
                # 先尝试解析JSON（如果看起来像JSON）
                json_data = None
                if line_stripped.startswith('{'):
                    try:
                        json_data = json.loads(line_stripped)
                    except Exception:
                        pass
                
                for condition in conditions:
                    cond_type = condition.get('type')
                    
                    if cond_type == 'prefix':
                        if not line_stripped.startswith(condition.get('value', '')):
                            all_matched = False
                            break
                    
                    elif cond_type == 'json_field_equals':
                        if json_data is None:
                            all_matched = False
                            break
                        field = condition.get('field')
                        expected = condition.get('equals')
                        if json_data.get(field) != expected:
                            all_matched = False
                            break

                    elif cond_type == 'json_field_in':
                        if json_data is None:
                            all_matched = False
                            break
                        field = condition.get('field')
                        values = condition.get('values', [])
                        if json_data.get(field) not in values:
                            all_matched = False
                            break
                    
                    elif cond_type == 'contains':
                        if condition.get('text') not in line_stripped:
                            all_matched = False
                            break
                
                if all_matched:
                    matched = True
                    if json_data:
                        context.update(json_data)
                    context['full_line'] = line_stripped
            
            # 如果匹配成功，应用提取规则
            if matched and extract_cfg:
                result = {}
                event_extract_cfg = rule.get('events') or extract_cfg
                render_context = dict(context)

                for output_key, template in extract_cfg.items():
                    # 应用模板替换 / JSON Path 提取
                    value = self._resolve_extract_value(template, render_context)
                    if not self._has_value(value):
                        continue
                    
                    # 应用过滤器
                    filters = rule.get('filters', {})
                    if output_key in filters:
                        filter_cfg = filters[output_key]
                        
                        # if_not_empty: 值为空时跳过
                        if filter_cfg.get('if_not_empty') and not self._has_value(value):
                            continue
                        
                        # if_contains: 不包含指定文本时跳过
                        if_contains = filter_cfg.get('if_contains')
                        if if_contains and if_contains not in str(value):
                            continue
                        
                        # transform: 值转换（upper/lower/strip）
                        transform = filter_cfg.get('transform')
                        if isinstance(value, str):
                            if transform == 'upper':
                                value = value.upper()
                            elif transform == 'lower':
                                value = value.lower()
                            elif transform == 'strip':
                                value = value.strip()
                    
                    if self._has_value(value):
                        result[output_key] = value
                        render_context[output_key] = value
                
                if result:
                    # 从 events 配置生成事件；没有 events 时向后兼容 extract
                    event_payload = {}
                    for event_key, template in event_extract_cfg.items():
                        value = self._resolve_extract_value(template, render_context)
                        if self._has_value(value):
                            event_payload[event_key] = value
                    events = self._generate_events(event_payload)
                    return result, events
        
        return {}, []

    def _has_value(self, value) -> bool:
        """判断提取值是否有效，保留 0/False，过滤 None/空字符串/空列表。"""
        if value is None:
            return False
        if isinstance(value, str):
            return value != ""
        if isinstance(value, (list, tuple, dict, set)):
            return len(value) > 0
        return True

    def _resolve_extract_value(self, template, context: dict):
        """解析 extract/events 的值，支持普通模板和 JSON Path。"""
        if isinstance(template, str) and template.startswith('$.'):
            return self._get_json_path(context, template)
        return self._apply_template(template, context)

    def _get_json_path(self, data, path: str):
        """轻量 JSON Path：支持 $.a.b[0].c 与列表通配 $.items[*].name。"""
        if not path.startswith('$.'):
            return None

        def parse_tokens(expr: str):
            tokens = []
            i = 2
            buf = ''
            while i < len(expr):
                ch = expr[i]
                if ch == '.':
                    if buf:
                        tokens.append(buf)
                        buf = ''
                    i += 1
                    continue
                if ch == '[':
                    if buf:
                        tokens.append(buf)
                        buf = ''
                    end = expr.find(']', i)
                    if end == -1:
                        return []
                    token = expr[i + 1:end]
                    if token == '*':
                        tokens.append('*')
                    else:
                        try:
                            tokens.append(int(token))
                        except ValueError:
                            tokens.append(token.strip('"\''))
                    i = end + 1
                    continue
                buf += ch
                i += 1
            if buf:
                tokens.append(buf)
            return tokens

        def walk(current, tokens):
            if not tokens:
                return [current]
            token, rest = tokens[0], tokens[1:]
            results = []
            if token == '*':
                if isinstance(current, list):
                    for item in current:
                        results.extend(walk(item, rest))
                elif isinstance(current, dict):
                    for item in current.values():
                        results.extend(walk(item, rest))
            elif isinstance(token, int):
                if isinstance(current, list) and 0 <= token < len(current):
                    results.extend(walk(current[token], rest))
            else:
                if isinstance(current, dict) and token in current:
                    results.extend(walk(current[token], rest))
            return results

        values = walk(data, parse_tokens(path))
        values = [v for v in values if self._has_value(v)]
        if not values:
            return None
        if len(values) == 1:
            only_value = values[0]
            if '[*]' in path:
                return [only_value]
            return only_value
        return values

    def _apply_template(self, template: str, context: dict) -> str:
        """
        🌟 模板替换引擎：将 {{variable}} 或 {{variable.method().method()}} 替换为context中的值
        
        支持的功能：
        1. 简单变量替换: {{service}} → "http"
        2. 方法调用链: {{service.upper()}} → "HTTP"
        3. 多方法链式调用: {{service.replace("ssl","https").upper()}} → "HTTPS"
        4. 组合模板: "{{service}}://{{host}}:{{port}}" → "https://example.com:443"
        
        支持的字符串方法：
        - upper(), lower(), strip(), lstrip(), rstrip()
        - replace(old, new), split(sep), join(iterable)
        - startswith(prefix), endswith(suffix)
        - find(substring), count(substring)
        - 以及所有str类型的安全方法
        """
        if not isinstance(template, str):
            return str(template)
        
        import re
        
        # 匹配 {{...}} 格式的占位符
        pattern = r'\{\{([^}]+)\}\}'
        
        def replace_placeholder(match):
            """处理单个占位符，支持方法调用链"""
            expression = match.group(1).strip()
            
            # 如果表达式中包含方法调用（有括号）
            if '(' in expression:
                # 解析表达式：变量名.方法调用链
                parts = expression.split('.')
                var_name = parts[0].strip()
                
                # 获取基础值
                if var_name not in context:
                    logging.debug(f"⚠️ [{self.name}] 模板变量不存在: {var_name}")
                    return ""
                
                value = context[var_name]
                if not isinstance(value, str):
                    value = str(value)
                
                # 依次应用方法调用
                for part in parts[1:]:
                    part = part.strip()
                    if not part:
                        continue
                    
                    # 解析方法调用：method_name(args)
                    method_match = re.match(r'^(\w+)\((.*)\)$', part)
                    if method_match:
                        method_name = method_match.group(1)
                        args_str = method_match.group(2).strip()
                        
                        # 安全检查：只允许str类型的安全方法
                        safe_methods = {
                            'upper', 'lower', 'strip', 'lstrip', 'rstrip',
                            'capitalize', 'swapcase', 'title',
                            'replace', 'split', 'rsplit', 'partition', 'rpartition',
                            'join', 'startswith', 'endswith',
                            'find', 'rfind', 'index', 'rindex', 'count',
                            'zfill', 'center', 'ljust', 'rjust',
                            'encode', 'decode'
                        }
                        
                        if method_name not in safe_methods:
                            logging.warning(f"⚠️ [{self.name}] 不允许的方法调用: {method_name}")
                            return ""
                        
                        try:
                            # 解析参数
                            if args_str:
                                # 处理字符串参数（去除引号）
                                args = []
                                kwargs = {}
                                
                                # 简单的参数解析（支持字符串和数字）
                                param_parts = self._parse_args(args_str)
                                
                                method = getattr(value, method_name)
                                value = method(*param_parts, **kwargs)
                            else:
                                # 无参数方法
                                method = getattr(value, method_name)
                                value = method()
                            
                            # 确保返回值是字符串
                            if not isinstance(value, str):
                                value = str(value)
                                
                        except Exception as e:
                            logging.warning(f"⚠️ [{self.name}] 方法调用失败: {method_name}({args_str}) - {e}")
                            return ""
                    else:
                        # 不是方法调用，可能是属性访问（暂不支持）
                        logging.debug(f"⚠️ [{self.name}] 不支持的表达式: {part}")
                        return ""
                
                return value
            else:
                # 简单变量替换
                var_name = expression
                if var_name in context:
                    value = context[var_name]
                    return str(value) if not isinstance(value, str) else value
                else:
                    logging.debug(f"⚠️ [{self.name}] 模板变量不存在: {var_name}")
                    return ""
        
        # 替换所有占位符
        result = re.sub(pattern, replace_placeholder, template)
        
        # 检查是否有未替换的占位符
        if '{{' in result and '}}' in result:
            logging.debug(f"⚠️ [{self.name}] 模板未完全替换: {result}")
            return ""
        
        return result
    
    def _parse_args(self, args_str: str) -> list:
        """
        解析方法调用的参数字符串
        支持：字符串（带引号）、数字、布尔值
        例如：'"ssl", "https"' → ['ssl', 'https']
        """
        import ast
        
        try:
            # 使用ast.literal_eval安全解析参数
            # 需要包裹成元组格式
            if ',' in args_str:
                # 多个参数
                tuple_str = f"({args_str})"
            else:
                # 单个参数
                tuple_str = f"({args_str},)"
            
            params = ast.literal_eval(tuple_str)
            return list(params) if isinstance(params, tuple) else [params]
        except:
            # 解析失败，返回原始字符串（去除空格）
            return [args_str.strip()]

    def _apply_event_extractor(self, event_type: str, value: str):
        """按 YAML 中 event_extractors 的正则配置抽取/过滤事件值。

        - 未配置或配置为空字符串：原样输出
        - 配置非空正则：用 re.search 匹配事件值
          - 有命名分组 value：输出该分组
          - 否则有普通分组：输出第一个分组
          - 否则输出完整匹配
        - 匹配失败：丢弃该事件并打印 warning
        """
        pattern = self.event_extractors.get(event_type)
        if pattern is None or pattern == "":
            return value

        value_str = str(value)
        try:
            matches = list(re.finditer(pattern, value_str))
        except re.error as e:
            logging.warning(f"⚠️ [{self.name}] 事件 [{event_type}] 的 event_extractors 正则非法，事件已丢弃: {pattern} ({e})")
            return None

        if not matches:
            logging.warning(f"⚠️ [{self.name}] 事件 [{event_type}] 值不匹配 event_extractors，已丢弃: {value_str} | regex={pattern}")
            return None

        extracted_values = []
        for match in matches:
            if "value" in match.groupdict():
                extracted = match.group("value")
            elif match.groups():
                extracted = match.group(1)
            else:
                extracted = match.group(0)

            if self._has_value(extracted):
                extracted_values.append(extracted)

        if not extracted_values:
            logging.warning(f"⚠️ [{self.name}] 事件 [{event_type}] 正则匹配成功但抽取值为空，已丢弃: {value_str} | regex={pattern}")
            return None

        # 单个匹配保持向后兼容；多个匹配用于如 DOMAIN 从 SUBDOMAIN 中抽取主域名候选。
        if len(extracted_values) == 1:
            return extracted_values[0]
        return extracted_values

    def _generate_events(self, extracted_dict: dict) -> list:
        """🌟 事件生成器：将字典转换为Event对象列表"""
        events = []
        if not extracted_dict:
            return events
        
        for event_type, value in extracted_dict.items():
            # 只在outputs中声明的类型才生成事件
            if event_type not in self.outputs:
                continue
            
            if isinstance(value, list):
                for item in value:
                    extracted_value = self._apply_event_extractor(event_type, str(item))
                    if extracted_value is None:
                        continue
                    if isinstance(extracted_value, list):
                        for sub_item in extracted_value:
                            events.append(Event(event_type, str(sub_item), self.name))
                    else:
                        events.append(Event(event_type, str(extracted_value), self.name))
            else:
                extracted_value = self._apply_event_extractor(event_type, str(value))
                if extracted_value is None:
                    continue
                if isinstance(extracted_value, list):
                    for sub_item in extracted_value:
                        events.append(Event(event_type, str(sub_item), self.name))
                else:
                    events.append(Event(event_type, str(extracted_value), self.name))
        
        return events

    async def _save_data(self, root_target: str, data_dict: dict):
        """数据持久化落盘子模块"""
        if not self.save_cfg:
            return

        raw_path = self.save_cfg.get('output_path', './outputs/results.txt')
        final_path = raw_path.replace("{{DOMAIN}}", root_target)
        os.makedirs(os.path.dirname(final_path), exist_ok=True)

        fmt = self.save_cfg.get('format', 'text')
        mode = 'a' if self.save_cfg.get('mode', 'append') == 'append' else 'w'

        if fmt == 'json':
            write_content = json.dumps(data_dict, ensure_ascii=False)
        else:
            write_content = self.save_cfg.get('template', '')
            for k, v in data_dict.items():
                write_content = write_content.replace(f"{{{{{k}}}}}", str(v))

        def sync_write():
            with open(final_path, mode, encoding='utf-8') as f:
                f.write(write_content + "\n")
        
        await asyncio.to_thread(sync_write)

    async def _save_debug_log(self, event: Event, output_lines: list):
        """🌟 Debug模式：将模块完整输出保存到logs文件夹"""
        # 生成时间戳：20260521_143025
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 构建文件名：模块名_事件类型_事件值_时间戳.txt
        # 注意：事件值可能包含特殊字符，需要清理
        safe_event_value = event.value.replace("/", "_").replace(":", "_").replace("\\", "_")
        filename = f"{self.name}_{event.type}_{safe_event_value}_{timestamp}.txt"
        
        # 确保logs目录存在
        log_dir = "./outputs/logs"
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, filename)
        
        # 异步写入文件
        def sync_write_debug_log():
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write(f"# Debug Log for Module: {self.name}\n")
                f.write(f"# Event Type: {event.type}\n")
                f.write(f"# Event Value: {event.value}\n")
                f.write(f"# Timestamp: {timestamp}\n")
                f.write(f"# Command: {self.cmd_template.replace('{{data}}', event.value)}\n")
                f.write("=" * 80 + "\n\n")
                for line in output_lines:
                    f.write(line + "\n")
        
        await asyncio.to_thread(sync_write_debug_log)
        logging.info(f"💾 [Debug] 已保存模块输出到: {log_path}")

    async def execute_and_parse(self, event: Event, root_target: str, timeout: int = 900, orchestrator=None, debug: bool = False):
        """核心作业逻辑：支持自定义超时。若 timeout <= 0 则视为长驻背景服务（不限制时间）"""
        
        cmd = self.cmd_template.replace("{{data}}", event.value)
        logging.info(f"🚀 [{self.name}] 触发运行: {cmd}")

        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT  # 🌟 合并stderr到stdout，方便debug日志记录
        )

        # 🌟 新增：用于收集完整输出的缓冲区（仅在debug模式下使用）
        # 🌟 修复问题6：限制缓冲区大小防止内存溢出
        MAX_DEBUG_LINES = 10000
        full_output_buffer = [] if debug else None

        async def read_and_parse_loop():
            while True:
                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    break 
                
                line = line_bytes.decode('utf-8', errors='ignore').strip()
                if not line:
                    continue

                # 🌟 debug模式：收集所有输出行（带上限）
                if debug and full_output_buffer is not None:
                    if len(full_output_buffer) < MAX_DEBUG_LINES:
                        full_output_buffer.append(line)
                    elif len(full_output_buffer) == MAX_DEBUG_LINES:
                        full_output_buffer.append("... [输出过多，已截断] ...")

                # 🌟 核心优化点：直接调用抽象出来的解析函数，一行代码完成翻译
                extracted_dict, new_events = self._parse_line(line)

                # 如果成功翻译并提取出有价值的数据
                if extracted_dict:
                    # 触发异步落盘存储
                    await self._save_data(root_target, extracted_dict)
                    
                    # 🌟 核心改动：实时发布事件到总线，而非等待命令结束
                    if orchestrator:
                        for new_evt in new_events:
                            # 🌟 修复Bug 1: 子事件继承父事件的root_target
                            if not hasattr(new_evt, 'root_target') or not new_evt.root_target:
                                new_evt.root_target = event.root_target if hasattr(event, 'root_target') else event.value
                            new_evt.cancel_token = getattr(event, 'cancel_token', None) or orchestrator._cancel_token_for(event.type, event.value)
                            if orchestrator.is_event_canceled(new_evt):
                                continue
                            # 🌟 新增：传递self作为source_module，让emit_event可以落盘无消费者的事件
                            await orchestrator.emit_event(new_evt, source_module=self)

        try:
            if timeout > 0:
                await asyncio.wait_for(read_and_parse_loop(), timeout=timeout)
                await process.wait() 
            else:
                logging.info(f"ℹ️  [{self.name}] 识别为长驻背景进程，时间限制已解除。")
                await read_and_parse_loop()
                
        except (asyncio.TimeoutError, asyncio.CancelledError):
            logging.warning(f"⏰ 警告：模块 [{self.name}] 触发停止或超时信号，正在强杀底层进程...")
            try:
                process.terminate()
                # 🌟 修复问题3：给5秒宽限期，超时后强制kill
                await asyncio.wait_for(process.wait(), timeout=5.0)
                logging.info(f"💀 模块 [{self.name}] 关联的底层子进程已被终止。")
            except asyncio.TimeoutError:
                logging.warning(f"💀 模块 [{self.name}] 拒绝优雅终止，正在强制杀死...")
                process.kill()
                await process.wait()
                logging.info(f"💀 模块 [{self.name}] 关联的底层子进程已被强制杀死。")
            except Exception as e:
                logging.error(f"❌ 清理子进程时发生异常: {e}")

        # 🌟 核心改动：命令执行结束后，如果开启debug模式，保存完整输出到logs文件夹
        if debug and full_output_buffer:
            # 🌟 修复问题7：添加容错，debug失败不影响主流程
            try:
                await self._save_debug_log(event, full_output_buffer)
            except Exception as debug_err:
                logging.error(f"❌ [Debug] 保存debug日志失败: {debug_err}")

        # 为了向后兼容，仍返回空列表（实际事件已实时发送）
        return []

# ==========================================
# 2. 编排总控引擎（纯粹的结果导向型，全局跨域绝对去重）
# ==========================================
class Orchestrator:
    def __init__(self, modules_dir: str, max_workers: int = 10, max_processes: int = 5, debug: bool = False):
        self.modules_dir = modules_dir
        self.queue = asyncio.Queue()  
        self.modules = []            
        self.daemon_modules = []     
        self.seen_events = set()     
        self.max_workers = max_workers
        self.process_semaphore = asyncio.Semaphore(max_processes)
        self.module_semaphores = {}  # 🌟 新增：模块级信号量字典 {module_name: Semaphore}
        self.debug = debug  # 🌟 新增：debug模式开关
        self.daemon_tasks = []
        self.workers = [] 
        self.cancelled_roots = set()  # {(event_type, event_value)} 被 stop_event.txt 终止的根事件
        self.running_event_tasks = {}  # {cancel_token: set(asyncio.Task)} 正在运行的事件级模块任务
        
        # 🌟 新增：事件流追踪字典
        self.event_consumers = {}  # {事件类型: [消费该事件的模块名列表]}
        self.event_producers = {}  # {事件类型: [生产该事件的模块名列表]}

    def load_modules(self):
        """动态扫描并加载所有 YAML 模块配置文件"""
        if self.modules or self.daemon_modules:
            return 
            
        if not os.path.exists(self.modules_dir):
            raise FileNotFoundError(f"未找到模块目录: {self.modules_dir}")
            
        for f in os.listdir(self.modules_dir):
            if f.endswith(('.yaml', '.yml')):
                full_path = os.path.join(self.modules_dir, f)
                try:
                    mod = PipelineModule(full_path)
                    
                    # 🌟 核心改动：为每个模块创建独立的并发控制信号量
                    self.module_semaphores[mod.name] = asyncio.Semaphore(mod.max_parallel_num)
                    
                    # 🌟 新增：记录模块的事件消费关系
                    for input_type in mod.inputs:
                        if input_type not in self.event_consumers:
                            self.event_consumers[input_type] = []
                        self.event_consumers[input_type].append(mod.name)
                    
                    # 🌟 新增：记录模块的事件生产关系
                    for output_type in mod.outputs:
                        if output_type not in self.event_producers:
                            self.event_producers[output_type] = []
                        self.event_producers[output_type].append(mod.name)
                    
                    if "START" in mod.inputs:
                        self.daemon_modules.append(mod)
                        logging.info(f"📦 [背景服务] 注册常驻组件: {mod.name} (max_parallel={mod.max_parallel_num})")
                    else:
                        self.modules.append(mod)
                        logging.info(f"🔨 [扫描任务] 注册常规组件: {mod.name} (max_parallel={mod.max_parallel_num})")
                except Exception as e:
                    logging.error(f"❌ 加载 YAML 配置文件失败 [{f}]: {e}")
        
        # 🌟 新增：打印事件流图谱
        self._print_event_flow()
    
    def _cancel_token_for(self, event_type: str, event_value: str) -> str:
        return f"{event_type}:{event_value}"

    def is_event_canceled(self, event: Event) -> bool:
        """判断事件是否属于已终止的根事件或其子事件。"""
        token = getattr(event, 'cancel_token', None)
        if token and token in self.cancelled_roots:
            return True
        if (event.type, event.value) in self.cancelled_roots:
            return True
        root_target = getattr(event, 'root_target', None)
        if root_target and (event.type, root_target) in self.cancelled_roots:
            return True
        if root_target:
            for canceled_type, canceled_value in self.cancelled_roots:
                if root_target == canceled_value:
                    return True
        return False

    def _drain_canceled_events_from_queue(self) -> int:
        """从 asyncio.Queue 中剔除已取消事件，并为被剔除项补 task_done。"""
        kept = []
        dropped = 0
        while True:
            try:
                event = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if self.is_event_canceled(event):
                dropped += 1
                self.queue.task_done()
            else:
                kept.append(event)
        for event in kept:
            self.queue.put_nowait(event)
        return dropped

    def cancel_event_tree(self, event_type: str, event_value: str) -> int:
        """终止一个事件及其 root_target 子树，返回从队列移除的事件数量。"""
        cancel_token = self._cancel_token_for(event_type, event_value)
        self.cancelled_roots.add((event_type, event_value))
        self.cancelled_roots.add((event_type, event_value.strip()))
        running_tasks = list(self.running_event_tasks.get(cancel_token, set()))
        for task in running_tasks:
            task.cancel()
        return self._drain_canceled_events_from_queue()

    def _get_event_flow_roots(self):
        """返回事件流图谱的根事件。

        根事件不只包含“没有生产者”的内部起点，还包含用户可直接投递的入口
        事件。否则 DOMAIN/IP/URL/LIVE_URL/SUBDOMAIN 等既可由模块产出、又可由
        target.txt 直接输入的事件，会因为存在生产者而从链路图中消失。
        """
        user_entry_events = ("START", "DOMAIN", "IP", "URL", "LIVE_URL", "SUBDOMAIN", "PORT_OPEN")
        roots = []

        for event_type in user_entry_events:
            if event_type in self.event_consumers and event_type not in roots:
                roots.append(event_type)

        for event_type in sorted(self.event_consumers):
            if event_type not in self.event_producers or len(self.event_producers[event_type]) == 0:
                if event_type not in roots:
                    roots.append(event_type)

        return roots

    def _build_event_flow_lines(self, root_event: str):
        """从指定根事件构建可打印的事件流转链路行。"""
        all_modules = self.daemon_modules + self.modules
        modules_by_name = {mod.name: mod for mod in all_modules}
        lines = []

        def trace_chain(event_type, indent=0, visited=None):
            if visited is None:
                visited = set()

            if event_type in visited:
                return
            visited.add(event_type)

            prefix = "   " * indent
            consumers = self.event_consumers.get(event_type, [])
            producers = self.event_producers.get(event_type, [])
            producer_str = f" ← {', '.join(producers)}" if producers else " ← [用户输入]"
            lines.append(f"{prefix}📍 {event_type}{producer_str}")

            next_event_types = []
            for consumer in consumers:
                mod = modules_by_name.get(consumer)
                if not mod:
                    continue
                for output_type in mod.outputs:
                    if output_type != event_type and output_type not in next_event_types:
                        next_event_types.append(output_type)

            for output_type in next_event_types:
                trace_chain(output_type, indent + 1, visited)

        trace_chain(root_event)
        return lines

    def _print_event_flow(self):
        """🌟 打印事件流图谱，展示模块间的事件消费和生产关系"""
        logging.info("\n" + "="*80)
        logging.info("📊 事件流图谱 - 模块关系可视化")
        logging.info("="*80)
        
        # 1. 打印每个模块的输入输出
        logging.info("\n🔧 模块详情（输入 → 输出）:")
        logging.info("-"*80)
        
        all_modules = self.daemon_modules + self.modules
        for mod in all_modules:
            module_type = "📦 背景服务" if "START" in mod.inputs else "🔨 扫描任务"
            logging.info(f"\n   {module_type}: {mod.name}")
            logging.info(f"   {'─'*60}")
            
            # 输入事件
            inputs_str = ", ".join(mod.inputs)
            logging.info(f"   📥 接收: {inputs_str}")
            
            # 输出事件
            outputs_str = ", ".join(mod.outputs)
            logging.info(f"   📤 产出: {outputs_str}")
            
            # 查找上游模块（谁为这个模块提供输入）
            upstream = []
            for input_type in mod.inputs:
                if input_type in self.event_producers:
                    for producer in self.event_producers[input_type]:
                        upstream.append(f"{producer}({input_type})")
            
            # 查找下游模块（这个模块的输出被谁消费）
            downstream = []
            for output_type in mod.outputs:
                if output_type in self.event_consumers:
                    for consumer in self.event_consumers[output_type]:
                        downstream.append(f"{consumer}({output_type})")
            
            if upstream:
                logging.info(f"   ⬆️  上游: {', '.join(upstream)}")
            else:
                logging.info(f"   ⬆️  上游: [根节点 - 由用户输入]")
            
            if downstream:
                logging.info(f"   ⬇️  下游: {', '.join(downstream)}")
            else:
                logging.info(f"   ⬇️  下游: [终端节点 - 无消费者]")
        
        # 2. 打印完整的事件流转链路
        logging.info("\n\n🔄 事件流转链路:")
        logging.info("-"*80)
        
        # 找到根事件：包括用户可直接投递的入口事件，以及没有生产者的内部起点
        root_events = self._get_event_flow_roots()
        
        for root_event in root_events:
            for line in self._build_event_flow_lines(root_event):
                logging.info(line)
        
        # 3. 打印统计信息
        logging.info("\n\n📈 统计信息:")
        logging.info("-"*80)
        logging.info(f"   总模块数: {len(all_modules)}")
        logging.info(f"   ├─ 背景服务: {len(self.daemon_modules)}")
        logging.info(f"   └─ 扫描任务: {len(self.modules)}")
        logging.info(f"   事件类型总数: {len(set(list(self.event_consumers.keys()) + list(self.event_producers.keys())))}")
        logging.info(f"   ├─ 有消费者的事件: {len(self.event_consumers)}")
        logging.info(f"   └─ 有生产者的事件: {len(self.event_producers)}")
        
        # 找出孤立事件（只有生产者没有消费者，或只有消费者没有生产者）
        all_event_types = set(list(self.event_consumers.keys()) + list(self.event_producers.keys()))
        orphan_events = []
        for event_type in all_event_types:
            has_producer = event_type in self.event_producers and len(self.event_producers[event_type]) > 0
            has_consumer = event_type in self.event_consumers and len(self.event_consumers[event_type]) > 0
            if not (has_producer and has_consumer):
                orphan_events.append(event_type)
        
        if orphan_events:
            logging.info(f"\n   ⚠️  孤立事件（可能需要注意）:")
            for event_type in sorted(orphan_events):
                has_producer = event_type in self.event_producers
                has_consumer = event_type in self.event_consumers
                status = "只有生产者" if has_producer else "只有消费者"
                logging.info(f"   └─ {event_type} ({status})")
        
        logging.info("\n" + "="*80 + "\n")

    async def setup_engine(self):
        """全局初始化（常驻服务如 Xray 与消费 Worker 在这里只拉起一次）"""
        self.load_modules()
        
        # 拉起全局常驻背景服务
        if self.daemon_modules and not self.daemon_tasks:
            logging.info(f"🚀 [引擎准备] 正在激活全局常驻背景服务...")
            start_event = Event("START", "SYSTEM_LAUNCH", "ENGINE_START")
            for d_mod in self.daemon_modules:
                # 统一落盘到静态目录 "GLOBAL_BATCH"，不在乎单个域名的报告划分
                task = asyncio.create_task(self._run_daemon_safe(d_mod, start_event, "output_save"))
                self.daemon_tasks.append(task)
            await asyncio.sleep(0.5) 

        # 拉起全局常规资产 Worker
        if not self.workers:
            logging.info(f"👷 [引擎准备] 正在拉起 {self.max_workers} 个常规资产消费 Worker...")
            self.workers = [
                asyncio.create_task(self._worker()) 
                for _ in range(self.max_workers)
            ]

    # 🌟 修复核心点 1：增加 force 参数，允许特定情况强行破开去重限制入队
    async def emit_event(self, event: Event, force: bool = False, source_module: PipelineModule = None):
        """
        向事件传送带发布一个资产事件（全局强力拦截去重，支持主入口强投豁免）
        
        🌟 新增：如果事件没有消费者，直接落盘而不出队，避免卡死
        """
        unique_key = f"{event.type}:{event.value}"
        if self.is_event_canceled(event):
            logging.info(f"🛑 [StopEvent] 丢弃已终止事件: [{event.type}]{event.value}")
            return
        
        if force:
            self.seen_events.add(unique_key)  # 依旧将其打上标记，防止衍生任务重复处理它
            await self.queue.put(event)        # 强行无脑塞入核心传送带队列
            return
        
        # 🌟 新增：检查是否有模块消费这个事件类型
        has_consumer = event.type in self.event_consumers and len(self.event_consumers[event.type]) > 0
        
        if not has_consumer:
            # 没有消费者，直接落盘而不出队
            if unique_key not in self.seen_events:
                self.seen_events.add(unique_key)
                
                # 如果有source_module，调用其_save_data方法落盘
                if source_module:
                    root_target = getattr(event, 'root_target', 'UNKNOWN')
                    # 构造一个简单的数据字典用于落盘
                    data_dict = {event.type: event.value}
                    await source_module._save_data(root_target, data_dict)
                    
                    logging.info(f"💾 [无消费者] 事件 [{event.type}]{event.value} 已直接落盘（无模块消费）")
                else:
                    logging.warning(f"⚠️ [无消费者] 事件 [{event.type}]{event.value} 被丢弃（无模块消费且无source_module）")
            return
        
        # 有消费者，正常入队
        if unique_key not in self.seen_events:
            self.seen_events.add(unique_key)
            await self.queue.put(event)

    async def _run_daemon_safe(self, module: PipelineModule, event: Event, root_target: str):
        """独立运行常驻背景服务"""
        try:
            # 🌟 核心改动：传入 orchestrator 引用，让常驻服务实时发送事件
            await module.execute_and_parse(event, root_target, 
                                          timeout=0, 
                                          orchestrator=self,
                                          debug=self.debug)  # 🌟 传递debug参数
            # 注意：不再处理返回值，事件已在模块内部实时发送
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logging.error(f"❌ 背景服务 [{module.name}] 运行时异常: {e}")

    async def scan_target(self, root_type: str, root_value: str):
        """投递单条/单个域名根资产，并等待其闭环（可无痛被循环调用）"""
        logging.info(f"🔥 [下发任务] 投放新资产 -> [{root_value}] 展开全流水线渗透...")
        
        # 🌟 修复Bug 1: 直接在Event中携带root_target，避免并发竞态
        init_event = Event(root_type, root_value, "ENGINE_START", root_target=root_value)
        init_event.cancel_token = self._cancel_token_for(root_type, root_value)
        
        # 🌟 修复核心点 2：下发批量任务的主域名时，将 force 设为 True
        await self.emit_event(init_event, force=True)
        
        await self.queue.join()
        
        # 🌟 修复Bug 3: 使用LRU策略清理，避免重复扫描
        if len(self.seen_events) > 10000:
            logging.info(f"🧹 清理事件去重集合（保留最近的5000条），当前大小: {len(self.seen_events)}")
            # 转换为列表，删除最早的一半
            items = list(self.seen_events)
            to_remove = items[:len(items)//2]
            for item in to_remove:
                self.seen_events.discard(item)
        
        logging.info(f"📝 资产 [{root_value}] 引发的级联任务全部消化完毕。\n" + "="*50)

    async def _worker(self):
        """消费者协程：源源不断地从传送带抢资产，不需要知道任何域名信息"""
        while True:
            try:
                current_event = await self.queue.get()
                if self.is_event_canceled(current_event):
                    logging.info(f"🛑 [StopEvent] 跳过已终止事件: [{current_event.type}]{current_event.value}")
                    continue
                # 🌟 修复问题9：降低日志频率，改为DEBUG级别
                if logging.getLogger().level <= logging.DEBUG:
                    logging.debug(f"🔔 [Worker 拿到新事件] -> {current_event}")
                
                tasks = []
                for module in self.modules:
                    if current_event.type in module.inputs:
                        # 🌟 修复Bug 1: 从event中获取root_target，避免并发竞态
                        root_target = getattr(current_event, 'root_target', 'UNKNOWN')
                        tasks.append(asyncio.create_task(self._run_module_safe(module, current_event, root_target)))
                
                if tasks:
                    for task in tasks:
                        if not hasattr(current_event, 'cancel_token') or not current_event.cancel_token:
                            current_event.cancel_token = self._cancel_token_for(current_event.type, current_event.value)
                        self.running_event_tasks.setdefault(current_event.cancel_token, set()).add(task)
                        task.add_done_callback(lambda done_task, token=current_event.cancel_token: self.running_event_tasks.get(token, set()).discard(done_task))
                    await asyncio.gather(*tasks, return_exceptions=True)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"❌ Worker 异常错误: {e}")
            finally:
                self.queue.task_done()

    async def _run_module_safe(self, module: PipelineModule, event: Event, root_target: str):
        """在信号量和自定义超时看门狗内安全启动外部扫描工具进程"""
        # 🌟 核心改动：双重信号量控制 - 全局 + 模块级
        async with self.process_semaphore:  # 第一层：全局并发控制（max_processes）
            async with self.module_semaphores[module.name]:  # 第二层：模块级并发控制（max_parallel_num）
                try:
                    # 🌟 使用模块自身配置的 timeout（从 YAML 读取）
                    mod_timeout = module.timeout
                    
                    # 传入 orchestrator 引用，让模块实时发送事件
                    if self.is_event_canceled(event):
                        logging.info(f"🛑 [StopEvent] 模块 [{module.name}] 跳过已终止事件: [{event.type}]{event.value}")
                        return
                    await module.execute_and_parse(event, root_target, 
                                                  timeout=mod_timeout, 
                                                  orchestrator=self,
                                                  debug=self.debug)  # 🌟 传递debug参数
                    # 注意：不再处理返回值，事件已在模块内部实时发送
                except Exception as e:
                    logging.error(f"❌ 模块 [{module.name}] 运行时触发致命错误: {e}")

    async def shutdown_engine(self):
        """全局终结，清场收工"""
        logging.info("🧹 [全局清理] 正在关闭引擎...")
        for w in self.workers:
            w.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers = []

        if self.daemon_tasks:
            for d_task in self.daemon_tasks:
                d_task.cancel()
            await asyncio.gather(*self.daemon_tasks, return_exceptions=True)
            self.daemon_tasks = []
        logging.info("🏁 [引擎关闭] 运行环境清理完毕。")


# ==========================================
# 3. 入口点激活（完美的纯顺序批量处理）
# ==========================================
async def main():
    # 实例化引擎：开10个多事件消费并发，限制操作系统最多只有5个底层的扫描器跑着
    engine = Orchestrator("./modules", max_workers=10, max_processes=5)
    
    # 启动环境（Xray 在这里启动，自始至终只拉起这 1 次）
    await engine.setup_engine()
    
    # 你的多域名批量扫描列表
    targets = ["evilcorp.com"]
    
    for domain in targets:
        # 下发单个目标。当扫描到 target-b 时，如果遇到了 evilcorp 已经跑过的相同 URL，
        # 会在 emit_event 里直接一脚踢飞拦截，绝不重复发包浪费时间！
        await engine.scan_target("DOMAIN", domain)
        
    # 所有域名洗劫完毕，关闭引擎和 Xray
    await engine.shutdown_engine()

if __name__ == "__main__":
    asyncio.run(main())
