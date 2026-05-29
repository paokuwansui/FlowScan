import asyncio
import os
import logging
# 引入最新版本的 Orchestrator 主引擎类和 Event 模型
from runner import Orchestrator, Event
from loader import loader

# 配置批量调度的日志输出格式
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# 统一配置存储路径
TARGET_FILE = "./target.txt"
FINISH_FILE = "./finish_target.txt"
STOP_EVENT_FILE = "./stop_event.txt"
# Backward-compatible alias for old imports; new code should use TARGET_FILE/FINISH_FILE.
DOMAIN_FILE = TARGET_FILE
MODULES_DIR = "./modules"

def parse_target_line(line: str) -> tuple[str, str]:
    """
    🌟 解析目标行，提取事件类型和事件值
    
    支持格式：
    - [IP]127.0.0.1          → ('IP', '127.0.0.1')
    - [URL]http://xxx.com    → ('URL', 'http://xxx.com')
    - [LIVE_URL]https://...  → ('LIVE_URL', 'https://...')
    - evilcorp.com           → ('DOMAIN', 'evilcorp.com')  # 默认类型
    
    Args:
        line: 从 target.txt 读取的一行文本
        
    Returns:
        (event_type, event_value) 元组
    """
    import re
    
    # 尝试匹配 [TYPE]value 格式
    match = re.match(r'^\[([A-Z_]+)\](.+)$', line)
    if match:
        event_type = match.group(1)
        event_value = match.group(2)
        return event_type, event_value
    
    # 默认返回 DOMAIN 类型（向后兼容）
    return "DOMAIN", line

def parse_stop_event_lines(lines) -> set[tuple[str, str]]:
    """解析 stop_event.txt 行，返回需要终止的事件集合。

    格式和 target.txt 一致，推荐显式写 [TYPE]value，例如：
    - [URL]http://www.baidu.com
    - [LIVE_URL]https://www.baidu.com
    - [DOMAIN]baidu.com
    """
    stop_events = set()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        event_type, event_value = parse_target_line(line)
        stop_events.add((event_type, event_value))
    return stop_events


def get_stop_events() -> set[tuple[str, str]]:
    """读取 stop_event.txt 中当前要求终止的事件。"""
    if not os.path.exists(STOP_EVENT_FILE):
        return set()
    with open(STOP_EVENT_FILE, 'r', encoding='utf-8') as f:
        return parse_stop_event_lines(f)


async def stop_event_watcher(engine: Orchestrator, poll_interval: float = 1.0):
    """实时监听 stop_event.txt，有事件时终止该事件及其 root_target 子事件。

    采用追加/保留均可的语义：文件中存在的 stop 事件会被持续视为取消规则。
    """
    applied = set()
    while True:
        try:
            stop_events = await asyncio.to_thread(get_stop_events)
            for event_type, event_value in sorted(stop_events):
                key = (event_type, event_value)
                if key not in applied:
                    logging.warning(f"🛑 [StopEvent] 收到终止事件: [{event_type}]{event_value}")
                    applied.add(key)
                dropped = engine.cancel_event_tree(event_type, event_value)
                if dropped:
                    logging.warning(f"🧹 [StopEvent] 已从队列移除 {dropped} 个 [{event_type}]{event_value} 的排队/子事件")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logging.error(f"❌ [StopEvent] 读取或处理 {STOP_EVENT_FILE} 失败: {e}")
        await asyncio.sleep(poll_interval)


def get_finished_targets() -> set:
    """同步读取已完成的目标文件，并转化为本地 set 集合（带去重、去空行、去注释）"""
    if not os.path.exists(FINISH_FILE):
        return set()
    with open(FINISH_FILE, 'r', encoding='utf-8') as f:
        return {line.strip() for line in f if line.strip() and not line.startswith('#')}

def append_to_finish_file(target_line: str):
    """当某个目标彻底扫描完毕后，实时追加写入 finish_target.txt 中。"""
    with open(FINISH_FILE, 'a', encoding='utf-8') as f:
        f.write(target_line + "\n")

async def batch_file_watcher(debug: bool = False, max_concurrent_targets: int = 1):
    """
    常驻循环：不断读取 target.txt，通过 finish_target.txt 过滤，动态引入最新引擎执行
    
    Args:
        debug: 是否开启debug模式，将模块完整输出保存到logs文件夹
        max_concurrent_targets: 同时并发的目标任务数量（默认1，建议5-10）
    """
    # 🌟 1. 实例化核心 YAML 编排引擎并进行【全局环境初始化】
    # 这一步会自动加载组件、拉起 10 个 Workers，并让背景常驻服务（如 Xray）有且仅启动 1 次！
    engine = Orchestrator(MODULES_DIR, max_workers=10, max_processes=5, debug=debug)
    await engine.setup_engine()
    
    logging.info(f"👀 批量持久化监控器启动！")
    logging.info(f"   目标输入文件: {TARGET_FILE}")
    logging.info(f"   扫描状态记录: {FINISH_FILE}")
    logging.info(f"   事件终止文件: {STOP_EVENT_FILE}")
    stop_task = asyncio.create_task(stop_event_watcher(engine))
    if debug:
        logging.info(f"   🐛 Debug模式已开启，模块输出将保存到 ./outputs/logs/")
    logging.info(f"   ⚡ 最大并发目标数: {max_concurrent_targets}")

    try:
        # 2. 核心常驻业务循环
        while True:
            # 2.1 确保 target.txt 存在
            if not os.path.exists(TARGET_FILE):
                with open(TARGET_FILE, 'w', encoding='utf-8') as f:
                    pass
                logging.warning(f"⚠️  未找到目标文件，已自动创建空文件: {TARGET_FILE}")

            # 2.2 异步线程池读取待扫描的 target.txt，防止磁盘阻塞
            def read_source_lines():
                with open(TARGET_FILE, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            current_targets = await asyncio.to_thread(read_source_lines)

            # 2.3 💥 从本地断点记录文件中读取最新已完成的域名列表
            finished_targets = await asyncio.to_thread(get_finished_targets)

            # 2.4 过滤计算：只有既在 target.txt 中，又【不在】finish_target.txt 中的域名才允许跑
            pending_targets = [target for target in current_targets if target not in finished_targets]

            if pending_targets:
                logging.info(f"✨ 监控到 {len(pending_targets)} 个尚未扫描的有效新目标。")
                
                # 🌟 并发处理：使用信号量控制并发数量
                semaphore = asyncio.Semaphore(max_concurrent_targets)
                
                async def process_target(target_line: str):
                    """处理单个目标的协程"""
                    async with semaphore:  # 限制并发数
                        # 🌟 核心改动：解析目标行，提取事件类型和事件值
                        event_type, event_value = parse_target_line(target_line)
                        if engine.is_event_canceled(Event(event_type, event_value, "STOP_CHECK", root_target=event_value)):
                            logging.warning(f"🛑 [StopEvent] 目标 [{event_type}]{event_value} 已在 {STOP_EVENT_FILE} 中，跳过调度。")
                            return
                        
                        logging.info(f"\n================ 🛠️  开始编排目标: [{event_type}]{event_value} ================")
                        
                        try:
                            # 🌟 3. 直接调用最新重构的 scan_target 函数，它内部已经：
                            #    - 开启了 force=True 参数（彻底解决了 queue.join() 引发的秒过空转 Bug）
                            #    - 自动通过全局多并发 Workers 抢占并调度常规扫描器（如 Nuclei）
                            #    - 在信号量 process_semaphore 限制内安全控流发包
                            #    - 统一将结果聚合落盘到 "output_save" 或 "GLOBAL_BATCH" 静态目录
                            await engine.scan_target(event_type, event_value)
                                
                            # 💥 4. 当前目标的整条级联链路被 Workers 完全消费干净后（join成功返回），将其固化进已完成文件
                            await asyncio.to_thread(append_to_finish_file, target_line)
                            logging.info(f"💾 状态已落盘！目标 [{event_type}]{event_value} 成功填入 {FINISH_FILE}")

                        except Exception as e:
                            # 🌟 修复Bug 6: 失败目标仍标记为完成，避免无限重试
                            logging.error(f"❌ 目标 [{event_type}]{event_value} 扫描失败: {e}")
                            # 仍然标记为完成，避免5秒后无限重试
                            await asyncio.to_thread(append_to_finish_file, target_line)
                            # 记录到失败文件供后续审查
                            try:
                                with open('failed_targets.txt', 'a', encoding='utf-8') as f:
                                    f.write(f"{target_line} | {str(e)}\n")
                            except:
                                pass
                        
                        logging.info(f"================ ✅ 目标 [{event_type}]{event_value} 编排作业结束 ================\n")
                
                # 🌟 并发执行所有待处理目标
                tasks = [process_target(target_line) for target_line in pending_targets]
                await asyncio.gather(*tasks)
            
            # 6. 每隔 5 秒重新扫一次 target.txt 文件（此时如果没有新目标，引擎在内存中几乎 0 消耗挂起）
            await asyncio.sleep(5.0)
            
    except asyncio.CancelledError:
        pass
    finally:
        stop_task.cancel()
        await asyncio.gather(stop_task, return_exceptions=True)
        # 🌟 6. 优雅闭环清场：当用户按下 Ctrl+C 终止程序时，在退出前强制强杀后台常驻的所有 Workers 和 Xray 进程
        await engine.shutdown_engine()

if __name__ == "__main__":
    import sys
    
    # 🌟 支持通过命令行参数 --debug 开启debug模式
    debug_mode = "--debug" in sys.argv or "-d" in sys.argv
    
    # 🌟 支持通过命令行参数 --concurrent N 设置并发目标数
    max_concurrent = 1  # 默认值为1（保持向后兼容）
    for i, arg in enumerate(sys.argv):
        if arg in ("--concurrent", "-c") and i + 1 < len(sys.argv):
            try:
                max_concurrent = int(sys.argv[i + 1])
                if max_concurrent < 1:
                    max_concurrent = 1
                break
            except ValueError:
                pass
    
    try:
        loader()
        asyncio.run(batch_file_watcher(debug=debug_mode, max_concurrent_targets=max_concurrent))
    except KeyboardInterrupt:
        logging.info("\n🛑 收到终止信号，批量监控器已安全退出。")
