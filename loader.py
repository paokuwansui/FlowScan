import os
import yaml
import logging
import subprocess

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

class ModuleEnvironmentManager:
    def __init__(self, yaml_path):
        self.yaml_path = yaml_path
        self.name = os.path.basename(yaml_path)
        self.cfg = {}
        self.command_set = set()

    def load_yaml(self):
        """同步解析 YAML 文件"""
        if self.cfg: 
            return
        with open(self.yaml_path, 'r', encoding='utf-8') as f:
            self.cfg = yaml.safe_load(f)
        self.name = self.cfg.get('name', self.name)

    def _run_command_sync(self, cmd: str, timeout: float) -> subprocess.CompletedProcess:
        """
        统一治理命令的标准输出、标准错误合并、编码平滑转换及超时熔断
        """
        # stdout=subprocess.PIPE, stderr=subprocess.STDOUT 强行合并捕获常规输出与红字报错
        # text=True 转换为字符串，errors='ignore' 斩断 Windows 等环境怪异回显导致的编码死锁
        return subprocess.run(
            # cmd,
            f"bash -c '{cmd}'",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors='ignore',
            timeout=timeout
        )

    def verify_environment(self) -> bool:
        """第 1 阶段：同步验证命令是否可用"""
        check_cfg = self.cfg.get('check', {})
        check_cmd = check_cfg.get('command')
        
        include_keyword = (check_cfg.get('expect_keyword') or "").lower()
        exclude_keyword = (check_cfg.get('exclude_keyword') or "").lower()

        if not check_cmd or (not include_keyword and not exclude_keyword):
            logging.warning(f"模块 [{self.name}] 未配置核心 check 验证规则，跳过验证。")
            return True

        try:
            # 🌟 优化点：通过抽象出的函数一行拉起，施加30秒看门狗硬超时
            result = self._run_command_sync(check_cmd, timeout=30.0)
            output = result.stdout.lower()
        except subprocess.TimeoutExpired:
            logging.warning(f"⚠️  模块 [{self.name}] 环境检查命令执行超时（30秒）。")
            return False
        except Exception as e:
            logging.debug(f"模块 [{self.name}] 环境检查命令执行引发异常: {e}")
            return False

        if exclude_keyword and exclude_keyword in output:
            logging.debug(f"模块 [{self.name}] 触发排除词 '{exclude_keyword}'，环境不可用。")
            return False

        if include_keyword:
            return include_keyword in output

        return True

    def install_module(self):
        """第 2 阶段：执行安装步骤"""
        install_cfg = self.cfg.get('install', {})
        steps = install_cfg.get('steps', [])

        if not steps:
            raise RuntimeError("检查未通过，且 YAML 中未配置 install.steps 安装步骤。")

        logging.info(f"🛠️  [{self.name}] 正在启动自动安装流程，共 {len(steps)} 个步骤...")
        for idx, step in enumerate(steps, 1):
            logging.info(f"   运行安装步骤 ({idx}/{len(steps)}): {step}")
            if step in self.command_set:
                logging.info(f"🛠️  [{self.name}] {step}命令已在其他模块安装中执行")
                continue
            try:
                # 🌟 优化点：复用抽象命令执行器，执行编译或下载任务，给足 10 分钟窗口
                res = self._run_command_sync(step, timeout=600.0)
                
                if res.returncode != 0:
                    raise RuntimeError(f"退出码: {res.returncode}，报错回显: {res.stdout.strip()}")
            except subprocess.TimeoutExpired:
                raise RuntimeError(f"安装步骤 [{step}] 执行超时（600秒）。")
            except Exception as cmd_err:
                raise RuntimeError(f"安装步骤 [{step}] 执行失败，原因: {cmd_err}")
            self.command_set.add(step)

    def setup(self) -> bool:
        """生命周期核心（纯同步单线程硬串行流程）"""
        self.load_yaml()
        logging.info(f"🔍 正在检查模块环境: [{self.name}]")

        if self.verify_environment():
            logging.info(f"✅ [{self.name}] 状态：可用 (通过环境检查)")
            return True

        logging.warning(f"⚠️  [{self.name}] 状态：不可用（未找到命令或验证失败）")
        try:
            self.install_module()
        except Exception as e:
            logging.error(f"❌ 警告：模块 [{self.name}] 自动安装过程中触发致命错误: {e}")
            return False

        logging.info(f"🔄 [{self.name}] 正在重新验证安装结果...")
        if self.verify_environment():
            logging.info(f"🎉 [{self.name}] 状态：可用 (自动安装成功！)")
            return True
        else:
            logging.error(f"❌ 警告：模块 [{self.name}] 安装命令已执行，但重新检测仍未通过！")
            return False


def loader():
    modules_dir = "./modules"
    
    if not os.path.exists(modules_dir):
        logging.error(f"找不到目录: {modules_dir}，请先创建它并放入 YAML 模块。")
        return

    yaml_files = [
        os.path.join(modules_dir, f) 
        for f in os.listdir(modules_dir) 
        if f.endswith(('.yaml', '.yml'))
    ]

    if not yaml_files:
        logging.warning(f"目录 {modules_dir} 下没有找到任何 YAML 模块文件。")
        return

    logging.info(f"🚀 共发现 {len(yaml_files)} 个模块定义。")

    success_count = 0
    ready_check_commands = set()

    for path in yaml_files:
        manager = ModuleEnvironmentManager(path)
        
        try:
            manager.load_yaml()
            check_cmd = manager.cfg.get('check', {}).get('command', '')
        except Exception as e:
            logging.error(f"❌ 警告：预解析 YAML 文件失败 [{os.path.basename(path)}]: {e}，直接跳入下个模块。")
            logging.info("-" * 40)
            continue

        if not check_cmd:
            logging.error(f"❌ 警告：[{manager.name}] 没有检测命令，跳过该模块检查")
            continue

        result = manager.setup()
        
        if result is True:
            success_count += 1
            if check_cmd:
                ready_check_commands.add(check_cmd)
            
        logging.info("-" * 40) 

    logging.info(f"\n==========================================")
    logging.info(f"📊 环境初始化结束。成功: {success_count}/{len(yaml_files)}")
    logging.info(f"==========================================")


if __name__ == "__main__":
    try:
        loader()
    except KeyboardInterrupt:
        logging.info("\n🛑 收到终止信号，环境管理器安全退出。")
