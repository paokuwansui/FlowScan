"""help — 命令帮助"""

_HELP = (
    "内置命令:\n"
    "  beacon                     列出所有 Beacon\n"
    "  use <beacon_id>            选中 Beacon\n"
    "  show [beacon_id]           Beacon 详情\n"
    "  modules                    列出可用植入模块\n"
    "  info <module>              模块详情\n"
    "  raw [beacon_id] <code>     下发原始 Python 代码\n"
    "  broadcast <module|raw> ...  对所有 Beacon 批量下发\n"
    "  platform [id] <linux|win|mac> 手动设置平台\n"
    "  <module> [args...]         执行模块 (如 ls ./)\n"
    "  result [beacon_id] [n]     查看执行结果\n"
    "  sysinfo [beacon_id]        收集用户名和 OS 版本\n"
    "  log [n]                    审计日志\n"
    "  reload                     重载配置并热加载模块\n"
    "  config                     显示配置\n"
    "  s_modules            列出 server 端模块\n"
    "  s_exec <mod> [args]  执行 server 端模块\n"
    "  uplevel [id] <proto> <host> <port> <key> [fp] [retry] [timeout]  升级通道（tls，多级回退）\n"
    "  exit                       退出\n"
)


def run(disp, args):
    return _HELP
