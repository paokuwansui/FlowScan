"""
core/events.py — 审计事件类型常量 (10.3)

事件文件 (JSONL) 的一行一事件，event 字段使用这里的常量，
消灭散落字符串 (E2 关联)。
"""

EVT_CONNECT = "connect"             # beacon 上线/注册
EVT_DISCONNECT = "disconnect"       # beacon 断开/超时移除
EVT_TASK_SENT = "task_sent"         # 任务下发
EVT_TASK_RESULT = "task_result"     # 任务结果回传
EVT_AUTO_CMD_SENT = "auto_cmd_sent" # 首次上线自动命令下发
EVT_UPLEVEL = "uplevel"             # 通道升级发起
EVT_SERVER_START = "server_start"
EVT_SERVER_STOP = "server_stop"

ALL_EVENTS = (
    EVT_CONNECT, EVT_DISCONNECT, EVT_TASK_SENT, EVT_TASK_RESULT,
    EVT_AUTO_CMD_SENT, EVT_UPLEVEL, EVT_SERVER_START, EVT_SERVER_STOP,
)
