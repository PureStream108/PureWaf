# PureWaf

![License](https://img.shields.io/badge/license-Apache_2.0-cyan.svg)

![Github stars](https://img.shields.io/github/stars/PureStream108/PureWaf.svg)

![Example](https://github.com/PureStream108/PureWaf/actions/workflows/eg.yml/badge.svg)

[![codecov](https://codecov.io/gh/PureStream108/PureWaf/branch/main/graph/badge.svg)](https://codecov.io/gh/PureStream108/PureWaf)

该项目仅用于教育和学习环节（比如说CTF），不得应用于其他任何恶意目的。

如果该项目出现任何错误或您有任何建议，欢迎在 `issues` 中提出。

## Foreword

CTF中，你是否会因为被像这样：

```php
if(!preg_match('/wget|dir|nl|nc|cat|tail|more|flag|sh|cut|awk|strings|od|curl|ping|\\*|sort|zip|mod|sl|find|sed|cp|mv|ty|php|tee|txt|grep|base|fd|df|\\\\|more|cc|tac|less|head|\.|\{|\}|uniq|copy|%|file|xxd|date|\[|\]|flag|bash|env|!|\?|ls|\'|\"|id/i',$cmd)) {
	echo "你传的参数似乎挺正经的,放你过去吧<br>";
	system($cmd);
} else {
	echo "nonono,hacker!!!";
}
```

或者是这样：

```php
<?php

highlight_file(__FILE__);

$comm1 = $_GET['comm1'];
$comm2 = $_GET['comm2'];


if(preg_match("/\'|\`|\\|\*|\n|\t|\xA0|\r|\{|\}|\(|\)|<|\&[^\d]|@|\||tail|bin|less|more|string|nl|pwd|cat|sh|flag|find|ls|grep|echo|w/is", $comm1))
    $comm1 = "";
if(preg_match("/\'|\"|;|,|\`|\*|\\|\n|\t|\r|\xA0|\{|\}|\(|\)|<|\&[^\d]|@|\||ls|\||tail|more|cat|string|bin|less||tac|sh|flag|find|grep|echo|w/is", $comm2))
    $comm2 = "";

$flag = "#flag in /flag";

$comm1 = '"' . $comm1 . '"';
$comm2 = '"' . $comm2 . '"';

$cmd = "file $comm1 $comm2";
system($cmd);
?>

```

的恶心人的WAF所困扰？还在一遍一遍看哪个命令没被Waf？

那么PureWaf就是为了一把梭掉这种Waf而诞生。

## Quick Start

```bash
pip install PureWaf

import PureWaf
```

## Parameters

**waf_words**

接收被过滤的字符串，格式为： `waf|star|system`，以 `|` 作为分割。

**waf_chars**

接收被过滤的字符，格式为：`#$%!`，不用分割。

**waf_regex**

接收正则表达式，格式为： `/flag|waf|system|\\|(|)/`，适用于字符串和字符混合的 waf，用 `/../` 包裹。

**limit_length**

默认为 999999 ，题目没有限制的情况下不用填写。

**flagfile**

题目Flag的文件命，默认为 `/flag`，正常情况下不用更改。

**read_env**

默认为 False（关闭），开启后就会输出读取环境变量的 payload，以应对 FLAG 放在环境变量的情况。

**reflect_shell & port & ip**

反弹shell功能开关，默认为 False（关闭），开启后输入 port 和 ip 两个参数就会自动输出反弹shell的 payload。

**phpinfo**

默认为 False（关闭），开启后会输出能读取 phpinfo 相关的 payload，建议配合 phpv 使用。

**log_level**

日志查看功能，默认为 "INFO"，也可以设置为 “DEBUG” 和 “QUIET”，对应不同等级的提示。

**total_payload**

默认为 False（关闭），开启后会输出全部 pass 的 payload（默认只输出）。

**phpv**

php版本，默认为7.0，针对不同php版本的题目环境，你可以自行设置 phpv，以便 PureWaf 将已经不适用的 payload 给剔除。

## Examples

...

## Limitations

- 暂时无法实现读取并写入新文件的操作
- 暂时无法实现输出除了读取文件/列目录/读环境变量...以外的命令操作
- 暂时无法实现自定义命令
- 暂时没有图形化界面
- 暂时没有内部检查payload是否可行机制（类似起一个http服务）
- 暂时没有白名单选项

（我们将在未来计划消除这些限制，并同步更新至README）

## Contributing

1

## Thanks & References

...

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=PureStream108/PureWaf&type=date&legend=top-left)](https://www.star-history.com/#PureStream108/PureWaf&type=date&legend=top-left)
