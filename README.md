# PureWaf
Tips：该项目仅用于教育和学习环节（比如说CTF），不得应用于其他任何恶意目的。如果该项目出现任何错误或您有任何建议，欢迎在issues中提出。

## 前言

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

的恶心人的WAF所困扰？那么PureWaf就是为了一把梭掉这种Waf而诞生

## 快速开始

