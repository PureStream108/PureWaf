# Parameters

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

**upload**

默认为 False（关闭），开启后会生成由 `<?php` 等包裹后的 payload，适用于部分上传文件场景，可结合 phpv 使用

**webui**

默认为 False，暂仅支持 Python 3.9 及以上

**auto**

默认为 False，当且仅当 `webui=True`  或者 `agent=true`时自身才可以生效，此时将解锁自动分析能力，只需将你的 php 源码丢给它即可 ~~（不过只支持单文件，必须得是单文件里有明确可以绕过点的）~~

如果你开启了 `agent=true` ，那么将解锁分析多文件的能力！具体可以看 [Use With LLM](docs/LLM.md)

**agent**

默认为 False，开启后将使用你自定义的模型结合 PureWaf 进行快又准确的解答！