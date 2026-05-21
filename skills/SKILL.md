---
name: purewaf-usage
description: PureWaf 原生功能专用指南。PureWaf 是面向 CTF/教学场景的 PHP RCE WAF-bypass payload 生成器。用于手工分析 PHP 挑战源码，将 filter 和 sink 映射到 PureWaf 原始 FILTER 风格 API，直接调用 `purewaf()` 或 `PureWaf.bypass`，或在不使用 PureWaf AUTO、WebUI、Agent、LLM、`.env`、`pure/`、`purewaf_agent_state.json` 工作流的前提下解释原生 `Final Payload` 输出。
---

## 规则

- 不要使用 `auto=True`、`webui=True`、`agent=True`、`PureWaf.auto`、`PureWaf.agent`、`run_webui.py`、上传 zip 项目、`.env`、`pure/` 或 `purewaf_agent_state.json`。
- 不要依赖 LLM sink metadata、项目文件选择、agent review、dataflow validation、fallback repair 或 WebUI 输出字段。
- 将 PureWaf 视为 CTF/教学用途的 payload 生成器
- 以 PHP 挑战源码和用户明确给出的过滤规则为准。除非用户明确要求分析文档，否则不要把 writeup、README、`.md` 或 `.txt` 笔记当作 payload 真相来源。
- 保持源码推理路径：识别 sink，提取 filter，选择 `payload_context`，生成候选，本地过滤，解释最终 payload。

## 工作流

1. 阅读 PHP 源码或用户提供的 WAF 约束。
2. 手工提取被拦截的词、字符、正则、长度限制、PHP 版本、目标文件和 sink 类型。
3. 选择尽可能窄的 `payload_context`。
4. 通过默认原生路径调用 `purewaf()`；不要传入 `auto`、`webui` 或 `agent` 参数。
5. 如果需要 technique metadata 或自定义排序，直接使用 `PureWaf.bypass.BypassOptions`、`generate_candidates()`、`generate_candidate_records()`、`infer_payload_techniques()`、`filter_payloads()` 和 `PureWaf.utils.parse_*`。
6. 只表达原生 payload 语义：`Final Payload` 就是要放进漏洞输入点的候选字符串。

## 映射

提取约束：

- 黑名单词：来自 `preg_match`、`stripos`、`strpos`、`strstr`、`in_array`、switch/case filter 或自定义 substring 检查的 token。
- 被拦截字符：来自正则、`str_replace`、字符循环或 allowlist 反推的显式字符。
- 正则：保留实际作为 WAF 的 PHP regex；可行时以 `/.../flags` 形式传入。
- 长度：最大 payload 长度映射到 `limit_length`。
- PHP 版本：版本映射到 `phpv`。
- 目标：读 flag 用 `flagfile="/flag"`，根目录枚举用 `flagfile="/"`，读环境变量用 `read_env=True`，phpinfo 用 `phpinfo=True`，只有 sink 期待 PHP/upload wrapper 内容时才用 `upload=True`。

按 sink 选择 `payload_context`：

- `shell_command`：`system`、`passthru`、`shell_exec`、`exec`、`popen`、`proc_open`、反引号或用户可控命令参数。
- `php_code`：`eval`、`assert`、PHP callback/code execution、短标签上传 wrapper，或必须是合法 PHP 代码的 payload。
- `file_path`：`file_get_contents`、`readfile`、`highlight_file`、`show_source`、`include`、`require` 或路径类输入。
- `url_query_value`：只在用户明确需要从原生候选池得到 URL-safe query 参数值候选时使用。
- `any`：只有源码无法证明更窄上下文时才使用。

不要因为 `file_path` sink 就使用 `cat /flag` 这类 shell 命令；这类场景应优先使用 `/flag` 或 stream wrapper 这类路径/资源字符串。

## 优先使用 Public API

当任务是“给定这些过滤规则，找一个 payload”时，优先使用 `purewaf()`：

```python
from PureWaf import purewaf

payload = purewaf(
    waf_words="cat|flag",
    waf_chars=" /",
    waf_regex="",
    payload_context="shell_command",
    limit_length=999999,
    flagfile="/flag",
    read_env=False,
    reflect_shell=False,
    phpinfo=False,
    upload=False,
    phpv=7.4,
    total_payload=False,
)
```

原生 `purewaf()` 返回选中的 flag payload 字符串，并只记录一个兼容输出：

```text
[+] Final Payload: <payload>
```

如果没有 flag payload 通过，可能退回根目录枚举 payload 或返回 `N/A`。原生模式不要期待 `Final Payload Value`、`Final Request`、`Final Cookie` 或 `Final Header`。

## API

需要候选记录、自定义排序或 technique label 时，直接使用 `PureWaf.bypass`：

```python
from PureWaf import bypass, utils

options = bypass.BypassOptions(
    flagfile="/flag",
    read_env=False,
    reflect_shell=False,
    ip="127.0.0.1",
    port=4444,
    phpinfo=False,
    php_version=7.4,
    upload=False,
    payload_context="shell_command",
)

records = bypass.generate_candidate_records(options)
waf_words = utils.parse_waf_words("cat|flag")
waf_chars = utils.parse_waf_chars(" /")
waf_regex = utils.parse_waf_regex("")

passed = bypass.filter_payloads(
    [record.payload for record in records],
    waf_words,
    waf_chars,
    waf_regex,
    limit_length=999999,
    show_progress=False,
)
```

只需要 `List[str]` 兼容输出时使用 `generate_candidates()`。需要解释 payload 技术来源时使用 `generate_candidate_records()` 或 `infer_payload_techniques()`。

## Payload Review

- 用 `utils.is_payload_allowed()` 或 `bypass.filter_payloads()` 按手工提取的 filter 规则验证候选。
- 按 context 检查语法：`shell_command` 用 shell 语法，`php_code` 用 PHP 语法，`file_path` 用路径/资源语法。
- 目标是读 flag 时优先 `/flag` payload；只有 flag 路径未知时才使用根目录枚举。
- 如果最短候选和源码 context 冲突，选择 context 正确的候选，不要盲信长度。
- 如果用户输入在到达 sink 前被转换，手工推理并把显式 WAF 约束编码进 PureWaf 参数；不要切换到 AUTO。

## Tamper 和编码

- 常规 targeted replacement 和 encoding fallback 交给 public `purewaf()` 处理。
- 只有明确需要底层流程时才用 `bypass.apply_encodings()`。
- 除非源码证明存在 shell 解释，否则不要把 shell-only tamper 用到 `php_code` 或 `file_path`。
- backslash split 和 randomcase 这类 manual-only tamper 是 sink-dependent，不是默认选择。
