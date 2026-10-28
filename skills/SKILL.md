---
name: purewaf-usage
description: PureWaf 原生功能中文指南（适用 2.2.0）。PureWaf 是面向 CTF/教学场景的 PHP RCE WAF-bypass payload 生成器；本文只讲原生 FILTER 风格 API、planner、php_oracle 和 recognition/sast 的只读分析，不涉及 AUTO、WebUI、Agent、LLM 或项目上传。
---

## 规则

- 不要使用 `auto=True`、`webui=True`、`agent=True`、`PureWaf.auto`、`PureWaf.agent`、`run_webui.py`、`.env`、`pure/` 或 `purewaf_agent_state.json`。
- 不要依赖 LLM sink metadata、项目文件选择、agent review、dataflow validation 或 WebUI 输出字段。
- 以 PHP 挑战源码和用户明确给出的过滤规则为准；不要把 writeup、README 或笔记当作 payload 真相来源。
- 保持源码推理路径：识别 sink → 提取 filter → 选择 payload_context → 生成候选 → 本地过滤 → 解释最终 payload。
- `php_oracle` 会执行题目源码，只对可信源码使用；默认优先 native，需要 POSIX shell 时用 docker。

## 工作流

1. 阅读 PHP 源码，定位 sink 和用户可控输入。
2. 手工提取被拦截的词、字符、正则、长度限制、PHP 版本、目标文件和 sink 类型。
3. 选择尽可能窄的 `payload_context`。
4. 通过默认原生路径调用 `purewaf()`，不要传 `auto`、`webui` 或 `agent`。
5. 需要候选列表、技术标签或自定义排序时，使用 `PureWaf.bypass`。
6. 需要确认 payload 真能读到 flag 时，用 `php_oracle.verify_payloads` 做本地验证。
7. 需要组合绕过算子时，用 `planner.generate` 或 `planner.feedback_search`。
8. 需要结构化源码分析时，用 `recognition.recognize(source, "sast")`；它只读，不会触发 AUTO。

## 映射

提取约束：

- 黑名单词：来自 `preg_match`、`stripos`、`strpos`、`strstr`、`in_array`、switch/case 或自定义 substring 检查的 token。
- 被拦截字符：来自正则、`str_replace`、字符循环或 allowlist 反推的显式字符。
- 正则：保留实际作为 WAF 的 PHP regex，以 `/.../flags` 形式传入 `waf_regex`。
- 长度：最大 payload 长度映射到 `limit_length`。
- PHP 版本：版本映射到 `phpv`。
- 目标：读 flag 用 `flagfile="/flag"`；根目录枚举用 `flagfile="/"`；读环境变量用 `read_env=True`；phpinfo 用 `phpinfo=True`；只有 sink 期待 PHP/upload wrapper 内容时才用 `upload=True`。

按 sink 选择 `payload_context`：

- `shell_command`：`system`、`passthru`、`shell_exec`、`exec`、`popen`、`proc_open`、反引号或用户可控命令参数。
- `php_code`：`eval`、`assert`、PHP callback/code execution、短标签上传 wrapper，或必须是合法 PHP 代码的 payload。
- `file_path`：`file_get_contents`、`readfile`、`highlight_file`、`show_source`、`include`、`require` 或路径类输入。
- `url_query_value`：只在用户明确需要 URL-safe query 参数值候选时使用。
- `any`：只有源码无法证明更窄上下文时才使用。

不要因为 `file_path` sink 就使用 `cat /flag` 这类 shell 命令；这类场景应优先使用 `/flag`、`php://filter/resource=/flag` 这类路径或 stream wrapper 字符串。

## Public API

给定过滤规则找 payload 时，优先使用 `purewaf()`：

```python
from PureWaf import purewaf

payload = purewaf(
    waf_words="cat|flag",
    waf_chars=" /",
    waf_regex="/flag|cat/i",
    payload_context="shell_command",
    limit_length=999999,
    flagfile="/flag",
    read_env=False,
    reflect_shell=False,
    phpinfo=False,
    upload=False,
    phpv=8.3,
    total_payload=False,
)
```

原生 `purewaf()` 返回选中的 flag payload 字符串，只打印 `[+] Final Payload: <payload>`。没有 flag payload 时可能退回根目录枚举 payload 或返回 `N/A`；原生模式不要期待 `Final Request`、`Final Cookie` 或 `Final Header`。

需要候选记录、自定义排序或 technique label 时使用 `PureWaf.bypass`：

```python
from PureWaf import bypass, utils

options = bypass.BypassOptions(
    flagfile="/flag",
    read_env=False,
    reflect_shell=False,
    ip="127.0.0.1",
    port=4444,
    phpinfo=False,
    php_version=8.3,
    upload=False,
    payload_context="shell_command",
    waf_regex="/flag|cat/i",
    generator="hybrid",
)

records = bypass.generate_candidate_records(options)
passed = bypass.filter_payloads(
    [record.payload for record in records],
    utils.parse_waf_words("cat|flag"),
    utils.parse_waf_chars(" /"),
    utils.parse_waf_regex("/flag|cat/i"),
    limit_length=999999,
    show_progress=False,
)
```

`generator` 可选 `template`、`planner`、`hybrid`；默认 `hybrid`。

## 本地验证

```python
from PureWaf import php_oracle

result = php_oracle.verify_payloads(
    source,
    ["cat /flag", "c''at /flag"],
    input_source="GET",
    input_key="c",
    runtime="native",
)
print(result.passed, result.payload)
```

需要 POSIX shell 时把 `runtime` 换成 `"docker"`；多文件项目可传 `project_files={...}, entry="index.php"`。

## 组合算子

```python
from PureWaf import planner

payloads = planner.generate("cat /flag", depth=3)
best = planner.feedback_search(
    "cat /flag",
    lambda batch: {p for p in batch if "base64" in p},
)
```

planner 只对 `shell_command` / `any` 生效，算子包括 quote、wildcard、backslash、IFS、concat、base64。

## 只读分析

```python
from PureWaf import recognition

analysis = recognition.recognize(source, "sast")
for finding in analysis.findings:
    print(finding.sink.kind, finding.sink.function, finding.sources)
```

`recognition` / `sast` 需要 tree-sitter 可选依赖；`recognize_project(files, entry)` 可跟随字面量 include。

## Payload Review

- 用 `utils.is_payload_allowed()` 或 `bypass.filter_payloads()` 按手工提取的规则验证候选。
- 按 context 检查语法：shell 用 shell 语法，php_code 用 PHP 语法，file_path 用路径/资源语法。
- 目标是读 flag 时优先 `/flag` payload；只有 flag 路径未知时才使用根目录枚举。
- 最短候选与 context 冲突时，选择 context 正确的候选，不要盲信长度。
- 输入在到达 sink 前被转换时，手工推理并把显式约束编码进参数，不要切换到 AUTO。

## Tamper 和编码

- 常规 targeted replacement 和 encoding fallback 交给 `purewaf()` 处理。
- 只有明确需要底层流程时才用 `bypass.apply_encodings()`。
- 除非源码证明存在 shell 解释，否则不要把 shell-only tamper 用到 `php_code` 或 `file_path`。
- backslash split 和 randomcase 属于 sink-dependent 的手工选择，不是默认选项。
