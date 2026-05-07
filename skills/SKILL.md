---
name: purewaf-usage
description: Standalone guidance for correctly using PureWaf's local CTF/education PHP RCE WAF-bypass payload generator, including FILTER mode, single-source AUTO reasoning, sink/filter interpretation, payload context selection, and code-maintenance boundaries. Use when Codex needs to analyze PHP challenge source, choose PureWaf parameters, interpret PureWaf payload output, or modify the PureWaf repo. Do not use this skill to open WebUI, invoke PureWaf agent mode, read or create `.env`, or read or create `pure/`.
---

# PureWaf Usage

Use this skill as a standalone operating guide for PureWaf. It is not bundled with a target challenge and must not assume hidden files, writeups, API credentials, or an agent runtime.

## Hard Rules

- Treat PureWaf as a CTF and education-oriented PHP RCE/WAF-bypass payload generator.
- Do not treat PureWaf as a scanner, crawler, target probe, exploitation framework, reverse shell manager, or credential tool.
- Do not open, start, or instruct the user to open the WebUI.
- Do not invoke `agent=True` or rely on PureWaf agent mode.
- Do not read, create, modify, or require `.env`.
- Do not read, create, modify, or require `pure/`.
- Do not use writeups, README files, `.md`, or `.txt` notes as ground truth for a challenge payload unless the user explicitly asks to analyze those documents as documents.
- Do not claim a payload works against a live target unless execution evidence is provided by the user.
- Prefer source-based reasoning: PHP code, known filters, known sink, PHP version, payload context, and PureWaf output.

## Workflow

1. Identify the user goal.
   - If filters are known, use FILTER mode.
   - If PHP source is provided, perform local single-source AUTO reasoning.
   - If the task is repository maintenance, inspect the local code before changing behavior.

2. Classify the sink.
   - `command_exec`: shell command sinks such as `system`, `passthru`, `shell_exec`, `exec`, `popen`, `proc_open`, and wrappers that forward to them.
   - `php_code`: PHP code execution contexts such as `eval`, `assert`, dangerous callback dispatch, or include-like PHP execution.
   - `file_read_path`: path sinks such as `file_get_contents`, `readfile`, `highlight_file`, and `show_source`.
   - `file_write_upload`: write/upload sinks such as `file_put_contents`, `move_uploaded_file`, and upload-to-webroot flows.

3. Extract constraints.
   - Words: blacklist tokens from `preg_match`, `stripos`, `strpos`, `strstr`, `in_array`, and custom wrapper filters.
   - Characters: explicit blocked characters from regexes or replacements.
   - Regex: preserve the original PHP regex when available.
   - Sanitizers: `escapeshellarg`, `escapeshellcmd`, `addslashes`, `htmlspecialchars`, `htmlentities`.
   - Preprocessors: `urldecode`, `rawurldecode`, `base64_decode`, `strtolower`, `strtoupper`, `trim`, `iconv`.
   - Environment hints: PHP version, `open_basedir`, disabled functions, fixed command prefixes.

4. Choose payload context.
   - Use `shell_command` when user input is executed by a shell command sink.
   - Use `php_code` when user input is evaluated as PHP code.
   - Use `any` for path reads, uploads, ambiguous contexts, or when the source cannot prove a narrower context.

5. Generate or interpret PureWaf output.
   - Prefer `/flag` payloads when the CTF objective is flag read.
   - Use root discovery payloads only when the task is directory enumeration or `/flag` is not yet known.
   - Present the selected result as `Final Payload: ...`.
   - If PureWaf output conflicts with the PHP source constraints, explain the conflict and re-check sink context instead of blindly trusting the shortest string.

## FILTER Mode

Use the public `purewaf()` API when the filter constraints are already known:

```python
from PureWaf import purewaf

result = purewaf(
    waf_words=["cat", "flag"],
    waf_chars=[" ", "/"],
    waf_regex=[],
    payload_context="shell_command",
    phpv=7.4,
    log_level="INFO",
)
```

Common parameters:

- `waf_words`: blocked words or substrings.
- `waf_chars`: blocked single characters.
- `waf_regex`: blocked regex patterns.
- `payload_context`: `shell_command`, `php_code`, or `any`.
- `read_env`: prefer environment-reading payloads.
- `upload`: prefer upload wrapper payloads.
- `phpv`: PHP version for version-gated payloads.
- `total_payload`: evaluate more candidates when needed.

## Single-Source AUTO Reasoning

When PHP source is provided and WebUI/agent mode is not allowed, use local AUTO analysis only:

```python
from PureWaf.auto import resolve_auto_parameters
from PureWaf import bypass

source = """<?php system($_GET['cmd']);"""
analysis = resolve_auto_parameters(source, use_llm=False)

if analysis.error:
    raise RuntimeError(analysis.error)

records = bypass.generate_candidate_records(
    bypass.BypassOptions(
        flagfile="/flag",
        read_env=analysis.read_env,
        reflect_shell=False,
        ip="127.0.0.1",
        port=4444,
        phpinfo=False,
        php_version=analysis.php_version_hint or 7.0,
        payload_context=analysis.payload_context,
        auto_context=analysis.to_context(),
    )
)
```

Use this path to understand sink metadata, preprocessors, and payload techniques. Do not use it as proof of live exploitability.

## Payload Review Rules

- Validate payloads against the PHP source path from input to sink.
- Check whether filters happen before or after preprocessing.
- For `file_read_path`, distinguish wrapper payloads such as `php://filter` from literal path payloads.
- For `command_exec`, distinguish shell syntax from PHP code syntax.
- For `php_code`, reject shell-only strings unless they are wrapped in valid PHP execution syntax.
- For uploads, reason about extension checks, MIME/content checks, destination path, and whether the written file is executable.
- If multiple inputs are concatenated, keep all relevant input refs; select the controllable key that best explains the final path or command.

## Code Maintenance Rules

- Keep `generate_candidates()` returning `List[str]` for compatibility.
- Use `generate_candidate_records()` and `infer_payload_techniques()` when technique metadata is needed.
- Prefer adding payload templates to `PureWaf/bypass_data.py`.
- Prefer tamper plugins in `PureWaf/tamper.py` over hardcoded transformations in `PureWaf/bypass.py`.
- Keep AUTO source analysis in `PureWaf/auto.py`.
- Add focused tests for every regression or new payload family.
- Do not copy GPL payload/code from external tools; localize ideas only when license-safe.
- Run the full suite before claiming completion:

```powershell
python -m unittest discover -s tests -v
```
