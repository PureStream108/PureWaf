---
name: purewaf-llm-auto
description: Use when working with PureWaf AUTO mode, PHP RCE/WAF-bypass payload generation, or LLM-assisted sink analysis. Explains PureWaf's AUTO workflow, sink metadata boundaries, and how LLM analysis should support local payload generation without producing payloads itself.
---

# PureWaf LLM AUTO

Use this skill to help a user run PureWaf with optional LLM-assisted AUTO analysis.

## Core Rules

- Treat PureWaf as a CTF and education-oriented PHP RCE/WAF-bypass payload generator, not a scanner.
- Use LLM assistance only for sink detection metadata. Do not ask the LLM to generate payloads.
- Keep payload generation and filtering inside PureWaf's local engine.
- Do not expose `.env` secrets in responses, logs, commits, or examples.

## Setup

Supported aliases:

- `API_KEY` or `PUREWAF_LLM_API_KEY`
- `BASE_URL` or `PUREWAF_LLM_BASE_URL`
- `MODEL`, `LLM_MODEL`, or `PUREWAF_LLM_MODEL`

`MODEL` is required.

## Workflow

1. Install PureWaf with its dependencies.
2. Launch the WebUI, usually with `python run_webui.py` or `purewaf(webui=True)`.
3. Switch to AUTO mode.
4. Paste a single PHP source file.
5. Run analysis.
6. Use the final payload selected by PureWaf, not raw LLM text.

## Safety Boundary

When assisting with this project, keep LLM output constrained to sink metadata:

```json
{
  "sinks": [
    {
      "function": "system",
      "kind": "command_exec",
      "payload_context": "shell_command",
      "argument_index": 0,
      "confidence": 0.9,
      "evidence": "source-based reason"
    }
  ]
}
```

Allowed sink kinds: `command_exec`, `file_read_path`, `file_write_upload`.
Allowed payload contexts: `shell_command`, `php_code`, `any`.
