import base64
import re
import urllib.parse


def parse_waf_words(waf_words: str):
    """
    解析 WAF 过滤词列表
    Parse WAF forbidden words list
    (关键字绕过) Bypass: Keyword Bypass
    """
    if not waf_words:
        return []
    parts = [p.strip() for p in waf_words.split("|") if p.strip()]
    cleaned = []
    for token in parts:
        token = _strip_regex_delimiters(token)
        if token:
            cleaned.append(token)
    return cleaned


def parse_waf_chars(waf_chars: str):
    """
    解析 WAF 过滤字符集
    Parse WAF forbidden characters set
    (基础命令绕过与通配符利用) Bypass: Basic Command Bypass
    """
    if not waf_chars:
        return set()
    return {ch for ch in waf_chars if not ch.isspace()}


def parse_waf_regex(waf_regex: str):
    """
    解析 WAF 正则表达式
    Parse WAF regular expression
    """
    if not waf_regex:
        return None
    pattern = waf_regex.strip()
    flags = 0
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last = pattern.rfind("/")
        flag_str = pattern[last + 1 :]
        pattern = pattern[1:last]
        flags |= _parse_regex_flags(flag_str)
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None


def dedupe_preserve_order(items):
    """
    保持顺序去重
    Deduplicate list while preserving order
    """
    seen = set()
    result = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def is_payload_allowed(payload: str, waf_words, waf_chars, waf_regex, limit_length: int):
    """
    检查 Payload 是否被 WAF 允许
    Check if payload is allowed by WAF
    """
    if limit_length is not None and len(payload) > limit_length:
        return False
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
    URL encoding
    """
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str):
    """
    双重 URL 编码
    Double URL encoding
    """
    return urllib.parse.quote(url_encode(payload), safe="")


def unicode_escape_encode(payload: str):
    """
    Unicode 转义编码
    Unicode escape encoding
    """
    return "".join("\\u%04x" % ord(ch) for ch in payload)


def hex_escape_encode(payload: str):
    """
    十六进制转义编码
    Hex escape encoding
    """
    return "".join("\\x%02x" % ord(ch) for ch in payload)


def octal_escape_encode(payload: str):
    """
    八进制转义编码
    Octal escape encoding
    """
    return "".join("\\%03o" % ord(ch) for ch in payload)


def base64_encode(payload: str):
    """
    Base64 编码
    Base64 encoding
    """
    data = payload.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def get_encoding_strategies():
    """
    获取所有编码策略
    Get all encoding strategies
    Note: Some strategies return raw encoded strings, others return execution wrappers.
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
    剥离正则表达式定界符
    Strip regex delimiters
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
    解析正则表达式标志
    Parse regex flags
    """
    flags = 0
    for ch in flag_str:
        if ch == "i":
            flags |= re.IGNORECASE
        elif ch == "s":
            flags |= re.DOTALL
        elif ch == "m":
            flags |= re.MULTILINE
    return flags
