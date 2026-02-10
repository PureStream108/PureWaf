# This file is the main file of the PureWaf package.

import logging
import os
import sys
import time

from . import bypass
from . import utils

version = "1.0-beta_v2"


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

    # Validate phpv
    try:
        phpv = float(phpv)
    except (ValueError, TypeError):
        logger.error(f"[!] Invalid php_version: {phpv}. Using default 7.0")
        phpv = 7.0

    # Print Configuration
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
        flagfile="/",  # Target root directory
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

    # Generate payloads for Root Directory
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

    # Generate payloads for Flag File
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
    logger.info(f"[+] Shortest Root Directory Payload : {shortest_root}")
    logger.info(f"[+] Shortest Flag File Payload : {shortest_flag}")
    logger.info("-" * 40)
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
