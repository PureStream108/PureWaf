# This file is the main file of the PureWaf package.

import logging
import os
import sys
import time

from . import bypass
from . import utils

version = "1.0-beta_v1"


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
    readfile="/flag",
    read_env=False,
    reflect_shell=False,
    port=8080,
    ip="127.0.0.1",
    phpinfo=False,
    log_level="INFO",
    total_payload=False,
):
    logger, show_progress = _configure_logger(log_level)
    logger.info(banner(version).rstrip())
    time.sleep(1)

    # Print Configuration
    logger.info("")
    logger.info("-" * 40)
    logger.info(f"[*] Configuration:")
    logger.info(f"    - waf_words: {waf_words}")
    logger.info(f"    - waf_chars: {waf_chars}")
    logger.info(f"    - waf_regex: {waf_regex}")
    logger.info(f"    - limit_length: {limit_length}")
    logger.info(f"    - readfile: {readfile}")
    logger.info(f"    - read_env: {read_env}")
    logger.info(f"    - reflect_shell: {reflect_shell}")
    logger.info(f"    - port: {port}")
    logger.info(f"    - ip: {ip}")
    logger.info(f"    - phpinfo: {phpinfo}")
    logger.info(f"    - log_level: {log_level}")
    logger.info(f"    - total_payload: {total_payload}")
    logger.info("-" * 40)
    logger.info("")

    waf_words_list = utils.parse_waf_words(waf_words)
    waf_chars_set = utils.parse_waf_chars(waf_chars)
    waf_regex_obj = utils.parse_waf_regex(waf_regex)

    options = bypass.BypassOptions(
        readfile=readfile,
        read_env=read_env,
        reflect_shell=reflect_shell,
        ip=ip,
        port=port,
        phpinfo=phpinfo,
    )

    base_payloads = bypass.generate_candidates(options)
    if not base_payloads:
        logger.warning("[!] No base payloads generated.")
        return ""

    strategies = utils.get_encoding_strategies()
    encoded_payloads = bypass.apply_encodings(base_payloads, strategies)

    passed = bypass.filter_payloads(
        encoded_payloads,
        waf_words_list,
        waf_chars_set,
        waf_regex_obj,
        limit_length,
        show_progress=show_progress,
        verbose=total_payload,
    )

    if not passed:
        logger.warning("[!] No payload passed WAF filters.")
        return ""

    logger.info("")
    shortest = min(passed, key=len)
    logger.info("[+] Shortest payload length: %d", len(shortest))
    logger.info("")

    if total_payload:
        logger.info("[+] Total passed payloads: %d", len(passed))
        for payload in passed:
            logger.info(payload)

    return shortest


if __name__ == "__main__":
    purewaf()
