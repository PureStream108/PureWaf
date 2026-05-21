import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Set, Tuple

from . import bypass
from . import utils

if TYPE_CHECKING:
    from .agent import LlmWafExtraction

_COMMAND_SINKS = {
    "assert",
    "eval",
    "exec",
    "include",
    "include_once",
    "passthru",
    "require",
    "require_once",
    "shell_exec",
    "system",
}
_CALLBACK_SINKS = {
    "array_filter",
    "array_map",
    "call_user_func",
    "call_user_func_array",
    "uasort",
    "usort",
}
_FACTORY_SINKS = {
    "create_function",
    "preg_replace",
}
_FILE_READ_SINKS = {
    "file_get_contents",
    "readfile",
    "highlight_file",
    "show_source",
}
_WRITE_SINKS = {
    "copy",
    "file_put_contents",
    "fwrite",
    "move_uploaded_file",
}
_WORD_FILTER_CALLS = {"str_contains", "stripos", "strpos", "strstr", "stristr", "strchr", "strrchr"}
_REGEX_FILTER_CALLS = {"preg_match", "preg_match_all"}
_IN_ARRAY_CALLS = {"in_array", "array_search"}
_USER_INPUT_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)(?:\s*\[[^\]]+\])?")
_VAR_RE = re.compile(r"\$[A-Za-z_]\w*")
_LEN_FILTER_RE_TEMPLATE = r"(?:strlen|mb_strlen)\s*\(\s*{target}\s*\)\s*(>=|>|<=|<)\s*(\d+)"
_REPLACE_FILTER_CALLS = {"str_replace", "str_ireplace"}
_PREPROCESSOR_CALLS = {
    "strtolower",
    "strtoupper",
    "trim",
    "ltrim",
    "rtrim",
    "urldecode",
    "rawurldecode",
    "base64_decode",
    "iconv",
    "mb_convert_encoding",
}
_SANITIZER_CALLS = {
    "escapeshellcmd",
    "escapeshellarg",
    "addslashes",
    "stripslashes",
    "htmlspecialchars",
    "htmlentities",
}
_SANITIZER_CHAR_CONSTRAINTS = {
    "addslashes": "'\"\\",
    "htmlspecialchars": "<>&\"'",
    "htmlentities": "<>&\"'",
}


@dataclass
class AutoContext:
    sink_kind: str = ""
    sink_function: str = ""
    input_refs: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    preprocessors: List[str] = field(default_factory=list)
    fixed_command_prefix: str = ""
    fixed_command_tail: str = ""
    input_slots: List[str] = field(default_factory=list)
    open_basedir: str = ""
    disable_functions: List[str] = field(default_factory=list)
    php_version_hint: Optional[float] = None
    input_key: str = ""
    multi_input_filters: Dict[str, "_FilterAccumulator"] = field(default_factory=dict)
    llm_used: bool = False
    llm_error: str = ""
    llm_sink_candidates: List[Dict[str, object]] = field(default_factory=list)
    route_path: str = ""
    route_method: str = ""
    input_source: str = ""
    strategy_hints: List[str] = field(default_factory=list)
    agent_transform_chain: Optional[Dict[str, object]] = None


@dataclass
class AutoAnalysisResult:
    sink_kind: str = ""
    payload_context: str = "any"
    waf_words: str = ""
    waf_chars: str = ""
    waf_regex: str = ""
    limit_length: int = 999999
    read_env: bool = False
    upload: bool = False
    analysis_lines: List[str] = field(default_factory=list)
    error: str = ""
    sink_function: str = ""
    input_refs: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    preprocessors: List[str] = field(default_factory=list)
    fixed_command_prefix: str = ""
    fixed_command_tail: str = ""
    input_slots: List[str] = field(default_factory=list)
    open_basedir: str = ""
    disable_functions: List[str] = field(default_factory=list)
    php_version_hint: Optional[float] = None
    input_key: str = ""
    multi_input_filters: Dict[str, "_FilterAccumulator"] = field(default_factory=dict)
    llm_used: bool = False
    llm_error: str = ""
    llm_sink_candidates: List[Dict[str, object]] = field(default_factory=list)
    llm_waf_extraction: Optional["LlmWafExtraction"] = None
    route_path: str = ""
    route_method: str = ""
    input_source: str = ""
    strategy_hints: List[str] = field(default_factory=list)
    agent_transform_chain: Optional[Dict[str, object]] = None

    def to_context(self) -> AutoContext:
        return AutoContext(
            sink_kind=self.sink_kind,
            sink_function=self.sink_function,
            input_refs=list(self.input_refs),
            sanitizers=list(self.sanitizers),
            preprocessors=list(self.preprocessors),
            fixed_command_prefix=self.fixed_command_prefix,
            fixed_command_tail=self.fixed_command_tail,
            input_slots=list(self.input_slots),
            open_basedir=self.open_basedir,
            disable_functions=list(self.disable_functions),
            php_version_hint=self.php_version_hint,
            input_key=self.input_key,
            multi_input_filters=dict(self.multi_input_filters),
            llm_used=self.llm_used,
            llm_error=self.llm_error,
            llm_sink_candidates=list(self.llm_sink_candidates),
            route_path=self.route_path,
            route_method=self.route_method,
            input_source=self.input_source,
            strategy_hints=list(self.strategy_hints),
            agent_transform_chain=dict(self.agent_transform_chain) if isinstance(self.agent_transform_chain, dict) else None,
        )


@dataclass
class _FunctionDef:
    name: str
    param: str
    body: str


@dataclass
class _SinkInfo:
    kind: str
    payload_context: str
    target_expr: str
    target_var: Optional[str]
    function_name: str = ""
    fixed_command_prefix: str = ""
    fixed_command_tail: str = ""
    input_slots: List[str] = field(default_factory=list)


@dataclass
class _FilterAccumulator:
    words: List[str] = field(default_factory=list)
    chars: List[str] = field(default_factory=list)
    regexes: List[str] = field(default_factory=list)
    limit_length: Optional[int] = None
    errors: List[str] = field(default_factory=list)

    def add_word(self, value: str):
        cleaned = value.strip()
        if not cleaned:
            return
        if len(cleaned) == 1:
            self.add_char(cleaned)
            return
        if cleaned not in self.words:
            self.words.append(cleaned)

    def add_char(self, value: str):
        if len(value) != 1:
            self.add_word(value)
            return
        if value not in self.chars:
            self.chars.append(value)

    def add_regex(self, value: str):
        cleaned = value.strip()
        if cleaned and cleaned not in self.regexes:
            self.regexes.append(cleaned)

    def add_limit(self, value: int):
        if self.limit_length is None or value < self.limit_length:
            self.limit_length = value

    def merge(self, other: "_FilterAccumulator"):
        for word in other.words:
            self.add_word(word)
        for char in other.chars:
            self.add_char(char)
        for regex in other.regexes:
            self.add_regex(regex)
        if other.limit_length is not None:
            self.add_limit(other.limit_length)
        for error in other.errors:
            if error not in self.errors:
                self.errors.append(error)

    def has_filters(self) -> bool:
        return bool(self.words or self.chars or self.regexes or self.limit_length is not None)


def analyze_php_auto(source: str, use_llm: bool = False, agent_session=None, precomputed_llm_analysis=None) -> AutoAnalysisResult:
    result = AutoAnalysisResult()
    result.analysis_lines.append("[*] AUTO: analyzing PHP source")

    if not (source or "").strip():
        result.error = "AUTO input is empty; paste PHP source first."
        return result

    normalized = _strip_php_comments(source)
    functions, global_text = _extract_functions(normalized)
    assignments = _extract_assignments(global_text)
    array_sources = _extract_array_sources(global_text)

    # Pick up environment hints that work independently of any sink detection.
    result.open_basedir = _detect_open_basedir(normalized)
    result.disable_functions = _detect_disable_functions(normalized)
    result.php_version_hint = _detect_php_version_hint(normalized)
    if result.open_basedir:
        result.analysis_lines.append(f"[*] AUTO: open_basedir => {result.open_basedir}")
    if result.disable_functions:
        result.analysis_lines.append(
            f"[*] AUTO: disable_functions => {','.join(result.disable_functions)}"
        )
    if result.php_version_hint is not None:
        result.analysis_lines.append(f"[*] AUTO: php_version_hint => {result.php_version_hint}")

    sink = None
    if precomputed_llm_analysis is not None:
        sink = _apply_precomputed_llm_analysis(
            precomputed_llm_analysis, source, global_text, assignments, result
        )
    if sink is None and use_llm:
        sink = _detect_llm_sink(source, global_text, assignments, result, agent_session=agent_session)
    if sink is None:
        sink = _detect_sink(global_text, assignments, array_sources)
    if sink is None:
        result.error = "no supported sink/filter pattern detected; use FILTER mode instead"
        return result

    result.sink_kind = sink.kind
    result.sink_function = sink.function_name
    result.payload_context = sink.payload_context
    result.fixed_command_prefix = sink.fixed_command_prefix or ""
    result.fixed_command_tail = sink.fixed_command_tail or ""
    result.analysis_lines.append(f"[*] AUTO: detected sink => {sink.kind}")
    if sink.function_name:
        result.analysis_lines.append(f"[*] AUTO: sink_function => {sink.function_name}")
    if sink.payload_context != "any":
        result.analysis_lines.append(f"[*] AUTO: payload_context => {sink.payload_context}")
    if result.fixed_command_prefix:
        result.analysis_lines.append(
            f"[*] AUTO: fixed_command_prefix => {result.fixed_command_prefix}"
        )

    input_refs = _resolve_input_refs(sink.target_expr, assignments, set())

    # Multi-input with fixed command prefix => split-slot mode.
    if sink.input_slots and sink.fixed_command_prefix:
        slot_filters: Dict[str, _FilterAccumulator] = {}
        for slot in sink.input_slots:
            acc = _collect_filters_for_variable(global_text, slot)
            wrapper = _collect_filters_from_wrapper_calls(global_text, slot, functions)
            acc.merge(wrapper)
            if acc.errors:
                result.error = acc.errors[0]
                return result
            slot_filters[slot] = acc
        result.input_slots = list(sink.input_slots)
        result.multi_input_filters = slot_filters
        result.analysis_lines.append(
            f"[*] AUTO: multi-input slots => {','.join(sink.input_slots)}"
        )
        # For visibility also merge a conservative union into waf_* strings.
        union = _FilterAccumulator()
        for acc in slot_filters.values():
            union.merge(acc)
        _assign_result_filters(result, union, allow_regex_merge=True)
        _merge_llm_waf_into_result(result)
        _collect_auto_context_metadata(result, global_text, sink, input_refs, assignments)
        _apply_agent_transform_chain_metadata(result)
        return result

    if len(input_refs) > 1 and sink.kind != "file_read_path":
        result.error = "multiple filtered inputs cannot be mapped to one PureWaf model"
        return result
    if len(input_refs) > 1:
        result.analysis_lines.append(
            "[*] AUTO: multiple input refs preserved for file_read_path => "
            + ",".join(sorted(input_refs))
        )

    target_filter_expr = sink.target_var or sink.target_expr.strip()
    if not target_filter_expr:
        result.error = "no supported sink/filter pattern detected; use FILTER mode instead"
        return result

    filter_targets = _resolve_filter_target_vars(target_filter_expr, assignments)
    filters = _FilterAccumulator()
    sanitizers: List[str] = []
    preprocessors: List[str] = []
    for filter_target in filter_targets:
        target_filters = _collect_filters_for_variable(global_text, filter_target)
        wrapper_filters = _collect_filters_from_wrapper_calls(
            global_text,
            filter_target,
            functions,
        )
        target_filters.merge(wrapper_filters)
        filters.merge(target_filters)

        san_acc = _collect_sanitizers_and_preprocessors(
            global_text, filter_target, assignments, functions
        )
        for san in san_acc["sanitizers"]:
            if san not in sanitizers:
                sanitizers.append(san)
        for preprocessor in san_acc["preprocessors"]:
            if preprocessor not in preprocessors:
                preprocessors.append(preprocessor)
        for ch in san_acc["extra_chars"]:
            filters.add_char(ch)

    if filters.errors:
        result.error = filters.errors[0]
        return result

    # Also accumulate any preprocessor/sanitizer side-effects into filters
    # (e.g. addslashes => adds `' " \` chars).
    result.sanitizers = sanitizers
    result.preprocessors = preprocessors
    if result.sanitizers:
        result.analysis_lines.append(
            f"[*] AUTO: sanitizers => {','.join(result.sanitizers)}"
        )
    if result.preprocessors:
        result.analysis_lines.append(
            f"[*] AUTO: preprocessors => {','.join(result.preprocessors)}"
        )
    if (
        not filters.has_filters()
        and not result.sanitizers
        and not result.preprocessors
        and sink.kind != "file_read_path"
    ):
        result.error = "no supported sink/filter pattern detected; use FILTER mode instead"
        return result

    _assign_result_filters(result, filters, allow_regex_merge=True)
    _merge_llm_waf_into_result(result)
    _collect_auto_context_metadata(result, global_text, sink, input_refs, assignments)
    _apply_agent_transform_chain_metadata(result)

    return result


def _merge_llm_waf_into_result(result: AutoAnalysisResult):
    ext = result.llm_waf_extraction
    if ext is None:
        return
    existing_words = set(result.waf_words.split("|")) if result.waf_words else set()
    for word in ext.waf_words:
        existing_words.add(word)
    existing_words.discard("")
    result.waf_words = "|".join(sorted(existing_words))

    existing_chars = set(result.waf_chars)
    for ch in ext.waf_chars:
        existing_chars.add(ch)
    result.waf_chars = "".join(sorted(existing_chars))

    if ext.waf_regex:
        if not result.waf_regex:
            result.waf_regex = ext.waf_regex[0]
        else:
            all_regexes = [result.waf_regex] + ext.waf_regex
            result.waf_regex = _merge_regex_literals_or(all_regexes)

    if ext.limit_length is not None:
        result.limit_length = min(result.limit_length, ext.limit_length)

    result.analysis_lines.append("[*] AUTO: merged LLM WAF extraction into filters")


def _assign_result_filters(
    result: AutoAnalysisResult,
    filters: "_FilterAccumulator",
    allow_regex_merge: bool,
):
    result.waf_words = "|".join(filters.words)
    result.waf_chars = "".join(filters.chars)
    if filters.regexes:
        if len(filters.regexes) == 1:
            result.waf_regex = filters.regexes[0]
        elif allow_regex_merge:
            result.waf_regex = _merge_regex_literals_or(filters.regexes)
            result.analysis_lines.append(
                f"[*] AUTO: merged {len(filters.regexes)} regex filters via OR"
            )
        else:
            result.waf_regex = filters.regexes[0]
    if filters.limit_length is not None:
        result.limit_length = filters.limit_length

    if result.waf_words:
        result.analysis_lines.append(f"[*] AUTO: extracted waf_words => {result.waf_words}")
    if result.waf_chars:
        result.analysis_lines.append(f"[*] AUTO: extracted waf_chars => {result.waf_chars}")
    if result.waf_regex:
        result.analysis_lines.append(f"[*] AUTO: extracted waf_regex => {result.waf_regex}")
    if result.limit_length != 999999:
        result.analysis_lines.append(f"[*] AUTO: extracted limit_length => {result.limit_length}")


def _merge_regex_literals_or(regexes: List[str]) -> str:
    bodies: List[str] = []
    flag_chars: Set[str] = set()
    for literal in regexes:
        body, flags = _split_regex_body_flags(literal)
        if body is None:
            return regexes[0]
        bodies.append(body)
        flag_chars.update(flags)
    combined = "|".join(f"(?:{b})" for b in bodies)
    return f"/{combined}/{''.join(sorted(flag_chars))}"


def _split_regex_body_flags(literal: str) -> Tuple[Optional[str], str]:
    stripped = literal.strip()
    if stripped.startswith("/") and stripped.count("/") >= 2:
        last = stripped.rfind("/")
        return stripped[1:last], stripped[last + 1 :]
    return None, ""


def _collect_auto_context_metadata(
    result: AutoAnalysisResult,
    global_text: str,
    sink: "_SinkInfo",
    input_refs: Set[str],
    assignments: Dict[str, List[str]],
):
    refs = sorted(input_refs, key=_input_ref_sort_key)
    if not refs and sink.input_slots:
        # Multi-input mode: resolve each slot's input ref.
        for slot in sink.input_slots:
            slot_refs = _resolve_input_refs(slot, assignments, set())
            refs.extend(sorted(slot_refs))
    result.input_refs = refs
    result.input_key = _extract_input_key(refs[0]) if refs else ""


def _apply_agent_transform_chain_metadata(result: AutoAnalysisResult):
    chain = result.agent_transform_chain
    if not isinstance(chain, dict):
        return

    route = chain.get("route")
    if isinstance(route, dict):
        result.route_path = str(route.get("path", "") or "").strip()[:220]
        result.route_method = str(route.get("method", "") or "").strip().upper()[:12]

    input_ref = chain.get("input")
    if isinstance(input_ref, dict):
        result.input_source = str(input_ref.get("source", "") or "").strip().upper()[:24]
        if not result.input_key:
            result.input_key = str(input_ref.get("key", "") or "").strip()[:120]

    hints = chain.get("strategy_hints")
    if isinstance(hints, list):
        result.strategy_hints = [
            re.sub(r"\s+", " ", str(item or "")).strip()[:160]
            for item in hints[:12]
            if str(item or "").strip()
        ]

    if result.route_path:
        result.analysis_lines.append(f"[*] AUTO: route_path => {result.route_path}")
    if result.input_key:
        result.analysis_lines.append(f"[*] AUTO: input_key => {result.input_key}")
    if result.strategy_hints:
        result.analysis_lines.append(
            "[*] AUTO: strategy_hints => " + "; ".join(result.strategy_hints[:4])
        )


def _input_ref_sort_key(ref: str):
    match = re.match(r"\$_([A-Z]+)", ref or "")
    source = match.group(1) if match else ""
    priority = {
        "GET": 0,
        "POST": 1,
        "REQUEST": 2,
        "COOKIE": 3,
        "FILES": 4,
        "SERVER": 5,
    }.get(source, 9)
    return (priority, ref)


def _apply_precomputed_llm_analysis(
    llm_analysis,
    source: str,
    global_text: str,
    assignments: Dict[str, List[str]],
    result: AutoAnalysisResult,
) -> Optional[_SinkInfo]:
    """Use sink/WAF data already obtained from the combined project-selection LLM call."""
    result.llm_used = llm_analysis.used
    result.llm_error = llm_analysis.error
    result.llm_sink_candidates = [c.as_dict() for c in llm_analysis.candidates]
    result.llm_waf_extraction = llm_analysis.waf_extraction
    if getattr(llm_analysis, "transform_chain", None) is not None:
        result.agent_transform_chain = llm_analysis.transform_chain.as_dict()

    if llm_analysis.used:
        result.analysis_lines.append(
            f"[*] AUTO: precomputed LLM sink analysis => model={llm_analysis.model}"
        )
    if llm_analysis.error:
        result.analysis_lines.append(f"[*] AUTO: {llm_analysis.error}")

    for candidate in llm_analysis.candidates:
        result.analysis_lines.append(
            "[*] AUTO: LLM sink candidate => "
            f"{candidate.kind}:{candidate.function}[{candidate.argument_index}] "
            f"context={candidate.payload_context} confidence={candidate.confidence:.2f}"
        )

    for candidate in llm_analysis.candidates:
        sink = _sink_from_llm_candidate(candidate, global_text, assignments)
        if sink is not None:
            return sink

    if llm_analysis.candidates:
        result.analysis_lines.append("[*] AUTO: no usable precomputed LLM sink candidate matched source calls")
    return None


def _detect_llm_sink(
    source: str,
    global_text: str,
    assignments: Dict[str, List[str]],
    result: AutoAnalysisResult,
    agent_session=None,
) -> Optional[_SinkInfo]:
    try:
        from .agent import PureWafLlmSinkAgent
    except Exception as exc:
        result.llm_error = f"LLM skipped: agent unavailable: {exc}"
        result.analysis_lines.append(f"[*] AUTO: {result.llm_error}")
        return None

    analysis = PureWafLlmSinkAgent(session=agent_session).analyze_php(source)
    result.llm_used = analysis.used
    result.llm_error = analysis.error
    result.llm_sink_candidates = [candidate.as_dict() for candidate in analysis.candidates]
    result.llm_waf_extraction = analysis.waf_extraction
    if getattr(analysis, "transform_chain", None) is not None:
        result.agent_transform_chain = analysis.transform_chain.as_dict()

    if analysis.used:
        result.analysis_lines.append(f"[*] AUTO: LLM sink analysis => model={analysis.model}")
    if analysis.error:
        result.analysis_lines.append(f"[*] AUTO: {analysis.error}")

    for candidate in analysis.candidates:
        result.analysis_lines.append(
            "[*] AUTO: LLM sink candidate => "
            f"{candidate.kind}:{candidate.function}[{candidate.argument_index}] "
            f"context={candidate.payload_context} confidence={candidate.confidence:.2f}"
        )

    for candidate in analysis.candidates:
        sink = _sink_from_llm_candidate(candidate, global_text, assignments)
        if sink is not None:
            return sink

    if analysis.candidates:
        result.analysis_lines.append("[*] AUTO: no usable LLM sink candidate matched source calls")
    return None


def _sink_from_llm_candidate(
    candidate,
    global_text: str,
    assignments: Dict[str, List[str]],
) -> Optional[_SinkInfo]:
    for name, args_text, _start, _end in _iter_named_calls(global_text, {candidate.function}):
        args = _split_top_level(args_text)
        if candidate.argument_index >= len(args):
            continue
        target_expr = args[candidate.argument_index].strip()
        if not _expression_looks_input_related(target_expr):
            continue

        prefix = ""
        tail = ""
        slots: List[str] = []
        if candidate.kind == "command_exec":
            prefix, tail, slots = _parse_fixed_command_concat(target_expr, assignments)

        return _SinkInfo(
            kind=candidate.kind,
            payload_context="file_path"
            if candidate.kind == "file_read_path" and candidate.payload_context == "any"
            else candidate.payload_context,
            target_expr=target_expr,
            target_var=_extract_simple_var(target_expr),
            function_name=name.lower(),
            fixed_command_prefix=prefix,
            fixed_command_tail=tail,
            input_slots=slots,
        )
    return None


def resolve_auto_parameters(source: str, use_llm: bool = False, agent_session=None, precomputed_llm_analysis=None) -> AutoAnalysisResult:
    result = analyze_php_auto(source, use_llm=use_llm, agent_session=agent_session, precomputed_llm_analysis=precomputed_llm_analysis)
    if result.error:
        return result

    auto_context = result.to_context()
    for label, read_env, upload in _iter_strategy_candidates(result.sink_kind):
        result.analysis_lines.append(f"[*] AUTO: strategy probe => {label}")
        if _probe_strategy(
            waf_words=result.waf_words,
            waf_chars=result.waf_chars,
            waf_regex=result.waf_regex,
            limit_length=result.limit_length,
            read_env=read_env,
            upload=upload,
            payload_context=result.payload_context,
            auto_context=auto_context,
        ):
            result.read_env = read_env
            result.upload = upload
            result.analysis_lines.append(
                f"[*] AUTO: selected strategy => read_env={result.read_env} upload={result.upload}"
            )
            return result

    result.error = "auto mode could not find a passing strategy; use FILTER mode instead"
    return result


def _iter_strategy_candidates(sink_kind: str) -> Iterable[Tuple[str, bool, bool]]:
    if sink_kind == "file_write_upload":
        yield ("upload=True", False, True)
        yield ("read_env=True, upload=True", True, True)
        return
    if sink_kind == "file_read_path":
        yield ("baseline", False, False)
        return

    yield ("baseline", False, False)
    yield ("read_env=True", True, False)


def _probe_strategy(
    waf_words: str,
    waf_chars: str,
    waf_regex: str,
    limit_length: int,
    read_env: bool,
    upload: bool,
    payload_context: str,
    auto_context: Optional["AutoContext"] = None,
) -> bool:
    options = bypass.BypassOptions(
        flagfile="/flag",
        read_env=read_env,
        reflect_shell=False,
        ip="127.0.0.1",
        port=8080,
        phpinfo=False,
        php_version=(auto_context.php_version_hint if auto_context and auto_context.php_version_hint else 7.0),
        upload=upload,
        payload_context=payload_context,
        auto_context=auto_context,
    )
    waf_words_list = utils.parse_waf_words(waf_words)
    waf_chars_set = utils.parse_waf_chars(waf_chars)
    waf_regex_obj = utils.parse_waf_regex(waf_regex)

    base_payloads = bypass.generate_candidates(options)
    targeted_payloads = bypass._build_targeted_candidates(
        base_payloads,
        waf_words_list,
        waf_chars_set,
        waf_regex_obj,
        payload_context=payload_context,
    )
    passed_payloads = bypass.filter_payloads(
        targeted_payloads,
        waf_words_list,
        waf_chars_set,
        waf_regex_obj,
        limit_length,
        show_progress=False,
        verbose=False,
    )
    if passed_payloads:
        return True

    encoded_payloads = bypass.apply_encodings(base_payloads, utils.get_encoding_strategies())
    fallback_payloads = bypass.filter_payloads(
        encoded_payloads,
        waf_words_list,
        waf_chars_set,
        waf_regex_obj,
        limit_length,
        show_progress=False,
        verbose=False,
    )
    return bool(fallback_payloads)


def _strip_php_comments(text: str) -> str:
    chars: List[str] = []
    idx = 0
    length = len(text)
    in_single = False
    in_double = False

    while idx < length:
        ch = text[idx]
        nxt = text[idx + 1] if idx + 1 < length else ""

        if in_single:
            chars.append(ch)
            if ch == "\\" and idx + 1 < length:
                chars.append(text[idx + 1])
                idx += 2
                continue
            if ch == "'":
                in_single = False
            idx += 1
            continue

        if in_double:
            chars.append(ch)
            if ch == "\\" and idx + 1 < length:
                chars.append(text[idx + 1])
                idx += 2
                continue
            if ch == '"':
                in_double = False
            idx += 1
            continue

        if ch == "'":
            in_single = True
            chars.append(ch)
            idx += 1
            continue
        if ch == '"':
            in_double = True
            chars.append(ch)
            idx += 1
            continue
        if ch == "/" and nxt == "*":
            idx += 2
            while idx < length - 1 and not (text[idx] == "*" and text[idx + 1] == "/"):
                chars.append("\n" if text[idx] == "\n" else " ")
                idx += 1
            idx += 2
            continue
        if ch == "/" and nxt == "/":
            idx += 2
            while idx < length and text[idx] != "\n":
                idx += 1
            continue
        if ch == "#":
            idx += 1
            while idx < length and text[idx] != "\n":
                idx += 1
            continue

        chars.append(ch)
        idx += 1

    return "".join(chars)


def _extract_functions(text: str) -> Tuple[Dict[str, _FunctionDef], str]:
    functions: Dict[str, _FunctionDef] = {}
    spans: List[Tuple[int, int]] = []
    pattern = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", re.I)

    for match in pattern.finditer(text):
        params_start = match.end() - 1
        params_end = _find_matching(text, params_start, "(", ")")
        if params_end == -1:
            continue
        body_start = _skip_spaces(text, params_end + 1)
        if body_start >= len(text) or text[body_start] != "{":
            continue
        body_end = _find_matching(text, body_start, "{", "}")
        if body_end == -1:
            continue

        params_text = text[params_start + 1 : params_end]
        params = [
            param.strip()
            for param in _split_top_level(params_text)
            if param.strip()
        ]
        if len(params) != 1 or not re.fullmatch(r"\$[A-Za-z_]\w*", params[0]):
            continue

        body = text[body_start + 1 : body_end]
        functions[match.group(1)] = _FunctionDef(
            name=match.group(1),
            param=params[0],
            body=body,
        )
        spans.append((match.start(), body_end + 1))

    global_chars = list(text)
    for start, end in spans:
        for idx in range(start, end):
            global_chars[idx] = " "
    return functions, "".join(global_chars)


def _skip_spaces(text: str, start: int) -> int:
    idx = start
    while idx < len(text) and text[idx].isspace():
        idx += 1
    return idx


def _find_matching(text: str, start: int, open_char: str, close_char: str) -> int:
    depth = 0
    idx = start
    in_single = False
    in_double = False

    while idx < len(text):
        ch = text[idx]
        if in_single:
            if ch == "\\" and idx + 1 < len(text):
                idx += 2
                continue
            if ch == "'":
                in_single = False
            idx += 1
            continue
        if in_double:
            if ch == "\\" and idx + 1 < len(text):
                idx += 2
                continue
            if ch == '"':
                in_double = False
            idx += 1
            continue

        if ch == "'":
            in_single = True
            idx += 1
            continue
        if ch == '"':
            in_double = True
            idx += 1
            continue
        if ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return idx
        idx += 1

    return -1


def _split_top_level(text: str, delimiter: str = ",") -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    paren = 0
    bracket = 0
    brace = 0
    idx = 0
    in_single = False
    in_double = False

    while idx < len(text):
        ch = text[idx]
        if in_single:
            current.append(ch)
            if ch == "\\" and idx + 1 < len(text):
                current.append(text[idx + 1])
                idx += 2
                continue
            if ch == "'":
                in_single = False
            idx += 1
            continue

        if in_double:
            current.append(ch)
            if ch == "\\" and idx + 1 < len(text):
                current.append(text[idx + 1])
                idx += 2
                continue
            if ch == '"':
                in_double = False
            idx += 1
            continue

        if ch == "'":
            in_single = True
            current.append(ch)
            idx += 1
            continue
        if ch == '"':
            in_double = True
            current.append(ch)
            idx += 1
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket -= 1
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace -= 1
        elif ch == delimiter and paren == 0 and bracket == 0 and brace == 0:
            parts.append("".join(current).strip())
            current = []
            idx += 1
            continue
        current.append(ch)
        idx += 1

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _iter_named_calls(text: str, names: Iterable[str]):
    names = tuple(sorted(set(names), key=len, reverse=True))
    if not names:
        return
    pattern = re.compile(r"\b(" + "|".join(re.escape(name) for name in names) + r")\s*\(", re.I)
    for match in pattern.finditer(text):
        open_paren = match.end() - 1
        close_paren = _find_matching(text, open_paren, "(", ")")
        if close_paren == -1:
            continue
        yield match.group(1), text[open_paren + 1 : close_paren], match.start(), close_paren + 1


def _detect_sink(
    text: str,
    assignments: Dict[str, List[str]],
    array_sources: Dict[str, List[str]],
) -> Optional[_SinkInfo]:
    sinks: List[_SinkInfo] = []

    for name, args_text, _start, _end in _iter_named_calls(text, _COMMAND_SINKS):
        args = _split_top_level(args_text)
        if not args:
            continue
        target_expr = args[0].strip()
        if not _expression_looks_input_related(target_expr):
            continue
        prefix, tail, slots = _parse_fixed_command_concat(target_expr, assignments)
        target_var = _extract_simple_var(target_expr)
        sinks.append(
            _SinkInfo(
                kind="command_exec",
                payload_context=_command_sink_payload_context(name),
                target_expr=target_expr,
                target_var=target_var,
                function_name=name.lower(),
                fixed_command_prefix=prefix,
                fixed_command_tail=tail,
                input_slots=slots,
            )
        )

    for sink in _detect_callback_sinks(text, assignments, array_sources):
        sinks.append(sink)

    for name, args_text, _start, _end in _iter_named_calls(text, _FILE_READ_SINKS):
        args = _split_top_level(args_text)
        if not args:
            continue
        target_expr = args[0].strip()
        if not _supports_file_read_target_expr(target_expr, assignments):
            continue
        sinks.append(
            _SinkInfo(
                kind="file_read_path",
                payload_context="file_path",
                target_expr=target_expr,
                target_var=_extract_simple_var(target_expr),
                function_name=name.lower(),
            )
        )

    for name, args_text, _start, _end in _iter_named_calls(text, _WRITE_SINKS):
        args = _split_top_level(args_text)
        if name.lower() in {"file_put_contents", "fwrite"}:
            if len(args) < 2:
                continue
            target_expr = args[1].strip()
        else:
            if not args:
                continue
            target_expr = args[0].strip()
        if not _expression_looks_input_related(target_expr):
            continue
        sinks.append(
            _SinkInfo(
                kind="file_write_upload",
                payload_context="php_code",
                target_expr=target_expr,
                target_var=_extract_simple_var(target_expr),
                function_name=name.lower(),
            )
        )

    if not sinks:
        return None

    unique = {(sink.kind, sink.payload_context, sink.target_expr) for sink in sinks}
    if len(unique) == 1:
        return sinks[0]

    priority = {"command_exec": 0, "file_write_upload": 1, "file_read_path": 2}
    sinks.sort(key=lambda s: priority.get(s.kind, 9))
    return sinks[0]


def _detect_callback_sinks(
    text: str,
    assignments: Dict[str, List[str]],
    array_sources: Dict[str, List[str]],
) -> List[_SinkInfo]:
    sinks: List[_SinkInfo] = []

    for name, args_text, _start, _end in _iter_named_calls(text, _CALLBACK_SINKS):
        args = _split_top_level(args_text)
        target_expr = None
        lowered = name.lower()

        if lowered == "call_user_func" and len(args) >= 2:
            target_expr = args[1].strip()
        elif lowered == "call_user_func_array" and len(args) >= 2:
            target_expr = _unwrap_array_arg(args[1], assignments, array_sources)
        elif lowered == "array_map" and len(args) >= 2:
            target_expr = _unwrap_array_arg(args[1], assignments, array_sources)
        elif lowered == "array_filter" and len(args) >= 1:
            target_expr = _unwrap_array_arg(args[0], assignments, array_sources)
        elif lowered in {"usort", "uasort"} and len(args) >= 1:
            target_expr = _unwrap_array_arg(args[0], assignments, array_sources) or args[0].strip()

        if not target_expr or not _expression_looks_input_related(target_expr):
            continue
        sinks.append(
            _SinkInfo(
                kind="command_exec",
                payload_context="php_code",
                target_expr=target_expr,
                target_var=_extract_simple_var(target_expr),
                function_name=name.lower(),
            )
        )

    for name, args_text, _start, _end in _iter_named_calls(text, _FACTORY_SINKS):
        args = _split_top_level(args_text)
        lowered = name.lower()
        target_expr = None

        if lowered == "create_function" and len(args) >= 2:
            target_expr = args[1].strip()
        elif lowered == "preg_replace" and len(args) >= 2:
            regex_text = _extract_regex_literal(args[0])
            if regex_text and regex_text.rstrip("/").endswith("e"):
                target_expr = args[1].strip()

        if not target_expr or not _expression_looks_input_related(target_expr):
            continue
        sinks.append(
            _SinkInfo(
                kind="command_exec",
                payload_context="php_code",
                target_expr=target_expr,
                target_var=_extract_simple_var(target_expr),
                function_name=name.lower(),
            )
        )

    return sinks


def _expression_looks_input_related(expr: str) -> bool:
    if _USER_INPUT_RE.search(expr):
        return True
    if _extract_simple_var(expr):
        return True
    # Accept concat expressions that mix string literals with user variables,
    # e.g. "file " . $a . " " . $b — needed for fixed-prefix command detection.
    parts = _split_top_level(expr, ".")
    if len(parts) >= 2:
        for raw in parts:
            chunk = raw.strip()
            if re.fullmatch(r"\$[A-Za-z_]\w*", chunk):
                return True
            if _USER_INPUT_RE.search(chunk):
                return True
    return False


def _supports_file_read_target_expr(expr: str, assignments: Dict[str, List[str]]) -> bool:
    stripped = expr.strip()
    if _USER_INPUT_RE.fullmatch(stripped):
        return True
    if re.fullmatch(r"\$[A-Za-z_]\w*", stripped):
        return bool(_resolve_input_refs(stripped, assignments, set()))
    return False


def _command_sink_payload_context(name: str) -> str:
    lowered = (name or "").lower()
    if lowered in {"eval", "assert"}:
        return "php_code"
    if lowered in {"system", "exec", "shell_exec", "passthru", "popen", "proc_open"}:
        return "shell_command"
    return "any"


def _extract_simple_var(expr: str) -> Optional[str]:
    stripped = expr.strip()
    if re.fullmatch(r"\$[A-Za-z_]\w*", stripped):
        return stripped
    return None


def _extract_assignments(text: str) -> Dict[str, List[str]]:
    assignments: Dict[str, List[str]] = {}
    for match in re.finditer(r"(\$[A-Za-z_]\w*)\s*=\s*(.+?);", text, re.S):
        assignments.setdefault(match.group(1), []).append(match.group(2).strip())
    return assignments


def _extract_array_sources(text: str) -> Dict[str, List[str]]:
    arrays: Dict[str, List[str]] = {}

    for match in re.finditer(r"(\$[A-Za-z_]\w*)\s*=\s*array\s*\(", text, re.I):
        close = _find_matching(text, match.end() - 1, "(", ")")
        if close == -1:
            continue
        items = _split_top_level(text[match.end() : close])
        if items:
            arrays[match.group(1)] = [item.strip() for item in items]

    for match in re.finditer(r"(\$[A-Za-z_]\w*)\s*=\s*\[", text):
        close = _find_matching(text, match.end() - 1, "[", "]")
        if close == -1:
            continue
        items = _split_top_level(text[match.end() : close])
        if items:
            arrays[match.group(1)] = [item.strip() for item in items]

    for match in re.finditer(r"(\$[A-Za-z_]\w*)\s*\[[^\]]+\]\s*=\s*(.+?);", text, re.S):
        arrays.setdefault(match.group(1), []).append(match.group(2).strip())

    return arrays


def _unwrap_array_arg(
    expr: str,
    assignments: Dict[str, List[str]],
    array_sources: Dict[str, List[str]],
) -> Optional[str]:
    stripped = expr.strip()

    if stripped.startswith("array(") and stripped.endswith(")"):
        items = _split_top_level(stripped[6:-1])
        if len(items) == 1:
            return items[0].strip()
        return None

    if stripped.startswith("[") and stripped.endswith("]"):
        items = _split_top_level(stripped[1:-1])
        if len(items) == 1:
            return items[0].strip()
        return None

    if re.fullmatch(r"\$[A-Za-z_]\w*", stripped):
        sources = array_sources.get(stripped) or []
        if len(sources) == 1:
            return sources[0]
        for rhs in assignments.get(stripped, []):
            nested = _unwrap_array_arg(rhs, assignments, array_sources)
            if nested:
                return nested
    return None


def _resolve_input_refs(expr: str, assignments: Dict[str, List[str]], seen: Set[str]) -> Set[str]:
    refs = {re.sub(r"\s+", "", match) for match in _USER_INPUT_RE.findall(expr or "")}
    if refs:
        return refs

    resolved: Set[str] = set()
    for var in _VAR_RE.findall(expr or ""):
        if var.startswith("$_") or var in seen:
            continue
        rhs_list = assignments.get(var) or []
        for rhs in rhs_list:
            resolved.update(_resolve_input_refs(rhs, assignments, seen | {var}))
    return resolved


def _resolve_filter_target_vars(expr: str, assignments: Dict[str, List[str]]) -> List[str]:
    ordered: List[str] = []

    def add_var(var: str, seen: Set[str]):
        if not re.fullmatch(r"\$[A-Za-z_]\w*", var):
            return
        if var.startswith("$_") or var in seen:
            return
        if var not in ordered:
            ordered.append(var)
        for rhs in assignments.get(var, []):
            for nested in _VAR_RE.findall(rhs or ""):
                add_var(nested, seen | {var})

    for var in _VAR_RE.findall(expr or ""):
        add_var(var, set())
    if not ordered and re.fullmatch(r"\$[A-Za-z_]\w*", (expr or "").strip()):
        ordered.append(expr.strip())
    return ordered


def _collect_filters_from_wrapper_calls(
    global_text: str,
    target_var: str,
    functions: Dict[str, _FunctionDef],
) -> _FilterAccumulator:
    acc = _FilterAccumulator()
    for name, args_text, _start, _end in _iter_named_calls(global_text, functions.keys()):
        args = _split_top_level(args_text)
        if len(args) != 1 or not _expr_matches_target(args[0], target_var):
            continue
        nested = _collect_filters_for_function(functions[name], functions, {name})
        acc.merge(nested)
    return acc


def _collect_filters_for_function(
    function_def: _FunctionDef,
    functions: Dict[str, _FunctionDef],
    stack: Set[str],
) -> _FilterAccumulator:
    acc = _collect_filters_for_variable(function_def.body, function_def.param)
    for name, args_text, _start, _end in _iter_named_calls(function_def.body, functions.keys()):
        if name in stack:
            continue
        args = _split_top_level(args_text)
        if len(args) != 1 or not _expr_matches_target(args[0], function_def.param):
            continue
        nested = _collect_filters_for_function(functions[name], functions, stack | {name})
        acc.merge(nested)
    return acc


def _collect_filters_for_variable(text: str, target_var: str) -> _FilterAccumulator:
    acc = _FilterAccumulator()
    arrays = _extract_array_literals(text)
    assignments = _extract_assignments(text)

    for name, args_text, _start, _end in _iter_named_calls(text, _REGEX_FILTER_CALLS):
        args = _split_top_level(args_text)
        if len(args) < 2 or not _expr_matches_target(args[1], target_var):
            continue
        regex_text = _extract_regex_literal(args[0])
        if regex_text is None:
            acc.errors.append("dynamic regex construction is not supported in auto mode")
            return acc
        acc.add_regex(regex_text)

    for name, args_text, _start, _end in _iter_named_calls(text, _WORD_FILTER_CALLS):
        args = _split_top_level(args_text)
        if len(args) < 2 or not _expr_matches_target(args[0], target_var):
            continue
        literal = _parse_php_string_literal(args[1].strip())
        if literal is not None:
            acc.add_word(literal)

    for name, args_text, _start, _end in _iter_named_calls(text, _IN_ARRAY_CALLS):
        args = _split_top_level(args_text)
        if len(args) < 2 or not _expr_matches_target(args[0], target_var):
            continue
        array_expr = args[1].strip()
        array_values = _resolve_array_values(array_expr, arrays)
        if array_values is None:
            acc.errors.append("dynamic array construction is not supported in auto mode")
            return acc
        for value in array_values:
            acc.add_word(value)

    for array_var, item_var, body in _extract_foreach_loops(text):
        if not _foreach_body_filters_target(body, target_var, item_var):
            continue
        values = arrays.get(array_var)
        if values is None:
            acc.errors.append("dynamic array construction is not supported in auto mode")
            return acc
        for value in values:
            acc.add_word(value)

    len_pattern = re.compile(_LEN_FILTER_RE_TEMPLATE.format(target=re.escape(target_var)), re.I)
    for match in len_pattern.finditer(text):
        op = match.group(1)
        bound = int(match.group(2))
        if op == ">":
            acc.add_limit(bound)
        elif op == ">=":
            acc.add_limit(max(bound - 1, 0))
        elif op == "<":
            acc.add_limit(max(bound - 1, 0))
        elif op == "<=":
            acc.add_limit(bound)

    for rhs in assignments.get(target_var, []):
        replaced_tokens = _extract_replace_search_tokens(rhs, target_var)
        if replaced_tokens is None:
            acc.errors.append("dynamic str_replace filters are not supported in auto mode")
            return acc
        for token in replaced_tokens:
            if len(token) == 1:
                acc.add_char(token)
            else:
                acc.add_word(token)

    return acc


def _resolve_array_values(
    expr: str,
    arrays: Dict[str, List[str]],
) -> Optional[List[str]]:
    stripped = expr.strip()
    if stripped.startswith("array(") and stripped.endswith(")"):
        values = _parse_string_list(stripped[6:-1])
        return values
    if stripped.startswith("[") and stripped.endswith("]"):
        values = _parse_string_list(stripped[1:-1])
        return values
    if re.fullmatch(r"\$[A-Za-z_]\w*", stripped):
        return arrays.get(stripped)
    return None


def _extract_replace_search_tokens(expr: str, target_var: str) -> Optional[List[str]]:
    stripped = expr.strip()
    if not stripped:
        return []

    for name, args_text, start, end in _iter_named_calls(stripped, _REPLACE_FILTER_CALLS):
        if start != 0 or end != len(stripped):
            continue
        args = _split_top_level(args_text)
        if len(args) < 3 or not _expr_matches_target(args[2], target_var):
            continue
        return _parse_replace_search_arg(args[0])

    return []


def _parse_replace_search_arg(token: str) -> Optional[List[str]]:
    stripped = token.strip()
    literal = _parse_php_string_literal(stripped)
    if literal is not None:
        return [literal]

    if stripped.startswith("array(") and stripped.endswith(")"):
        return _parse_string_list(stripped[6:-1])

    if stripped.startswith("[") and stripped.endswith("]"):
        return _parse_string_list(stripped[1:-1])

    return None


def _extract_array_literals(text: str) -> Dict[str, List[str]]:
    arrays: Dict[str, List[str]] = {}

    for match in re.finditer(r"(\$[A-Za-z_]\w*)\s*=\s*array\s*\(", text, re.I):
        close = _find_matching(text, match.end() - 1, "(", ")")
        if close == -1:
            continue
        items = _parse_string_list(text[match.end() : close])
        if items is not None:
            arrays[match.group(1)] = items

    for match in re.finditer(r"(\$[A-Za-z_]\w*)\s*=\s*\[", text):
        close = _find_matching(text, match.end() - 1, "[", "]")
        if close == -1:
            continue
        items = _parse_string_list(text[match.end() : close])
        if items is not None:
            arrays[match.group(1)] = items

    return arrays


def _parse_string_list(text: str) -> Optional[List[str]]:
    values: List[str] = []
    for part in _split_top_level(text):
        literal = _parse_php_string_literal(part.strip())
        if literal is None:
            return None
        values.append(literal)
    return values


def _parse_php_string_literal(token: str) -> Optional[str]:
    stripped = token.strip()
    if len(stripped) < 2 or stripped[0] not in {"'", '"'} or stripped[-1] != stripped[0]:
        return None

    quote = stripped[0]
    body = stripped[1:-1]
    if quote == "'":
        return body.replace("\\\\", "\\").replace("\\'", "'")

    result: List[str] = []
    idx = 0
    escapes = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        '"': '"',
        "\\": "\\",
        "$": "$",
    }
    while idx < len(body):
        ch = body[idx]
        if ch != "\\" or idx + 1 >= len(body):
            result.append(ch)
            idx += 1
            continue
        nxt = body[idx + 1]
        if nxt == "x" and idx + 3 < len(body):
            hex_value = body[idx + 2 : idx + 4]
            if re.fullmatch(r"[0-9A-Fa-f]{2}", hex_value):
                result.append(chr(int(hex_value, 16)))
                idx += 4
                continue
        result.append(escapes.get(nxt, "\\" + nxt))
        idx += 2
    return "".join(result)


def _extract_regex_literal(token: str) -> Optional[str]:
    stripped = token.strip()
    if stripped.startswith("/") and stripped.count("/") >= 2:
        return stripped

    literal = _parse_php_string_literal(stripped)
    if literal is None:
        return None
    return literal


def _extract_foreach_loops(text: str) -> List[Tuple[str, str, str]]:
    loops: List[Tuple[str, str, str]] = []
    pattern = re.compile(r"\bforeach\s*\(", re.I)

    for match in pattern.finditer(text):
        args_end = _find_matching(text, match.end() - 1, "(", ")")
        if args_end == -1:
            continue
        body_start = _skip_spaces(text, args_end + 1)
        if body_start >= len(text) or text[body_start] != "{":
            continue
        body_end = _find_matching(text, body_start, "{", "}")
        if body_end == -1:
            continue

        header = text[match.end() : args_end]
        header_match = re.search(r"(\$[A-Za-z_]\w*)\s+as\s+(?:\$[A-Za-z_]\w*\s*=>\s*)?(\$[A-Za-z_]\w*)", header)
        if not header_match:
            continue
        loops.append((header_match.group(1), header_match.group(2), text[body_start + 1 : body_end]))

    return loops


def _foreach_body_filters_target(body: str, target_var: str, item_var: str) -> bool:
    for _name, args_text, _start, _end in _iter_named_calls(body, _WORD_FILTER_CALLS):
        args = _split_top_level(args_text)
        if len(args) < 2:
            continue
        if _expr_matches_target(args[0], target_var) and _expr_matches_target(args[1], item_var):
            return True
    return False


def _expr_matches_target(expr: str, target_var: str) -> bool:
    return expr.strip() == target_var


def _parse_fixed_command_concat(
    expr: str,
    assignments: Dict[str, List[str]],
    _depth: int = 0,
) -> Tuple[str, str, List[str]]:
    """Parse `"file " . $a . " " . $b` style concatenations.

    Also follows `$cmd = "file " . $a . " " . $b;` assignment chains one level
    deep so that `system($cmd)` still surfaces the fixed prefix.

    Returns (prefix_command_name, tail_string_literals, [var slots]).
    When no fixed prefix is detected, returns ("", "", []).
    """

    if _depth > 4:
        return "", "", []

    stripped = expr.strip()
    if re.fullmatch(r"\$[A-Za-z_]\w*", stripped):
        for rhs in assignments.get(stripped, []):
            prefix, tail, slots = _parse_fixed_command_concat(
                rhs, assignments, _depth + 1
            )
            if prefix:
                return prefix, tail, slots
        return "", "", []

    parts = _split_top_level(stripped, ".")
    if len(parts) < 2:
        return "", "", []

    head = parts[0].strip()
    head_literal = _parse_php_string_literal(head)
    if head_literal is None:
        return "", "", []
    head_literal = head_literal.strip()
    if not head_literal:
        return "", "", []
    prefix_word = head_literal.split()[0]
    if not re.fullmatch(r"[A-Za-z][\w.\-/]*", prefix_word):
        return "", "", []

    slots: List[str] = []
    tail_literals: List[str] = []
    for raw in parts[1:]:
        chunk = raw.strip()
        if re.fullmatch(r"\$[A-Za-z_]\w*", chunk):
            slots.append(chunk)
            continue
        literal = _parse_php_string_literal(chunk)
        if literal is not None:
            tail_literals.append(literal)
            continue
        # Any other expression => not a fixed-prefix pattern we can reason about.
        return "", "", []

    if not slots:
        return "", "", []
    return prefix_word, "".join(tail_literals), slots


def _collect_sanitizers_and_preprocessors(
    global_text: str,
    target_var: str,
    assignments: Dict[str, List[str]],
    functions: Dict[str, _FunctionDef],
) -> Dict[str, object]:
    sanitizers: List[str] = []
    preprocessors: List[str] = []

    def note(name: str):
        lowered = name.lower()
        if lowered in _SANITIZER_CALLS:
            if lowered not in sanitizers:
                sanitizers.append(lowered)
        elif lowered in _PREPROCESSOR_CALLS:
            if lowered not in preprocessors:
                preprocessors.append(lowered)

    # 1) direct assignments: $var = sanitizer($var); OR $var = fn($var);
    for rhs in assignments.get(target_var, []):
        for fname in _find_outer_function_calls(rhs):
            lowered = fname.lower()
            if lowered in _SANITIZER_CALLS or lowered in _PREPROCESSOR_CALLS:
                note(fname)

    # 2) sink argument wrappers elsewhere - scan all calls containing target_var.
    for name in set(list(_SANITIZER_CALLS) + list(_PREPROCESSOR_CALLS)):
        for _nm, args_text, _start, _end in _iter_named_calls(global_text, {name}):
            args = _split_top_level(args_text)
            if not args:
                continue
            if _expr_matches_target(args[0], target_var):
                note(name)

    # 3) Wrapper functions that internally sanitize then return.
    stack: Set[str] = set()
    for fn_name, fn in functions.items():
        for _nm, args_text, _start, _end in _iter_named_calls(global_text, {fn_name}):
            args = _split_top_level(args_text)
            if args and _expr_matches_target(args[0], target_var):
                _collect_sanitizers_from_function(fn, functions, stack, note)

    extra_chars: List[str] = []
    for san in sanitizers:
        constraints = _SANITIZER_CHAR_CONSTRAINTS.get(san)
        if constraints:
            extra_chars.extend(list(constraints))

    return {
        "sanitizers": sanitizers,
        "preprocessors": preprocessors,
        "extra_chars": extra_chars,
    }


def _collect_sanitizers_from_function(
    function_def: _FunctionDef,
    functions: Dict[str, _FunctionDef],
    stack: Set[str],
    note,
):
    if function_def.name in stack:
        return
    stack = stack | {function_def.name}
    for fname in _find_outer_function_calls(function_def.body):
        lowered = fname.lower()
        if lowered in _SANITIZER_CALLS or lowered in _PREPROCESSOR_CALLS:
            note(fname)
    for nested_name in functions:
        if nested_name in stack:
            continue
        for _nm, args_text, _start, _end in _iter_named_calls(
            function_def.body, {nested_name}
        ):
            args = _split_top_level(args_text)
            if args and _expr_matches_target(args[0], function_def.param):
                _collect_sanitizers_from_function(
                    functions[nested_name], functions, stack, note
                )


def _find_outer_function_calls(text: str) -> List[str]:
    """Return all function names whose call encloses the entire rest of text."""
    names: List[str] = []
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
        start = match.end() - 1
        end = _find_matching(text, start, "(", ")")
        if end == -1:
            continue
        names.append(match.group(1))
    return names


def _detect_open_basedir(text: str) -> str:
    for _nm, args_text, _start, _end in _iter_named_calls(text, {"ini_set"}):
        args = _split_top_level(args_text)
        if len(args) < 2:
            continue
        key = _parse_php_string_literal(args[0].strip())
        if key is None or key.lower() != "open_basedir":
            continue
        value = _parse_php_string_literal(args[1].strip())
        if value:
            return value
    return ""


def _detect_disable_functions(text: str) -> List[str]:
    disabled: List[str] = []

    for _nm, args_text, _start, _end in _iter_named_calls(text, {"ini_set"}):
        args = _split_top_level(args_text)
        if len(args) < 2:
            continue
        key = _parse_php_string_literal(args[0].strip())
        if key is None or key.lower() != "disable_functions":
            continue
        value = _parse_php_string_literal(args[1].strip())
        if value:
            for part in re.split(r"[,;\s]+", value):
                part = part.strip()
                if part and part not in disabled:
                    disabled.append(part)
    return disabled


def _detect_php_version_hint(text: str) -> Optional[float]:
    # PHP_VERSION < 7.4
    for _nm, args_text, _start, _end in _iter_named_calls(text, {"version_compare"}):
        args = _split_top_level(args_text)
        for arg in args:
            literal = _parse_php_string_literal(arg.strip())
            if literal is None:
                continue
            m = re.match(r"^(\d+)\.(\d+)", literal)
            if m:
                try:
                    return float(f"{m.group(1)}.{m.group(2)}")
                except ValueError:
                    pass
    # PHP_VERSION_ID >= 70400
    m = re.search(r"PHP_VERSION_ID\s*[<>=!]+\s*(\d{5,6})", text)
    if m:
        vid = int(m.group(1))
        major = vid // 10000
        minor = (vid // 100) % 100
        try:
            return float(f"{major}.{minor}")
        except ValueError:
            pass
    return None


def _extract_input_key(ref: str) -> str:
    if not ref:
        return ""
    m = re.match(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\[([^\]]+)\]", ref)
    if not m:
        return ""
    raw = m.group(1).strip()
    literal = _parse_php_string_literal(raw)
    if literal is not None:
        return literal
    return raw.strip("'\"")
