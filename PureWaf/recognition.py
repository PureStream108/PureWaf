from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .sast.parser import Span

ENGINES = ("heuristic", "sast", "both")
ENGINE_ENV_VAR = "PUREWAF_ENGINE"


@dataclass
class SinkFinding:
    kind: str
    function: str
    argument_index: int = 0
    target_expr: str = ""
    payload_context: str = "any"
    span: Optional[Span] = None


@dataclass
class SourceRef:
    superglobal: str
    key: str
    span: Optional[Span] = None


@dataclass
class FilterRule:
    kind: str
    target: str = ""
    params: Dict[str, object] = field(default_factory=dict)
    span: Optional[Span] = None
    order: int = 0


@dataclass
class PathCondition:
    guard: Optional[FilterRule]
    polarity: str = "true"
    span: Optional[Span] = None
    filter_polarity: str = ""


@dataclass
class RecognitionFinding:
    engine: str
    sink: SinkFinding
    sources: List[SourceRef] = field(default_factory=list)
    path_conditions: List[PathCondition] = field(default_factory=list)
    filters: List[FilterRule] = field(default_factory=list)
    spans: List[Span] = field(default_factory=list)
    confidence: float = 0.5
    notes: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    findings: List[RecognitionFinding] = field(default_factory=list)
    conflicts: List[Dict[str, object]] = field(default_factory=list)
    engine: str = "heuristic"
    notes: List[str] = field(default_factory=list)


def engine_from_env(default: str = "heuristic") -> str:
    value = str(os.environ.get(ENGINE_ENV_VAR, "") or "").strip().lower()
    return value if value in ENGINES else default


def _source_refs(refs) -> List[SourceRef]:
    sources = []
    for ref in refs or []:
        match = re.match(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[['\"]([^'\"]+)['\"]\]", str(ref))
        if match:
            sources.append(SourceRef(match.group(1).upper(), match.group(2)))
    return sources


def _heuristic_finding(source: str, use_llm: bool = False) -> Optional[RecognitionFinding]:
    from . import auto

    result = auto.analyze_php_auto(source, use_llm=use_llm)
    if result.error or not result.sink_kind:
        return None
    filters: List[FilterRule] = []
    for word in (result.waf_words or "").split("|"):
        word = word.strip()
        if word:
            filters.append(FilterRule(kind="char" if len(word) == 1 else "word", params={"needle": word}))
    for char in result.waf_chars or "":
        filters.append(FilterRule(kind="char", params={"needle": char}))
    if result.waf_regex:
        filters.append(FilterRule(kind="regex", params={"pattern": result.waf_regex}))
    notes = list(result.analysis_lines)
    return RecognitionFinding(
        engine="heuristic",
        sink=SinkFinding(
            kind=result.sink_kind,
            function=result.sink_function,
            target_expr="",
            payload_context=result.payload_context,
        ),
        sources=_source_refs(result.input_refs),
        filters=filters,
        confidence=0.7 if filters else 0.6,
        notes=notes,
    )


def _guard_filter_rule(text: str) -> Optional[FilterRule]:
    match = re.search(r"preg_match(?:_all)?\s*\(\s*(['\"])(.+?)\1", text or "", re.S)
    if match:
        return FilterRule(kind="regex", params={"pattern": match.group(2)})
    match = re.search(
        r"(str_contains|str_starts_with|str_ends_with|strpos|stripos)\s*\(\s*[^,]+,\s*(['\"])(.+?)\2",
        text or "",
        re.S,
    )
    if match:
        return FilterRule(
            kind="char" if len(match.group(3)) == 1 else "word",
            params={"needle": match.group(3), "function": match.group(1)},
        )
    match = re.search(r"in_array\s*\(\s*[^,]+,\s*\[(.*?)\]", text or "", re.S)
    if match:
        values = [item.strip().strip("'\"") for item in match.group(1).split(",")]
        return FilterRule(kind="in_array", params={"values": [item for item in values if item]})
    return None


def _sast_findings(source: str) -> Tuple[List[RecognitionFinding], List[str]]:
    from . import sast
    from .sast import cfg, filters as sast_filters, sinks as sast_sinks

    notes: List[str] = []
    if not sast.available():
        return [], ["sast unavailable: install the sast extra (tree-sitter, tree-sitter-php)"]
    parsed = sast.parse(source)
    if parsed.has_error:
        notes.extend(parsed.errors[:3])
    assignments = cfg.collect_assignments(parsed)
    functions = cfg.collect_functions(parsed)
    param_refs = cfg.param_input_refs(parsed, assignments, functions)
    all_filters = sast_filters.find_filters(parsed)
    findings: List[RecognitionFinding] = []
    for sink in sast_sinks.find_sinks(parsed, assignments):
        sink_node = _node_at(parsed, sink.span)
        if cfg.is_dead_branch(parsed, sink_node):
            notes.append(f"unreachable sink {sink.function} at line {sink.span.start_line}")
            continue
        sink_refs = cfg.resolve_sink_refs(
            parsed, sink_node, sink.target_expr, assignments, param_refs, functions
        )
        sources = _source_refs(sink_refs)
        related = [
            item
            for item in all_filters
            if item.target == sink.target_expr
            or cfg.resolve_sink_refs(
                parsed, sink_node, item.target, assignments, param_refs, functions
            )
            & sink_refs
        ]
        guards = cfg.guard_conditions(parsed, sink_node) if sink_node is not None else []
        path_conditions = []
        for text, polarity in guards:
            rule = _guard_filter_rule(text)
            filter_polarity = ""
            if rule is not None:
                negated = text.lstrip().startswith("!") or bool(
                    re.search(
                        r"!\s*(?:preg_match|str_contains|str_starts_with|str_ends_with|strpos|stripos|in_array)\b",
                        text,
                    )
                )
                must_match = (polarity == "true") != negated
                filter_polarity = "must_match" if must_match else "must_not_match"
            path_conditions.append(
                PathCondition(
                    guard=rule or FilterRule(kind="condition", params={"text": text}),
                    polarity=polarity,
                    filter_polarity=filter_polarity,
                )
            )
        positive_filters = {
            (
                condition.guard.kind,
                condition.guard.params.get("pattern")
                if condition.guard.kind == "regex"
                else condition.guard.params.get("needle"),
            )
            for condition in path_conditions
            if condition.guard is not None and condition.filter_polarity == "must_match"
        }
        kept_filters = []
        for item in related:
            key = (
                item.kind,
                item.params.get("pattern") if item.kind == "regex" else item.params.get("needle"),
            )
            if key in positive_filters:
                notes.append(
                    f"guard requires {key[1]!r} to match; not treated as a blacklist"
                )
                continue
            kept_filters.append(item)

        findings.append(
            RecognitionFinding(
                engine="sast",
                sink=SinkFinding(
                    kind=sink.kind,
                    function=sink.function,
                    argument_index=sink.argument_index,
                    target_expr=sink.target_expr,
                    payload_context=sink.payload_context,
                    span=sink.span,
                ),
                sources=sources,
                path_conditions=path_conditions,
                filters=[
                    FilterRule(
                        kind=item.kind,
                        target=item.target,
                        params=dict(item.params),
                        span=item.span,
                        order=item.order,
                    )
                    for item in kept_filters
                ],
                spans=[sink.span],
                confidence=0.85 if related else 0.75,
                notes=list(sink.notes or []),
            )
        )
    return findings, notes


def _node_at(parsed, span: Optional[Span]):
    if span is None:
        return None
    for node in _walk_all(parsed.root):
        if node.start_point[0] + 1 == span.start_line and node.start_point[1] == span.start_col:
            return node
    return None


def _walk_all(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(getattr(current, "children", None) or [])


def recognize(source: str, engine: str = "heuristic", use_llm: bool = False) -> AnalysisResult:
    engine = engine if engine in ENGINES else "heuristic"
    if engine == "heuristic":
        finding = _heuristic_finding(source, use_llm=use_llm)
        return AnalysisResult(
            findings=[finding] if finding else [],
            engine=engine,
            notes=[] if finding else ["heuristic engine found no supported sink"],
        )
    if engine == "sast":
        findings, notes = _sast_findings(source)
        return AnalysisResult(findings=findings, engine=engine, notes=notes)

    heuristic = _heuristic_finding(source, use_llm=use_llm)
    sast_findings, notes = _sast_findings(source)
    merged = arbitrate(([heuristic] if heuristic else []) + sast_findings)
    merged.engine = "both"
    merged.notes.extend(notes)
    return merged


def arbitrate(findings: List[RecognitionFinding]) -> AnalysisResult:
    result = AnalysisResult(findings=[], conflicts=[])
    heuristic = [item for item in findings if item.engine == "heuristic"]
    sast = [item for item in findings if item.engine == "sast"]

    def key(finding: RecognitionFinding):
        return (finding.sink.kind, finding.sink.function)

    sast_by_key = {key(item): item for item in sast}
    heuristic_by_key = {key(item): item for item in heuristic}

    for k, item in sast_by_key.items():
        other = heuristic_by_key.get(k)
        if other is None:
            item.notes.append("sast_only")
            item.confidence = min(item.confidence, 0.8)
            result.findings.append(item)
            continue
        merged = RecognitionFinding(
            engine="both",
            sink=item.sink,
            sources=item.sources or other.sources,
            path_conditions=item.path_conditions or other.path_conditions,
            filters=item.filters or other.filters,
            spans=item.spans or other.spans,
            confidence=0.95,
            notes=item.notes + ["engines agree"],
        )
        if _filter_signature(item.filters) != _filter_signature(other.filters):
            result.conflicts.append(
                {
                    "type": "conflict_filter",
                    "sink": k,
                    "sast": _filter_signature(item.filters),
                    "heuristic": _filter_signature(other.filters),
                    "resolution": "sast path conditions win; heuristic filters kept as soft warnings",
                }
            )
            merged.confidence = 0.8
        result.findings.append(merged)

    for k, item in heuristic_by_key.items():
        if k in sast_by_key:
            continue
        item.notes.append("heuristic_only")
        item.confidence = min(item.confidence, 0.5)
        result.findings.append(item)
        result.conflicts.append(
            {
                "type": "heuristic_only",
                "sink": k,
                "resolution": "low confidence; require oracle or LLM confirmation",
            }
        )

    if not sast and heuristic:
        result.conflicts.append(
            {"type": "sast_missing", "resolution": "sast produced no finding for this source"}
        )
    return result


def recognize_project(
    files: Dict[str, str], entry: str = "", engine: str = "sast"
) -> AnalysisResult:
    if not files:
        return AnalysisResult(engine=engine, notes=["empty project"])
    entry = entry or next(iter(files))
    result = AnalysisResult(engine=engine)
    queue: List[str] = [entry]
    seen: set = set()
    from . import sast
    from .sast import cfg

    while queue:
        path = queue.pop(0)
        if path in seen or path not in files:
            continue
        seen.add(path)
        analysis = recognize(files[path], engine)
        for finding in analysis.findings:
            finding.notes.append(f"file={path}")
            result.findings.append(finding)
        result.notes.extend(analysis.notes)
        result.conflicts.extend(analysis.conflicts)
        if sast.available():
            parsed = sast.parse(files[path])
            for target in cfg.include_targets(parsed):
                resolved = os.path.normpath(
                    os.path.join(os.path.dirname(path), target)
                ).replace("\\", "/")
                if resolved in files and resolved not in seen:
                    queue.append(resolved)
    return result


def _filter_signature(filters: List[FilterRule]):
    return sorted(
        (item.kind, str(item.params.get("needle") or item.params.get("pattern") or ""))
        for item in filters
    )
