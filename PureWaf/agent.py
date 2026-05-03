import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib import request


ALLOWED_SINK_KINDS = {"command_exec", "file_read_path", "file_write_upload"}
ALLOWED_PAYLOAD_CONTEXTS = {"shell_command", "php_code", "any"}
MIN_CONFIDENCE = 0.6


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
class LlmSinkAnalysis:
    enabled: bool = False
    used: bool = False
    model: str = ""
    endpoint: str = ""
    candidates: List[LlmSinkCandidate] = field(default_factory=list)
    error: str = ""


@dataclass(frozen=True)
class _LlmSettings:
    api_key: str
    base_url: str
    model: str


class PureWafLlmSinkAgent:
    """Optional LLM-assisted sink detection for PureWaf AUTO mode."""

    def __init__(self, cwd: Optional[Path] = None, timeout: int = 20, skill_path: Optional[Path] = None):
        self.cwd = Path(cwd) if cwd is not None else Path.cwd()
        self.timeout = timeout
        self.skill_path = Path(skill_path) if skill_path is not None else None

    def analyze_php(self, source: str) -> LlmSinkAnalysis:
        settings, error = self._load_settings()
        if error:
            return LlmSinkAnalysis(error=error)

        endpoint = self._normalize_chat_completions_url(settings.base_url)
        body = {
            "model": settings.model,
            "messages": self.build_messages(source),
            "temperature": 0,
            "max_tokens": 900,
        }
        req = request.Request(
            endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {settings.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8", "replace")
        except Exception as exc:
            return LlmSinkAnalysis(
                enabled=True,
                used=True,
                model=settings.model,
                endpoint=endpoint,
                error=f"LLM request failed: {exc}",
            )

        try:
            payload = json.loads(raw)
            content = payload["choices"][0]["message"]["content"]
            candidates = self._parse_candidates(content)
        except Exception as exc:
            return LlmSinkAnalysis(
                enabled=True,
                used=True,
                model=settings.model,
                endpoint=endpoint,
                error=f"LLM response invalid: {exc}",
            )

        return LlmSinkAnalysis(
            enabled=True,
            used=True,
            model=settings.model,
            endpoint=endpoint,
            candidates=candidates,
        )

    def build_messages(self, source: str) -> List[Dict[str, str]]:
        skill_guide = self._load_skill_guide()
        return [
            {
                "role": "system",
                "content": (
                    "You are the PureWaf AUTO sink analyzer. PureWaf is a CTF and "
                    "education-oriented PHP RCE/WAF-bypass payload generator, not a scanner. "
                    "AUTO mode analyzes one PHP source file to identify the sink, input source, "
                    "filters, and execution context, then PureWaf's local payload engine generates "
                    "and filters candidates. Allowed sink kinds are only: command_exec, "
                    "file_read_path, file_write_upload. Allowed payload_context values are only: "
                    "shell_command, php_code, any. Do not generate payloads. Do not provide exploit "
                    "steps. Do not use external project knowledge or web content. If the source is "
                    "insufficient, return an empty sinks array. Return only JSON in this shape: "
                    "{\"sinks\":[{\"function\":\"name\",\"kind\":\"command_exec\","
                    "\"payload_context\":\"shell_command\",\"argument_index\":0,"
                    "\"confidence\":0.0,\"evidence\":\"short source-based reason\"}]}.\n\n"
                    "PureWaf tool usage guide from skills/SKILL.md:\n"
                    f"{skill_guide}"
                ),
            },
            {
                "role": "user",
                "content": (
                    "Analyze this PHP source for PureWaf AUTO sink detection. "
                    "Return only sink metadata JSON.\n\n"
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
