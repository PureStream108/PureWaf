import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib import request


ALLOWED_SINK_KINDS = {"command_exec", "file_read_path", "file_write_upload"}
ALLOWED_PAYLOAD_CONTEXTS = {"shell_command", "php_code", "any"}
MIN_CONFIDENCE = 0.6
PHP_PROJECT_EXTENSIONS = {".php", ".phtml", ".inc"}
PROJECT_SKIP_DIRS = {".git", "__MACOSX", "node_modules", "vendor"}
MAX_PROJECT_FILES = 80
MAX_PROJECT_FILE_BYTES = 1024 * 1024
MAX_PROJECT_SOURCE_BYTES = 2 * 1024 * 1024


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


@dataclass
class LlmPayloadReview:
    used: bool = False
    model: str = ""
    endpoint: str = ""
    valid: bool = False
    fallback_payload: str = ""
    notes: str = ""
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

        content, endpoint, chat_error = self._chat_completion(
            settings,
            self.build_messages(source),
            max_tokens=900,
        )
        if chat_error:
            return LlmSinkAnalysis(
                enabled=True,
                used=True,
                model=settings.model,
                endpoint=endpoint,
                error=chat_error,
            )

        try:
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

    def _chat_completion(
        self,
        settings: "_LlmSettings",
        messages: List[Dict[str, str]],
        max_tokens: int,
    ) -> Tuple[str, str, str]:
        endpoint = self._normalize_chat_completions_url(settings.base_url)
        body = {
            "model": settings.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": max_tokens,
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
            return "", endpoint, f"LLM request failed: {exc}"

        try:
            payload = json.loads(raw)
            content = payload["choices"][0]["message"]["content"]
        except Exception as exc:
            return "", endpoint, f"LLM response invalid: {exc}"
        return str(content), endpoint, ""

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


class PureWafProjectAgent(PureWafLlmSinkAgent):
    """Project-level LLM helper for PureWaf agent AUTO mode."""

    def scan_project_files(self, project_dir: Path) -> List[ProjectSourceFile]:
        root = Path(project_dir).resolve()
        if not root.is_dir():
            raise ValueError("project directory not found")

        files: List[ProjectSourceFile] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(root).parts
            if any(part in PROJECT_SKIP_DIRS for part in rel_parts[:-1]):
                continue
            if path.suffix.lower() not in PHP_PROJECT_EXTENSIONS:
                continue

            size = path.stat().st_size
            with path.open("rb") as handle:
                raw = handle.read(MAX_PROJECT_FILE_BYTES + 1)
            truncated = len(raw) > MAX_PROJECT_FILE_BYTES
            content = raw[:MAX_PROJECT_FILE_BYTES].decode("utf-8", "replace")
            files.append(
                ProjectSourceFile(
                    path=path.relative_to(root).as_posix(),
                    content=content,
                    size=size,
                    truncated=truncated,
                )
            )
            if len(files) >= MAX_PROJECT_FILES:
                break

        if not files:
            raise ValueError("no PHP files found in project")
        return files

    def build_project_source(self, project_dir: Path) -> ProjectSourceBundle:
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

        return ProjectSourceBundle(
            root=root,
            files=selected_files,
            selected_paths=selected_paths,
            source=source,
            analysis_lines=lines,
        )

    def select_project_files(self, files: Sequence[ProjectSourceFile]) -> Tuple[List[str], str]:
        settings, error = self._load_settings()
        if error:
            return [], error

        content, _endpoint, chat_error = self._chat_completion(
            settings,
            self.build_project_selection_messages(files),
            max_tokens=900,
        )
        if chat_error:
            return [], chat_error

        valid_paths = {file.path for file in files}
        try:
            selected = self._parse_selected_paths(content, valid_paths)
        except Exception as exc:
            return [], f"LLM project selection invalid: {exc}"
        return selected, ""

    def build_project_selection_messages(
        self, files: Sequence[ProjectSourceFile]
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
                    "You are selecting PHP files for PureWaf agent AUTO analysis. "
                    "Choose only project files that are relevant to user input, filtering, "
                    "routing, and dangerous sink reachability. Return only JSON shaped as "
                    "{\"selected_files\":[\"relative/path.php\"],\"reason\":\"short reason\"}. "
                    "Do not generate payloads in this step."
                ),
            },
            {
                "role": "user",
                "content": "Project PHP file inventory:\n\n" + "\n\n---\n\n".join(file_blocks),
            },
        ]

    @staticmethod
    def _parse_selected_paths(content: str, valid_paths: Set[str]) -> List[str]:
        parsed = PureWafLlmSinkAgent._load_json_content(content)
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
    ) -> LlmPayloadReview:
        settings, error = self._load_settings()
        if error:
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
            ),
            max_tokens=1000,
        )
        if chat_error:
            return LlmPayloadReview(
                used=True,
                model=settings.model,
                endpoint=endpoint,
                error=chat_error,
            )

        try:
            review = self._parse_payload_review(content)
        except Exception as exc:
            return LlmPayloadReview(
                used=True,
                model=settings.model,
                endpoint=endpoint,
                error=f"LLM payload review invalid: {exc}",
            )
        review.used = True
        review.model = settings.model
        review.endpoint = endpoint
        return review

    def build_payload_review_messages(
        self,
        source: str,
        analysis_lines: Sequence[str],
        shortest_root: str,
        shortest_flag: str,
        root_payloads: Sequence[str],
        flag_payloads: Sequence[str],
    ) -> List[Dict[str, str]]:
        payload_summary = {
            "shortest_root": shortest_root,
            "shortest_flag": shortest_flag,
            "root_payloads": list(root_payloads[:8]),
            "flag_payloads": list(flag_payloads[:8]),
            "analysis_lines": list(analysis_lines[-20:]),
        }
        return [
            {
                "role": "system",
                "content": (
                    "You are reviewing PureWaf-generated payloads for a CTF/education PHP "
                    "RCE/WAF-bypass scenario. Use only the supplied source and PureWaf output. "
                    "If PureWaf produced a usable payload, statically judge whether it fits the "
                    "detected sink/filter context. If PureWaf produced no usable payload, you may "
                    "provide one fallback payload. Return only JSON shaped as "
                    "{\"valid\":true,\"fallback_payload\":\"\",\"notes\":\"short source-based note\"}."
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
    def _parse_payload_review(content: str) -> LlmPayloadReview:
        parsed = PureWafLlmSinkAgent._load_json_content(content)
        return LlmPayloadReview(
            valid=bool(parsed.get("valid", False)),
            fallback_payload=str(parsed.get("fallback_payload", "") or "").strip()[:1000],
            notes=str(parsed.get("notes", "") or "").strip()[:500],
        )
