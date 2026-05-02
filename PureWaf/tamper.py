import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Tuple

from . import utils


Transform = Callable[[str], Iterable[str]]


@dataclass(frozen=True)
class TamperPlugin:
    name: str
    technique: str
    description: str
    transform: Transform
    payload_contexts: Tuple[str, ...] = ("any", "shell_command")
    target_os: str = "unix"
    shell_only: bool = True
    auto_apply: bool = True
    trigger_chars: Tuple[str, ...] = ()
    trigger_on_words: bool = False
    trigger_on_regex: bool = False


def _replace_spaces(replacement: str) -> Transform:
    def transform(payload: str):
        if " " not in payload:
            return []
        return [payload.replace(" ", replacement)]

    return transform


def _replace_slash_with_env(payload: str):
    if "/" not in payload:
        return []
    return [payload.replace("/", "${PWD:0:1}")]


def _split_alpha_tokens(separator: str) -> Transform:
    pattern = re.compile(r"[A-Za-z]{2,}")

    def transform(payload: str):
        if not pattern.search(payload):
            return []
        return [pattern.sub(lambda match: separator.join(match.group(0)), payload)]

    return transform


def _insert_uninitialized_variable(payload: str):
    pattern = re.compile(r"[A-Za-z]{2,}")
    marker = "${PUREWAF_X}"
    if not pattern.search(payload):
        return []
    return [pattern.sub(lambda match: marker.join(match.group(0)), payload)]


def _alternate_case(payload: str):
    out = []
    upper = True
    for ch in payload:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    rendered = "".join(out)
    if rendered == payload:
        return []
    return [rendered]


_PLUGINS = (
    TamperPlugin(
        name="space2ifs",
        technique="tamper:space2ifs",
        description="Replace shell spaces with ${IFS}.",
        transform=_replace_spaces("${IFS}"),
        trigger_chars=(" ",),
        trigger_on_regex=True,
    ),
    TamperPlugin(
        name="space2htab",
        technique="tamper:space2htab",
        description="Replace shell spaces with horizontal tabs.",
        transform=_replace_spaces("\t"),
        trigger_chars=(" ",),
        trigger_on_regex=True,
    ),
    TamperPlugin(
        name="space2plus",
        technique="tamper:space2plus",
        description="Replace spaces with plus signs for URL-decoded sinks.",
        transform=_replace_spaces("+"),
        trigger_chars=(" ",),
        trigger_on_regex=True,
    ),
    TamperPlugin(
        name="slash2env",
        technique="tamper:slash2env",
        description="Replace / with a shell substring expansion that usually yields /.",
        transform=_replace_slash_with_env,
        trigger_chars=("/",),
        trigger_on_regex=True,
    ),
    TamperPlugin(
        name="singlequotes",
        technique="tamper:singlequotes",
        description="Split command words with empty single quotes.",
        transform=_split_alpha_tokens("''"),
        trigger_on_words=True,
        trigger_on_regex=True,
    ),
    TamperPlugin(
        name="doublequotes",
        technique="tamper:doublequotes",
        description="Split command words with empty double quotes.",
        transform=_split_alpha_tokens('""'),
        trigger_on_words=True,
        trigger_on_regex=True,
    ),
    TamperPlugin(
        name="backslashes",
        technique="tamper:backslashes",
        description="Split words with backslashes. Kept manual-only because command-token escapes are sink-dependent.",
        transform=_split_alpha_tokens("\\"),
        auto_apply=False,
        trigger_on_words=True,
        trigger_on_regex=True,
    ),
    TamperPlugin(
        name="uninitializedvariable",
        technique="tamper:uninitializedvariable",
        description="Insert a deterministic unset shell variable between letters.",
        transform=_insert_uninitialized_variable,
        trigger_on_words=True,
        trigger_on_regex=True,
    ),
    TamperPlugin(
        name="randomcase",
        technique="tamper:randomcase",
        description="Alternate letter case. Kept manual-only because Unix command names are case-sensitive.",
        transform=_alternate_case,
        auto_apply=False,
        trigger_on_words=True,
        trigger_on_regex=True,
    ),
)


def get_plugins():
    return list(_PLUGINS)


def get_plugin(name: str):
    normalized = (name or "").strip().lower()
    for plugin in _PLUGINS:
        if plugin.name == normalized:
            return plugin
    return None


def _context_allowed(plugin: TamperPlugin, payload_context: str):
    normalized = str(payload_context or "any").strip().lower()
    if normalized in {"php", "php_eval", "php_code", "eval"}:
        normalized = "php_code"
    elif normalized in {"shell", "shell_cmd", "shell_command", "command"}:
        normalized = "shell_command"
    else:
        normalized = "any"
    return "any" in plugin.payload_contexts or normalized in plugin.payload_contexts


def _triggered(plugin: TamperPlugin, reasons):
    reasons = reasons or {}
    blocked_chars = set(reasons.get("blocked_chars") or [])
    if blocked_chars and any(ch in blocked_chars for ch in plugin.trigger_chars):
        return True

    regex_match = reasons.get("regex_match")
    if plugin.trigger_on_regex and regex_match:
        if not plugin.trigger_chars:
            return True
        if any(ch in regex_match for ch in plugin.trigger_chars):
            return True

    blocked_words = reasons.get("blocked_words") or []
    if plugin.trigger_on_words and blocked_words:
        return True
    return False


def apply_contextual_tampers(payload, reasons, payload_context="any", shell_like=True):
    variants = []
    for plugin in _PLUGINS:
        if not plugin.auto_apply:
            continue
        if plugin.shell_only and not shell_like:
            continue
        if not _context_allowed(plugin, payload_context):
            continue
        if not _triggered(plugin, reasons):
            continue
        try:
            variants.extend(plugin.transform(payload))
        except Exception:
            continue
    return [item for item in utils.dedupe_preserve_order(variants) if item != payload]
