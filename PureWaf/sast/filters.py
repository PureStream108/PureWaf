from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import parser as php
from .parser import ParsedSource, Span


REGEX_FILTERS = {
    "preg_match",
    "preg_match_all",
    "mb_ereg",
    "mb_eregi",
    "mb_ereg_match",
}
WORD_FILTERS = {
    "str_contains",
    "str_starts_with",
    "str_ends_with",
    "strpos",
    "stripos",
    "strstr",
    "stristr",
}
IN_ARRAY_FILTERS = {"in_array", "array_search"}
REPLACE_FILTERS = {"str_replace", "str_ireplace"}
SANITIZERS = {
    "escapeshellarg",
    "escapeshellcmd",
    "addslashes",
    "stripslashes",
    "htmlspecialchars",
    "htmlentities",
    "intval",
    "floatval",
    "filter_var",
    "ctype_alnum",
    "ctype_digit",
    "ctype_alpha",
}


@dataclass
class Filter:
    kind: str
    target: str
    params: Dict[str, object] = field(default_factory=dict)
    span: Optional[Span] = None
    order: int = 0


def collect_string_constants(parsed: ParsedSource) -> Dict[str, str]:
    constants: Dict[str, str] = {}
    for node in php.walk(parsed.root):
        if node.type != "assignment_expression":
            continue
        left = php.child_by_field(node, "left")
        right = php.child_by_field(node, "right")
        if left is None or right is None or left.type != "variable_name":
            continue
        value = php.string_literal(right)
        if value is not None:
            constants[parsed.text(left).strip()] = value
    return constants


def _resolve_string(parsed: ParsedSource, node, constants: Dict[str, str]) -> Optional[str]:
    literal = php.string_literal(node)
    if literal is not None:
        return literal
    if node.type == "variable_name":
        return constants.get(parsed.text(node).strip())
    return None


def _resolve_array(parsed: ParsedSource, node, constants: Dict[str, str]) -> Optional[List[str]]:
    if node.type != "array_creation_expression":
        return None
    values: List[str] = []
    for child in php.named_children(node):
        if child.type == "array_element_initializer":
            inner = php.named_children(child)
            if not inner:
                continue
            value = _resolve_string(parsed, inner[0], constants)
            if value is None:
                return None
            values.append(value)
        else:
            value = _resolve_string(parsed, child, constants)
            if value is None:
                return None
            values.append(value)
    return values


def find_filters(parsed: ParsedSource) -> List[Filter]:
    constants = collect_string_constants(parsed)
    filters: List[Filter] = []
    order = 0
    for node in php.walk(parsed.root):
        if node.type != "function_call_expression":
            continue
        name = php.call_name(node)
        args = php.arguments_of(node)
        span = parsed.span(node)

        if name in REGEX_FILTERS and len(args) >= 2:
            pattern = _resolve_string(parsed, args[0], constants)
            if pattern is not None:
                filters.append(
                    Filter(
                        kind="regex",
                        target=parsed.text(args[1]).strip(),
                        params={"pattern": pattern, "function": name},
                        span=span,
                        order=order,
                    )
                )
                order += 1
            continue

        if name in WORD_FILTERS and len(args) >= 2:
            needle = _resolve_string(parsed, args[1], constants)
            if needle is not None:
                filters.append(
                    Filter(
                        kind="char" if len(needle) == 1 else "word",
                        target=parsed.text(args[0]).strip(),
                        params={"needle": needle, "function": name},
                        span=span,
                        order=order,
                    )
                )
                order += 1
            continue

        if name in IN_ARRAY_FILTERS and len(args) >= 2:
            values = _resolve_array(parsed, args[1], constants)
            if values is not None:
                filters.append(
                    Filter(
                        kind="in_array",
                        target=parsed.text(args[0]).strip(),
                        params={"values": values, "function": name},
                        span=span,
                        order=order,
                    )
                )
                order += 1
            continue

        if name in REPLACE_FILTERS and len(args) >= 3:
            search = _resolve_string(parsed, args[0], constants)
            if search is not None:
                filters.append(
                    Filter(
                        kind="char" if len(search) == 1 else "word",
                        target=parsed.text(args[2]).strip(),
                        params={"needle": search, "function": name},
                        span=span,
                        order=order,
                    )
                )
                order += 1
            continue

        if name == "strlen" and args:
            filters.append(
                Filter(
                    kind="length",
                    target=parsed.text(args[0]).strip(),
                    params={"function": name},
                    span=span,
                    order=order,
                )
            )
            order += 1
            continue

        if name in SANITIZERS and args:
            filters.append(
                Filter(
                    kind="sanitizer",
                    target=parsed.text(args[0]).strip(),
                    params={"name": name},
                    span=span,
                    order=order,
                )
            )
            order += 1

    return filters
