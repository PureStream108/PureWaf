from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable, Iterator, List, Optional, Tuple


class SastUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class Span:
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def as_dict(self) -> dict:
        return {
            "start_line": self.start_line,
            "start_col": self.start_col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }


@dataclass
class ParsedSource:
    source: str
    source_bytes: bytes
    tree: object
    errors: List[str] = field(default_factory=list)

    @property
    def root(self):
        return self.tree.root_node

    @property
    def has_error(self) -> bool:
        return bool(self.errors)

    def text(self, node) -> str:
        return self.source_bytes[node.start_byte : node.end_byte].decode(
            "utf-8", "replace"
        )

    def span(self, node) -> Span:
        return Span(
            node.start_point[0] + 1,
            node.start_point[1],
            node.end_point[0] + 1,
            node.end_point[1],
        )


_LANGUAGE = None
_PARSER = None
_LOCK = threading.Lock()


def available() -> bool:
    try:
        _ensure_parser()
    except SastUnavailable:
        return False
    return True


def _ensure_parser():
    global _LANGUAGE, _PARSER
    if _PARSER is not None:
        return _PARSER
    with _LOCK:
        if _PARSER is not None:
            return _PARSER
        try:
            import tree_sitter_php
            from tree_sitter import Language, Parser
        except Exception as exc:  # pragma: no cover - depends on optional extra
            raise SastUnavailable(
                "tree-sitter is not installed; pip install 'PureWaf[sast]'"
            ) from exc
        try:
            language = Language(tree_sitter_php.language_php())
        except Exception:
            language = Language(tree_sitter_php.language())
        _LANGUAGE = language
        _PARSER = Parser(language)
        return _PARSER


def _source_hash(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8", "surrogateescape")).hexdigest()


@lru_cache(maxsize=64)
def _parse_cached(digest: str, source: str) -> ParsedSource:
    parser = _ensure_parser()
    data = source.encode("utf-8", "surrogateescape")
    tree = parser.parse(data)
    errors = []
    for node in walk(tree.root_node):
        if node.type == "ERROR" or node.is_missing:
            errors.append(
                f"syntax error near line {node.start_point[0] + 1}: "
                + data[node.start_byte : node.end_byte].decode("utf-8", "replace")[:80]
            )
            if len(errors) >= 5:
                break
    return ParsedSource(source=source, source_bytes=data, tree=tree, errors=errors)


def parse(source: str) -> ParsedSource:
    return _parse_cached(_source_hash(source or ""), source or "")


def walk(node) -> Iterator[object]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        children = getattr(current, "children", None) or []
        stack.extend(reversed(children))


def child_by_field(node, name: str):
    try:
        return node.child_by_field_name(name)
    except Exception:
        return None


def named_children(node) -> List[object]:
    return [child for child in (getattr(node, "children", None) or []) if child.is_named]


def unwrap_parentheses(node):
    current = node
    while current is not None and current.type == "parenthesized_expression":
        children = named_children(current)
        if not children:
            break
        current = children[0]
    return current


def arguments_of(call_node) -> List[object]:
    arguments = child_by_field(call_node, "arguments")
    if arguments is None:
        for child in named_children(call_node):
            if child.type == "arguments":
                arguments = child
                break
    if arguments is None:
        return []
    result = []
    for child in named_children(arguments):
        child = unwrap_parentheses(child)
        if child.type == "argument":
            inner = named_children(child)
            if inner:
                child = unwrap_parentheses(inner[0])
        result.append(child)
    return result


def call_name(call_node) -> str:
    name = child_by_field(call_node, "function")
    if name is None:
        for child in named_children(call_node):
            if child.type == "name":
                name = child
                break
    if name is None:
        return ""
    return (getattr(name, "text", b"") or b"").decode("utf-8", "replace").lower()


def string_literal(node) -> Optional[str]:
    if node is None:
        return None
    if node.type == "string":
        raw = node.text.decode("utf-8", "replace")
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
            body = raw[1:-1]
            if raw[0] == "'":
                return body.replace("\\'", "'").replace("\\\\", "\\")
            return body
    if node.type == "encapsed_string":
        parts = named_children(node)
        if all(part.type == "string_content" for part in parts):
            return "".join(part.text.decode("utf-8", "replace") for part in parts)
    return None
