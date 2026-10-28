from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from . import parser as php
from .parser import ParsedSource, Span


_SUPERGLOBAL_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]",
    re.I,
)
_TERMINATORS = {"return_statement", "throw_expression", "break_statement", "continue_statement"}


@dataclass
class Assignment:
    var: str
    expr: str
    span: Span
    order: int


@dataclass
class FunctionInfo:
    name: str
    params: List[str]
    start_byte: int
    end_byte: int


def collect_assignments(parsed: ParsedSource) -> Dict[str, List[Assignment]]:
    result: Dict[str, List[Assignment]] = {}
    for node in php.walk(parsed.root):
        if node.type != "assignment_expression":
            continue
        left = php.child_by_field(node, "left")
        right = php.child_by_field(node, "right")
        if left is None or right is None or left.type != "variable_name":
            continue
        var = parsed.text(left).strip()
        result.setdefault(var, []).append(
            Assignment(
                var=var,
                expr=parsed.text(right).strip(),
                span=parsed.span(node),
                order=node.start_byte,
            )
        )
    return result


def collect_functions(parsed: ParsedSource) -> Dict[str, FunctionInfo]:
    functions: Dict[str, FunctionInfo] = {}
    for node in php.walk(parsed.root):
        if node.type != "function_definition":
            continue
        name_node = php.child_by_field(node, "name")
        if name_node is None:
            continue
        name = parsed.text(name_node).strip()
        params_node = None
        for child in php.named_children(node):
            if child.type == "formal_parameters":
                params_node = child
                break
        params: List[str] = []
        if params_node is not None:
            for child in php.named_children(params_node):
                if child.type != "simple_parameter":
                    continue
                for sub in php.named_children(child):
                    if sub.type == "variable_name":
                        params.append(parsed.text(sub).strip())
                        break
        functions[name] = FunctionInfo(name, params, node.start_byte, node.end_byte)
    return functions


def enclosing_function_name(parsed: ParsedSource, node) -> str:
    current = node
    while current is not None:
        if current.type == "function_definition":
            name_node = php.child_by_field(current, "name")
            return parsed.text(name_node).strip() if name_node is not None else ""
        current = getattr(current, "parent", None)
    return ""


def param_input_refs(
    parsed: ParsedSource,
    assignments: Dict[str, List[Assignment]],
    functions: Dict[str, FunctionInfo],
) -> Dict[Tuple[str, str], Set[str]]:
    refs: Dict[Tuple[str, str], Set[str]] = {}
    for node in php.walk(parsed.root):
        if node.type != "function_call_expression":
            continue
        name = php.call_name(node)
        info = functions.get(name)
        if info is None:
            continue
        args = php.arguments_of(node)
        for index, param in enumerate(info.params):
            if index >= len(args):
                break
            text = parsed.text(args[index]).strip()
            found = resolve_input_refs(text, assignments, before=node.start_byte)
            if found:
                refs.setdefault((name, param), set()).update(found)
    return refs


def resolve_sink_refs(
    parsed: ParsedSource,
    node,
    expr: str,
    assignments: Dict[str, List[Assignment]],
    param_refs: Dict[Tuple[str, str], Set[str]],
    functions: Dict[str, FunctionInfo],
) -> Set[str]:
    refs = resolve_input_refs(expr, assignments, before=getattr(node, "start_byte", None))
    if refs:
        return refs
    name = enclosing_function_name(parsed, node)
    if not name or name not in functions:
        return refs
    for var in re.findall(r"\$[A-Za-z_]\w*", expr or ""):
        refs.update(param_refs.get((name, var), set()))
    return refs


_INCLUDE_TYPES = {
    "include_expression",
    "include_once_expression",
    "require_expression",
    "require_once_expression",
}


def include_targets(parsed: ParsedSource) -> List[str]:
    targets: List[str] = []
    for node in php.walk(parsed.root):
        if node.type not in _INCLUDE_TYPES:
            continue
        children = php.named_children(node)
        if not children:
            continue
        literal = php.string_literal(children[-1])
        if literal is None:
            match = re.search(r"['\"]([^'\"]+\.php)['\"]", parsed.text(children[-1]))
            literal = match.group(1) if match else None
        if literal:
            targets.append(literal)
    return targets


def superglobal_refs(expr: str) -> Set[str]:
    refs = set()
    for match in _SUPERGLOBAL_RE.finditer(expr or ""):
        refs.add(f"$_{match.group(1).upper()}['{match.group(2)}']")
    return refs


def _last_assignment(
    var: str,
    assignments: Dict[str, List[Assignment]],
    before: Optional[int],
) -> Optional[Assignment]:
    items = assignments.get(var) or []
    if before is None:
        return items[-1] if items else None
    candidates = [item for item in items if item.order < before]
    return candidates[-1] if candidates else None


def resolve_input_refs(
    expr: str,
    assignments: Dict[str, List[Assignment]],
    seen: Optional[Set[str]] = None,
    before: Optional[int] = None,
) -> Set[str]:
    direct = superglobal_refs(expr)
    if direct:
        return direct
    seen = seen or set()
    refs: Set[str] = set()
    for var in re.findall(r"\$[A-Za-z_]\w*", expr or ""):
        if var.startswith("$_") or var in seen:
            continue
        assignment = _last_assignment(var, assignments, before)
        if assignment is None:
            continue
        refs.update(
            resolve_input_refs(
                assignment.expr,
                assignments,
                seen | {var},
                before=assignment.order,
            )
        )
    return refs


def _contains(ancestor, node) -> bool:
    return ancestor.start_byte <= node.start_byte and node.end_byte <= ancestor.end_byte


def _condition_text(parsed: ParsedSource, condition) -> str:
    if condition is None:
        return ""
    return parsed.text(php.unwrap_parentheses(condition)).strip()


def _is_negated(text: str) -> bool:
    return text.lstrip().startswith("!")


def _terminates(block) -> bool:
    if block is None:
        return False
    named = php.named_children(block)
    if not named:
        return False
    last = named[-1]
    if last.type in _TERMINATORS:
        return True
    if last.type == "expression_statement":
        text = last.text.decode("utf-8", "replace").strip().lower()
        return text.startswith(("exit", "die"))
    return False


def _switch_subject(parsed: ParsedSource, node):
    parent = node
    while parent is not None and parent.type != "switch_statement":
        parent = getattr(parent, "parent", None)
    if parent is None:
        return ""
    for child in php.named_children(parent):
        if child.type == "parenthesized_expression":
            return parsed.text(php.unwrap_parentheses(child)).strip()
    return ""


def _match_subject(parsed: ParsedSource, node):
    parent = node
    while parent is not None and parent.type != "match_expression":
        parent = getattr(parent, "parent", None)
    if parent is None:
        return ""
    for child in php.named_children(parent):
        if child.type == "parenthesized_expression":
            return parsed.text(php.unwrap_parentheses(child)).strip()
    return ""


def guard_conditions(parsed: ParsedSource, node) -> List[Tuple[str, str]]:
    guards: List[Tuple[str, str]] = []
    current = node
    while current is not None:
        parent = getattr(current, "parent", None)
        if parent is None:
            break

        if parent.type in {"if_statement", "else_if_clause"}:
            condition = php.child_by_field(parent, "condition")
            text = _condition_text(parsed, condition)
            body = php.child_by_field(parent, "body")
            alternative = php.child_by_field(parent, "alternative")
            negated = _is_negated(text)
            if body is not None and _contains(body, current):
                guards.append((text, "false" if negated else "true"))
            elif alternative is not None and _contains(alternative, current):
                guards.append((text, "true" if negated else "false"))
        elif parent.type == "case_statement":
            subject = _switch_subject(parsed, parent)
            value = ""
            for child in php.named_children(parent):
                if child.type != "break_statement":
                    value = parsed.text(child).strip()
                    break
            if subject and value:
                guards.append((f"{subject} == {value}", "true"))
        elif parent.type == "match_conditional_expression":
            subject = _match_subject(parsed, parent)
            condition = php.named_children(parent)
            if subject and condition:
                guards.append(
                    (f"{subject} == {parsed.text(condition[0]).strip()}", "true")
                )
        elif parent.type == "catch_clause":
            caught = ""
            for child in php.named_children(parent):
                if child.type == "type_list":
                    caught = parsed.text(child).strip()
                    break
            guards.append((f"catch {caught}".strip(), "true"))
        elif parent.type in {"compound_statement", "program"}:
            siblings = php.named_children(parent)
            for sibling in siblings:
                if sibling.start_byte >= current.start_byte:
                    break
                if sibling.type != "if_statement":
                    continue
                body = php.child_by_field(sibling, "body")
                alternative = php.child_by_field(sibling, "alternative")
                if alternative is not None or not _terminates(body):
                    continue
                condition = php.child_by_field(sibling, "condition")
                text = _condition_text(parsed, condition)
                if text:
                    guards.append((text, "true" if _is_negated(text) else "false"))
        current = parent
    return guards


def is_dead_branch(parsed: ParsedSource, node) -> bool:
    if node is None:
        return False
    for condition, polarity in guard_conditions(parsed, node):
        literal = condition.strip().strip("()").strip().lower()
        if literal in {"false", "0", "''", '""', "null"} and polarity == "true":
            return True
        if literal in {"true", "1"} and polarity == "false":
            return True
    parent = getattr(node, "parent", None)
    while parent is not None:
        if parent.type in {"compound_statement", "program"}:
            for sibling in php.named_children(parent):
                if sibling.start_byte >= node.start_byte:
                    break
                if sibling.type in _TERMINATORS:
                    return True
        parent = getattr(parent, "parent", None)
    return False
