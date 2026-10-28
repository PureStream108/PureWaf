from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from . import parser as php
from .parser import ParsedSource, Span


COMMAND_SINKS = {
    "system": "shell_command",
    "exec": "shell_command",
    "shell_exec": "shell_command",
    "passthru": "shell_command",
    "popen": "shell_command",
    "proc_open": "shell_command",
    "pcntl_exec": "shell_command",
    "eval": "php_code",
    "assert": "php_code",
}

FILE_READ_SINKS = {
    "file_get_contents",
    "readfile",
    "highlight_file",
    "show_source",
    "file",
    "fopen",
    "readgzfile",
    "gzfile",
}

FILE_WRITE_SINKS = {
    "file_put_contents": 1,
    "fwrite": 1,
    "fputs": 1,
    "copy": 1,
    "move_uploaded_file": 1,
    "rename": 1,
}

CALLBACK_SINKS = {
    "call_user_func": 0,
    "call_user_func_array": 0,
    "forward_static_call": 0,
    "forward_static_call_array": 0,
    "array_map": 0,
    "array_walk": 1,
    "array_walk_recursive": 1,
    "array_filter": 1,
    "usort": 1,
    "uasort": 1,
    "uksort": 1,
    "ob_start": 0,
    "register_shutdown_function": 0,
    "set_error_handler": 0,
    "preg_replace_callback": 1,
}

INCLUDE_NODE_TYPES = {
    "include_expression": "include",
    "include_once_expression": "include_once",
    "require_expression": "require",
    "require_once_expression": "require_once",
}


@dataclass
class Sink:
    kind: str
    function: str
    argument_index: int
    target_expr: str
    span: Span
    payload_context: str
    array_input: bool = False
    notes: Optional[List[str]] = None


def _has_user_input(text: str) -> bool:
    lowered = (text or "").lower()
    return any(
        marker in lowered
        for marker in ("$_get", "$_post", "$_request", "$_cookie", "$_files", "$_server")
    )


def _expr_text(parsed: ParsedSource, node) -> str:
    return parsed.text(php.unwrap_parentheses(node)).strip()


def _input_related(
    text: str,
    assignments,
    before: int = None,
    parsed=None,
    node=None,
    param_refs=None,
    functions=None,
) -> bool:
    if _has_user_input(text):
        return True
    if not assignments and not param_refs:
        return False
    from . import cfg

    if cfg.resolve_input_refs(text, assignments or {}, before=before):
        return True
    if parsed is not None and node is not None and param_refs and functions:
        return bool(
            cfg.resolve_sink_refs(
                parsed, node, text, assignments or {}, param_refs, functions
            )
        )
    return False


def find_sinks(parsed: ParsedSource, assignments=None) -> List[Sink]:
    from . import cfg

    functions = cfg.collect_functions(parsed)
    param_refs = cfg.param_input_refs(parsed, assignments or {}, functions)
    sinks: List[Sink] = []
    for node in php.walk(parsed.root):
        node_type = node.type
        if node_type == "function_call_expression":
            _collect_call(parsed, node, sinks, assignments, param_refs, functions)
        elif node_type in INCLUDE_NODE_TYPES:
            _collect_include(parsed, node, sinks, assignments, param_refs, functions)
        elif node_type == "shell_command_expression":
            text = parsed.text(node)
            if _has_user_input(text):
                sinks.append(
                    Sink(
                        kind="command_exec",
                        function="backtick",
                        argument_index=0,
                        target_expr=text,
                        span=parsed.span(node),
                        payload_context="shell_command",
                    )
                )
    return sinks


def _collect_call(
    parsed: ParsedSource,
    node,
    sinks: List[Sink],
    assignments=None,
    param_refs=None,
    functions=None,
) -> None:
    name = php.call_name(node)
    if not name:
        return
    args = php.arguments_of(node)

    if name in COMMAND_SINKS:
        if not args:
            return
        target = args[0]
        text = _expr_text(parsed, target)
        if _input_related(text, assignments, node.start_byte, parsed, node, param_refs, functions):
            sinks.append(
                Sink(
                    kind="command_exec",
                    function=name,
                    argument_index=0,
                    target_expr=text,
                    span=parsed.span(node),
                    payload_context=COMMAND_SINKS[name],
                )
            )
        return

    if name in FILE_READ_SINKS:
        if not args:
            return
        text = _expr_text(parsed, args[0])
        if _input_related(text, assignments, node.start_byte, parsed, node, param_refs, functions):
            sinks.append(
                Sink(
                    kind="file_read_path",
                    function=name,
                    argument_index=0,
                    target_expr=text,
                    span=parsed.span(node),
                    payload_context="file_path",
                )
            )
        return

    if name in FILE_WRITE_SINKS:
        index = FILE_WRITE_SINKS[name]
        if len(args) <= index:
            return
        text = _expr_text(parsed, args[index])
        if _input_related(text, assignments, node.start_byte, parsed, node, param_refs, functions):
            sinks.append(
                Sink(
                    kind="file_write_upload",
                    function=name,
                    argument_index=index,
                    target_expr=text,
                    span=parsed.span(node),
                    payload_context="php_code",
                )
            )
        return

    if name in CALLBACK_SINKS:
        index = CALLBACK_SINKS[name]
        if len(args) <= index:
            return
        callback = args[index]
        if name in {"call_user_func_array", "forward_static_call_array"} and len(args) >= 2:
            carrier = args[1]
            carrier_text = _expr_text(parsed, carrier)
            if _input_related(carrier_text, assignments, node.start_byte, parsed, node, param_refs, functions):
                sinks.append(
                    Sink(
                        kind="command_exec",
                        function=name,
                        argument_index=1,
                        target_expr=carrier_text,
                        span=parsed.span(node),
                        payload_context="shell_command",
                        array_input=True,
                    )
                )
                return
        text = _expr_text(parsed, callback)
        if _input_related(text, assignments, node.start_byte, parsed, node, param_refs, functions):
            sinks.append(
                Sink(
                    kind="command_exec",
                    function=name,
                    argument_index=index,
                    target_expr=text,
                    span=parsed.span(node),
                    payload_context="php_code",
                )
            )


def _collect_include(
    parsed: ParsedSource,
    node,
    sinks: List[Sink],
    assignments=None,
    param_refs=None,
    functions=None,
) -> None:
    children = php.named_children(node)
    if not children:
        return
    target = children[-1]
    text = _expr_text(parsed, target)
    if not _input_related(text, assignments, node.start_byte, parsed, node, param_refs, functions):
        return
    sinks.append(
        Sink(
            kind="php_include",
            function=INCLUDE_NODE_TYPES[node.type],
            argument_index=0,
            target_expr=text,
            span=parsed.span(node),
            payload_context="file_path",
        )
    )
