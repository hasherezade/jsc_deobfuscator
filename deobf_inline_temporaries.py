#!/usr/bin/env python3
# JSC Deobfuscator - static deobfuscation of View8 pseudocode generated from
# compiled V8 JavaScript bytecode.
#
# Copyright (C) 2026 Aleksandra "Hasherezade" Doniec @ Check Point Research
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""
Strict final-pass inlining of local V8 register temporaries.

The pass is deliberately fail-closed and limited to function-local registers.
It does not propagate global assignments and it does not perform unrelated
ACCU cleanup.

Candidate classes:

* primitive literals and plain aliases/named values may be propagated when the
  old register value has exactly one provable use and evaluation is not moved
  across a semantic barrier; primitive literals are never substituted into
  callee or spread positions;
* property reads may be propagated only into the immediately following visible
  statement, never into a property write, and only when no other property read
  would be evaluated before the substituted expression;
* property reads used as callees additionally require matching CallProperty*
  bytecode metadata, preserving detached-call versus method-call semantics.

Candidates and their original use sites are snapshotted before rewriting. A
line modified by this pass is never reinterpreted as a newly-created candidate,
which prevents transitive expression growth while still allowing several
independent aliases to be substituted into the same original target line. When
CallProperty* metadata proves that one register is the receiver of a downstream
property-callee temporary, that receiver definition is preserved so the safer
downstream substitution can reconstruct the method call explicitly.

General value inlining is disabled for every candidate whose definition-to-use
interval intersects a loop.  The sole exception is metadata-proven
``CallProperty*`` reconstruction of an immediately following method call,
which restores the receiver relation without moving evaluation across a
statement.  The pass intentionally does not otherwise try to reason about back
edges, per-iteration register lifetimes, skipped assignments, or repeated
property evaluation without a control-flow graph.

As a separate final cleanup, the pass may hide an exact ``return undefined``
that directly follows another visible return at the same indentation, but only
when View8 metadata shows no incoming bytecode edge into the later return block.
A hidden accumulator load marked as a jump target is therefore a hard barrier.
Other consecutive returns, including ``return r3``, remain visible for
investigation. At verbosity 1, preserved ambiguous or branch-target pairs are
reported with function and code indices; routine unreferenced fallback removals
are reported only at verbosity 2. This removes common decompiler fallback tails
without attempting general dead-code elimination or crossing a closing brace.
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple

from View8.Parser.shared_function_info import load_functions_from_file
from View8.view8_util import export_to_file
from deobf_commons import (
    mark_regs_used_and_defined,
    set_string_metadata,
    sync_string_metadata,
)


_ASSIGN_RE = re.compile(
    r"^(?P<indent>\s*)(?P<lhs>(?:r|a)\d+|ACCU)\s*=\s*(?P<rhs>.+?)\s*$"
)
_REG_ASSIGN_RE = re.compile(
    r"^(?P<indent>\s*)(?P<lhs>r\d+)\s*=\s*(?P<rhs>.+?)\s*$"
)
_GLOBAL_WRITE_RE = re.compile(
    r"^\s*global_[A-Za-z0-9_$]+(?:\s*|(?:\[[^\]]+\]|\.[A-Za-z_$][A-Za-z0-9_$]*)+)\s*="
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_FUNC_RE = re.compile(r"^func_[A-Za-z0-9_$]+_0x[0-9a-fA-F]+$")
_ALIAS_RE = re.compile(r"^(?:r|a)\d+$")
_NUMBER_RE = re.compile(r"^(?:-?\d+(?:\.\d+)?|\(-?\d+(?:\.\d+)?\))$")
_STRING_RE = re.compile(r'''^(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')$''')
_STRING_LITERAL_TOKEN_RE = re.compile(
    r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')'''
)
_ROOT_RE = (
    r"(?:<this>|[A-Za-z_$][A-Za-z0-9_$]*|(?:r|a)\d+|"
    r"Scope\[\d+\](?:\[\d+\])*)"
)
_PROPERTY_TAIL_RE = (
    r"(?:(?:\.[A-Za-z_$][A-Za-z0-9_$]*)|"
    r"(?:\[(?:\d+|@@S\d+@@|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')\]))+"
)
_PROP_RE = re.compile(rf"^{_ROOT_RE}{_PROPERTY_TAIL_RE}$")
_ANY_PROP_RE = re.compile(rf"{_ROOT_RE}{_PROPERTY_TAIL_RE}")
_SIMPLE_PROPERTY_BASE_RE = re.compile(
    r"^(?P<base><this>|(?:r|a)\d+|[A-Za-z_$][A-Za-z0-9_$]*)"
    r"(?=(?:\.|\[))"
)
_TOKEN_RE = re.compile(r"\b((?:r|a)\d+|ACCU)\b")
_CALLISH_RE = re.compile(r"(?:[A-Za-z_$][A-Za-z0-9_$]*|\])\s*\(")
_CONTROL_PREFIXES = (
    "if ", "if(", "else", "while ", "while(", "for ", "for(",
    "switch ", "switch(", "case ", "default:", "try", "catch",
    "finally", "do", "break", "continue", "throw", "yield",
)
_LOOP_HEADER_RE = re.compile(
    r"^(?:while\s*(?:\(|$)|for(?:\s+await)?\s*(?:\(|$)|do(?:\s*\{|$))"
)
_TERMINAL_PREFIXES = ("return", "throw")
_PRIMITIVES = {"true", "false", "null", "undefined", "NaN", "Infinity"}

KIND_PRIMITIVE = "primitive"
KIND_ALIAS = "alias"
KIND_NAMED = "named"
KIND_PROPERTY = "property"


@dataclass(frozen=True)
class Candidate:
    index: int
    register: str
    rhs: str
    dependencies: frozenset[str]
    kind: str
    original_line: str


@dataclass(frozen=True)
class UsePlan:
    use_index: int
    scan_end: int


def _mask_strings(text: str) -> Tuple[str, list[str]]:
    """Replace quoted strings with placeholders containing no identifiers."""
    stored: list[str] = []
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch not in ('"', "'"):
            out.append(ch)
            i += 1
            continue
        quote = ch
        start = i
        i += 1
        escaped = False
        while i < len(text):
            current = text[i]
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                i += 1
                break
            i += 1
        stored.append(text[start:i])
        out.append(f"@@S{len(stored) - 1}@@")
    return "".join(out), stored


def _restore_strings(text: str, stored: Sequence[str]) -> str:
    for index, value in enumerate(stored):
        text = text.replace(f"@@S{index}@@", value)
    return text


def _token_pattern(token: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?<![A-Za-z0-9_$]){re.escape(token)}(?![A-Za-z0-9_$])"
    )


def _count_token(text: str, token: str) -> int:
    masked, _ = _mask_strings(text)
    return len(_token_pattern(token).findall(masked))


def _replace_token(text: str, token: str, replacement: str) -> Tuple[str, int]:
    masked, stored = _mask_strings(text)
    replaced, count = _token_pattern(token).subn(
        lambda _match: replacement,
        masked,
    )
    return _restore_strings(replaced, stored), count


def _count_uses_in_line(text: str, token: str) -> int:
    """Count token uses while excluding a direct assignment LHS definition."""
    match = _ASSIGN_RE.match(text)
    if match:
        return _count_token(match.group("rhs"), token)
    return _count_token(text, token)


def _replace_use_in_line(
    text: str,
    token: str,
    replacement: str,
) -> Tuple[str, int]:
    """Replace token uses without replacing a direct assignment LHS."""
    match = _ASSIGN_RE.match(text)
    if not match:
        return _replace_token(text, token, replacement)
    new_rhs, count = _replace_token(match.group("rhs"), token, replacement)
    if not count:
        return text, 0
    return f'{match.group("indent")}{match.group("lhs")} = {new_rhs}', count


def _dependencies(rhs: str) -> frozenset[str]:
    masked, _ = _mask_strings(rhs)
    return frozenset(_TOKEN_RE.findall(masked))


def _candidate_kind(rhs: str) -> Optional[str]:
    rhs = rhs.strip()
    if _STRING_RE.match(rhs) or _NUMBER_RE.match(rhs) or rhs in _PRIMITIVES:
        return KIND_PRIMITIVE
    if _ALIAS_RE.match(rhs) or rhs == "<this>":
        return KIND_ALIAS
    if _FUNC_RE.match(rhs) or _IDENTIFIER_RE.match(rhs):
        return KIND_NAMED
    if _PROP_RE.match(rhs):
        return KIND_PROPERTY
    return None


def _metadata(obj) -> dict:
    value = getattr(obj, "metadata", None)
    return value if isinstance(value, dict) else {}


def _candidate_from_original_line(
    index: int,
    obj,
    original_line: str,
    max_rhs_len: int,
) -> Optional[Candidate]:
    # A target created by a previous local-temporary inlining pass is not a fresh candidate.
    if _metadata(obj).get("inlined_local_temporary_target"):
        return None
    match = _REG_ASSIGN_RE.match(original_line)
    if not match:
        return None
    rhs = match.group("rhs").strip()
    if len(rhs) > max_rhs_len:
        return None
    kind = _candidate_kind(rhs)
    if kind is None:
        return None
    register = match.group("lhs")
    dependencies = _dependencies(rhs)
    if register in dependencies or "ACCU" in dependencies:
        return None
    return Candidate(
        index=index,
        register=register,
        rhs=rhs,
        dependencies=dependencies,
        kind=kind,
        original_line=original_line,
    )


def _is_control_boundary(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped in {"{", "}"}:
        return True
    return stripped.startswith(_CONTROL_PREFIXES)


def _is_terminal(line: str) -> bool:
    stripped = line.strip()
    return any(
        stripped == prefix or stripped.startswith(prefix + " ")
        for prefix in _TERMINAL_PREFIXES
    )


def _is_property_write(line: str) -> bool:
    """Recognize a top-level assignment whose LHS evaluates a property."""
    masked, _ = _mask_strings(line)
    depth_round = 0
    depth_square = 0
    for index, ch in enumerate(masked):
        if ch == "(":
            depth_round += 1
        elif ch == ")":
            depth_round = max(0, depth_round - 1)
        elif ch == "[":
            depth_square += 1
        elif ch == "]":
            depth_square = max(0, depth_square - 1)
        elif ch == "=" and depth_round == 0 and depth_square == 0:
            prev_ch = masked[index - 1] if index else ""
            next_ch = masked[index + 1] if index + 1 < len(masked) else ""
            if prev_ch in "=!<>" or next_ch in "=>":
                continue
            lhs = masked[:index].strip()
            return bool("[" in lhs or "." in lhs)
    return False


def _is_simple_candidate_assignment(line: str) -> Optional[Tuple[str, str, str]]:
    match = _ASSIGN_RE.match(line)
    if not match:
        return None
    rhs = match.group("rhs").strip()
    kind = _candidate_kind(rhs)
    if kind is None:
        return None
    return match.group("lhs"), rhs, kind


def _is_movement_barrier(line: str, candidate_kind: str) -> bool:
    """Return True when delaying the candidate evaluation is unsafe."""
    stripped = line.strip()
    if not stripped:
        return False
    if _is_control_boundary(stripped) or _is_terminal(stripped):
        return True
    if _GLOBAL_WRITE_RE.match(stripped) or _is_property_write(stripped):
        return True
    if _CALLISH_RE.search(stripped):
        return True
    assignment = _is_simple_candidate_assignment(stripped)
    if assignment is None:
        return True
    _lhs, _rhs, intervening_kind = assignment
    # A bare named reference is re-evaluated at the use site. Do not delay it
    # past a getter/proxy-capable property read, which could mutate that name.
    if candidate_kind == KIND_NAMED and intervening_kind == KIND_PROPERTY:
        return True
    return False


def _next_visible_statement(original_lines: Sequence[Optional[str]], start: int) -> Optional[int]:
    for index in range(start, len(original_lines)):
        line = original_lines[index]
        if line and line.strip():
            return index
    return None


def _is_loop_header(line: str) -> bool:
    """Recognize loop headers emitted by View8's decompiled printer."""
    return _LOOP_HEADER_RE.match(line.strip()) is not None


def _loop_line_indices(
    original_lines: Sequence[Optional[str]],
) -> frozenset[int]:
    """Return visible code indices that belong to textual loop regions.

    View8 prints structured blocks with a standalone opening brace and a
    matching closing brace at the header indentation.  We deliberately use
    this conservative printed structure rather than infer bytecode back edges.
    A loop header, its braces, and every line in its body are marked.  For a
    braceless loop, the next visible statement is marked as its body.

    ``do { ... } while (...)`` tails are marked as part of the same loop and
    are not reinterpreted as the start of a second loop.
    """
    loop_indices: set[int] = set()
    do_while_tails: set[int] = set()

    for header_index, line in enumerate(original_lines):
        if line is None or header_index in do_while_tails:
            continue
        stripped = line.strip()
        if not _is_loop_header(stripped):
            continue

        loop_indices.add(header_index)
        header_indent = _leading_indent(line)
        is_do_loop = stripped == "do" or stripped.startswith("do {")

        if stripped.endswith("{"):
            open_index = header_index
        else:
            open_index = _next_visible_statement(
                original_lines,
                header_index + 1,
            )

        if (
            open_index is None
            or original_lines[open_index] is None
            or (
                open_index != header_index
                and original_lines[open_index].strip() != "{"
            )
        ):
            # Conservatively support a braceless one-statement loop.
            if open_index is not None:
                loop_indices.add(open_index)
            continue

        loop_indices.add(open_index)
        close_index: Optional[int] = None
        for index in range(open_index + 1, len(original_lines)):
            body_line = original_lines[index]
            if body_line is None or not body_line.strip():
                continue
            loop_indices.add(index)
            body_stripped = body_line.strip()
            if (
                body_stripped.startswith("}")
                and _leading_indent(body_line) == header_indent
            ):
                close_index = index
                break

        if not is_do_loop or close_index is None:
            continue

        tail_index = _next_visible_statement(original_lines, close_index + 1)
        if tail_index is None:
            continue
        tail_line = original_lines[tail_index]
        if (
            tail_line is not None
            and _leading_indent(tail_line) == header_indent
            and tail_line.strip().startswith("while")
        ):
            loop_indices.add(tail_index)
            do_while_tails.add(tail_index)

    return frozenset(loop_indices)


def _candidate_interval_touches_loop(
    candidate: Candidate,
    plan: UsePlan,
    loop_indices: frozenset[int],
) -> bool:
    """Return True when the definition-to-use interval intersects a loop.

    Checking the full interval also prevents moving a value from before a loop
    to after it, which could change evaluation count or observe mutations
    performed by the loop.
    """
    return any(
        index in loop_indices
        for index in range(candidate.index, plan.use_index + 1)
    )


def _loop_callproperty_reconstruction_is_safe(
    original_lines: Sequence[Optional[str]],
    candidate: Candidate,
    plan: UsePlan,
    use_obj,
) -> bool:
    """Allow only metadata-proven method-call reconstruction in loops.

    General value propagation remains disabled in and across loops.  The sole
    exception is the exact bytecode-shaped pattern::

        r23 = r24["method"]
        ACCU = r23(args)          # CallProperty* r23, r24, ...

    This does not move the property read across another statement or change its
    evaluation count.  It only restores the receiver relation already encoded
    by the V8 ``CallProperty*`` instruction.  Detached calls, aliases, literals,
    and upstream receiver substitutions do not qualify.
    """
    if candidate.kind != KIND_PROPERTY:
        return False

    original_target = original_lines[plan.use_index]
    if not original_target:
        return False

    if not _is_direct_callee_use(original_target, candidate.register):
        return False

    next_index = _next_visible_statement(original_lines, candidate.index + 1)
    if next_index != plan.use_index:
        return False

    return _property_callee_substitution_is_safe(candidate, use_obj)


def _old_value_scan_end(
    original_lines: Sequence[Optional[str]],
    start: int,
    register: str,
    definition_indent: str,
) -> Optional[int]:
    """Return the last index belonging to the current register lifetime.

    A V8 register may be reused for several unrelated temporary values.  Once a
    direct assignment at the same structural indentation overwrites the
    register, later textual uses belong to the new value and must not block
    inlining of the previous one.  Nested assignments are not treated as
    unconditional lifetime boundaries because their execution may be
    conditional.

    ``None`` means that another use of the current value was found before a
    provable overwrite.  Uses on the overwrite line itself are checked before
    the definition, preserving read-before-write forms such as ``r1 = r1``.
    """
    for index in range(start, len(original_lines)):
        line = original_lines[index]
        if not line or not line.strip():
            continue

        if _count_uses_in_line(line, register):
            return None

        assignment = _ASSIGN_RE.match(line)
        if (
            assignment
            and assignment.group("lhs") == register
            and assignment.group("indent") == definition_indent
        ):
            return index - 1

    return len(original_lines) - 1


def _find_unique_safe_use(
    original_lines: Sequence[Optional[str]],
    candidate: Candidate,
) -> Optional[UsePlan]:
    """Find exactly one original use of the candidate's old register value."""
    use_index: Optional[int] = None
    movement_safe = True
    nonlinear_seen = False

    for index in range(candidate.index + 1, len(original_lines)):
        line = original_lines[index]
        if not line or not line.strip():
            continue
        assignment = _ASSIGN_RE.match(line)
        defined = assignment.group("lhs") if assignment else None
        uses = _count_uses_in_line(line, candidate.register)

        if uses:
            if uses != 1 or use_index is not None or not movement_safe:
                return None
            use_index = index

        # The RHS is evaluated before the LHS write. This permits a form such
        # as r7 = r7(":") while still ending the old value's lifetime there.
        if defined == candidate.register:
            if use_index == index:
                return UsePlan(use_index=index, scan_end=index)
            if use_index is not None and not nonlinear_seen:
                return UsePlan(use_index=use_index, scan_end=index - 1)
            return None

        # Re-evaluating an alias/property after one of its source registers was
        # overwritten is unsafe. A dependency overwritten on the use line is
        # still read first on that line's RHS.
        if defined in candidate.dependencies and use_index != index:
            return None

        if use_index is None:
            if _is_movement_barrier(line, candidate.kind):
                movement_safe = False
            continue

        if index == use_index and _is_terminal(line):
            return UsePlan(use_index=use_index, scan_end=index)

        if _is_control_boundary(line):
            nonlinear_seen = True
            candidate_match = _REG_ASSIGN_RE.match(candidate.original_line)
            if candidate_match is None:
                return None
            scan_end = _old_value_scan_end(
                original_lines,
                index + 1,
                candidate.register,
                candidate_match.group("indent"),
            )
            if scan_end is None:
                return None
            return UsePlan(use_index=use_index, scan_end=scan_end)

        # Calls and writes after the first use are not movement concerns, but
        # scanning continues so a second use behind them cannot be missed.

    if use_index is None:
        return None
    return UsePlan(use_index=use_index, scan_end=len(original_lines) - 1)


def _opcode_and_operands(obj) -> Tuple[str, list[str]]:
    instruction = (getattr(obj, "v8_instruction", "") or "").strip()
    if not instruction:
        return "", []
    opcode, *rest = instruction.split(None, 1)
    opcode = opcode.split(".", 1)[0]
    operands = []
    if rest:
        operands = [part.strip() for part in rest[0].split(",")]
    return opcode, operands


def _is_direct_callee_use(line: str, register: str) -> bool:
    masked, _ = _mask_strings(line)
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9_$]){re.escape(register)}\s*\(",
            masked,
        )
    )


def _is_spread_use(line: str, register: str) -> bool:
    """Recognize a register used as a spread operand, including ``...(rN)``."""
    masked, _ = _mask_strings(line)
    return bool(
        re.search(
            rf"\.\.\.\s*(?:\(\s*)?{re.escape(register)}"
            rf"(?![A-Za-z0-9_$])",
            masked,
        )
    )


def _primitive_target_is_safe(line: str, register: str) -> bool:
    """Keep impossible/decompiler-specific primitive calls visible for analysis."""
    if _is_direct_callee_use(line, register):
        return False
    if _is_spread_use(line, register):
        return False
    return True


def _property_callee_substitution_is_safe(candidate: Candidate, use_obj) -> bool:
    """Preserve detached-call versus property-call receiver semantics."""
    if not _is_direct_callee_use(use_obj.decompiled, candidate.register):
        return True
    base_match = _SIMPLE_PROPERTY_BASE_RE.match(candidate.rhs)
    if not base_match:
        return False
    opcode, operands = _opcode_and_operands(use_obj)
    if not opcode.startswith("CallProperty") or len(operands) < 2:
        return False
    callee, receiver = operands[0], operands[1]
    return callee == candidate.register and receiver == base_match.group("base")


def _would_hide_callproperty_receiver(
    func,
    original_lines: Sequence[Optional[str]],
    candidate: Candidate,
    plan: UsePlan,
) -> bool:
    """Keep a receiver register needed by a downstream ``CallProperty*``.

    Consider the bytecode-shaped chain::

        r24 = object_expression
        r23 = r24["method"]
        ACCU = r23(args)          # CallProperty* r23, r24, ...

    Inlining ``r24`` into the second line first would leave a detached-looking
    ``r23(args)`` call and lose the explicit receiver relation in the printed
    pseudocode.  The snapshot pass would then refuse to reinterpret the changed
    ``r23`` definition, so the safer downstream transformation could no longer
    produce ``r24["method"](args)``.

    Reject only this exact, metadata-proven pattern.  Detached calls and
    non-callee property reads are unaffected.
    """
    target_line = original_lines[plan.use_index]
    if not target_line:
        return False

    target_match = _REG_ASSIGN_RE.match(target_line)
    if not target_match:
        return False

    target_rhs = target_match.group("rhs").strip()
    if _candidate_kind(target_rhs) != KIND_PROPERTY:
        return False

    base_match = _SIMPLE_PROPERTY_BASE_RE.match(target_rhs)
    if not base_match or base_match.group("base") != candidate.register:
        return False

    downstream = Candidate(
        index=plan.use_index,
        register=target_match.group("lhs"),
        rhs=target_rhs,
        dependencies=_dependencies(target_rhs),
        kind=KIND_PROPERTY,
        original_line=target_line,
    )
    downstream_plan = _find_unique_safe_use(original_lines, downstream)
    if downstream_plan is None:
        return False

    downstream_target = original_lines[downstream_plan.use_index]
    if not downstream_target or not _is_direct_callee_use(
        downstream_target,
        downstream.register,
    ):
        return False

    call_obj = func.code[downstream_plan.use_index]
    opcode, operands = _opcode_and_operands(call_obj)
    if not opcode.startswith("CallProperty") or len(operands) < 2:
        return False

    callee, receiver = operands[0], operands[1]
    return callee == downstream.register and receiver == candidate.register


def _property_access_before_use(line: str, register: str) -> bool:
    """Reject target lines that would move another property read before this one."""
    masked, _ = _mask_strings(line)
    match = _token_pattern(register).search(masked)
    if not match:
        return True
    prefix = masked[:match.start()]
    return _ANY_PROP_RE.search(prefix) is not None


def _target_is_allowed(
    original_lines: Sequence[Optional[str]],
    candidate: Candidate,
    plan: UsePlan,
    use_obj,
) -> bool:
    original_target = original_lines[plan.use_index]
    if not original_target:
        return False
    if _GLOBAL_WRITE_RE.match(original_target.strip()):
        return False

    if candidate.kind == KIND_PRIMITIVE:
        return _primitive_target_is_safe(
            original_target,
            candidate.register,
        )

    if candidate.kind != KIND_PROPERTY:
        return True

    # Property reads are moved only into the immediately following visible
    # statement. This prevents delayed getter/proxy evaluation.
    next_index = _next_visible_statement(original_lines, candidate.index + 1)
    if next_index != plan.use_index:
        return False

    # Evaluating a property-assignment reference before the substituted read
    # changes JavaScript evaluation order, so property candidates never enter a
    # property write.
    if _is_property_write(original_target):
        return False

    # The original property read occurred before the target statement. Do not
    # place it after another property access already present in that statement.
    if _property_access_before_use(original_target, candidate.register):
        return False

    return _property_callee_substitution_is_safe(candidate, use_obj)


def _no_remaining_use(func, candidate: Candidate, plan: UsePlan) -> bool:
    """Post-substitution invariant checked before hiding the definition."""
    for index in range(candidate.index + 1, plan.scan_end + 1):
        obj = func.code[index]
        if not obj.visible or not obj.decompiled:
            continue
        if _count_uses_in_line(obj.decompiled, candidate.register):
            return False
    return True


def _snapshot(func) -> list[Optional[str]]:
    original_lines: list[Optional[str]] = []
    for obj in func.code:
        if obj.visible and obj.decompiled:
            original_lines.append(obj.decompiled)
        else:
            original_lines.append(None)
    return original_lines



def _leading_indent(line: str) -> str:
    """Return the exact leading whitespace used for block comparison."""
    return line[:len(line) - len(line.lstrip())]


def _is_return_statement(line: str) -> bool:
    stripped = line.strip()
    return stripped == "return" or stripped.startswith("return ")


def _is_undefined_fallback_return(line: str) -> bool:
    """Recognize only the canonical decompiler fallback form."""
    return line.strip() == "return undefined"


def _get_metadata(obj, key: str):
    """Read View8 metadata without depending on one concrete object type."""
    getter = getattr(obj, "get_metadata", None)
    if callable(getter):
        return getter(key)
    metadata = getattr(obj, "metadata", None)
    if isinstance(metadata, dict):
        return metadata.get(key)
    return None


def _string_metadata_key(value: str) -> str:
    """Normalize one metadata value for exact literal-token matching.

    Most string-deobfuscation passes store the escaped literal contents, while
    the chain-joining helper currently stores the complete quoted literal.
    Treat those two representations as the same value without unescaping or
    doing substring matching.
    """
    stripped = value.strip()
    if _STRING_RE.fullmatch(stripped):
        return stripped[1:-1]
    return value


def _literal_keys_in_expression(expression: str) -> set[str]:
    """Return exact string-literal token contents from an expression."""
    return {
        match.group(0)[1:-1]
        for match in _STRING_LITERAL_TOKEN_RE.finditer(expression)
    }


def _propagate_string_metadata(
    source_obj,
    target_obj,
    propagated_expression: str,
) -> None:
    """Copy only annotations represented by the substituted expression.

    A source line may retain historical metadata for decoded chunks that were
    subsequently joined into a larger literal.  Copying the complete metadata
    set would therefore reintroduce fragments such as ``"ate"`` when the
    expression being propagated is ``"_inflate"``.  Only exact literal
    tokens present in the propagated RHS are transferred.
    """
    literal_keys = _literal_keys_in_expression(propagated_expression)
    if not literal_keys:
        return

    string_meta = _get_metadata(source_obj, "string")
    if isinstance(string_meta, str):
        values = (string_meta,)
    elif isinstance(string_meta, set):
        values = tuple(sorted(string_meta))
    else:
        return

    copied_keys = set()
    for value in values:
        if not isinstance(value, str):
            continue
        key = _string_metadata_key(value)
        if key not in literal_keys or key in copied_keys:
            continue
        set_string_metadata(target_obj, value)
        copied_keys.add(key)


def _jump_target_metadata_available(func) -> bool:
    """Return True only when View8 completed target analysis for the function."""
    return _get_metadata(func, "jump_target_metadata_available") is True


def _has_incoming_jump(obj) -> bool:
    """Return True when View8 marked this code object as a bytecode target."""
    if _get_metadata(obj, "is_jump_target") is True:
        return True
    count = _get_metadata(obj, "incoming_jump_count")
    return isinstance(count, int) and count > 0


def _incoming_jump_targets_between(func, previous_index: int, current_index: int):
    """Find branch targets that can independently enter the later return block.

    The range excludes the earlier return and includes the current return.  In
    normal View8 output the actual target is often an invisible accumulator
    load immediately before the visible ``return undefined`` line.
    """
    targets = []
    for index in range(previous_index + 1, current_index + 1):
        obj = func.code[index]
        if _has_incoming_jump(obj):
            targets.append((index, obj))
    return targets


def _format_incoming_jump_target(index: int, obj) -> str:
    opcode = (getattr(obj, "v8_instruction", "") or "").strip()
    incoming = _get_metadata(obj, "incoming_jumps") or []
    details = f"code[{index}]"
    if opcode:
        details += f" opcode={opcode!r}"
    if incoming:
        details += f" incoming={incoming!r}"
    return details


def remove_consecutive_returns_in_func(func, verbosity: int = 0) -> int:
    """Conservatively hide only an unreferenced ``return undefined`` tail.

    A directly consecutive, same-indent ``return undefined`` is removed only
    when View8 metadata shows no incoming jump target between the preceding
    visible return and the fallback return.  Invisible accumulator loads and
    placeholders remain textually ignorable, but a hidden bytecode target is a
    hard barrier.  Non-undefined pairs are preserved as ambiguous diagnostics.
    """
    previous_return: Optional[Tuple[str, str, int]] = None
    changes = 0

    for index, obj in enumerate(func.code):
        if not obj.visible or not obj.decompiled or not obj.decompiled.strip():
            continue

        line = obj.decompiled
        if _is_return_statement(line):
            indent = _leading_indent(line)
            if previous_return is not None and previous_return[0] == indent:
                previous_line = previous_return[1]
                previous_index = previous_return[2]

                if _is_undefined_fallback_return(line):
                    if not _jump_target_metadata_available(func):
                        metadata_error = _get_metadata(
                            func,
                            "jump_target_metadata_error",
                        )
                        if verbosity > 0:
                            print(
                                f"[{func.name}] preserve fallback return at "
                                f"code[{index}] after code[{previous_index}]"
                            )
                            print(f"    previous: {previous_line.strip()}")
                            print(f"    current:  {line.strip()}")
                            reason = "jump-target metadata unavailable"
                            if isinstance(metadata_error, str) and metadata_error:
                                reason += f": {metadata_error}"
                            else:
                                reason += "; regenerate with patched View8"
                            print(f"    reason: {reason}")
                        obj.set_metadata("preserved_consecutive_return", True)
                        obj.set_metadata(
                            "preserved_consecutive_return_reason",
                            "jump_target_metadata_unavailable",
                        )
                        previous_return = (indent, line, index)
                        continue

                    incoming_targets = _incoming_jump_targets_between(
                        func,
                        previous_index,
                        index,
                    )
                    if incoming_targets:
                        if verbosity > 0:
                            print(
                                f"[{func.name}] preserve branch-target fallback "
                                f"return at code[{index}] after code[{previous_index}]"
                            )
                            print(f"    previous: {previous_line.strip()}")
                            print(f"    current:  {line.strip()}")
                            print("    reason: incoming bytecode edge enters the fallback block")
                            for target_index, target_obj in incoming_targets:
                                print(
                                    "    target:   "
                                    + _format_incoming_jump_target(
                                        target_index,
                                        target_obj,
                                    )
                                )
                        obj.set_metadata("preserved_consecutive_return", True)
                        obj.set_metadata(
                            "preserved_consecutive_return_reason",
                            "incoming_jump_target",
                        )
                        obj.set_metadata(
                            "preserved_consecutive_return_target_indices",
                            [target_index for target_index, _ in incoming_targets],
                        )
                        previous_return = (indent, line, index)
                        continue

                    if verbosity > 1:
                        print(
                            f"[{func.name}] hide unreferenced fallback return "
                            f"at code[{index}] after code[{previous_index}]"
                        )
                        print(f"    previous: {previous_line.strip()}")
                        print(f"    removed:  {line.strip()}")
                    obj.visible = False
                    obj.set_metadata("removed_consecutive_return", True)
                    obj.set_metadata(
                        "removed_consecutive_return_kind",
                        "unreferenced_undefined_fallback",
                    )
                    changes += 1
                    # Keep the last visible return as the anchor so additional
                    # unreferenced fallback returns can be removed as well.
                    continue

                if verbosity > 0:
                    print(
                        f"[{func.name}] preserve ambiguous consecutive returns "
                        f"at code[{index}] after code[{previous_index}]"
                    )
                    print(f"    previous: {previous_line.strip()}")
                    print(f"    current:  {line.strip()}")
                    print(
                        "    reason: current return is not exact "
                        "'return undefined'"
                    )
                obj.set_metadata("ambiguous_consecutive_return", True)
                obj.set_metadata(
                    "ambiguous_consecutive_return_previous_index",
                    previous_index,
                )
                obj.set_metadata(
                    "ambiguous_consecutive_return_previous_line",
                    previous_line.strip(),
                )

            previous_return = (indent, line, index)
            continue

        previous_return = None

    return changes

def inline_temporaries_in_func(
    func,
    verbosity: int = 0,
    max_rounds: int = 1,
    max_rhs_len: int = 120,
    max_result_len: int = 600,
) -> int:
    """Apply one snapshot-based, non-transitive local inlining pass."""
    del max_rounds  # retained only for call-site compatibility

    original_lines = _snapshot(func)
    loop_indices = _loop_line_indices(original_lines)
    candidates: list[Candidate] = []
    for index, original_line in enumerate(original_lines):
        if original_line is None:
            continue
        candidate = _candidate_from_original_line(
            index,
            func.code[index],
            original_line,
            max_rhs_len,
        )
        if candidate is not None:
            candidates.append(candidate)

    changes = 0
    for candidate in candidates:
        def_obj = func.code[candidate.index]

        # If another substitution changed or hid this definition, using the
        # snapshot RHS would create a transitive candidate. Skip it.
        if (
            not def_obj.visible
            or not def_obj.decompiled
            or def_obj.decompiled != candidate.original_line
        ):
            continue

        plan = _find_unique_safe_use(original_lines, candidate)
        if plan is None:
            continue
        use_obj = func.code[plan.use_index]
        original_target = original_lines[plan.use_index]
        interval_touches_loop = _candidate_interval_touches_loop(
            candidate,
            plan,
            loop_indices,
        )
        if (
            interval_touches_loop
            and not _loop_callproperty_reconstruction_is_safe(
                original_lines,
                candidate,
                plan,
                use_obj,
            )
        ):
            if verbosity > 1:
                print(
                    f"[{func.name}] preserve {candidate.register}: "
                    "definition-to-use interval touches a loop"
                )
            continue
        if (
            original_target is None
            or not use_obj.visible
            or not use_obj.decompiled
            or _count_uses_in_line(original_target, candidate.register) != 1
            or _count_uses_in_line(use_obj.decompiled, candidate.register) != 1
        ):
            continue
        if _would_hide_callproperty_receiver(
            func,
            original_lines,
            candidate,
            plan,
        ):
            if verbosity > 1:
                print(
                    f"[{func.name}] preserve receiver {candidate.register} "
                    "for downstream CallProperty"
                )
            continue
        if not _target_is_allowed(
            original_lines,
            candidate,
            plan,
            use_obj,
        ):
            continue

        old_line = use_obj.decompiled
        new_line, replacements = _replace_use_in_line(
            old_line,
            candidate.register,
            candidate.rhs,
        )
        if replacements != 1 or len(new_line) > max_result_len:
            continue

        use_obj.decompiled = new_line
        if not _no_remaining_use(func, candidate, plan):
            use_obj.decompiled = old_line
            continue

        if verbosity > 1:
            print(
                f"[{func.name}] inline {candidate.kind} "
                f"{candidate.register} = {candidate.rhs}"
            )
            print(f"    before: {old_line.strip()}")
            print(f"    after:  {new_line.strip()}")

        # The defining line is about to become invisible. Preserve any decoded
        # string annotation on the visible line that now contains the value.
        _propagate_string_metadata(def_obj, use_obj, candidate.rhs)
        sync_string_metadata(use_obj)

        def_obj.visible = False
        def_obj.set_metadata("inlined_local_temporary", candidate.register)
        use_obj.set_metadata("inlined_local_temporary_target", True)
        mark_regs_used_and_defined(func)
        changes += 1

    return changes + remove_consecutive_returns_in_func(func, verbosity)


def inline_temporaries_default(
    functions: Dict[str, object],
    verbosity: int = 0,
) -> int:
    changed_functions = 0
    total_changes = 0
    for func in functions.values():
        changes = inline_temporaries_in_func(func, verbosity)
        if changes:
            changed_functions += 1
            total_changes += changes
    print(
        f"Applied strict local final-pass cleanup: {total_changes} change(s) "
        f"in {changed_functions} function(s)"
    )
    return total_changes


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Strictly inline single-use local register temporaries."
    )
    parser.add_argument("--inp", "-i", required=True, help="Serialized View8 input")
    parser.add_argument("--out", "-o", required=True, help="Output base path")
    parser.add_argument("--verbosity", "-v", type=int, default=0)
    parser.add_argument(
        "--export_format",
        "-e",
        nargs="+",
        choices=["v8_opcode", "translated", "decompiled", "serialized"],
        default=["serialized", "decompiled"],
    )
    args = parser.parse_args()
    if not os.path.isfile(args.inp):
        raise FileNotFoundError(args.inp)
    functions = load_functions_from_file(args.inp)
    inline_temporaries_default(functions, args.verbosity)
    export_to_file(args.out, functions, args.export_format)


if __name__ == "__main__":
    main()
