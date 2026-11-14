#!/usr/bin/env python3
# JSC Deobfuscator - static deobfuscation of View8 pseudocode generated from
# compiled V8 JavaScript bytecode.
#
# Copyright (C) 2026 Aleksandra "Hasherezade" Doniec
# SPDX-License-Identifier: GPL-2.0-or-later
"""Variant 3: custom-Base64 chunks, numeric index wrappers, no RC4.

This is deliberately conservative. It replaces direct calls only where the
callee's arithmetic chain reaches the explicitly supplied Base64 leaf, and
where the index is a literal or a property of a locally known constant object.
Unresolved register, scope, or indirect calls are preserved for later passes.
Only load trusted, locally generated View8 pickle files.
"""

import argparse
import ast
import json
import re
from pathlib import Path
from collections import Counter
from dataclasses import dataclass

from View8.Parser.shared_function_info import load_functions_from_file
from View8.view8_util import export_to_file
from deobf_commons import customB64, load_string_array, set_string_metadata, simplify_chain_assignments, save_string_list, hide_safe_unreferenced_constants
from deobf_scope2 import propagate_variables_default
from deobf_str2 import _fold_adjacent_string_literals_in_line

FUNC = r'func_[A-Za-z0-9_$]+_0x[0-9a-fA-F]+'
FUNC_CALL = re.compile(r'(?<![A-Za-z0-9_$])(' + FUNC + r')\s*\(')
RET_CALL = re.compile(r'^return\s+(' + FUNC + r')\s*\(\s*(r\d+|a[01])\s*,\s*(r\d+|a[01])\s*\)\s*$')
ASSIGN = re.compile(r'^(r\d+)\s*=\s*(.*?)\s*$')
LEAF_SHIFT = re.compile(r'^a0\s*=\s*\(\s*a0\s*([+-])\s*(\d+)\s*\)\s*$')
DICT_DEF = re.compile(r'^(r\d+)\s*=\s*new\s*(\{.*\})\s*$')
R_PROP = re.compile(r'^(r\d+)\["([^"\\]+)"\]$')
INT = re.compile(r'^-?\d+$')
BLOCK = re.compile(r'^(?:[{}]|else\b|catch\b|finally\b|if\b|while\b|for\b|do\b|switch\b|case\b|default\s*:|try\b)')
FUNCTION_REF = re.compile(r'(?<![A-Za-z0-9_$])(' + FUNC + r')(?![A-Za-z0-9_$])')
_CUSTOM_B64_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
_ADJACENT_LITERAL_OPERATOR = re.compile(r'"\s*\+\s*"')

@dataclass(frozen=True)
class Wrapper:
    parent: str
    input_slot: int    # Which public argument is the numeric index?
    parent_slot: int   # Where is that index forwarded to the parent?
    subtract: int      # Signed subtraction relative to the parent input.


@dataclass(frozen=True)
class Resolved:
    subtract: int      # array index = input - subtract
    input_slot: int
    depth: int


@dataclass
class DecoderGraph:
    """One verified variant-3 decoder family and its caller-to-callee tree."""
    provider: str
    leaf: str
    chunks: list
    leaf_shift: int
    resolved: dict
    detected: dict
    pending: dict
    auxiliary: set
    provider_aliases: set

    def as_dict(self):
        """Export edges in call direction, without embedding the string array."""
        nodes = []
        for name, value in sorted(self.resolved.items()):
            nodes.append({"name": name, "role": "leaf" if name == self.leaf else "wrapper",
                          "subtract": value.subtract, "index_argument": value.input_slot,
                          "depth": value.depth})
        nodes.append({"name": self.provider, "role": "chunk_array_provider"})
        for name in sorted(self.auxiliary - {self.provider} - set(self.resolved)):
            nodes.append({"name": name, "role": "decoder_auxiliary"})
        edges = []
        for name in sorted(set(self.resolved) - {self.leaf}):
            wrapper = self.detected[name]
            edges.append({"caller": name, "callee": wrapper.parent, "type": "wrapper_call"})
        edges.append({"caller": self.leaf, "callee": self.provider, "type": "array_lookup"})
        for name in sorted(self.auxiliary):
            if name == self.provider:
                continue
            # The array provider aliases its cache helper; the leaf references
            # the Base64 decoder helper. The exact relationship is recognizable
            # from the corresponding function body, not inferred from names.
            src = self.provider if name in self.provider_aliases else self.leaf
            edges.append({"caller": src, "callee": name, "type": "decoder_helper"})
        return {"variant": 3, "leaf": self.leaf, "provider": self.provider,
                "chunks": len(self.chunks), "connected_wrappers": len(self.resolved) - 1,
                "disconnected_wrapper_candidates": len(self.pending),
                "nodes": nodes, "edges": edges}



def visible_lines(func):
    """Return executable pseudocode statements, excluding View8 body braces.

    Real View8 functions keep the opening and closing braces as *visible*
    CodeLine objects. They are not part of the wrapper's statements: in
    particular, the final visible line is `}`, not the `return` statement.
    """
    result = []
    for line in func.code:
        if not getattr(line, 'visible', True) or not line.decompiled:
            continue
        statement = line.decompiled.strip()
        if statement and statement not in ('{', '}'):
            result.append(statement)
    return result


def parse_integer_dict(source):
    try:
        value = ast.literal_eval(source)
    except (SyntaxError, ValueError, MemoryError, TypeError):
        return None
    if isinstance(value, dict) and value and all(isinstance(k, str) and type(v) is int for k, v in value.items()):
        return value
    return None


def atom_number(expr, locals_map):
    """Only literal arithmetic and local constant-dictionary reads; never eval."""
    expr = expr.strip()
    if INT.fullmatch(expr):
        return int(expr)
    m = R_PROP.fullmatch(expr)
    if m:
        return locals_map.get(m.group(1), {}).get(m.group(2))
    return None


def signed_number(expr, locals_map):
    expr = expr.strip()
    if expr.startswith('(') and expr.endswith(')'):
        expr = expr[1:-1].strip()
    if expr.startswith('-'):
        number = atom_number(expr[1:].strip(), locals_map)
        return -number if number is not None else None
    if expr.startswith('+'):
        return atom_number(expr[1:].strip(), locals_map)
    return atom_number(expr, locals_map)


def parse_wrapper(func):
    """Recognize straight-line wrappers, rejecting extra side effects.

    Examples:
      r1 = (a0 - 1512); return func_X(r1, a1)
      r2 = new {"l":682}; r1 = (a0 - (-r2["l"])); return func_X(r1,a1)
    """
    lines = visible_lines(func)
    if not (2 <= len(lines) <= 9):
        return None
    m = RET_CALL.fullmatch(lines[-1])
    if not m:
        return None
    parent, arg0, arg1 = m.groups()
    reg_defs = {}
    known = {}
    for line in lines[:-1]:
        d = DICT_DEF.fullmatch(line)
        if d:
            name, value = d.groups()
            value = parse_integer_dict(value)
            if value is None or name in known:
                return None
            known[name] = value
            continue
        a = ASSIGN.fullmatch(line)
        if not a or a.group(1) in reg_defs:
            return None
        name, expression = a.groups()
        if expression == 'Scope[0]':  # View8 closure initialization
            continue
        # Detect the index-bearing arithmetic register, preserving its source slot.
        arithmetic = re.fullmatch(r'\(\s*(a[01])\s*([+-])\s*(.+?)\s*\)', expression)
        if not arithmetic:
            return None
        source, operation, operand = arithmetic.groups()
        value = signed_number(operand, known)
        if value is None:
            return None
        reg_defs[name] = (int(source[1]), value if operation == '-' else -value)
    args = (arg0, arg1)
    mapped = [(slot, reg_defs[arg]) for slot, arg in enumerate(args) if arg in reg_defs]
    if len(mapped) != 1 or len(reg_defs) != 1:
        return None
    parent_slot, (source_slot, subtract) = mapped[0]
    # Require the other argument to be forwarded unchanged. Do not assume
    # that the second argument is meaningless for an unrelated decoder.
    if args[1 - parent_slot] != f'a{1 - source_slot}':
        return None
    return Wrapper(parent, source_slot, parent_slot, subtract)


def infer_leaf_shift(func):
    lines = visible_lines(func)
    # This path is safe only if the leaf does not consume its a1 parameter.
    if any(re.search(r'\ba1\b', line) for line in lines):
        raise ValueError('Base64 leaf uses a1; this variant-3 assumption is invalid')
    candidates = []
    for line in lines:
        m = LEAF_SHIFT.fullmatch(line)
        if m:
            op, delta = m.groups()
            candidates.append(int(delta) * (1 if op == '-' else -1))
    if len(candidates) != 1:
        raise ValueError(f'Expected one constant a0 shift in the leaf; found {candidates}')
    return candidates[0]


def resolve_graph(functions, root, leaf_shift):
    """Resolve only wrappers whose argument flow reaches the selected leaf."""
    detected = {name: d for name, fn in functions.items()
                if (d := parse_wrapper(fn)) is not None}
    resolved = {root: Resolved(leaf_shift, 0, 0)}
    pending = dict(detected)
    while pending:
        added = []
        for name, d in pending.items():
            parent = resolved.get(d.parent)
            if parent is None or parent.input_slot != d.parent_slot:
                continue
            resolved[name] = Resolved(parent.subtract + d.subtract,
                                      d.input_slot, parent.depth + 1)
            added.append(name)
        if not added:
            break
        for name in added:
            del pending[name]
    return resolved, detected, pending


def split_call_arguments(line, begin):
    """Parse two uncomplicated arguments; reject calls with nested calls.

    begin is the character just after the opening parenthesis. Bracketed
    dictionary property reads and parenthesized signed numbers are allowed.
    """
    depth = 0
    bracket = 0
    quote = None
    escaped = False
    pieces = []
    last = begin
    for pos in range(begin, min(len(line), begin + 600)):
        ch = line[pos]
        if quote:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
        elif ch == '[':
            bracket += 1
        elif ch == ']':
            bracket -= 1
            if bracket < 0:
                return None
        elif ch == '(':
            depth += 1
        elif ch == ')':
            if depth == 0:
                pieces.append(line[last:pos].strip())
                return (pieces, pos + 1) if bracket == 0 else None
            depth -= 1
        elif ch == ',' and depth == 0 and bracket == 0:
            pieces.append(line[last:pos].strip())
            last = pos + 1
    return None


def numeric_index(expr, known):
    expr = expr.strip()
    while expr.startswith('(') and expr.endswith(')'):
        expr = expr[1:-1].strip()
    return signed_number(expr, known)


def replace_in_line(obj, resolved, chunks, known, counters, verbosity=0):
    """Replace proven direct calls, starting from the rightmost occurrence."""
    line = obj.decompiled or ''
    candidates = list(FUNC_CALL.finditer(line))
    if not candidates:
        return
    changed = False
    for m in reversed(candidates):
        callee = m.group(1)
        if callee not in resolved:
            continue
        args_match = split_call_arguments(line, m.end())
        if not args_match:
            counters['unparsed_calls'] += 1
            continue
        args, end = args_match
        rule = resolved[callee]
        if len(args) not in (1, 2) or rule.input_slot >= len(args):
            counters['unsupported_arity'] += 1
            continue
        value = numeric_index(args[rule.input_slot], known)
        if value is None:
            counters['unresolved_indices'] += 1
            continue
        location = value - rule.subtract
        if not (0 <= location < len(chunks)):
            counters['index_out_of_bounds'] += 1
            continue
        try:
            decoded = customB64(chunks[location])
        except (ValueError, UnicodeError, TypeError):
            counters['decode_errors'] += 1
            continue
        # json.dumps creates a double-quoted JS-compatible string token.
        quoted = json.dumps(decoded, ensure_ascii=True)
        line = line[:m.start()] + quoted + line[end:]
        set_string_metadata(obj, decoded)
        counters['replaced'] += 1
        changed = True
        if verbosity > 1:
            print(f'{callee}({value}, ...) -> array[{location}] -> {decoded!r}')
    if changed:
        obj.decompiled = line
        # Use the same safe literal folding for newly decoded calls as for
        # pre-existing literal expressions.
        _fold_literal_pairs_in_visible_line(obj, verbosity, '<decoder replacement>')


def _fold_literal_pairs_in_visible_line(obj, verbosity, name):
    """Fold adjacent string literals using the variant-2 implementation."""
    raw = obj.decompiled
    if '+' not in raw or not _ADJACENT_LITERAL_OPERATOR.search(raw):
        return 0
    return _fold_adjacent_string_literals_in_line(obj, verbosity, name)
    

def process_calls(functions, resolved, chunks, verbosity=0, function_names=None):
    """Process only visible functions, ignoring decoder implementations."""
    counters = Counter()
    if function_names is None:
        selected = functions.items()
    else:
        selected = ((name, functions[name]) for name in function_names if name in functions)
    for name, func in selected:
        if name in resolved or not getattr(func, 'visible', True):
            continue
        known = {}
        for obj in func.code:
            if not getattr(obj, 'visible', True) or not obj.decompiled:
                continue
            # Decoder replacement folds the lines it changes, but View8 can
            # also emit literal + literal expressions that contain no decoder
            # call (including inside return expressions and property accesses).
            # Fold them here while walking the code for decoder calls, rather
            # than paying for a second corpus-wide scan. Refreshes already
            # restrict this walk to changed functions.
            joined = _fold_literal_pairs_in_visible_line(obj, verbosity, name)
            if joined:
                counters['adjacent_literals_folded'] += joined
            line = obj.decompiled.strip()
            # Local property values are valid only in the same straight-line
            # block. Invalidate on branches rather than guessing the path.
            if BLOCK.match(line):
                known.clear()
                # Calls in conditions can still have literal indices.
                if 'func_' in line:
                    replace_in_line(obj, resolved, chunks, known, counters, verbosity)
                continue
            d = DICT_DEF.fullmatch(line)
            if d:
                var, literal = d.groups()
                known.pop(var, None)
                values = parse_integer_dict(literal)
                if values is not None:
                    known[var] = values
            # Existing direct calls may follow constant-dictionary setup.
            if 'func_' in line:
                replace_in_line(obj, resolved, chunks, known, counters, verbosity)
            a = ASSIGN.fullmatch(line)
            if a and not d:
                known.pop(a.group(1), None)
    return counters



def identify_auxiliary_string_helpers(functions, strfunc, deobf_root):
    """Identify the array provider's cached alias and the leaf's Base64 helper.

    Only a concrete provider-alias assignment or a function containing the
    expected custom Base64 alphabet qualifies. Do not hide unrelated functions
    merely because they are called by the leaf.
    """
    auxiliary = set()
    provider = functions.get(strfunc)
    if provider is not None:
        alias_pattern = re.compile(r'^' + re.escape(strfunc) + r'\s*=\s*(' + FUNC + r')$')
        for line in visible_lines(provider):
            match = alias_pattern.fullmatch(line)
            if match and match.group(1) in functions:
                auxiliary.add(match.group(1))

    leaf = functions.get(deobf_root)
    if leaf is not None:
        for line in visible_lines(leaf):
            # We only consider a helper referenced as the RHS of an assignment.
            match = re.search(r'=\s*(' + FUNC + r')\s*$', line)
            if not match:
                continue
            name = match.group(1)
            candidate = functions.get(name)
            if candidate is None or name in (strfunc, deobf_root):
                continue
            # This specific decoder scheme is already identified by its
            # custom alphabet. A different decoder must not be guessed here.
            if any(_CUSTOM_B64_ALPHABET in (obj.decompiled or '')
                   for obj in candidate.code):
                auxiliary.add(name)
    return auxiliary


# Auto-discovery is intentionally separate from caller-graph resolution. A
# wrapper-shaped function by itself is not evidence of string deobfuscation.
# The leaf must be tied to a chunk array AND the custom Base64 implementation.
_ARRAY_MIN_ENTRIES = 64
_INDEXED_CHUNK = re.compile(r'\br\d+\s*\[\s*a0\s*\]')


def _chunk_array_candidates(functions, selected=None):
    """Find large string arrays whose entries resemble short Base64 chunks.

    Parsing only sizeable array literals avoids ast parsing of unrelated const
    pools. No function metadata is changed during discovery.
    """
    selected = [selected] if selected else functions.keys()
    arrays = {}
    for name in selected:
        func = functions.get(name)
        if func is None:
            continue
        for literal in func.const_pool:
            if not (literal.startswith('[') and len(literal) >= 256):
                continue
            try:
                values = ast.literal_eval(literal)
            except (SyntaxError, ValueError, MemoryError, TypeError):
                continue
            if not isinstance(values, list) or len(values) < _ARRAY_MIN_ENTRIES:
                continue
            if not all(isinstance(v, str) for v in values):
                continue
            # Don't mistake arbitrary long literal arrays for an encoded pool.
            alphabet = set(_CUSTOM_B64_ALPHABET)
            plausible = sum(1 for v in values if 2 <= len(v) <= 32 and set(v) <= alphabet)
            if plausible / len(values) < .95:
                continue
            arrays[name] = values
            break
    return arrays


def _b64_helper_names(functions):
    # The distinctive alphabet is constant-pool data even when View8 has
    # hidden or simplified the instructions referencing it.
    return {name for name, func in functions.items()
            if any(_CUSTOM_B64_ALPHABET in value for value in func.const_pool)}


def _provider_alias(func, provider):
    pattern = re.compile(r'^' + re.escape(provider) + r'\s*=\s*(' + FUNC + r')$')
    return {m.group(1) for line in visible_lines(func)
            if (m := pattern.fullmatch(line))}


def _matches_base64_leaf(func, provider, helpers):
    lines = visible_lines(func)
    if not any(_INDEXED_CHUNK.search(line) for line in lines):
        return False
    # Require an invocation (not just an incidental mention) of the provider.
    if not any(re.search(r'\b' + re.escape(provider) + r'\s*\(\s*\)', line)
               for line in lines):
        return False
    if not any(re.search(r'=\s*' + re.escape(helper) + r'\s*$', line)
               for line in lines for helper in helpers):
        return False
    try:
        infer_leaf_shift(func)
    except ValueError:
        return False
    return True


def auto_discover_variant3_decoder_graph(functions, strfunc=None, deobf_root=None):
    """Auto-select a unique evidence-backed (array provider, leaf) pair.

    Optional names act as constraints/overrides for backwards compatibility.
    Without overrides, refuse ambiguity rather than choosing a guess. The
    graph includes *only* straightforward wrappers connected to the leaf.
    """
    if strfunc and strfunc not in functions:
        raise ValueError(f'Specified chunk-array function not found: {strfunc}')
    if deobf_root and deobf_root not in functions:
        raise ValueError(f'Specified leaf decoder not found: {deobf_root}')
    if strfunc and deobf_root:
        # Preserve the earlier API and its small synthetic test arrays. The
        # caller has explicitly supplied both identities; don't impose the
        # automatic discovery heuristics on this manual override.
        chunks = load_string_array(functions, strfunc)
        arrays = {strfunc: chunks} if chunks else {}
    else:
        arrays = _chunk_array_candidates(functions, strfunc)
    if not arrays:
        raise ValueError('No candidate custom-Base64 chunk arrays found')
    helpers = _b64_helper_names(functions) if not deobf_root else set()
    matches = []
    # Explicit names preserve the existing manual fallback. Unspecified names
    # must satisfy both structural tests and a connected wrapper graph.
    for provider, chunks in arrays.items():
        if deobf_root:
            leaf_candidates = [deobf_root]
        else:
            leaf_candidates = []
            for name, func in functions.items():
                if name == provider:
                    continue
                # Cheap early filter before building statement lists.
                if any(provider + '()' in (obj.decompiled or '') for obj in func.code):
                    leaf_candidates.append(name)
        for leaf in leaf_candidates:
            func = functions[leaf]
            if deobf_root and not strfunc and not any(
                    provider + '()' in (obj.decompiled or '') for obj in func.code):
                continue
            if not deobf_root and not _matches_base64_leaf(func, provider, helpers):
                continue
            try:
                leaf_shift = infer_leaf_shift(func)
            except ValueError:
                continue
            resolved, detected, pending = resolve_graph(functions, leaf, leaf_shift)
            if len(resolved) <= 1:
                continue
            auxiliary = identify_auxiliary_string_helpers(functions, provider, leaf)
            if not deobf_root and not (auxiliary & helpers):
                continue
            aliases = _provider_alias(functions[provider], provider)
            matches.append(DecoderGraph(provider, leaf, chunks, leaf_shift,
                                        resolved, detected, pending,
                                        auxiliary, aliases))
    if not matches:
        raise ValueError('No uniquely connected Base64 decoder family found; '
                         'use --strfunc and --deobf-root to inspect manually')
    if len(matches) != 1:
        names = ', '.join(f'{m.leaf} -> {m.provider} ({len(m.resolved)-1} wrappers)'
                          for m in matches[:8])
        raise ValueError(f'Ambiguous Base64 decoder families ({len(matches)}): {names}. '
                         'Supply --strfunc / --deobf-root to disambiguate')
    return matches[0]


def write_variant3_graph(graph, path):
    """Write explicit caller/callee edges for auditing and later cleanup."""
    Path(path).write_text(json.dumps(graph.as_dict(), indent=2) + '\n', encoding='utf-8')


def hide_variant3_decoder_functions(functions, resolved, strfunc, deobf_root,
                                    policy='applied'):
    """Hide identified string helpers *after* successful variant-3 decoding.

    ``applied`` matches variant 2: hide decoded wrapper implementations,
    the leaf, chunk-array provider and positively identified auxiliary helpers.
    Some unresolved call sites can remain visible; this is a presentation-only
    transformation, and their targets remain intact in the serialized objects.

    ``referenced`` is conservative: any helper still referenced by a visible
    non-helper function remains visible, along with its dependencies. This
    includes first-class/indirect references, not only direct calls.
    """
    if policy not in ('applied', 'referenced'):
        raise ValueError(f'Unknown decoder hiding policy: {policy}')
    if deobf_root not in resolved or deobf_root not in functions or strfunc not in functions:
        raise ValueError('Decoder root or chunk array provider is unavailable')

    auxiliary = identify_auxiliary_string_helpers(functions, strfunc, deobf_root)
    candidates = (set(resolved) | {strfunc} | auxiliary) & set(functions)
    retained = set()
    external_references = set()
    residual_direct_calls = 0
    for name, func in functions.items():
        if name in candidates or not getattr(func, 'visible', True):
            continue
        for obj in func.code:
            if not getattr(obj, 'visible', True) or not obj.decompiled or 'func_' not in obj.decompiled:
                continue
            source = obj.decompiled
            names = {m.group(1) for m in FUNCTION_REF.finditer(source)} & candidates
            if not names:
                continue
            external_references.update(names)
            residual_direct_calls += sum(1 for m in FUNC_CALL.finditer(source)
                                         if m.group(1) in candidates)

    if policy == 'referenced':
        # Preserve all ancestors of externally referenced decoder wrappers;
        # otherwise retaining an unresolved wrapper without its parent and
        # leaf would still leave the source listing incomplete.
        retained.update(external_references)
        pending = list(retained)
        while pending:
            name = pending.pop()
            deps = set()
            if name in resolved and name != deobf_root:
                # The graph is resolved, but the wrapper body names its parent
                # explicitly. Only follow recognized direct wrapper parents.
                wrapper = parse_wrapper(functions[name])
                if wrapper is not None:
                    deps.add(wrapper.parent)
            if name == deobf_root:
                deps.add(strfunc)
                deps.update(auxiliary - {strfunc})
            if name == strfunc:
                deps.update(auxiliary)
            for dependency in deps & candidates:
                if dependency not in retained:
                    retained.add(dependency)
                    pending.append(dependency)

    hidden = 0
    for name in candidates - retained:
        func = functions[name]
        if getattr(func, 'visible', True):
            func.visible = False
            hidden += 1

    return {'identified': len(candidates), 'hidden': hidden,
            'retained': len(retained), 'external_references': len(external_references),
            'unresolved_direct_calls': residual_direct_calls,
            'auxiliary': len(auxiliary)}


def discover_variant3_decoder_graph(functions, strfunc=None, deobf_root=None):
    """Backward-compatible resolver API; defaults to automatic discovery."""
    return auto_discover_variant3_decoder_graph(functions, strfunc, deobf_root).resolved


_STATE = None
_GRAPH = None

def strings_deobfuscate_v3(functions, verbosity=0, strfunc=None, deobf_root=None,
                           hide_decoders=True, hide_policy='applied'):
    """Discover and apply variant-3 decoders; keep state for later refresh."""
    global _STATE, _GRAPH
    _STATE = None
    _GRAPH = None
    try:
        graph = auto_discover_variant3_decoder_graph(functions, strfunc, deobf_root)
    except ValueError as e:
        print(f'Variant 3 discovery failed: {e}')
        return False
    strfunc, deobf_root = graph.provider, graph.leaf
    chunks, leaf_shift = graph.chunks, graph.leaf_shift
    resolved, detected, pending = graph.resolved, graph.detected, graph.pending
    # Keep the existing provider metadata semantics after discovery, but do
    # not mutate any function while merely probing candidates.
    load_string_array(functions, strfunc)
    print(f'Variant 3 discovered leaf={deobf_root}; array={strfunc}')
    print(f'Variant 3: {len(chunks)} chunks; leaf subtract={leaf_shift}; '
          f'{len(detected)} candidate wrappers; {len(resolved)-1} connected')
    if verbosity and pending:
        print(f'  Disconnected / unresolved wrappers: {len(pending)}')
    if len(resolved) == 1:
        print('Variant 3: no decoder wrappers connected; no code modified')
        return False
    _STATE = (resolved, chunks)
    _GRAPH = graph
    stats = process_calls(functions, resolved, chunks, verbosity)
    # Like variant 2, clean unused index/string temporaries in the filter
    # itself.  Standalone and deobf_all.py calls now share this behavior.
    cleanup = cleanup_variant3_dead_assignments(functions)
    print(f"Variant 3 initial replacements: {dict(stats)}; "
          f"consolidated: {cleanup['consolidated']}; "
          f"hidden dead string assignments: {cleanup['hidden_folded_strings']}; "
          f"hidden unused constants: {cleanup['hidden']}")
    if hide_decoders:
        summary = hide_variant3_decoder_functions(
            functions, resolved, strfunc, deobf_root, policy=hide_policy
        )
        print(f'Variant 3 helper cleanup: {summary}')
        if hide_policy == 'applied' and summary['unresolved_direct_calls']:
            print('Note: unresolved decoder calls remain in the visible listing; '
                  'their implementations are preserved in the serialized .pkl. '
                  'Use --hide-policy referenced to keep those implementations visible.')
    return True


def refresh_deobfuscated_strings_v3(functions, verbosity=0, function_names=None):
    if _STATE is None:
        return False
    resolved, chunks = _STATE
    stats = process_calls(functions, resolved, chunks, verbosity, function_names)
    # A refresh can expose new string literals and make their index
    # temporaries dead.  Clean only the functions processed by this refresh.
    cleanup = cleanup_variant3_dead_assignments(functions, function_names)
    print(f"Variant 3 refresh: {dict(stats)}; "
          f"consolidated: {cleanup['consolidated']}; "
          f"hidden dead string assignments: {cleanup['hidden_folded_strings']}; "
          f"hidden unused constants: {cleanup['hidden']}")
    return True


def cleanup_variant3_dead_assignments(functions, function_names=None):
    """Consolidate strings and hide provably dead constants in variant 3.

    Invoked by initial decoding and subsequent decoder refreshes, regardless
    of whether they run standalone or via deobf_all.py.  The safety checks
    preserve control-flow boundaries, jump targets, and uncertain liveness.
    Also supports functions marked ``Flattened`` by the unflattener.
    """
    folding = {}
    consolidated = simplify_chain_assignments(
        functions, safe=True, function_names=function_names,
        hide_superseded=True, stats=folding
    )
    stats = hide_safe_unreferenced_constants(functions, function_names)
    stats['consolidated'] = consolidated
    stats['hidden_folded_strings'] = folding.get('hidden', 0)
    print(f'Variant 3 dead-constant cleanup: {stats}')
    return stats


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inp', required=True, help='Trusted, locally generated View8 .dec.pkl')
    p.add_argument('--out', help='Output pseudocode filename (.pkl saved beside it when requested)')
    p.add_argument('--strfunc', help='Function whose const pool contains the chunk array')
    p.add_argument('--deobf-root', help='Optional manual leaf-decoder override (otherwise autodetect)')
    p.add_argument('--graph-out', help='Optional JSON caller/callee graph output')
    p.add_argument('--mode', choices=('decode', 'strlist', 'hide', 'discover', 'cleanup'), default='decode',
                   help='Decode, collect strings, hide helpers, discover, or clean an existing .pkl')
    p.add_argument('--hide-policy', choices=('applied', 'referenced'), default='applied',
                   help='applied: match variant-2 cleanup; referenced: keep helpers still referenced by visible code')
    p.add_argument('--keep-decoder-functions', action='store_true',
                   help='Disable helper-function hiding when decoding (for debugging)')
    p.add_argument('--scope', type=int, choices=(0, 1), default=1)
    p.add_argument('--verbosity', type=int, default=0)
    p.add_argument('--export_format', nargs='+', choices=('decompiled', 'serialized'),
                   default=['decompiled', 'serialized'])
    args = p.parse_args()
    print(f'Loading trusted View8 serialized functions: {args.inp}', flush=True)
    functions = load_functions_from_file(args.inp)
    if args.mode == 'strlist':
        save_string_list(args.out or args.inp, functions, final_only=True)
        return
    if args.mode == 'cleanup':
        # Old serialized outputs can receive this literal-only refinement
        # without repeating decoder discovery or deobfuscation.
        folded = process_calls(functions, {}, [], args.verbosity)
        print(f"Variant 3 cleanup-only adjacent literal folds: "
              f"{folded.get('adjacent_literals_folded', 0)}")
        cleanup_variant3_dead_assignments(functions)
    elif args.mode in ('hide', 'discover'):
        try:
            graph = auto_discover_variant3_decoder_graph(
                functions, args.strfunc, args.deobf_root
            )
        except ValueError as e:
            p.error(str(e))
        print(f'Variant 3 discovered leaf={graph.leaf}; array={graph.provider}; '
              f'chunks={len(graph.chunks)}; connected wrappers={len(graph.resolved)-1}')
        if args.graph_out:
            write_variant3_graph(graph, args.graph_out)
            print(f'Graph written: {args.graph_out}')
        if args.mode == 'discover':
            return
        summary = hide_variant3_decoder_functions(
            functions, graph.resolved, graph.provider, graph.leaf,
            policy=args.hide_policy
        )
        print(f'Variant 3 helper cleanup: {summary}')
    else:
        if args.scope:
            propagate_variables_default(functions, 3, args.verbosity)
        ok = strings_deobfuscate_v3(
            functions, args.verbosity, args.strfunc, args.deobf_root,
            hide_decoders=not args.keep_decoder_functions,
            hide_policy=args.hide_policy
        )
        if not ok:
            raise SystemExit(1)
        if args.graph_out and _GRAPH is not None:
            write_variant3_graph(_GRAPH, args.graph_out)
            print(f'Graph written: {args.graph_out}')
    if args.out:
        export_to_file(args.out, functions, args.export_format)
        save_string_list(args.out, functions, final_only=True)
        print(f'Exported: {args.out}')
    else:
        print('No --out supplied; changes were not saved')


if __name__ == '__main__':
    main()
