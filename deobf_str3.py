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
from collections import Counter
from dataclasses import dataclass

from View8.Parser.shared_function_info import load_functions_from_file
from View8.view8_util import export_to_file
from deobf_commons import customB64, load_string_array, set_string_metadata, simplify_chain_assignments, save_string_list
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
        _fold_adjacent_string_literals_in_line(obj, verbosity)


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


_STATE = None

def strings_deobfuscate_v3(functions, verbosity=0, strfunc=None, deobf_root=None):
    """Discover and apply variant-3 decoders; keep state for later refresh."""
    global _STATE
    _STATE = None
    if not strfunc or not deobf_root:
        print('Variant 3 requires --strfunc (array) and --deobf-root (leaf)')
        return False
    if deobf_root not in functions:
        print(f'Leaf decoder not present: {deobf_root}')
        return False
    chunks = load_string_array(functions, strfunc)
    if chunks is None:
        return False
    try:
        leaf_shift = infer_leaf_shift(functions[deobf_root])
    except ValueError as e:
        print(f'Unsafe variant-3 leaf: {e}')
        return False
    resolved, detected, pending = resolve_graph(functions, deobf_root, leaf_shift)
    print(f'Variant 3: {len(chunks)} chunks; leaf subtract={leaf_shift}; '
          f'{len(detected)} candidate wrappers; {len(resolved)-1} connected')
    if verbosity and pending:
        print(f'  Disconnected / unresolved wrappers: {len(pending)}')
    if len(resolved) == 1:
        print('Variant 3: no decoder wrappers connected; no code modified')
        return False
    _STATE = (resolved, chunks)
    stats = process_calls(functions, resolved, chunks, verbosity)
    folding = {}
    consolidated = simplify_chain_assignments(
        functions, safe=True, hide_superseded=True, stats=folding
    )
    print(f"Variant 3 initial replacements: {dict(stats)}; consolidated: {consolidated}; "
          f"hidden dead string assignments: {folding.get('hidden', 0)}")
    return True


def refresh_deobfuscated_strings_v3(functions, verbosity=0, function_names=None):
    if _STATE is None:
        return False
    resolved, chunks = _STATE
    stats = process_calls(functions, resolved, chunks, verbosity, function_names)
    folding = {}
    consolidated = simplify_chain_assignments(
        functions, safe=True, function_names=function_names,
        hide_superseded=True, stats=folding
    )
    print(f"Variant 3 refresh: {dict(stats)}; consolidated: {consolidated}; "
          f"hidden dead string assignments: {folding.get('hidden', 0)}")
    return True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inp', required=True, help='Trusted, locally generated View8 .dec.pkl')
    p.add_argument('--out', help='Output pseudocode filename (.pkl saved beside it when requested)')
    p.add_argument('--strfunc', help='Function whose const pool contains the chunk array')
    p.add_argument('--deobf-root', help='Leaf decoder which calls custom Base64')
    p.add_argument('--mode', choices=('decode', 'strlist'), default='decode',
                   help='Decode strings or rebuild the final string list from an existing .pkl')
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
    if not args.strfunc or not args.deobf_root:
        p.error('--strfunc and --deobf-root are required in decode mode')
    if args.scope:
        propagate_variables_default(functions, 3, args.verbosity)
    ok = strings_deobfuscate_v3(functions, args.verbosity, args.strfunc, args.deobf_root)
    if not ok:
        raise SystemExit(1)
    if args.out:
        export_to_file(args.out, functions, args.export_format)
        save_string_list(args.out, functions, final_only=True)
        print(f'Exported: {args.out}')
    else:
        print('No --out supplied; changes were not saved')


if __name__ == '__main__':
    main()
