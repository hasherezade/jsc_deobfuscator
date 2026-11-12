#!/usr/bin/env python3
# JSC Deobfuscator - static deobfuscation of View8 pseudocode generated from
# compiled V8 JavaScript bytecode.
#
# Copyright (C) 2026 Aleksandra "Hasherezade" Doniec @ Check Point Research
# SPDX-License-Identifier: GPL-2.0-or-later
#
''' String decoder for samples using Base64 + RC4 string obfuscation
'''
import argparse
import os
import ast
import re
import base64
import urllib.parse
import tempfile
import time

from View8.Parser.shared_function_info import save_functions_to_file, load_functions_from_file
from deobf_commons import *
from View8.view8_util import export_to_file, print_funcs, find_functions_by_name
from deobf_scope2 import propagate_variables_default, find_and_process_func_variables

g_Verbosity = 0

str_array = None

deobf_roots = None
resolved_funcs = {}

group_index_first = set()
g_all_keys = set()

func_groups = dict()

g_crack_strings = False

def reset_resolver_state():
    """Reset all state that belongs to a single payload-resolution run."""
    global str_array
    global deobf_roots
    global resolved_funcs
    global group_index_first
    global g_all_keys
    global func_groups

    str_array = None
    deobf_roots = None
    resolved_funcs = {}
    group_index_first = set()
    g_all_keys = set()
    func_groups = {}

def test_values(func_name, group):
    global group_index_first
    global g_Verbosity

    # Work only with independent observations. The group is already deduplicated
    # by _append_to_group(), but keep this defensive conversion so callers cannot
    # accidentally reintroduce duplicate evidence.
    observations = list(dict.fromkeys(group[-4:]))
    if len(observations) < 3:
        return False

    candidate_sets = []
    for index, key in observations:
        matching = find_matching_diff(int(index), key)
        if not matching:
            return False
        candidate_sets.append(matching)

    candidates = set.intersection(*candidate_sets)
    if g_Verbosity > 1:
        print(f"Testing set: {func_name} Set: {candidates}")

    if len(candidates) != 1:
        return False

    diff = next(iter(candidates))
    is_index_first = func_name in group_index_first
    resolved_funcs[func_name] = (diff, is_index_first)

    if g_Verbosity > 0:
        sample_index, sample_key = observations[-1]
        sample_value = _decode_string(sample_index, sample_key, diff)
        print(
            f"{is_index_first} Func: {func_name} "
            f"Diff: {diff} Val: {sample_value} "
            f"Observations: {len(observations)}"
        )
    return True

def _append_to_group(func_groups, func_name,index,key):
    if func_name not in func_groups:
        func_groups[func_name] = []
    for (i,k) in func_groups[func_name]:
        if i == index and k == key:
            return False
    func_groups[func_name].append((index, key))
    return True

# Numeric decoder indices may be emitted either directly (``-301``) or
# wrapped in an extra pair of parentheses (``(-301)``). Keep this as one
# capturing group because the replacement helpers rely on stable group indexes.
_CALL_INDEX_RE = r"(\(\s*-?\d+\s*\)|-?\d+)"

_EXACT_NUM_INDEX_FIRST_RE = re.compile(
    rf'([\w#$]+)\(\s*{_CALL_INDEX_RE}\s*,\s*"([^"]*?)"\s*\)'
)
_EXACT_NUM_KEY_FIRST_RE = re.compile(
    rf'([\w#$]+)\(\s*"([^"]*?)"\s*,\s*{_CALL_INDEX_RE}\s*\)'
)
_SCOPE_NUM_INDEX_FIRST_RE = re.compile(
    rf'(Scope\[\d+\]\[\d+\])\(\s*{_CALL_INDEX_RE}\s*,\s*"([^"]*?)"\s*\)'
)
_SCOPE_NUM_KEY_FIRST_RE = re.compile(
    rf'(Scope\[\d+\]\[\d+\])\(\s*"([^"]*?)"\s*,\s*{_CALL_INDEX_RE}\s*\)'
)
_REGISTER_NUM_INDEX_FIRST_RE = re.compile(
    rf'(r\d+)\(\s*{_CALL_INDEX_RE}\s*,\s*"([^"]*?)"\s*\)'
)
_REGISTER_NUM_KEY_FIRST_RE = re.compile(
    rf'(r\d+)\(\s*"([^"]*?)"\s*,\s*{_CALL_INDEX_RE}\s*\)'
)


def _normalize_call_index(index):
    index = index.strip()
    if index.startswith("(") and index.endswith(")"):
        return index[1:-1].strip()
    return index


# gather immediate function args: key, value
def gather_function_args(line, func_groups, func_name, is_index_first):
    global group_index_first
    global g_all_keys
    escaped = re.sub(r'\$', r'\\$', func_name)
    if is_index_first:
        pattern = re.compile(rf'{escaped}\s*\(\s*{_CALL_INDEX_RE}\s*,\s*"([^"]*?)"\s*\)')
        index_pos = 1
        key_pos = 2
    else:
        pattern = re.compile(rf'{escaped}\s*\(\s*"([^"]*?)"\s*,\s*{_CALL_INDEX_RE}\s*\)')
        index_pos = 2
        key_pos = 1
    match = pattern.search(line)
    if not match:
        return None
    # parse the found arguments:
    index = _normalize_call_index(match.group(index_pos))
    key = match.group(key_pos)
    
    # store the arguments for further use:
    added = _append_to_group(func_groups, func_name, index, key)

    g_all_keys.add(key)

    if is_index_first:
        group_index_first.add(func_name)
    return added


def walk_str_refs(functions, deobf_funcs, unres_only = True, visible_only = True):
    global resolved_funcs
    # walk all functions in the decompiled code
    for name in functions:
        if name in resolved_funcs.keys(): #skip inner references from inside other str deobf functions
            continue
        indx = 0
        func = functions[name]
        # walk all lines in the function
        for line_obj in func.code:
            indx += 1
            line = line_obj.decompiled.strip()
            if visible_only and not line_obj.visible:
                continue
            # if any of the string deobfuscating function occurs in a line
            for func_name in deobf_funcs:
                func_name1 = re.sub(r'\$', r'\\$', func_name)
                str1 = func_name1 + "("
                if str1 not in line:
                    continue
                if unres_only:
                    pattern = re.compile(rf'{func_name1}\s*\(\s*{_CALL_INDEX_RE}\s*,\s*"([^"]*?)"\s*\)')
                    if pattern.search(line):
                        continue
                    pattern = re.compile(rf'{func_name1}\s*\(\s*"([^"]*?)"\s*,\s*{_CALL_INDEX_RE}\s*\)')
                    if pattern.search(line):
                        continue
                print(f"{name} : {indx} | {line}")
                
          
def _walk_str_deobf_refs(functions, name, deobf_funcs, brutforce_diffs):
    global group_index_first
    global g_all_keys
    global func_groups
    global g_Verbosity

    func = functions[name]
    if not func:
        return
    if g_Verbosity > 2:
        print(f"Testing string deobfuscation inside the function: {name}")
    for line_obj in func.code:
        line = line_obj.decompiled
            
        for func_name in deobf_funcs:
            if func_name not in line:
                continue
            if brutforce_diffs and func_name in resolved_funcs.keys():
                continue

            added = gather_function_args(line, func_groups, func_name, True)
            if added is None:
                added = gather_function_args(line, func_groups, func_name, False)
            if added is None:
                continue
            if brutforce_diffs and added:
                # this function is not resolved, try to run a brutforce to find the index diff
                group = func_groups[func_name]
                if g_Verbosity > 1:
                    print(f"In {name}: Testing string deobf function: {func_name} Group: {group}")
                if len(group) >= 3:
                    if test_values(func_name, group):
                        continue


def gather_all_used_keys(functions, deobf_funcs, max_keys=50):
    global g_all_keys
    for name in functions:
        _walk_str_deobf_refs(functions, name, deobf_funcs, False)
        if len(g_all_keys) == max_keys:
            break
    return g_all_keys

def walk_str_deobf_refs(functions, deobf_funcs, brutforce_diffs):
    global group_index_first
    global g_all_keys
    global func_groups
    global g_Verbosity

    initial_count = len(resolved_funcs)
    for name in functions:
        _walk_str_deobf_refs(functions, name, deobf_funcs, brutforce_diffs)
        if brutforce_diffs:
            if set(deobf_funcs).issubset(resolved_funcs):
                break
    if brutforce_diffs and g_Verbosity > 0:
        print(f"Resolved: {len(resolved_funcs) - initial_count} out of: {len(deobf_funcs)}")


def is_cleartext(text):
    acceptable = {'[', ']', '{', '}', '(', ')', '<', '>',  ' ', '\'', '\"', '\\', '/', '.', ':', '-', '_' , ',', '#', '@', '+', '|', '^', '!', '`', '=', '?', '%', '\r', '\n', '\t', '*', '$', ';', '&', '•'}
    for char in text:
        if not ('a' <= char <= 'z' or 'A' <= char <= 'Z' or '0' <= char <= '9') and (not char in acceptable):
            return False
    return True

def crack_collected_strings():
    global g_all_keys
    global str_array
    for index in range(0, len(str_array)):
        is_found = False
        for key in g_all_keys:
            text = _decode_string(index, key, 0)
            if is_cleartext(text):
                print(f"[L] {index} : {key} -> {text}")
                is_found = True

        if not is_found:
            for key in g_all_keys:
                text = _decode_string(index, key, 0)
                if text.isprintable():
                    print(f"[P] {index} : {key} -> {text}")
        print("")
###
# Load an array of obfuscated string from the initialization function:

def helper(i, n):
    global str_array
    return str_array[(int(i)-n)%len(str_array)]


def find_matching_diff(index, key):
    global str_array
    diff = set()
    for x in range(0, len(str_array)):
        s = helper(index, x)
        dec = rc4_decrypt(s, key)
        if is_cleartext(dec):
            if g_Verbosity > 3:
                print(f"val[{index} - {x}] = '{s}' -> '{dec}'")
            diff.add(x)
    return diff

def find_matching_diff2(key, index):
    return find_matching_diff(index, key)

###

def _decode_string(index, key, diff):
    value = helper(index, diff)
    dec_str = rc4_decrypt(value, key)
    #print(f"Decoded: {value} : {dec_str}")
    return dec_str

###

def get_deobf_from_const_pool(func):
    global resolved_funcs
    if not func.const_pool:
        return None
    for item in func.const_pool:
        if item in resolved_funcs.keys():
            return item
    return None

### 

_ANSI_SEQ = re.compile(
    r'\x1b(?:'
    r'\[[0-9;?]*[ -/]*[@-~]'          # CSI
    r'|\][^\x07\x1b]{0,64}(?:\x07|\x1b\\)'  # OSC, bounded
    r'|[@-Z\\-_]'                     # two-char Fe
    r')'
)
 
def is_cleartext_relaxed(text):
    """Replacement-time validity check.
 
    Same character policy as is_cleartext(), except that *well-formed* ANSI
    escape sequences are removed before validation. A lone ESC, a truncated
    sequence, or any other C0 byte still fails -- those are the real signature
    of a bad RC4 decode.
    """
    if '\x1b' not in text:
        return is_cleartext(text)
    stripped = _ANSI_SEQ.sub('', text)
    if '\x1b' in stripped:      # unconsumed ESC => malformed => reject
        return False
    return is_cleartext(stripped)

def _replace_call_with_string(line_obj, func_name, match, found_indx_first, check_printable, verbosity):
    global resolved_funcs

    def _get_key_indx_group(is_index_first):
        if is_index_first:
            return (2, 3)
        return (3, 2)

    line = line_obj.decompiled
    if func_name is None:
        return False
    if func_name not in resolved_funcs.keys():
        if verbosity > 0:
            print(f"Match on unresolved function: {func_name} : {line}")
        return False

    (diff, is_index_first) = resolved_funcs[func_name]
    if found_indx_first != is_index_first:
        if verbosity > 0:
            print(f"Mismatch of index/key order: {line}")
        return False

    (index_pos, key_pos) = _get_key_indx_group(is_index_first)
    index = _normalize_call_index(match.group(index_pos))
    key = match.group(key_pos)
    if (len(key) < 3):
        if verbosity > 0:
            print(f"Wrong key length: {len(key)} (key: {key})")
        return False

    value = helper(index, diff)
    orig_str = rc4_decrypt(value, key)

    if check_printable:
        if not is_cleartext_relaxed(orig_str):
            #g_rejected_decodes.append((func_name, index, key, orig_str))
            if verbosity > 0:
                print(f"The decoded string has invalid characters. Rejected {func_name}({index}, {key}): "
                      f"`{string_escape(orig_str)}` - ")
            return False

    dec_str = string_escape(orig_str)
    if verbosity > 0:
        print(f"{func_name}({index}, {key}) -> {dec_str}")

    line = line.replace(match.group(0), f'"{dec_str}"')
    if verbosity > 1:
        print(f"Replacing:\n\t{line_obj.decompiled.strip()}\nwith:\n\t{line.strip()}")
    line_obj.decompiled = line
    set_string_metadata(line_obj, dec_str)
    _fold_adjacent_string_literals_in_line(line_obj, verbosity)
    return True

def _find_and_replace_deobf_calls(functions, pattern1, pattern2, is_exact):
    global g_Verbosity
    global resolved_funcs

    replacements = 0
    for func in functions.values():
        for line_obj in func.code:
            if not line_obj.visible or not line_obj.decompiled:
                continue

            # A line may contain more than one function call. Do not stop on the
            # first syntactically matching non-decoder call; keep looking until
            # no known decoder call can be replaced.
            while True:
                line = line_obj.decompiled
                candidates = []
                candidates.extend((m.start(), True, m) for m in pattern1.finditer(line))
                candidates.extend((m.start(), False, m) for m in pattern2.finditer(line))
                candidates.sort(key=lambda item: item[0])

                replaced = False
                for _, found_indx_first, match in candidates:
                    if is_exact:
                        func_name = match.group(1)
                        if func_name not in resolved_funcs:
                            continue
                    else:
                        func_name = get_deobf_from_const_pool(func)
                        if func_name not in resolved_funcs:
                            break

                    if g_Verbosity > 2:
                        print(f"Matched: {line}")

                    verify_string = not is_exact
                    if _replace_call_with_string(
                        line_obj,
                        func_name,
                        match,
                        found_indx_first,
                        verify_string,
                        g_Verbosity,
                    ):
                        replacements += 1
                        replaced = True
                        break

                if not replaced:
                    break

    return replacements
  

def find_and_replace_exact_deobf_calls(functions):
    return _find_and_replace_deobf_calls(
        functions,
        _EXACT_NUM_INDEX_FIRST_RE,
        _EXACT_NUM_KEY_FIRST_RE,
        True,
    )

def find_and_replace_scope_deobf_calls(functions):
    return _find_and_replace_deobf_calls(
        functions,
        _SCOPE_NUM_INDEX_FIRST_RE,
        _SCOPE_NUM_KEY_FIRST_RE,
        False,
    )
  
def find_and_replace_reg_deobf_calls(functions):
    return _find_and_replace_deobf_calls(
        functions,
        _REGISTER_NUM_INDEX_FIRST_RE,
        _REGISTER_NUM_KEY_FIRST_RE,
        False,
    )


def find_and_replace_all_deobf_calls(functions):
    replacements = 0
    replacements += find_and_replace_exact_deobf_calls(functions)
    replacements += find_and_replace_scope_deobf_calls(functions)
    replacements += find_and_replace_reg_deobf_calls(functions)
    return replacements


_NUMERIC_RHS_RE = re.compile(r'^-?\d+$')
_REGISTER_RHS_RE = re.compile(r'^r\d+$')
_REGISTER_ASSIGN_RE = re.compile(r'^\s*(r\d+)\s*=\s*(.*?)\s*$')
_DECODER_CALLEE_RE = r'(?:func_[\w#$]+|Scope\[\d+\]\[\d+\]|r\d+)'
_DECODER_REG_INDEX_FIRST_RE = re.compile(
    rf'(?P<callee>{_DECODER_CALLEE_RE})\(\s*(?P<index>r\d+)\s*,\s*"(?P<key>[^"]*?)"\s*\)'
)
_DECODER_REG_KEY_FIRST_RE = re.compile(
    rf'(?P<callee>{_DECODER_CALLEE_RE})\(\s*"(?P<key>[^"]*?)"\s*,\s*(?P<index>r\d+)\s*\)'
)
_CALL_INDEX_OR_REGISTER_RE = r'(?:\(\s*-?\d+\s*\)|-?\d+|r\d+)'
_DECODER_REFRESH_CANDIDATE_RE = re.compile(
    rf'(?P<callee>Scope\[\d+\]\[\d+\]|[\w#$]+)\(\s*(?:'
    rf'(?P<index_first>{_CALL_INDEX_OR_REGISTER_RE})\s*,\s*"[^"]*?"|'
    rf'"[^"]*?"\s*,\s*(?P<index_second>{_CALL_INDEX_OR_REGISTER_RE})'
    rf')\s*\)'
)
_BLOCK_BOUNDARY_RE = re.compile(
    r'^\s*(?:[{}]|else\b|catch\b|finally\b|case\b|default\s*:|'
    r'if\b|while\b|for\b|do\b|switch\b|try\b|break\b|continue\b|return\b|throw\b)'
)
_CONDITION_CONTINUATION_RE = re.compile(r'^\s*(?:&&|\|\||\?\?)')
_CONDITION_HEADER_RE = re.compile(r'^\s*(?:if|while|for)\b')


def _strip_balanced_outer_parentheses(value):
    value = value.strip()
    while value.startswith('(') and value.endswith(')'):
        depth = 0
        balanced = True
        for index, char in enumerate(value):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth < 0:
                    balanced = False
                    break
                if depth == 0 and index != len(value) - 1:
                    balanced = False
                    break
        if not balanced or depth != 0:
            break
        value = value[1:-1].strip()
    return value


def _format_decoder_index(value):
    value = _strip_balanced_outer_parentheses(value)
    if not _NUMERIC_RHS_RE.fullmatch(value):
        return None
    return f'({value})' if value.startswith('-') else value


def _line_indent(line):
    return line[:len(line) - len(line.lstrip(' \t'))]


def _decoder_resolution_start(func, call_index, register):
    """Return the backward-scan start and base indentation for a decoder use.

    View8 renders a multi-line condition as, for example::

        if (condition)
        r13 = "propertyPrefix"
        r16 = (-426)
            || (decoder("key", r16))

    The continuation line is indented more deeply than the surrounding basic
    block even though it is part of the same expression. View8 may also place a
    contiguous sequence of direct register assignments between the condition
    header and that continuation. Treat those assignments as condition setup,
    but fail closed on any non-assignment statement, indentation change, or
    ambiguous write.
    """
    call_line = func.code[call_index].decompiled
    call_indent = _line_indent(call_line)
    if not _CONDITION_CONTINUATION_RE.match(call_line):
        return call_index - 1, call_indent

    register_write = re.compile(rf'\b{re.escape(register)}\s*=(?!=)')
    setup_indent = None
    candidate_index = None

    for index in range(call_index - 1, -1, -1):
        line_obj = func.code[index]
        if not line_obj.visible or not line_obj.decompiled:
            continue
        line = line_obj.decompiled
        line_indent = _line_indent(line)

        if len(line_indent) >= len(call_indent):
            # A write inside an earlier continuation fragment would require
            # expression-level data-flow reasoning. Fail closed instead.
            if register_write.search(line):
                return None
            continue

        if setup_indent is None:
            setup_indent = line_indent
        elif line_indent != setup_indent:
            return None

        if _CONDITION_HEADER_RE.match(line):
            if candidate_index is not None:
                return candidate_index, setup_indent
            # No setup assignment for this register: permit the ordinary
            # backward scan to continue before the current condition header.
            return index - 1, setup_indent

        assignment = _REGISTER_ASSIGN_RE.match(line)
        if assignment:
            if assignment.group(1) == register and candidate_index is None:
                # We scan backward, so the first matching assignment is the
                # nearest visible definition before the decoder call.
                candidate_index = index
            continue

        # Any non-assignment statement between the condition header and the
        # continuation breaks the narrow setup-block model. A hidden write to
        # the target register is likewise ambiguous.
        if register_write.search(line):
            return None
        return None

    return None


def _resolve_visible_numeric_register(func, call_index, register, seen=None):
    """Resolve a decoder-index register from the same visible basic block.

    Invisible flattened lines are deliberately ignored. The search stops at
    indentation changes and control-flow boundaries, so this helper cannot
    import a value from another branch or iteration path.
    """
    if seen is None:
        seen = set()
    if register in seen:
        return None
    seen.add(register)

    resolution_start = _decoder_resolution_start(func, call_index, register)
    if resolution_start is None:
        return None
    scan_start, call_indent = resolution_start

    for index in range(scan_start, -1, -1):
        line_obj = func.code[index]
        if not line_obj.visible or not line_obj.decompiled:
            continue
        line = line_obj.decompiled
        if _line_indent(line) != call_indent:
            return None
        if _BLOCK_BOUNDARY_RE.match(line):
            return None

        match = _REGISTER_ASSIGN_RE.match(line)
        if not match or match.group(1) != register:
            continue

        rhs = match.group(2).strip()
        numeric = _format_decoder_index(rhs)
        if numeric is not None:
            return numeric

        alias = _strip_balanced_outer_parentheses(rhs)
        if _REGISTER_RHS_RE.fullmatch(alias):
            return _resolve_visible_numeric_register(func, index, alias, seen)
        return None

    return None


def _decoder_name_for_callee(func, callee):
    if callee in resolved_funcs:
        return callee
    if callee.startswith('Scope[') or re.fullmatch(r'r\d+', callee):
        candidate = get_deobf_from_const_pool(func)
        if candidate in resolved_funcs:
            return candidate
    return None


def _call_order_matches(decoder_name, found_index_first):
    if decoder_name not in resolved_funcs:
        return False
    _, expected_index_first = resolved_funcs[decoder_name]
    return found_index_first == expected_index_first


def _line_has_known_decoder_call(func, line):
    """Return True when a line contains a call the refresh can process.

    This is intentionally only a cheap prefilter. It recognizes the same
    numeric and register-index call shapes as the real replacement code, but
    does not modify the line or attempt to decode anything.
    """
    if '"' not in line or '(' not in line:
        return False

    for match in _DECODER_REFRESH_CANDIDATE_RE.finditer(line):
        decoder_name = _decoder_name_for_callee(func, match.group('callee'))
        found_index_first = match.group('index_first') is not None
        if _call_order_matches(decoder_name, found_index_first):
            return True

    return False


def _normalize_refresh_function_names(functions, function_names=None):
    """Return unique, visible function names for a refresh request.

    Callers normally provide a set of names, but some transformation passes may
    return lists with duplicates or function objects. Normalize at the refresh
    boundary so candidate selection and diagnostics always operate on unique,
    currently visible functions from the current payload. Hidden helper
    functions cannot contribute decoder calls to the exported output.
    """
    if function_names is None:
        source = functions
    else:
        source = function_names

    normalized = set()
    for item in source:
        if isinstance(item, str):
            name = item
        else:
            name = getattr(item, "name", None)
        func = functions.get(name)
        if func is not None and getattr(func, "visible", True):
            normalized.add(name)
    return normalized


def select_decoder_refresh_candidates(functions, function_names=None):
    """Select only functions that currently contain a known decoder call.

    ``function_names`` is a transient dirty collection supplied by the
    pipeline. It is normalized to unique current-payload names before the
    textual prefilter runs.
    """
    names = _normalize_refresh_function_names(functions, function_names)

    candidates = {}
    for name in names:
        func = functions.get(name)
        if func is None:
            continue
        if getattr(func, "visible", True) is False:
            continue
        for line_obj in func.code:
            if not line_obj.visible or not line_obj.decompiled:
                continue
            if _line_has_known_decoder_call(func, line_obj.decompiled):
                candidates[name] = func
                break
    return candidates


def inline_decoder_argument_registers(functions, verbosity=0):
    """Inline only numeric registers used as known decoder indices.

    This is intentionally independent of the general temporary inliner. It
    operates on visible post-unflattening code and only within one textual basic
    block, including a loop body when the defining assignment and call are on
    the same path.
    """
    replacements = 0
    for func in functions.values():
        for line_index, line_obj in enumerate(func.code):
            if not line_obj.visible or not line_obj.decompiled:
                continue

            while True:
                line = line_obj.decompiled
                candidates = []
                candidates.extend((m.start(), True, m) for m in _DECODER_REG_INDEX_FIRST_RE.finditer(line))
                candidates.extend((m.start(), False, m) for m in _DECODER_REG_KEY_FIRST_RE.finditer(line))
                candidates.sort(key=lambda item: item[0])

                changed = False
                for _, found_index_first, match in candidates:
                    decoder_name = _decoder_name_for_callee(func, match.group('callee'))
                    if decoder_name is None:
                        continue
                    _, expected_index_first = resolved_funcs[decoder_name]
                    if found_index_first != expected_index_first:
                        continue

                    register = match.group('index')
                    numeric = _resolve_visible_numeric_register(
                        func, line_index, register
                    )
                    if numeric is None:
                        continue

                    start, end = match.span('index')
                    updated = line[:start] + numeric + line[end:]
                    if verbosity > 1:
                        print(
                            f"Decoder argument: {register} -> {numeric} in "
                            f"{getattr(func, 'name', '<unknown>')}"
                        )
                    line_obj.decompiled = updated
                    replacements += 1
                    changed = True
                    break

                if not changed:
                    break

    return replacements


def _prepare_decoder_calls(functions, verbosity=0):
    # Resolve function aliases, but leave numeric decoder arguments to the
    # decoder-specific visible-code resolver above.
    for name in functions:
        find_and_process_func_variables(
            functions, name, None, verbosity
        )
    return inline_decoder_argument_registers(functions, verbosity)


_ADJACENT_STRING_LITERALS_RE = re.compile(
    r'(?P<left>"(?:\\.|[^"\\])*")\s*\+\s*'
    r'(?P<right>"(?:\\.|[^"\\])*")'
)


def _literal_concat_boundary_is_safe(left_inner, right_inner):
    """Reject the only raw-splicing boundary that can change JS escapes.

    Joining the encoded interiors directly preserves ordinary, hex and Unicode
    escapes. Legacy octal escapes are different: ``"\\1" + "2"`` must not
    become ``"\\12"``. Fail closed for that boundary rather than trying to
    reinterpret the source literal.
    """
    if not right_inner or not right_inner[0].isdigit():
        return True
    return re.search(r'\\(?:0|[1-7][0-7]?)$', left_inner) is None


def _fold_adjacent_string_literals_in_line(line_obj, verbosity=0, func_name=None):
    """Fold adjacent string literals on one line only.

    Decoder replacement already knows the exact line it modified. Keeping the
    cleanup local avoids rescanning the complete payload after every string
    refresh, which is prohibitively expensive on large samples.
    """
    if not line_obj.visible or not line_obj.decompiled:
        return 0

    original_line = line_obj.decompiled
    line = original_line
    joined = 0
    search_from = 0

    while True:
        match = _ADJACENT_STRING_LITERALS_RE.search(line, search_from)
        if not match:
            break

        left_inner = match.group("left")[1:-1]
        right_inner = match.group("right")[1:-1]
        if not _literal_concat_boundary_is_safe(left_inner, right_inner):
            search_from = match.end()
            continue

        joined_inner = left_inner + right_inner
        joined_literal = f'"{joined_inner}"'
        line = line[:match.start()] + joined_literal + line[match.end():]
        set_string_metadata(line_obj, joined_inner)
        joined += 1

        # Search again from the start of the joined literal so chains such as
        # "a" + "b" + "c" collapse in the same pass.
        search_from = match.start()

    if not joined:
        return 0

    if verbosity > 1:
        owner = func_name or "<unknown>"
        print(
            f"Joined adjacent string literals in {owner}:\n"
            f"\t{original_line.strip()}\n"
            f"\t-> {line.strip()}"
        )
    line_obj.decompiled = line
    sync_string_metadata(line_obj)
    return joined


def fold_adjacent_string_literals(functions, verbosity=0):
    """Explicit corpus-wide literal folding helper.

    The production string pipeline does not call this function. It remains
    available for focused tests and manual cleanup, while normal decoder
    replacement folds only the lines that it actually changes.
    """
    joined_total = 0
    for func in functions.values():
        for line_obj in func.code:
            joined_total += _fold_adjacent_string_literals_in_line(
                line_obj, verbosity, getattr(func, "name", None)
            )
    return joined_total


def refresh_deobfuscated_strings(functions, verbosity=0, function_names=None):
    """Resolve decoder calls exposed by control-flow unflattening.

    The main string pass has already populated ``resolved_funcs`` and
    ``str_array``. Unflattening may subsequently expose calls whose numeric
    index was held in a register, so resolve only decoder-specific aliases and
    numeric arguments, then repeat call replacement. Decoder discovery and
    helper cleanup must not run twice.

    ``function_names`` may contain only functions changed since the previous
    string pass. A cheap decoder-call prefilter narrows that dirty set further
    before any function-variable propagation or replacement scans run.
    """
    global g_Verbosity
    global resolved_funcs
    global str_array

    if not resolved_funcs or not str_array:
        if verbosity:
            print("String refresh skipped: decoder state is unavailable")
        return False

    started = time.perf_counter()
    requested_names = _normalize_refresh_function_names(
        functions,
        function_names,
    )
    g_Verbosity = verbosity
    candidates = select_decoder_refresh_candidates(functions, requested_names)
    requested_count = len(requested_names)

    arguments_inlined = 0
    calls_replaced = 0
    if candidates:
        arguments_inlined = _prepare_decoder_calls(candidates, verbosity)
        calls_replaced = find_and_replace_all_deobf_calls(candidates)

    elapsed = time.perf_counter() - started
    print(
        f"String refresh: {len(candidates)}/{requested_count} candidate "
        f"function(s); inlined {arguments_inlined} decoder argument(s); "
        f"replaced {calls_replaced} decoder call(s); {elapsed:.3f} s"
    )
    return True

###

def strings_deobfuscate(functions, clean=True):
    global resolved_funcs
    global g_Verbosity
    _prepare_decoder_calls(functions, g_Verbosity)
    find_and_replace_all_deobf_calls(functions)
    if clean:
        hide_unreferenced_variables(functions, g_Verbosity)
    simplify_chain_assignments(functions)
    return True
###

import csv

def load_resolved_funcs_from_csv(csv_file, all_func, accepted_names=None):
    """
    Load resolved_funcs configuration from CSV file.
    
    Expected CSV format:
    ut,647,False
    func_c_0x315d8de770c9,1067,False
    func_s_0x1a413bcc80f9,250,False
    ...
    """
    resolved_funcs = {}
    if accepted_names is None:
        accepted_names = set(all_func)
    else:
        accepted_names = set(accepted_names)
    malformed_rows = 0
    foreign_rows = 0
    duplicate_rows = 0
    conflicting_funcs = set()

    def parse_bool(value):
        normalized = value.strip().lower()
        if normalized == 'true':
            return True
        if normalized == 'false':
            return False
        raise ValueError(f"invalid boolean value: {value!r}")

    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            # Process rows
            for row_number, row in enumerate(reader, start=1):
                if len(row) != 3:
                    print(f"Warning: Skipping malformed CSV row {row_number}: {row}")
                    malformed_rows += 1
                    continue

                func_name, number, boolean = (item.strip() for item in row)
                if not func_name or func_name not in accepted_names:
                    foreign_rows += 1
                    continue

                try:
                    config = (int(number), parse_bool(boolean))
                except ValueError as e:
                    print(f"Warning: Skipping malformed CSV row {row_number}: {e}")
                    malformed_rows += 1
                    continue

                if func_name in conflicting_funcs:
                    continue

                previous = resolved_funcs.get(func_name)
                if previous is not None:
                    if previous == config:
                        duplicate_rows += 1
                        continue
                    print(
                        f"Warning: Conflicting CSV definitions for {func_name}; "
                        "discarding the cached value"
                    )
                    conflicting_funcs.add(func_name)
                    resolved_funcs.pop(func_name, None)
                    continue

                resolved_funcs[func_name] = config
    except FileNotFoundError:
        print(f"Warning: CSV file '{csv_file}' not found")
        return {}
    except Exception as e:
        print(f"Error loading from CSV: {e}")
        return {}

    print(
        f"Loaded {len(resolved_funcs)} current-payload function configurations "
        f"from {csv_file}"
    )
    if foreign_rows or malformed_rows or duplicate_rows or conflicting_funcs:
        print(
            "Ignored CSV rows: "
            f"foreign={foreign_rows}, malformed={malformed_rows}, "
            f"duplicates={duplicate_rows}, conflicts={len(conflicting_funcs)}"
        )
    return resolved_funcs

def save_resolved_funcs_to_csv(resolved_funcs, csv_file):
    """
    Save resolved_funcs configuration to CSV file.
    Useful for converting your current hardcoded dict to CSV format.
    """
    output_dir = os.path.dirname(os.path.abspath(csv_file))
    temp_path = None
    try:
        os.makedirs(output_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode='w',
            newline='',
            encoding='utf-8',
            dir=output_dir,
            prefix=f".{os.path.basename(csv_file)}.",
            suffix='.tmp',
            delete=False,
        ) as f:
            temp_path = f.name
            writer = csv.writer(f)
            # Write data
            for func_name, (number, boolean) in sorted(resolved_funcs.items()):
                writer.writerow([func_name, number, boolean])

        os.replace(temp_path, csv_file)
        print(f"Saved {len(resolved_funcs)} function configurations to {csv_file}")
        return True
    except Exception as e:
        print(f"Error writing CSV file: {e}")
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        return False
###

def find_inner_root_diff(all_func, deobf_map, deobf_root, inner_root):
    _deobf_funcs = deobf_map.keys()
    funcs = find_functions_by_name(all_func, deobf_root)
    for f in funcs:
        if f in _deobf_funcs:
            if deobf_map[f].rfunc == inner_root:
                return deobf_map[f].diff_s
    return None

def _resolve_by_parent(func_name, parent_name, diff_s, is_index_first):
    global resolved_funcs

    if parent_name not in resolved_funcs:
        return False

    (comm_diff, _) = resolved_funcs[parent_name]
    total_diff = comm_diff + diff_s
    resolved_funcs[func_name] = (total_diff, is_index_first)
    return True

def _propagate_resolved_funcs(deobf_map):
    """Propagate resolved parent values through the decoder graph."""
    changed = True
    while changed:
        changed = False
        for dfunc in deobf_map.values():
            if dfunc.name in resolved_funcs:
                continue
            if _resolve_by_parent(
                dfunc.name,
                dfunc.rfunc,
                dfunc.diff_s,
                dfunc.is_index_first,
            ):
                changed = True

def _get_cache_function_names(all_func, deobf_map, deobf_root, inner_root):
    """Return all current-payload names that are meaningful in the decoder cache."""
    accepted_names = set(all_func)
    accepted_names.update(deobf_map)
    accepted_names.update(
        dfunc.rfunc for dfunc in deobf_map.values() if dfunc.rfunc
    )
    if deobf_root:
        accepted_names.add(deobf_root)
    if inner_root:
        accepted_names.add(inner_root)
    return accepted_names

def resolve_all_needed(all_func, deobf_map, deobf_root, inner_root):
    global resolved_funcs

    required_funcs = set(deobf_map)

    if not deobf_root:
        print("Failed to resolve string decoders: deobfuscation root is undefined")
        return required_funcs - set(resolved_funcs)
    if not inner_root:
        print("Failed to resolve string decoders: inner root is undefined")
        return required_funcs - set(resolved_funcs)
    if not find_functions_by_name(all_func, deobf_root):
        print(f"Failed to resolve string decoders: root {deobf_root} is missing")
        return required_funcs - set(resolved_funcs)
    if not find_functions_by_name(all_func, inner_root):
        print(f"Failed to resolve string decoders: inner root {inner_root} is missing")
        return required_funcs - set(resolved_funcs)

    deobf_root_diff_s = find_inner_root_diff(all_func, deobf_map, deobf_root, inner_root)
    if deobf_root_diff_s is None:
        print("Failed to find inner root diff: probably scopes are not filled!")
        return required_funcs - set(resolved_funcs)

    if deobf_root not in resolved_funcs:
        mini_set = {deobf_root}
        print(f"Trying to brutforce values of the initial function: {mini_set}")
        walk_str_deobf_refs(all_func, mini_set, True)
        if deobf_root not in resolved_funcs:
            print(f"Failed to resolve initial string decoder: {deobf_root}")
            return required_funcs - set(resolved_funcs)

    # fetch the resolved values of the deobf_root:
    (comm_diff1, is_index_first1) = resolved_funcs[deobf_root]

    # calculate the values for inner root basing on this:
    comm_diff = comm_diff1 - deobf_root_diff_s
    resolved_funcs[inner_root] = (comm_diff, not is_index_first1)

    print("Searching for all deobf funcs...")
    _propagate_resolved_funcs(deobf_map)
    print(f"Searching finished, total: {len(resolved_funcs)}")

    mini_set = set()
    for p in required_funcs:
        if p not in resolved_funcs:
            mini_set.add(p)
        if deobf_map[p].rfunc not in resolved_funcs:
            mini_set.add(deobf_map[p].rfunc)

    if mini_set:
        print(f"Trying to brutforce missing {len(mini_set)} functions: {mini_set}")
        walk_str_deobf_refs(all_func, mini_set, True)

        # Newly brute-forced parents may unlock more children.
        _propagate_resolved_funcs(deobf_map)

    missing_funcs = required_funcs - set(resolved_funcs)
    print(f"Resolving functions finished, total: {len(resolved_funcs)}")
    if missing_funcs:
        print(f"Failed to resolve {len(missing_funcs)} required functions: {missing_funcs}")
    return missing_funcs
       
def hide_by_metadata(all_func):
    hidden = 0
    for func in all_func.values():
        if func.metadata:
            if isinstance(func.metadata, str):
                if func.metadata == "StringChunksContainer":
                    func.visible = False
                    hidden += 1
                continue
            if isinstance(func.metadata, StrDeobfFunction):
                func.visible = False
                hidden += 1
                continue
    return hidden
    
def strings_deobfuscate_v2(all_func, verbosity, resolved_csv = "resolved_funcs.csv"):
    """
    Deobfuscate all strings in one run
    """
    global deobf_roots
    global str_array
    global resolved_funcs
    global g_Verbosity

    reset_resolver_state()
    g_Verbosity = verbosity

    start_name = get_start_function(all_func)
    print(f"Start Func: {start_name}")

    deobf_map = find_all_str_deobf(all_func, verbosity)
    deobf_funcs = deobf_map.keys()
    print(f"All Deobf functions found: {len(deobf_map)}")
    inner_root = None
    deobf_root = find_root_deobf(all_func, start_name)
    if deobf_root:
        deobf_roots = find_inner_deobf(all_func, deobf_root, verbosity)
        for k in deobf_roots:
            inner_root = k
            break
    print(f"Deobf root: {deobf_root}")
    print(f"Inner root: {inner_root}")

    # Do not hide any helper lines before the pass has completed successfully.
    # This keeps a failed in-memory run inspectable and avoids partially cleaned
    # output if a caller chooses to serialize it for diagnostics.
    str_array = find_and_load_string_array(all_func, start_name, hide_def=False)

    if str_array is None or len(str_array) == 0:
        print("Strings array not set.")
        return False

    print(f"Loaded string chunks: {len(str_array)}")

    if deobf_funcs is None or len(deobf_funcs) == 0:
        print("Strings deobfuscation functions undefined")
        return False

    required_funcs = set(deobf_map)
    cache_names = _get_cache_function_names(
        all_func,
        deobf_map,
        deobf_root,
        inner_root,
    )
    resolved_funcs = load_resolved_funcs_from_csv(
        resolved_csv,
        all_func,
        cache_names,
    )
    missing_funcs = required_funcs - set(resolved_funcs)
    if missing_funcs:
        print(f"Missing {len(missing_funcs)} required cached decoder functions")
        missing_funcs = resolve_all_needed(
            all_func,
            deobf_map,
            deobf_root,
            inner_root,
        )
        if missing_funcs:
            return False
        save_resolved_funcs_to_csv(resolved_funcs, resolved_csv)

    missing_funcs = required_funcs - set(resolved_funcs)
    if missing_funcs:
        print(f"String decoder coverage is incomplete: {missing_funcs}")
        return False

    is_ok = strings_deobfuscate(all_func)
    if not is_ok:
        print("String deobfuscation failed")
        return False
    print(f"String deobfuscation OK")

    # Preserve the historical successful-output cleanup, but only after all
    # required decoders were resolved and replacement completed.
    find_and_load_string_array(all_func, start_name, hide_def=True)
    hidden = hide_by_metadata(all_func)
    if hidden:
        print(f"Hidden {hidden} functions")
    drop_str_deobf_meta(all_func)
    return True


def main():
    global g_Verbosity
    global deobf_roots
    global str_array
    global g_crack_strings
    global resolved_funcs
    parser = argparse.ArgumentParser(description="JSCeal string deobfuscator, variant 2")

    # Create a mutually exclusive group
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--mode', '-m', choices=['crack_strings', 'brutforce', 'find', 'decode', 'refs', 'strlist'],
        help="Specify the operation mode. Options are 'crack_strings', 'brutforce', 'find', 'decode', 'refs', 'strlist' (mutually exclusive)", default='decode')

    parser.add_argument('--inp', '-i', help="The input file name. It must be a serialized View8 output.", default=None, required=True)
    parser.add_argument('--out', '-o', help="The output file name.", default=None)
    parser.add_argument('--export_format', '-e', nargs='+', choices=['v8_opcode', 'translated', 'decompiled', 'serialized'], 
                        help="Specify the export format(s). Options are 'v8_opcode', 'translated', and 'decompiled'. Multiple options can be combined.", 
                        default=['serialized', 'decompiled'])
    parser.add_argument('--scope', help="Propagate scope arguments.", default=1, type=int, required=False)
    parser.add_argument('--strfunc', '-s', help="The function including definitions for string deobfuscation (chunks). If none is given, it will be autodetected.", default=None, required=False)
    parser.add_argument('--deobf-root', '-d', help="The root function of all the deobfuscating functions.", default=None, required=False)
    parser.add_argument('--csv', '-c', help="A CSV with resolved string deobfuscation functions.", default="resolved_funcs.csv", required=False)
    parser.add_argument('--func', help="A function to be analyzed (cleaned).", default=None, required=False)
    parser.add_argument('--verbosity', '-v', help="Verbosity level (0-3)", default=0, type=int, required=False)
    args = parser.parse_args()

    reset_resolver_state()
    g_Verbosity = args.verbosity

    if not os.path.isfile(args.inp):
        raise FileNotFoundError(f"The input file {args.inp} does not exist.")
    
    print(f"Reading from serialized, already decompiled input: {args.inp}")
    all_func = load_functions_from_file(args.inp)

    if args.scope:
        propagate_variables_default(all_func, 3, args.verbosity) 

    if 'strlist' in args.mode: 
        save_string_list(args.inp, all_func)
        return

    start_name = get_start_function(all_func)
    print(f"Start Func: {start_name}")

    deobf_map = find_all_str_deobf(all_func, args.verbosity)
    deobf_funcs = deobf_map.keys()
    print(f"All Deobf functions found: {len(deobf_map)}")

    deobf_root = None
    if args.deobf_root:
        deobf_root = args.deobf_root
    else:
        deobf_root = find_root_deobf(all_func, start_name)

    inner_root = None
    if deobf_root:
        deobf_roots = find_inner_deobf(all_func, deobf_root, args.verbosity)
        for k in deobf_roots:
            inner_root = k
            break

    print(f"Deobf root: {deobf_root}")
    print(f"Inner root: {inner_root}")

    if args.csv:
        cache_names = _get_cache_function_names(
            all_func,
            deobf_map,
            deobf_root,
            inner_root,
        )
        resolved_funcs = load_resolved_funcs_from_csv(
            args.csv,
            all_func,
            cache_names,
        )
        print(f"Loaded list of: {len(resolved_funcs)} resolved functions, from: {args.csv}")

    # The function containing all the string chunks that will be further used:
    if args.strfunc:
        print(f"Func for string deobf: {args.strfunc}")
        str_array = load_string_array(all_func, args.strfunc)     
    else:
        str_array = find_and_load_string_array(all_func, start_name)

    if str_array is None or len(str_array) == 0:
        print("Strings array not set.")
        return
    print(f"Loaded string chunks: {len(str_array)}")

    if deobf_funcs is None or len(deobf_funcs) == 0:
        print("Strings deobfuscation functions undefined")
        return

    if 'crack_strings' in args.mode:
        print("Cracking strings...")
        gather_all_used_keys(all_func, deobf_funcs, 50)
        crack_collected_strings()
        print(f"Done.")
        return

    required_funcs = set(deobf_map)
    missing_funcs = required_funcs - set(resolved_funcs)

    if 'find' in args.mode or missing_funcs:
        missing_funcs = resolve_all_needed(all_func, deobf_map, deobf_root, inner_root)
        if missing_funcs:
            print(f"Unable to resolve all required string decoder functions")
            return
        save_resolved_funcs_to_csv(resolved_funcs, args.csv)
        if not args.out:
            print(f"Done.")
            return

    # Each of different string deobfuscation function uses a different, obfuscated constants. We may need to brutforce them:
    if 'brutforce' in args.mode or missing_funcs:
        print("Brutforcing diffs...")
        brutforce_diffs = True
        if args.func:
            print(f"Analysing: {args.func}")
            _walk_str_deobf_refs(all_func, args.func, deobf_funcs, brutforce_diffs)
        else:
            walk_str_deobf_refs(all_func, deobf_funcs, brutforce_diffs)
        if 'brutforce' in args.mode:
            print(f"Done.")
            return

    missing_funcs = required_funcs - set(resolved_funcs)
    if missing_funcs:
        print(f"String decoder coverage is incomplete: {missing_funcs}")
        return

    if 'refs' in args.mode:
        print("Listing references...")
        # List all calls to string deobfuscating functions
        for name in all_func:
            func = all_func[name]
            if not func.visible:
                continue
            indexes = find_calls_in_function(func, resolved_funcs.keys())
            print_selected_lines(func, indexes, "STR")
        if not args.out:
            print(f"Done.")
            return

    print("Filling in strings...")
    # Once all the components are ready we can proceed with the deobfuscation:
    if args.func:
        filtered = find_functions_by_name(all_func, args.func)
        if not args.func in filtered:
            print(f"Function {args.func} was not found. Found {len(filtered)} similar names.")
            for key in filtered.keys():
                print(key)
        if len(filtered) == 0:
            return
        print(f"Deobfuscating filtered")
        strings_deobfuscate(filtered)
        print_funcs(filtered)
    else:
        strings_deobfuscate(all_func)

    # The output may be saved into a file:
    if args.out:
        hidden = hide_by_metadata(all_func)
        if hidden:
            print(f"Hidden {hidden} functions")
        drop_str_deobf_meta(all_func)
        export_to_file(args.out, all_func, args.export_format)
        save_string_list(args.out, all_func)
    print(f"Done.")


if __name__ == "__main__":
    main()
