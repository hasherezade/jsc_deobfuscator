#!/usr/bin/env python3
# JSC Deobfuscator - static deobfuscation of View8 pseudocode generated from
# compiled V8 JavaScript bytecode.
#
# Copyright (C) 2026 Aleksandra "Hasherezade" Doniec @ Check Point Research
# SPDX-License-Identifier: GPL-2.0-or-later
#
''' Replace variables with their literal values: process global definitions
'''
import argparse
import os
import ast
import re
import json
from collections import defaultdict
from enum import IntFlag

from View8.Parser.shared_function_info import save_functions_to_file, load_functions_from_file
from View8.view8_util import *
from deobf_scope2 import split_rhs_lhs

g_Verbosity = 0

###
# Commons

CALLED_FUNC_PATTERN = re.compile(r'^(\w+)\(([^()]*)\)$')

def parse_called(line: str):
    match = CALLED_FUNC_PATTERN.match(line)
    if not match:
        return (None, None)
    return match.group(1), match.group(2)

def _remove_prefix(text: str, prefix: str):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

def _starts_with_any(rhs_expr: str, expr_set: set[str]):
    for f in expr_set:
        if rhs_expr.startswith(f):
            return True
    return False

###
# Process globals

def join_proxy_func(functions, func_name, verbosity):
    SCOPE_ACCESS = re.compile(r'Scope\[(\d+)]\[(\d+)]')
    pattern_scope = r'^Scope\[(\d+)\]\[(\d+)\]\s*=\s*(a\d+)$'
    pattern_ret_func = r'^return (func_[A-Za-z0-9_]+)$'

    scope_defs = {}

    defs_count = 0
    func2_name = None
    seen_return = False

    func = functions[func_name]

    def _replace(match):
        s_id = match.group(1)
        k = match.group(2)
        pair = (s_id, k)
        if pair in scope_defs:
            return str(scope_defs[pair])
        return match.group(0)

    indx = 0
    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break
        line = func.code[indx].decompiled.strip()
        match = re.match(pattern_scope, line)
        if match:
            pair = (match.group(1), match.group(2))
            scope_defs[pair] = match.group(3)
            defs_count += 1
            continue
        match = re.match(pattern_ret_func, line)
        if match:
            func2_name = match.group(1)
            break
        return False
    
    if not func2_name or not defs_count:
        return False

    if verbosity > 2:
        print_func(func_name,  functions[func_name])
        print_func(func2_name,  functions[func2_name])

    metadata = "ProxyFunc"
    pattern_main_proxy = r'^return (a\d+)$'
    pattern_exports_proxy = r'^return (a\d+)\[\"exports\"\]$'

    func2 = functions[func2_name]
    changed_lines = 0
    indx = 0
    while True:
        indx = next_visible_line(func2, indx)
        if indx is None:
            break
        line = func2.code[indx].decompiled
        if not "Scope" in line:
            continue
        line = SCOPE_ACCESS.sub(_replace, line)
        if line != func2.code[indx].decompiled:
            func2.code[indx].decompiled = line
            changed_lines += 1
            if re.match(pattern_main_proxy, line.strip()):
                metadata = "MainProxyFunc"
            elif re.match(pattern_exports_proxy, line.strip()):
                metadata = "ExportsProxyFunc"

    func.code = func2.code
    func.metadata = metadata
    func2.visible = False
    if verbosity:
        print_func(func_name, functions[func_name])
    return True

def tag_global_symbols(mapping: dict[str, str], tagged_map: dict[str, str]) -> dict[str, str]:
    """
    Tag found global symbols as the types they represent.
    """
    def _is_function(sym):
        if not sym.startswith("func_"):
            return False
        if "(" in rhs_expr and ")" in rhs_expr: # it is a call
            return False
        return True

    for name, sym in mapping.items():
        tag = "unk"

        if sym.startswith("func_"):
            tag = "function"
            if "[" in sym and "]" in sym:
                tag = "function_property"
            
        if sym.startswith("global_"):
            tag = "redir"
            if "[" in sym and "]" in sym:
                tag = "global_property"
            
        if sym.startswith("func_") or sym.startswith("global_"):
            if "(" in sym and ")" in sym: # it is a call
                tag = "function_call"

        if sym.startswith('\\^') or (sym.startswith('\\') and sym.endswith('\\')):
            tag = "regex"

        if sym.startswith('\"') and sym.endswith('\"'):
            tag = "string"

        if name in sym:
            tag = "recursive"

        if sym == '{}':
            tag = "set"

        if sym == '[]':
            tag = "array"

        if sym.startswith("new "):
            tag = "object"

        if sym.startswith("Object") and "[" in sym and "]" in sym:
            tag = "object_property"

        if tag:
            tagged_map[name] = tag
    return tagged_map

def print_tagged_symbols(tagged_map, globals_map, tag_filter = None, sym_filter = None):
    
    def _is_sym_referenced(sym, sym_filter):
        for s in sym_filter:
            if s in sym:
                return True
        return False
        
    for name, tag in tagged_map.items():
        sym = globals_map[name]
        if tag_filter and tag not in tag_filter:
            continue
        if sym_filter:
            if (name not in sym_filter and sym not in sym_filter) and not _is_sym_referenced(sym, sym_filter):
                continue
        
        print(f"`{name}`: {sym} -> {tag}")

def replace_global_proxy_calls(functions, globals_map, tagged_map, verbosity):
    
    proxy_sym_map = {}

    def _add_to_map(proxy_sym_map, meta_tag, name):
        if not meta_tag in proxy_sym_map.keys():
            proxy_sym_map[meta_tag] = set()
        proxy_sym_map[meta_tag].add(name)

    for name, tag in tagged_map.items():
        if tag != "function":
            continue
        sym = globals_map[name]
        if join_proxy_func(functions, sym, verbosity):
            if functions[sym].metadata:
                meta_tag = functions[sym].metadata
                _add_to_map(proxy_sym_map, meta_tag, name)

    # Convert symbolic names to functions
    proxy_funcs_map = {}
    for meta_tag in proxy_sym_map.keys():
        for sym in proxy_sym_map[meta_tag]:
            caller_func = globals_map[sym]
            if caller_func in functions.keys():
                _add_to_map(proxy_funcs_map, meta_tag, caller_func)

    if verbosity > 1:
        print(proxy_funcs_map)

    main_proxy_funcs = proxy_funcs_map.get("MainProxyFunc", set())
    exports_proxy_funcs = proxy_funcs_map.get("ExportsProxyFunc", set())

    if verbosity > 1:
        if not main_proxy_funcs:
            print("No global proxy functions tagged as MainProxyFunc; skipping")
        if not exports_proxy_funcs:
            print("No global proxy functions tagged as ExportsProxyFunc; skipping")

    for func_name in functions.keys():
        func = functions[func_name]
        _replace_proxy_calls(
            func,
            globals_map,
            main_proxy_funcs,
            "MainProxyFunc",
            "",
            verbosity,
        )
        _replace_proxy_calls(
            func,
            globals_map,
            exports_proxy_funcs,
            "ExportsProxyFunc",
            '["exports"]',
            verbosity,
        )

###
# Replace proxy function calls

PROXY_CALL_RE = re.compile(
    r"""
    \(\s*
        (?P<proxy>[A-Za-z_][A-Za-z0-9_]*)   # proxy function
        \s*\(\s*
            (?P<inner>[A-Za-z_][A-Za-z0-9_]*)  # wrapped function
        \s*\)
    \s*\)
    """,
    re.VERBOSE,
)

def _replace_proxy_in_line(line: str, proxy_funcs: set[str], out_arg: str) -> tuple[str, bool]:
    """
    Returns (new_line, changed)
    """

    def _repl(match: re.Match) -> str:
        proxy = match.group("proxy")
        inner = match.group("inner")

        if proxy not in proxy_funcs:
            return match.group(0)  # leave unchanged

        return f"{inner}{out_arg}"

    new_line, count = PROXY_CALL_RE.subn(_repl, line)
    return new_line, count > 0

def _replace_proxy_calls(func, globals_map: dict[str, str],
                        proxy_funcs: set[str], meta_tag: str, out_arg:str, verbosity) -> bool:
    changed = False
    indx = 0

    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break

        line = func.code[indx].decompiled

        # Fast skip
        if not any(p in line for p in proxy_funcs):
            continue

        new_line, did_change = _replace_proxy_in_line(line, proxy_funcs, out_arg)
        if did_change:
            if verbosity:
                print(f"[proxy] {line}  ->  {new_line}")
            func.code[indx].decompiled = new_line
            func.code[indx].set_metadata("ProxyCall", meta_tag)
            changed = True
    return changed

###
# Replace globals

def get_globals_set_from_start(start_func, hide_line=True):
    """
    Get the set of the global symbols defined in the Start function.
    """
    globals_set = None
    indx = 0
    while True:
        indx = next_visible_line(start_func, indx)
        if indx is None:
            break
        line = start_func.code[indx].decompiled.strip()
        if "DeclareGlobals([" not in line:
            continue
        globals_set = set(re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', line))
        if globals_set:
            if hide_line:
                start_func.code[indx].visible = False
            break
    return globals_set
    

ASSIGN_GLOBAL_SYM = re.compile(r'^\s*(global_[A-Za-z_$][\w$]*)\s*=\s*([^;]+)\s*;?\s*$')

GLOBAL_FORBIDDEN_EXPR = ['ACCU', 'new ', '\\^', '{', '[']

def collect_global_assignments(
    init_func,
    globals_set,
    globals_map: dict[str, str],
    verbosity,
    globals_sources=None,
) -> dict[str, str]:
    """
    init_func.code[*].decompiled contains lines like:  oQ = Object["create"]
    Returns: number of definitions changed
    """
    globals_sources = globals_sources if globals_sources is not None else {}
    reg_pattern = re.compile(r'(r\d+)')
    changed_count = 0
    global_prefix = "global_"

    for obj in init_func.code:
        if not (obj.visible and obj.decompiled):
            continue
        line = obj.decompiled.strip()
        m = ASSIGN_GLOBAL_SYM.match(line)
        if not m:
            continue
        name, rhs = m.group(1), m.group(2)
        curr_val = rhs.strip()
        m2 = reg_pattern.search(curr_val)
        if m2:
            if verbosity:
                print(f"Skipping line: `{line}` - it is using REG: `{m2.group(1)}`")
            continue

        should_hide = True
        if _starts_with_any(rhs, GLOBAL_FORBIDDEN_EXPR):
            should_hide = False

        if name.startswith(global_prefix):
            global_name = _remove_prefix(name, global_prefix)
            if not global_name in globals_set:
                if verbosity > 2:
                    print(f"WARNING: Not a recognized global name: {global_name}")
                continue
            if verbosity > 1:
                print(f"`{global_name}` assignment: {line.strip()}")

            if name in globals_map.keys():
                prev_val = globals_map[name]
                if prev_val != curr_val:
                    value = globals_map.pop(name, None)
                    globals_sources.pop(name, None)
                    changed_count += 1
                    if verbosity:
                        print(f"`{global_name}` WARNING: Repeated key definition: {name}. Prev `{prev_val}`, curr: `{curr_val}`. The key was removed")
            else:
                globals_map[name] = curr_val
                globals_sources[name] = obj
                changed_count += 1
                if should_hide:
                    obj.visible = False

    return changed_count

GLOBAL_SYM_PATTERN = re.compile(r'(global_[A-Za-z_$]\w*)')

def apply_globals_to_line(line: str, mapping: dict[str, str], verbosity):

    def _filter_matches(matches, globals_set):
        approved = set()
        for name in matches:
            if name not in globals_set:
                continue
            approved.add(name)
        return approved

    def _should_wrap(rhs_expr):
        if not rhs_expr.startswith("func_") and not rhs_expr.startswith("global_"):
            return True
        if "(" in rhs_expr and ")" in rhs_expr: # it is a call
            return True
        if "[" in rhs_expr and "]" in rhs_expr: # it is an array or object field
            return True
        return False

    (lhs, rhs) = split_rhs_lhs(line)

    matches = GLOBAL_SYM_PATTERN.findall(rhs)
    real_matches = _filter_matches(matches, mapping.keys())
    if (len(real_matches)) == 0:
        return None, set()

    _rhs = rhs
    replaced = 0
    replaced_names = set()
    for name in real_matches:
        rhs_expr = mapping[name]
        if _starts_with_any(rhs_expr, GLOBAL_FORBIDDEN_EXPR):
            if verbosity:
                print(f"`{name}` WARNING: The global resolves to forbidden expression: {rhs_expr}")
            continue
        if name in rhs_expr:
            if verbosity:
                print(f"`{name}` WARNING: Recursive expression: {name} -> {rhs_expr}")
            continue

        # Wrap to be safe in property/index contexts: sQ["call"] -> (Object["..."])["call"]
        val = rhs_expr
        if _should_wrap(rhs_expr):
            val = f"({rhs_expr})"

        # Replace identifier occurrences in RHS
        updated_rhs = _rhs.replace(name, val)
        if updated_rhs != _rhs:
            _rhs = updated_rhs
            replaced += 1
            replaced_names.add(name)

    if verbosity:
        print(f"Matches: {real_matches} Replaced: {replaced}")

    rhs = _rhs

    if not lhs:
        return rhs, replaced_names
    return lhs + rhs, replaced_names

def apply_globals_to_func(
    func,
    mapping: dict[str, str],
    verbosity=0,
    globals_sources=None,
) -> bool:

    globals_sources = globals_sources or {}

    # Imported lazily to keep the existing module dependency direction stable.
    from deobf_commons import propagate_string_metadata, sync_string_metadata

    changed = 0
    indx = 0
    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break
        obj = func.code[indx]
        line = obj.decompiled

        if not "global_" in line:
            continue

        new_line, replaced_names = apply_globals_to_line(
            line,
            mapping,
            verbosity,
        )
        if not new_line:
            continue

        if new_line != line:
            if verbosity:
                print(f"Repl: {line} -> {new_line}")
            obj.decompiled = new_line

            for name in replaced_names:
                source_obj = globals_sources.get(name)
                if source_obj is not None:
                    propagate_string_metadata(
                        source_obj,
                        obj,
                        mapping[name],
                    )
            sync_string_metadata(obj)

            changed += 1
    if changed and verbosity > 3:
        print_func(func.name, func)
    return changed

def _print_globals(globals_map):
    print("### Globals:")
    for key in globals_map.keys():
        print(f"`{key}` -> `{globals_map[key]}`")

def resolve_mapping(
    mapping: dict[str, str],
    max_passes: int = 8,
    sources=None,
) -> dict[str, str]:
    """
    If x -> y and y -> Object["create"], rewrite x -> Object["create"].
    Conservative: only resolves whole-identifier aliases.
    """
    out = dict(mapping)
    ident = re.compile(r'^[A-Za-z_$]\w*$')

    for _ in range(max_passes):
        changed = False
        for k, v in list(out.items()):
            if ident.match(v) and v in out and v != k:
                out[k] = out[v]
                if sources is not None and v in sources:
                    sources[k] = sources[v]
                changed = True
        if not changed:
            break
    mapping = out
    return out

def propagate_globals(functions, verbosity):

    start_name = get_start_function(functions)
    if not start_name:
        return False

    if verbosity > 1:
        print(f"Start func: {start_name}")
    init_func = functions[start_name]
    globals_set = get_globals_set_from_start(init_func)
    if verbosity > 1:
        print("# Globals Set")
        print(globals_set)

    globals_map = {}
    globals_sources = {}
    tagged_map = {}

    # Collecting globals from the start function:
    collect_round = 0
    while True:
        collect_round += 1
        if verbosity:
            print(f"Collecting global assigments, round {collect_round}")
        if not collect_global_assignments(
            init_func,
            globals_set,
            globals_map,
            verbosity,
            globals_sources,
        ):
            break
        resolve_mapping(globals_map, sources=globals_sources)
        apply_globals_to_func(
            init_func,
            globals_map,
            verbosity,
            globals_sources,
        )

    if len(globals_map) == 0:
        return False

    tag_global_symbols(globals_map, tagged_map)

    if verbosity > 1:
        _print_globals(globals_map)

    collect_round = 0
    empty_rounds = 0
    while empty_rounds < 5:
        collect_round += 1
        collected = 0
        changed = 0
        for func_name in functions.keys():
            func = functions[func_name]
            collected += collect_global_assignments(
                func,
                globals_set,
                globals_map,
                verbosity,
                globals_sources,
            )
            changed += apply_globals_to_func(
                func,
                globals_map,
                verbosity,
                globals_sources,
            )
        if verbosity:
            print(f"Collecting global assigments, round {collect_round} Items collected: {collected} Applied: {changed}")
        if collected == 0:
            break
        # if nothing has changed, reduce the number of attempts    
        if changed > 0:
            empty_rounds = 0
        else:
            empty_rounds += 1 

    tag_global_symbols(globals_map, tagged_map)
    replace_global_proxy_calls(functions, globals_map, tagged_map, verbosity)
    return True

###

def main():
    global g_Verbosity
    parser = argparse.ArgumentParser(description="JSCeal scope deobf - replace variables with literal values")
    parser.add_argument('--inp', '-i', help="The input file name. It must be a serialized View8 output.", default=None, required=True)
    parser.add_argument('--out', '-o', help="The output file name.", default=None)
    parser.add_argument('--export_format', '-e', nargs='+', choices=['v8_opcode', 'translated', 'decompiled', 'serialized'], 
                        help="Specify the export format(s). Options are 'v8_opcode', 'translated', and 'decompiled'. Multiple options can be combined.", 
                        default=['serialized', 'decompiled'])
    parser.add_argument('--func', help="A function to be analyzed (cleaned).", default=None, required=False)
    parser.add_argument('--verbosity', '-v', help="Verbosity level (0-3)", default=0, type=int, required=False)
    args = parser.parse_args()
    
    if not os.path.isfile(args.inp):
        raise FileNotFoundError(f"The input file {args.inp} does not exist.")

    if args.verbosity:
        g_Verbosity = args.verbosity

    globals_propagated = False

    print(f"Reading from serialized, already decompiled input: {args.inp}")
    all_func = load_functions_from_file(args.inp)

    # if selected, narrow down processing to the selected functions
    if args.func:
        name = args.func
        filtered = find_functions_by_name(all_func, args.func)
        if not args.func in filtered:
            print(f"Function {args.func} was not found. Found {len(filtered)} similar names.")
            for key in filtered.keys():
                print(key)
        if len(filtered) == 0:
            return
        print(f"Deobfuscating filtered")
        all_func = filtered

    print("[+] Propagate globals")
    if propagate_globals(all_func, g_Verbosity):
        globals_propagated = True

    if not globals_propagated:
        print("No changes applied")
        return

    if args.func:
        print_funcs(all_func)
    
    # The output may be saved into a file:
    if args.out:
        export_to_file(args.out, all_func, args.export_format)
    print(f"Done.")


if __name__ == "__main__":
    main()
