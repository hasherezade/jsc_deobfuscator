#!/usr/bin/env python3
# JSC Deobfuscator - static deobfuscation of View8 pseudocode generated from
# compiled V8 JavaScript bytecode.
#
# Copyright (C) 2026 Aleksandra "Hasherezade" Doniec @ Check Point Research
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''
JSC Deobfuscator
Applies sequentially all the deobfuscation filters with their default settings on the serialized decompiled file.
'''
import argparse
import os
import time

from View8.Parser.shared_function_info import save_functions_to_file, load_functions_from_file
from deobf_commons import *
from View8.view8_util import export_to_file, print_funcs, find_functions_by_name

from deobf_str2 import (
    strings_deobfuscate_v2,
    refresh_deobfuscated_strings,
    save_string_list,
)
from deobf_str1 import strings_deobfuscate_v1
from deobf_scope2 import propagate_variables_default, deobf_scope_default
from deobf_globals import propagate_globals
from deobf_unflattener import deobf_unflat_default
from deobf_replace_ops import deobf_replace_ops_default
from deobf_inline_temporaries import inline_temporaries_default


_SIGNATURE_MASK = (1 << 64) - 1


def _visible_code_signature(func):
    """Return a cheap per-run signature of the visible function body.

    The signature is used only inside one process to identify functions changed
    by later filters. Python's process-local string hashes make this much
    cheaper than copying or serializing complete function bodies.
    """
    signature1 = 1469598103934665603
    signature2 = 1099511628211
    visible_count = 0
    for line_obj in func.code:
        visible = bool(line_obj.visible)
        text = line_obj.decompiled if visible else None
        if visible:
            visible_count += 1
        token = hash((visible, text)) & _SIGNATURE_MASK
        signature1 ^= token
        signature1 = (signature1 * 1099511628211) & _SIGNATURE_MASK
        signature2 = (
            (signature2 ^ ((token + 0x9E3779B97F4A7C15) & _SIGNATURE_MASK))
            * 14029467366897019727
        ) & _SIGNATURE_MASK
    return (
        bool(getattr(func, "visible", True)),
        len(func.code),
        visible_count,
        signature1,
        signature2,
    )


def _snapshot_visible_code(functions):
    return {
        name: _visible_code_signature(func)
        for name, func in functions.items()
    }


def _changed_function_names(functions, snapshot):
    """Return changed functions that are still visible to the final output.

    Some later passes hide large families of helper functions. Their visibility
    transition changes the stored signature, but hidden functions cannot
    contain an exported decoder call and must not enter the final refresh.
    Check function visibility before calculating the comparatively expensive
    body signature.
    """
    return {
        name
        for name, func in functions.items()
        if getattr(func, "visible", True)
        and snapshot.get(name) != _visible_code_signature(func)
    }

def main():
    global g_Verbosity
    parser = argparse.ArgumentParser(description="JSCeal deobfuscator: deploys all deobfuscation passes.")

    parser.add_argument('--inp', '-i', help="The input file name. It must be a serialized View8 output.", default=None, required=True)
    parser.add_argument('--out', '-o', help="The output file name.", default=None, required=True)
    parser.add_argument('--export_format', '-e', nargs='+', choices=['v8_opcode', 'translated', 'decompiled', 'serialized'], 
                        help="Specify the export format(s). Options are 'v8_opcode', 'translated', and 'decompiled'. Multiple options can be combined.", 
                        default=['serialized', 'decompiled'])
    parser.add_argument('--csv', '-c', help="A CSV with resolved string deobfuscation functions. If omitted, defaults to <input_name>.resolved_funcs.csv.", default=None, required=False)
    parser.add_argument('--verbosity', '-v', help="Verbosity level (0-3)", default=0, type=int, required=False)
    parser.add_argument('--str_deobf', help="Variant of the string deobfuscation function (1 or 2)", default=2, type=int, required=False)
    args = parser.parse_args()
    
    if not os.path.isfile(args.inp):
        raise FileNotFoundError(f"The input file {args.inp} does not exist.")

    resolved_csv = args.csv
    if resolved_csv is None:
        input_stem, _ = os.path.splitext(args.inp)
        resolved_csv = f"{input_stem}.resolved_funcs.csv"

    print(f"Reading from serialized, already decompiled input: {args.inp}")
    all_func = load_functions_from_file(args.inp)
    start = time.perf_counter()

    propagate_variables_default(all_func, 3, args.verbosity) 

    str_start = time.perf_counter()
    is_ok = False
    if args.str_deobf == 1:
        is_ok = strings_deobfuscate_v1(all_func)
    else:
        is_ok = strings_deobfuscate_v2(all_func, args.verbosity, resolved_csv) 
    if not is_ok:
        print("Deobfuscating strings failed!")
        return
    elapsed_sec = time.perf_counter() - str_start
    elapsed_min = elapsed_sec / 60.0
    print(f"Deobfuscated strings in: {elapsed_sec} s. = {elapsed_min} min")
    is_ok = deobf_scope_default(all_func, args.verbosity) 
    if not is_ok:
        print("Deobfuscating scopes failed!")
        return
    unflattened_functions = set(deobf_unflat_default(
        all_func,
        args.verbosity,
        return_changed=True,
    ) or ())
    if args.str_deobf == 2:
        print("Refreshing decoded strings after unflattening...")
        refresh_deobfuscated_strings(
            all_func,
            args.verbosity,
            function_names=unflattened_functions,
        )

    # Later passes may expose an exact decoder callee or move a decoder call
    # into a resolvable expression. Snapshot once here, then refresh only the
    # functions whose visible code actually changed.
    post_unflatten_snapshot = _snapshot_visible_code(all_func)
    deobf_replace_ops_default(all_func, args.verbosity)
    
    print("Propagating globals...")
    propagate_globals(all_func, args.verbosity)
    
    print("Inlining temporary values...")
    inline_temporaries_default(all_func, args.verbosity)

    # Later simplification passes may expose the exact decoder callee or move a
    # known decoder call into its final expression. Run one last decoder-only
    # refresh before exporting so such calls cannot escape the string pass.
    if args.str_deobf == 2:
        print("Final refresh of decoded strings...")
        dirty_functions = set(_changed_function_names(
            all_func,
            post_unflatten_snapshot,
        ))
        refresh_deobfuscated_strings(
            all_func,
            args.verbosity,
            function_names=dirty_functions,
        )

    if not all_func:
        print("Deobfuscation failed")
        return
    elapsed_sec = time.perf_counter() - start
    elapsed_min = elapsed_sec / 60.0
    print(f"Deobfuscation OK. Total time: {elapsed_sec} s. = {elapsed_min} min")

    # The output may be saved into a file:
    if args.out:
        export_to_file(args.out, all_func, args.export_format)
        save_string_list(args.out, all_func)
    print(f"Done.")

if __name__ == "__main__":
    main()
