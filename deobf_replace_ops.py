#!/usr/bin/env python3
# JSC Deobfuscator - static deobfuscation of View8 pseudocode generated from
# compiled V8 JavaScript bytecode.
#
# Copyright (C) 2026 Aleksandra "Hasherezade" Doniec @ Check Point Research
# SPDX-License-Identifier: GPL-2.0-or-later
#
import argparse
import os
import ast
import re

from View8.Parser.shared_function_info import save_functions_to_file, load_functions_from_file
from deobf_commons import *
from View8.view8_util import *
from deobf_scope2 import find_and_process_func_variables, replace_functions_via_registers, propagate_local_dicts

g_Verbosity = 0

def find_ops(functions, verbosity=0):
    """
    Find all functions defining a single operation
    Returns a dict in a format: function_name -> operation definition
    """
    op_funcs = dict()
    for func_name, func in functions.items():
        args_count = func.argument_count
        lines_count = len(func.code)
        indx = 0
        op_line = None
        patt = "return "
        while indx < lines_count:
            indx = next_visible_line(func, indx)
            line = func.code[indx].decompiled.strip()
            if line == "{" or line == "}":
                continue
            if line.startswith(patt) and "a0" in line:
                op_line = line.lstrip(patt)
                func.code[indx].set_metadata("OpDefinition", op_line)
                break
            else:
                break
        if not op_line:
            continue
        op_funcs[func_name] = op_line
        func.metadata = "OpFunc"
        #print(f"OpLine: `{op_line}`")
    return op_funcs

###


def replace_operator(function_name, op):
    pattern = r'func_([a-zA-Z0-9_$]+)_(0x[0-9a-fx]+)'
    # Define the pattern to match the function name
    op_types = [
        '>', '>>', '<', '>>>', '==', '+', '<<', '%', '^', '>=', '===', '/', '<=', '-', '*', 
        '&', '|'
        ]
    type_names = [
        'GreaterThan', 'SignedRightShift', 'LessThan', 'UnsignedRightShift', 'Equals', 'Plus', 'SignedLeftShift', 'Modulo', 'Xor', 'GreaterOrEqual', 'EqualsStrict', 'Div', 'LessOrEqual', 'Minus', 'Mul',
        'And', 'Or'
        ]
    try:
        index = op_types.index(op)
    except ValueError:
        return function_name
    updated_function_name = re.sub(pattern, lambda m: f"func_{type_names[index]}_{m.group(2)}", function_name)
    return updated_function_name

def resolve_op_functions(op_func, all_func, verbosity):
    
    # Map new names
    func_dict = dict()
    pattern = re.compile(r'(a0\s([<=>!]+)\s+a1|\(a0\s([+\-*\/%<=>!^]+)\s+a1\))$')
    
    for func_name, op_def in op_func.items():
        match = re.match(pattern, op_def)
        op = None
        if match:
            op = match.group(2)
            if op is None:
                op = match.group(3)
        if op:
            new_name = replace_operator(func_name, op)
            func_dict[func_name] = new_name
            if verbosity:
                print(f"{func_name} OP: {op_def} NEW_NAME: {new_name}")
        else:
            if verbosity:
                print(f"{func_name} OP: {op_def}")
    return func_dict

###

def _func_content_to_temp(function_content, template_str, args_count):
    """Convert function content to a template.
    It protects against recursive replacements
    (i.e. a0 gets replaced with a1 that is arg of the caller function, and then both will get replaced by next iteration)
    """
    # function_content can be a one-liner call
    # so make sure that arguments only are replaced, and not a0, etc. if it occurs in the function name
    patt1 = re.compile(r'(func_[A-Za-z0-9_$]+)\((.*?)\)')
    match = re.match(patt1, function_content)
    if match:
        func_name = match.group(1)
        inner_args = match.group(2)
        for i in range(0, args_count):
            s = f"a{i}"
            template = f"{template_str}{i}"
            inner_args = inner_args.replace(s, template)
        function_content = f"{func_name}({inner_args})"
        return function_content

    # simple case, not a function call:
    for i in range(0, args_count):
        s = f"a{i}"
        template = f"{template_str}{i}"
        function_content = function_content.replace(s, template)
    return function_content 

def _replace_args(args, function_content, verbosity=0):
    """
    Replace the call to the one-liner function with the literal content of this function.
    Fill in arguments.
    """
    template_str = "TEMPLATE_"
    function_content = _func_content_to_temp(function_content, template_str, len(args))
    # do the actual replacement:
    for i in range(0, len(args)):
        s = f"{template_str}{i}"
        arg_val = args[i].strip()
        if verbosity:
            print(f"CONTENT `{function_content}` REPL: `{s}` VA: `{arg_val}`")
        function_content = function_content.replace(s, arg_val)
    return function_content


def _find_calls_in_line(line, func_dict):
    """
    Find all calls of the functions from the given list in the given line. 
    Return the list of pairs: (func_name, arguments_str)
    """
    if not line:
        return []

    patt1 = re.compile(r'(func_[A-Za-z0-9_$]+)\((.*?)\)')
    line = line.strip()

    results = []
    for match in patt1.finditer(line):
        func_name = match.group(1)
        if func_name in func_dict:
            args = match.group(2)
            results.append((func_name, args))
    return results


def _find_funcs_in_line(line, func_dict):
    """
    Find all calls of the functions from the given list in the given line. 
    Return the list of func_name 
    """
    if not line:
        return set()

    patt1 = re.compile(r'(func_[A-Za-z0-9_$]+)')
    line = line.strip()

    results = set()
    for match in patt1.finditer(line):
        func_name = match.group(1)
        if func_name in func_dict:
            results.add(func_name)
    return results

def hide_unreferenced_functions(functions, func_dict, verbosity):
    referenced = set()
    for func in functions.values():
        for i in range(len(func.code)):
            line_obj = func.code[i]
            if not line_obj.visible or not line_obj.decompiled:
                continue
            funcs = _find_funcs_in_line(line_obj.decompiled, func_dict)
            referenced.update(funcs)
    hidden = 0
    for func_name in func_dict.keys():
        if func_name not in referenced:
            functions[func_name].visible = False
            hidden += 1
            if verbosity:
                print(f"Hiding: {func_name}")
    return hidden


def replace_references_in_func(func, functions, func_dict, verbosity):
    """
    Replace all the calls to the op function by the literal op
    """
    patt_double_not = re.compile(r'!\s*!\s*\(\s*([^()]*)\s*\)') # double negation like: `(!!(r2 === r13))``

    repl_count = 0
    for i in range(len(func.code)):
        line_obj = func.code[i]
        if not line_obj.visible or not line_obj.decompiled:
            continue

        line = line_obj.decompiled
        all_calls = _find_calls_in_line(line, func_dict)
        for (called, args_str) in all_calls:
            args_num = functions[called].argument_count - 1
            args = args_str.split(',')
            if len(args) != args_num:
                continue

            replaced = _replace_args(args, func_dict[called])
            if not replaced:
                continue

            new_line = line.replace(f"{called}({args_str})", replaced)
            if verbosity:
                print(f"{func.name} : {i}:")
                print(f"\t{line.strip()} : {func_dict[called]} : {replaced}")
                print(f"\t{new_line.strip()}")

            if new_line:
                line = new_line

        if line != line_obj.decompiled:
            new_line = line

            #cleanup double negations:
            line = line.replace('!!Boolean', 'Boolean')

            while patt_double_not.search(line):
                line = patt_double_not.sub(r'\1', line)
                if line != new_line and verbosity:
                    print(f"\tCLEANED: {line.strip()}")

            line_obj.decompiled = line
            repl_count += 1

    return repl_count


def replace_references(functions, func_dict, verbosity):
    """
    Replace all the calls to the op function by the literal op (in all functions)
    """
    repl_count = 0
    for func in functions.values():
        repl = replace_references_in_func(func, functions, func_dict, verbosity)
        repl_count +=repl
    return repl_count

def hide_unref_scopes(functions, verbosity):
    """
    Hide lines with unreferenced scope assignment
    """
    pattern_scope = re.compile(r'^(r\d+) = Scope\[\d+\]$') # i.e. r1 = Scope[5428]

    patterns_set = set()
    patterns_set.add(pattern_scope)

    for name in functions.keys():
        hide_unreferenced_variables_in_func(name, functions[name], patterns_set, verbosity)

def shrink_proxy_functions(functions, verbosity):
    count = 0
    for name in functions.keys():
        if shrink_proxy_func(functions[name], verbosity):
            count += 1
    return count

def shrink_proxy_func(func, verbosity=0):
    # r1 = a1
    pattern_args = re.compile(r'^(r\d+)\s*=\s*(a\d+)\s*$')

    # map: r1 -> a1
    reg_to_arg = {}

    # remember which lines are proxy assignments (to hide)
    proxy_lines = []

    indx = 0
    ret_indx = None
    ret_line = None

    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break

        line = func.code[indx].decompiled.strip()

        m = pattern_args.match(line)
        if m:
            r_id = m.group(1)   # "r1"
            a_id = m.group(2)   # "a1"
            reg_to_arg[r_id] = a_id
            proxy_lines.append(indx)
            continue

        if line.startswith("return"):
            ret_indx = indx
            ret_line = line
            break

        # If we hit something else before return, it doesn't match the proxy pattern
        return False

    if ret_indx is None or ret_line is None:
        return False

    if not reg_to_arg:
        return False

    # Replace rN -> aM inside the return line (only full tokens, not substrings)
    def repl(m):
        tok = m.group(0)
        return reg_to_arg.get(tok, tok)

    pattern = r'\br\d+\b'
    new_ret_line = re.sub(pattern, repl, ret_line)

    # If nothing changed, no point shrinking
    if new_ret_line == ret_line:
        return False

    # Update the return line
    func.code[ret_indx].decompiled = new_ret_line

    # Remove proxy assignment lines
    for i in proxy_lines:
        func.code[i].visible = False

    if verbosity:
        print(f"[shrink_proxy_func] {func.name}: removed {len(proxy_lines)} proxy lines")

    return True

def deobf_replace_ops_rounds(all_func, verbosity):
    op_func = {}
    repl_round = 0
    repl_count = 0
    repl_total = 0
    while True:
        if verbosity:
            print(f"Ops replacement round: {repl_round}")
        curr_ops = find_ops(all_func, g_Verbosity)
        op_func.update(curr_ops)
        repl_round += 1
        repl_count = replace_references(all_func, op_func, g_Verbosity)
        repl_total += repl_count
        if verbosity:
            print(f"Replaced: {repl_count} ops")
        if not repl_count:
            break
    return (op_func, repl_total)


def deobf_replace_ops_default(all_func, verbosity):
    #preprocess: propagate local dictionaries within the functions:
    
    propagate_local_dicts(all_func, verbosity)
    # preprocess: make sure that functions called via registers are propagated:
    replace_functions_via_registers(all_func, verbosity)

    # hide unreferenced scope assignments:
    # this is important cleanup, because some operator functions are like:
    #function func_TVAGH_0x206d106bfac9(a0, a1)
    #{
    #    r1 = Scope[11269] <- this has to be hidden so that the function will be recognized as the operator function
    #    return (a0 + a1)
    #}
    hide_unref_scopes(all_func, verbosity)

    shrink_proxy_functions(all_func, verbosity)
    
    # replace ops in rounds, till saturated:
    (op_func, repl_total) = deobf_replace_ops_rounds(all_func, verbosity)
    if verbosity:
        print(f"Replaced ops: {repl_total}")

    # rename the ops functions (to label those that could not be replaced)
    func_dict = resolve_op_functions(op_func, all_func, verbosity)

    # after the cleanup some of the functions became unreferenced, hide them:
    hidden_count = hide_unreferenced_functions(all_func, op_func, verbosity)

    rename_functions_in_code(all_func, func_dict, verbosity)

    #if verbosity:
    print(f"Hidden: {hidden_count} op functions")
    return all_func


def main():
    global g_Verbosity
    parser = argparse.ArgumentParser(description="V8 deobf. - Replace ops")
    parser.add_argument('--inp', '-i', help="The input file name. It must be a serialized View8 output.", default=None, required=True)
    parser.add_argument('--out', '-o', help="The output file name.", default=None)
    parser.add_argument('--export_format', '-e', nargs='+', choices=['v8_opcode', 'translated', 'decompiled', 'serialized'], 
                        help="Specify the export format(s). Options are 'v8_opcode', 'translated', and 'decompiled'. Multiple options can be combined.", 
                        default=['serialized', 'decompiled'])
    parser.add_argument('--rename', help="Rename functions", action="store_true", default=None, required=False)
    parser.add_argument('--func', help="A function to be analyzed (cleaned).", default=None, required=False)
    parser.add_argument('--propagate', '-p', help="Propagate functions", default=1, type=int, required=False)
    parser.add_argument('--hide', help="Hide unreferenced functions", default=1, type=int, required=False)
    parser.add_argument('--verbosity', '-v', help="Verbosity level (0-3)", default=0, type=int, required=False)
    args = parser.parse_args()
    
    g_Verbosity = args.verbosity
    
    if not os.path.isfile(args.inp):
        raise FileNotFoundError(f"The input file {args.inp} does not exist.")

    print(f"Reading from serialized, already decompiled input: {args.inp}")
    all_func = load_functions_from_file(args.inp)

    if args.propagate:
        replace_functions_via_registers(all_func, g_Verbosity)

    if args.func:
        op_func = {}
        curr_ops = find_ops(all_func, g_Verbosity)
        op_func.update(curr_ops)
        func_name = args.func
        func = all_func[func_name]
        if not func:
            print(f"Func {func_name} not found.")
            return
        print(f"Processing: {func_name}...")
        replace_references_in_func(func, all_func, op_func, g_Verbosity)
        return

    (op_func, _) = deobf_replace_ops_rounds(all_func, g_Verbosity)

    if args.rename:
        resolve_op_functions(op_func, all_func, g_Verbosity)

    if args.hide:
        if g_Verbosity:
            print("Searching unreferenced variables to hide...")
        hide_unreferenced_variables(all_func, g_Verbosity)
        if g_Verbosity:
            print("Searching the functions to hide...")
        hidden_count = hide_unreferenced_functions(all_func, op_func, g_Verbosity)
        print(f"Hidden: {hidden_count}")

    if args.out:
        export_to_file(args.out, all_func, args.export_format)
    print(f"Done.")


if __name__ == "__main__":
    main()
