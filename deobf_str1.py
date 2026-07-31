#!/usr/bin/env python3
import argparse
import os
import ast
import re

from View8.Parser.shared_function_info import save_functions_to_file, load_functions_from_file
from deobf_commons import *
from View8.view8_util import export_to_file
from deobf_scope2 import propagate_variables_default

str_array = None
g_Verbosity = 0
g_RootFunc = None
g_RootIndex = None

# Default shift value used for string array index obfuscation
SHIFT_VAL = 222

###
# String deobfuscation

str_array = None
function_index = None

def load_string_array(functions, curr_func):
    global str_array
    func = functions.get(curr_func)
    #func.decompile()
    for var in func.const_pool:
        if var.startswith("["):
            str_array = ast.literal_eval(var)

def print_stored_str():
    global str_array
    i = 0
    for s in str_array:
        print(f"val[{i}] = '{s}'")
        i += 1

def helper(i, n):
    global str_array
    return str_array[(int(i)-n)%len(str_array)]

def find_deobf_root(functions, start_name):
    if start_name not in functions.keys():
        return (None, None)

    start_func = functions[start_name]
    root = None
    root_indx = None

    def _validate_root(root_func, arr_func_name):
        """The root function should occur inside the function responsible for fetching strings from the array.
        """
        patt = re.compile(rf'^Scope\[(\d+)\]\[(\d+)\] = {arr_func_name}\(\)$')
        for line_obj in root_func.code:
            line = line_obj.decompiled.strip()
            if patt.match(line):
                return True
        return False

    pattern = re.compile(r'Scope\[(\d+)\]\[(\d+)\] = (\w+)$')
    pattern2 = re.compile(r'ACCU\s*=\s*(func_[\w#$]+)\(([\w#$]+),\s*(\d+)\)')
    for line_obj in start_func.code:
        line = line_obj.decompiled.strip()
        match = pattern.match(line)
        if match:
            root_indx_1 = match.group(1)
            root_indx_2 = match.group(2)
            root_indx = (root_indx_1,root_indx_2)
            root = match.group(3)
            continue
        match = pattern2.match(line)
        if match:
            arr_func_name = match.group(2)
            if root:
                if _validate_root(functions[root], arr_func_name):
                    return (root, root_indx)
                root = None
    return (root, root_indx)

def _get_all_index(functions):
    global function_index
    global g_RootFunc
    global g_RootIndex
    pattern = re.compile(r'Scope\[(\d+)\]\[(\d+)\] = Scope\[(\d+)\]\[(\d+)\]$')
    pattern2 = re.compile(rf'Scope\[(\d+)\]\[(\d+)\] = {re.escape(g_RootFunc)}$')

    for func in functions.values():
        for line_obj in func.code:
            line = line_obj.decompiled
            match = pattern.search(line)
            if match:
                # Example: Scope[90][2] = Scope[0][2]
                index1 = (match.group(1), match.group(2))
                index2 = (match.group(3), match.group(4))
            
                if index2 in function_index:
                    function_index[index1] = function_index[index2]
                    
            match = pattern2.search(line)
            if match:
                # Example: Scope[277][4] = H
                index1 = (match.group(1), match.group(2))
                function_index[index1] = function_index[g_RootIndex]

def get_all_index(functions):
    global function_index
    list_size = len(function_index)
    #saturate the list:
    while True:
        _get_all_index(functions)
        if len(function_index) == list_size:
            break
        list_size = len(function_index)


def replace_index_with_string(functions, verbosity):
    global function_index
    global g_RootFunc
    global g_RootIndex
    pattern = re.compile(r'Scope\[(\d+)\]\[(\d+)\]\((\d+)\)')
    pattern2 = re.compile(rf'(?:{re.escape(g_RootFunc)}|\w+)\((\d{{3,}})\)')
    #pattern2 = re.compile(r'(?:H|\w+)\((\d{3,})\)')

    for func in functions.values():
        for line_obj in func.code:
            line = line_obj.decompiled
            match = pattern.search(line)
            str_val = None
            if match:
                # Example: ACCU = (r3 + Scope[73][2](3817))
                index = (match.group(1), match.group(2))
                if index not in function_index:
                    continue
            
                str_val = helper(match.group(3), function_index[index])
                str_val = string_escape(str_val)
                line = line.replace(match.group(0), f'"{str_val}"')
            
            match = pattern2.search(line)
            if match:
                # Examples: ACCU = r1[r0(17812)] , r5 = r1[r0(18914)]
                str_val = helper(match.group(1), function_index[g_RootIndex])
                str_val = string_escape(str_val)
                line = line.replace(match.group(0), f'"{str_val}"')

            if line != line_obj.decompiled:
                if verbosity > 0:
                    print(f"Replacing:\n\t{line_obj.decompiled.strip()}\nwith:\n\t{line.strip()}")
                set_string_metadata(line_obj, str_val)
                line_obj.decompiled = line

def strings_deobfuscate(functions, verbosity):
    global function_index
    list_size = len(function_index)
    #saturate the list:
    while True:
        get_all_index(functions)
        if len(function_index) == list_size:
            break
        list_size = len(function_index)
    replace_index_with_string(functions, verbosity)
    simplify_chain_assignments(functions)

def hide_by_metadata(all_func):
    hidden = 0
    for func in all_func.values():
        if func.metadata:
            if isinstance(func.metadata, str):
                if func.metadata == "StringChunksContainer":
                    func.visible = False
                    hidden += 1
                continue
    return hidden

###

def strings_deobfuscate_v1(all_func, clean=True, strfunc=None):
    global g_Verbosity
    global g_RootFunc
    global g_RootIndex
    global str_array
    global function_index

    start_name = get_start_function(all_func)
    print(f"Start Func: {start_name}")
    (root, root_indx) = find_deobf_root(all_func, start_name)
    if not root:
        print(f"Deobf root not found!")
        return False

    print(f"Deobf root function: {root} Index: {root_indx}")
    g_RootFunc = root
    g_RootIndex = root_indx
    function_index = { g_RootIndex : SHIFT_VAL }

    # The function containing all the string chunks that will be further used:
    if strfunc:
        print(f"Func for string deobf: {strfunc}")
        str_array = load_string_array(all_func, strfunc)
    else:
        str_array = find_and_load_string_array(all_func, start_name)

    if str_array is None or len(str_array) == 0:
        print("Strings array not set.")
        return False

    print(f"Loaded strings: {len(str_array)}")
    strings_deobfuscate(all_func, g_Verbosity)
    if clean:
        hidden = hide_by_metadata(all_func)
    drop_str_deobf_meta(all_func)
    return True
###


def main():
    global g_Verbosity
    global g_RootFunc
    global g_RootIndex
    global str_array
    global function_index
    parser = argparse.ArgumentParser(description="JSCeal string deobfuscator, variant 1")
    parser.add_argument('--inp', '-i', help="The input file name. It must be a serialized View8 output.", default=None, required=True)
    parser.add_argument('--out', '-o', help="The output file name.", default=None)
    parser.add_argument('--export_format', '-e', nargs='+', choices=['v8_opcode', 'translated', 'decompiled', 'serialized'], 
                        help="Specify the export format(s). Options are 'v8_opcode', 'translated', and 'decompiled'. Multiple options can be combined.", 
                        default=['serialized', 'decompiled'])
    parser.add_argument('--scope', help="Propagate scope arguments.", default=1, type=int, required=False)
    parser.add_argument('--strfunc', '-s', help="Function including definitions for string deobfuscation.", default=None)
    parser.add_argument('--verbosity', '-v', help="Verbosity level (0-3)", default=0, type=int, required=False)
    args = parser.parse_args()
    
    g_Verbosity = args.verbosity
    
    if not os.path.isfile(args.inp):
        raise FileNotFoundError(f"The input file {args.inp} does not exist.")

    print(f"Reading from serialized, already decompiled input: {args.inp}")
    all_func = load_functions_from_file(args.inp)

    if args.scope:
        propagate_variables_default(all_func, 3, args.verbosity) 

    strings_deobfuscate_v1(all_func, True, args.strfunc)

    if args.out:
        export_to_file(args.out, all_func, args.export_format)
    save_string_list(args.inp, all_func)
    print(f"Done.")


if __name__ == "__main__":
    main()
