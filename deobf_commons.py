#!/usr/bin/env python3
# JSC Deobfuscator - static deobfuscation of View8 pseudocode generated from
# compiled V8 JavaScript bytecode.
#
# Copyright (C) 2026 Aleksandra "Hasherezade" Doniec @ Check Point Research
# SPDX-License-Identifier: GPL-2.0-or-later
#

import os
import ast
import re
import urllib.parse
from bisect import bisect_left

from View8.Parser.shared_function_info import SharedFunctionInfo
from View8.view8_util import get_start_function, find_functions_by_name, next_visible_line
from deobf_scope2 import split_rhs_lhs

###
# String deobfuscation algorithms

def customB64(a0):
    """
    Custom Base64 decoder
    """
    r0 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    
    r1 = ""
    r2 = ""
    r5 = 0
    r6 = None
    r8 = 0
    
    # First loop: Custom Base64 decoding
    while True:
        r11 = r8
        r8 = r8 + 1
        
        if r11 >= len(a0):
            r7 = ""
        else:
            r7 = a0[r11]
        
        if not r7:
            break
        
        try:
            char_index = r0.index(r7)
        except ValueError:
            char_index = -1
        
        r7 = char_index
        
        if char_index != -1:
            if r5 % 4:
                r9 = r6 * 64
                r6 = r9 + r7
            else:
                r6 = r7
            
            r9 = r5
            r5 = r5 + 1
            
            if r9 % 4:
                shift_amount = (r5 * -2) & 6
                r12 = (r6 >> shift_amount) & 255
                r1 = r1 + chr(r12)
    
    # Second loop: Convert to URL-encoded format
    r3 = 0
    r4 = len(r1)
    
    while r3 < r4:
        r14 = ord(r1[r3])
        r12 = f"{r14:02x}"
        r2 = r2 + "%" + r12
        r3 = r3 + 1
    
    return urllib.parse.unquote(r2)

    
def rc4_decrypt(base64_data, key):
    """
    Simplified RC4 decryption with custom Base64
    
    Args:
        base64_data (str): Base64-encoded data (using custom alphabet)
        key (str): RC4 key
        
    Returns:
        str: Decrypted plaintext
    """
  
    encrypted_data = customB64(base64_data)
    
    # RC4 decryption
    # Initialize state array
    S = list(range(256))
    
    # Key scheduling
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]
    
    # Generate keystream and decrypt
    i = j = 0
    result = []
    
    for char in encrypted_data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        
        keystream_byte = S[(S[i] + S[j]) % 256]
        decrypted_byte = ord(char) ^ keystream_byte
        result.append(chr(decrypted_byte))
    
    return ''.join(result)

###
# Utils

def find_calls_in_function(func, searched_list):
    """
    Find inside the function calls to the functions from the supplied list
    """
    func_call_patt = re.compile(r'(func_[a-zA-Z0-9_$]+_0x[0-9a-fA-F]+)\(')
    line_indexes = set()
    for i in range(len(func.code)):
        if not func.code[i].visible or not func.code[i].decompiled:
            continue
        line = func.code[i].decompiled.strip()
        for name in func_call_patt.findall(line):
            if name in searched_list:
                line_indexes.add(i)
    return line_indexes

def print_selected_lines(func, lines_list, tag):
    """
    Print all the lines in the function with indexes given by the list
    """
    for i in lines_list:
        if i > len(func.code):
            continue
        line = func.code[i].decompiled.strip()
        print(f"[{tag}]: {func.name} : {line}")


def _hide_line(func, line_indx, verbosity=0, dbg=0):
    if func.code[line_indx].visible and verbosity > 1:
        print(f"{func.name}:\n\tHidden line: {func.code[line_indx].decompiled.strip()}")
    if (dbg):
        func.code[line_indx].decompiled += "###"
    else:
        func.code[line_indx].visible = False


def _hide_lines(func, lines_list, verbosity=0, dbg=0):
    for i in lines_list:
        _hide_line(func, i)


###

def load_string_array(functions, curr_func):
    str_array = None
    func = functions.get(curr_func)
    for var in func.const_pool:
        if var.startswith("["):
            str_array = ast.literal_eval(var)
    if str_array:
        func.metadata = "StringChunksContainer"
    return str_array

def print_stored_str(str_array):
    i = 0
    for s in str_array:
        print(f"val[{i}] = '{s}'")
        i += 1

def find_and_load_string_array(functions, start_name, hide_def=True):
    if not start_name or start_name not in functions.keys():
        return None
    pattern = re.compile(r'ACCU\s*=\s*(func_[\w#$]+)\(([\w#$]+),\s*(\d+)\)')
    func = functions[start_name]
    resolv_func_name = None
    str_func_name = None
    def_indx = None
    for indx in range(len(func.code)):
        line_obj = func.code[indx]
        if not line_obj.decompiled:
            continue
        line = line_obj.decompiled
        match = pattern.search(line)
        if match:
            resolv_func_name = match.group(1)
            str_func_name = match.group(2)
            def_indx = indx
            break
    if not str_func_name:
        print(f"Func with the string array was not found in {start_name}")
        return None
    if not str_func_name.startswith("func_"):
        s_patt = "func_" + str_func_name + "_"
    else:
        s_patt = str_func_name
    for name in functions:
        if s_patt in name:
            str_array = load_string_array(functions, name)
            if str_array is not None and len(str_array):
                print(f"Strings loaded from: {name}")
                if hide_def:
                    func.code[def_indx].visible = False
                    functions[name].visible = False
                    if resolv_func_name in functions.keys():
                        functions[resolv_func_name].visible = False
                    print("Hidden the strings definitions")
                return str_array
    return None

FULL_FUNCTION_NAME_PATTERN = r'func_[a-zA-Z0-9_$]+_0x[0-9a-fA-F]+'

def find_root_deobf(functions, start_name, verbosity = 0):

    pattern1 = re.compile(
        rf'\b({FULL_FUNCTION_NAME_PATTERN})'
        rf'\s*\(\s*(\d+)\s*,\s*"([^"]*?)"\s*\)'# variant with index first
    )
    pattern2 = re.compile(
        rf'\b({FULL_FUNCTION_NAME_PATTERN})'
        rf'\s*\(\s*"([^"]*?)"\s*,\s*(\d+)\s*\)'# variant with key first
    )
    if not start_name in functions.keys():
        return
    func = functions[start_name]
    for line_obj in func.code:
        if (not line_obj.visible or not line_obj.decompiled):
            continue
        line = line_obj.decompiled
        match = pattern1.search(line)
        if not match:
            match = pattern2.search(line)
        if not match:
            continue
        str_func_name = match.group(1)
        if verbosity > 0:
            print(f"Found: {str_func_name}")
        return str_func_name
    return None


def count_func_lines(func, visible_only=True):
    count = 0
    for current_obj in func.code:
        if (not current_obj.decompiled):
            continue
        if visible_only and (not current_obj.visible):
            continue
        line = current_obj.decompiled.strip()
        if (line == "{" or line== "}"):
            continue
        count += 1
    return count

###
# String deobfuscation utilities

def save_string_list(input_file, all_func):
    filename = input_file + '.strings.txt'
    strlist = list_metadata_strings(all_func)
    if len(strlist) == 0:
        print("This file does not have deobfuscated strings. Run deobfuscator first.")
        return
    with open(filename, 'w') as f:
        for line in strlist:
            f.write(f"{line}\n")
    print(f"Saved string list (total: {len(strlist)}) to: {filename}")
    return len(strlist)


def list_metadata_strings(functions, unique=False):
    str_list = set() if unique else []

    def _collect_string(my_str):
        if unique:
            str_list.add(my_str)
        else:
            str_list.append(my_str)

    for func in functions.values():
        for current_obj in func.code:
            if not current_obj.visible or not current_obj.decompiled:
                continue

            str_meta = current_obj.get_metadata("string")
            if not str_meta:
                continue

            if isinstance(str_meta, str):
                _collect_string(str_meta)

            elif isinstance(str_meta, set):
                # Keep non-unique listings deterministic.
                for my_str in sorted(str_meta):
                    _collect_string(my_str)

    return str_list


def set_string_metadata(line_obj, string):
    if not isinstance(string, str):
        return line_obj

    curr_str = line_obj.get_metadata("string")

    if curr_str is None:
        line_obj.set_metadata("string", string)

    elif isinstance(curr_str, str):
        if curr_str != string:
            line_obj.set_metadata("string", {curr_str, string})

    elif isinstance(curr_str, set):
        curr_str.add(string)

    return line_obj

_STRING_LITERAL_TOKEN_RE = re.compile(
    r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')'''
)

def _string_metadata_key(value):
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if _STRING_LITERAL_TOKEN_RE.fullmatch(stripped):
        return stripped[1:-1]
    return value


def propagate_string_metadata(source_obj, target_obj, propagated_expression):
    """Copy decoded-string annotations represented by an expression.

    Metadata is transferred only from the concrete source line that supplied
    the replacement and only for exact string-literal tokens present in the
    propagated expression.  This preserves provenance without globally
    matching equal string values across unrelated lines.
    """
    literal_keys = {
        match.group(0)[1:-1]
        for match in _STRING_LITERAL_TOKEN_RE.finditer(
            propagated_expression or ""
        )
    }
    if not literal_keys:
        return target_obj

    string_meta = source_obj.get_metadata("string")
    if isinstance(string_meta, str):
        values = (string_meta,)
    elif isinstance(string_meta, set):
        values = tuple(sorted(string_meta))
    else:
        return target_obj

    copied_keys = set()
    for value in values:
        key = _string_metadata_key(value)
        if key not in literal_keys or key in copied_keys:
            continue
        set_string_metadata(target_obj, value)
        copied_keys.add(key)

    return target_obj


def sync_string_metadata(line_obj):
    """Keep only string metadata represented by literals on the current line."""
    curr_str = line_obj.get_metadata("string")
    if isinstance(curr_str, str):
        values = (curr_str,)
    elif isinstance(curr_str, set):
        values = tuple(curr_str)
    else:
        return line_obj

    line = line_obj.decompiled or ""
    literal_keys = {
        match.group(0)[1:-1]
        for match in _STRING_LITERAL_TOKEN_RE.finditer(line)
    }

    kept = {
        value for value in values
        if _string_metadata_key(value) in literal_keys
    }

    if not kept:
        line_obj.drop_metadata("string")
    elif len(kept) == 1:
        line_obj.set_metadata("string", next(iter(kept)))
    else:
        line_obj.set_metadata("string", kept)

    return line_obj

###


def _simplify_chain_assignments(func):
    is_changed = False
    def_pattern = re.compile(r'(\w+) = "([^\"]+)"')
    indx = 0
    lines_list = set()
    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break

        current_obj = func.code[indx]
        curr_line = func.code[indx].decompiled

        # Match a simple assignment: VAR = "str"
        match = def_pattern.search(curr_line)
        if not match:
            continue

        var1, val1 = match.groups()
        #replace all...

        indx2 = indx
        while True:
            next_obj = None
            while True:
                indx2 = next_visible_line(func, indx2)
                if indx2 is None:
                    break
                if var1 in func.code[indx2].decompiled:
                    next_obj = func.code[indx2]
                    break

            if not next_obj:
                break

            # Match next line as: VAR = (VAR + "str2")
            next_line = next_obj.decompiled
           
            join_pattern = re.compile(rf'\({var1} \+ "([^"\\]*(\\.[^"\\]*)*)"\)')
            match2 = join_pattern.search(next_line)
            if match2:
                val2 = match2.group(1)
                lines_list.add(indx)
                #current_obj.visible = False # redefinition of the original value, hide the previous definition
                joined_str = f'"{val1 + val2}"'
                next_line = next_line.replace(match2.group(0), joined_str)
                next_obj.decompiled = next_line
                set_string_metadata(next_obj, joined_str)
                sync_string_metadata(next_obj)
                is_changed = True

            # it is possible that more lines are making use of this string, so stop search only if this is a new definition
            var_redef = f"{var1} = "
            _next_line = next_line.strip()
            if _next_line.startswith(var_redef):
                break

    _hide_lines(func, lines_list, 0)
    return is_changed

def simplify_chain_assignments(functions):
    for func in functions.values():
        while(_simplify_chain_assignments(func)): 
            continue # try to simplify till possibilities are exhausted

###
# Mark reg definitions
PATTERN_REG_DEF = re.compile(r'^(r\d+) =')
PATTERN_REG_USE = re.compile(r'\b(r\d+)\b')

def mark_regs_used_and_defined_in_line(code_obj):
    """
    If the line uses or defines some registers, set appropriate metadata.
    For defined register: "defined_reg":str
    For used registers: used_regs:set[str]
    """
    # First, erase the previously set metadate (the line content might have changed)
    code_obj.drop_metadata("defined_reg")
    code_obj.drop_metadata("used_regs")

    line = code_obj.decompiled.strip()
    lhs, rhs = split_rhs_lhs(line)
    used_regs = set(re.findall(PATTERN_REG_USE, rhs))
    if lhs:
        # is it a direct definition, i.e. `r1 = 345`?
        match = PATTERN_REG_DEF.search(lhs)
        if match:
            reg = match.group(1)
            code_obj.set_metadata("defined_reg", reg)
        else:
            # the register may also be used in the LHS expression, for example as an array index
            used = set(re.findall(PATTERN_REG_USE, lhs))
            used_regs.update(used)

    if used_regs and len(used_regs):
        code_obj.set_metadata("used_regs", used_regs)

def mark_regs_used_and_defined(func):
    """
    Process all visible lines in the functions. If the line uses or defines some registers, set appropriate metadata.
    For defined register: "defined_reg":str
    For used registers: used_regs:set[str]
    """
    # collect all usages and definitions
    for i in range(len(func.code)):
        code_obj = func.code[i]
        if (not code_obj.decompiled or not code_obj.visible):
            continue
        mark_regs_used_and_defined_in_line(code_obj)

def _add_to_set(key, value, dict_set) -> None:
    if not key in dict_set.keys():
        dict_set[key] = set()
    dict_set[key].add(value)

def _latest_definition_before(def_indices: set[int], usage_index: int) -> int | None:
    defs_sorted = sorted(def_indices)
    pos = bisect_left(defs_sorted, usage_index)  # first def >= usage_index
    if pos == 0:
        return None
    return defs_sorted[pos - 1]

def map_defs_to_usages(reg_usages: set[int], reg_defs:set[int]):
    """
    Map each line in which the register was used to the line where its value was defined.
    Lines are represented by their indexes.
    """
    def_to_usages = {}
    for usage_i in reg_usages:
        # get the index of the actual definition relevant for this line:
        def_indx = _latest_definition_before(reg_defs, usage_i)
        if def_indx is None:
            continue # missing definition for the usage, this is an anomaly
        _add_to_set(def_indx, usage_i, def_to_usages)
    return def_to_usages

def collect_regs_used_and_defined(func, defs, used):
    # collect all usages and definitions
    for i in range(len(func.code)):
        code_obj = func.code[i]
        if (not code_obj.decompiled or not code_obj.visible):
            continue
        used_regs = code_obj.get_metadata("used_regs")
        defined_reg = code_obj.get_metadata("defined_reg")
        if defined_reg is not None:
            _add_to_set(defined_reg, i, defs)
        if used_regs is not None:
            for reg in used_regs:
                _add_to_set(reg, i, used)
###
# Hide unreferenced variables

def _looks_control_flow_flattened(func):
    """
    Return True when the current decompiled body still looks like a
    javascript-obfuscator control-flow-flattened dispatcher.

    Before unflattening, textual line order is not execution order. A
    register definition may legitimately appear after its use in another
    dispatcher chunk, so aggressive linear dead-definition removal is not
    safe for these functions.
    """
    order_pattern = re.compile(r'"\d+(?:\|\d+)+"')
    has_order = False
    has_dispatcher_loop = False

    for line_obj in func.code:
        if not line_obj.visible or not line_obj.decompiled:
            continue
        line = line_obj.decompiled
        if not has_order and order_pattern.search(line):
            has_order = True
        if not has_dispatcher_loop and re.search(r'\bwhile\s*\(\s*true\s*\)', line):
            has_dispatcher_loop = True
        if has_order and has_dispatcher_loop:
            return True
    return False

def hide_unreferenced_variables_in_func(name, func, patterns_set, never_used_only=True, verbosity=0):
    '''
    Hide unreferenced variables of types defined by `patterns_set`.
    If `never_used_only` is set, the lines are hidden only if there is no use of the register where the definition was found, all thought the function.
    Otherwise, they are hidden if there is no use linked to the particular definition (more aggressive).
    '''
    defs = {}
    p_defs = {}
    used = {}

    def _display_sets():
        for reg in p_defs.keys():
            if reg not in used.keys():
                print(f"!!! Unreferenced: {reg}")
            print(f"### reg: {reg}")
            
            print("# Defined in:")
            if reg not in defs.keys():
                print("No def lines?")
            else:
                for i in defs[reg]:
                    print(f"{i}: {func.code[i].decompiled.strip()} : {func.code[i].visible}")

            if reg in used.keys():
                print("# Used in:")
                for i in used[reg]:
                    print(f"{i}: {func.code[i].decompiled.strip()}")
            print("# Matched defs:")
            for i in p_defs[reg]:
                print(f"{i}: {func.code[i].decompiled.strip()} : {func.code[i].visible}")
            print("###")

    collect_regs_used_and_defined(func, defs, used)

    # collect all definitions that match the given patterns:
    for i in range(len(func.code)):
        current_obj = func.code[i]
        if (not current_obj.decompiled or not current_obj.visible):
            continue
        line = current_obj.decompiled.strip()
        match = None
        for p in patterns_set:
            match = p.match(line)
            if match:
                break
        if match:
            # The CFF unflattener may reconstruct a conditional remainder as
            # a synthetic guard. A definition in that guard can legitimately
            # appear after a use in the linearized output, even though it was
            # required by the original dispatcher control flow. Do not let
            # the generic dead-assignment cleanup remove such definitions.
            if current_obj.get_metadata("CffGuardedRemainder"):
                continue
            reg = match.group(1)
            _add_to_set(reg, i, p_defs)

    if verbosity > 2:
        _display_sets()

    # Hide the unused definitions:
    for reg in p_defs.keys():
        if not reg in used.keys():
            _hide_lines(func, p_defs[reg])
            continue

        if never_used_only:
           continue 
        
        def_to_usages = map_defs_to_usages(used[reg], defs[reg])
        for p_indx in p_defs[reg]:
            if p_indx not in def_to_usages.keys():
                _hide_line(func, p_indx)


def hide_unreferenced_variables(functions, verbosity):
    pattern_n = re.compile(r'^(r\d+) = new {') #dictionaries
    pattern_s = re.compile(r'^(r\d+) = \"[ -~]+\"$') # strings
    pattern_d1 = re.compile(r'^(r\d+) = \(-\d+\)$') # negative number, i.e. r9 = (-49)
    pattern_d2 = re.compile(r'^(r\d+) = \d+$') # positive number, i.e. r9 = 103
    pattern_func = re.compile(r'^(r\d+) = func_[A-Za-z0-9_]+$')

    patterns_set1 = set()
    patterns_set1.add(pattern_n)
    patterns_set1.add(pattern_s)
    patterns_set1.add(pattern_func)
    patterns_set1.add(pattern_d1)

    patterns_set2 = set()
    patterns_set2.add(pattern_d2)

    for name in functions.keys():
        func = functions[name]
        mark_regs_used_and_defined(func)

        # A flattened dispatcher is not laid out in execution order. Keep any
        # matched definition whose register is used anywhere in the function;
        # otherwise a definition from a later dispatcher state can be hidden
        # before the unflattener has a chance to reorder the chunks.
        conservative = _looks_control_flow_flattened(func)
        hide_unreferenced_variables_in_func(name, func, patterns_set1, conservative, verbosity)
        # be more careful with hiding unreferenced lines with numbers - sometimes they seem unreferenced because of a bug, but they are crucial for understanding the logic
        hide_unreferenced_variables_in_func(name, func, patterns_set2, True, verbosity)

###

class StrDeobfFunction:
    def __init__(self, name=None, diff_s=None, is_index_first=None, rfunc=None):
        self.name = name
        self.diff_s = diff_s # diff relative to the function
        self.is_index_first = is_index_first
        self.rfunc = rfunc

    def __repr__(self):
        return f"StrDeobfFunction(name={self.name},diff_s={self.diff_s}, is_index_first={self.is_index_first}, rfunc={self.rfunc})"

def drop_str_deobf_meta(all_func):
    for func in all_func.values():
        if isinstance(getattr(func, "metadata", None), StrDeobfFunction):
            func.metadata = None

def get_str_deobf_function(name, func, verbosity):
    pattern1 = re.compile(r'\s*(r\d+) = \(a(\d+) - (\d+)\)')      # r1 = (a0 - 912)
    pattern2 = re.compile(r'\s*(r\d+) = \(a(\d+) - \((-\d+)\)\)') # r1 = (a0 - (-1041))
    pattern3 = re.compile(r'\s*return\s+([a-zA-Z_$][\w$]*)\s*\(')
    is_index_first = None
    a_val = None
    diff_s = None
    rfunc = None
    count = count_func_lines(func)
    if count > 4:
        return None
    for line_obj in func.code:
        if (not line_obj.visible or not line_obj.decompiled):
            continue
        line = line_obj.decompiled
        if a_val is None or diff_s is None:
            match = pattern1.match(line)
            if not match:
                match = pattern2.match(line)
            if match:
                a_val = int(match.group(2))
                diff_s = match.group(3)
                if a_val == 0:
                    is_index_first = True
                else:
                    is_index_first = False
                continue
        else:
            match = pattern3.match(line)
            if match:
                rfunc = match.group(1)
                break
    if a_val is not None and diff_s is not None and rfunc is not None:
        return StrDeobfFunction(name, int(diff_s), is_index_first, rfunc)
    return None


def find_inner_deobf(all_func, name, verbosity):
    func_set = set()
    funcs = find_functions_by_name(all_func, name)
    for name in funcs:
        print(f"Checking: {name}")
        func = all_func[name]
        d = get_str_deobf_function(name, func, verbosity)
        if d is not None:
            func_set.add(d.rfunc)
    return func_set

def find_all_str_deobf(all_func, verbosity):
    funcs_map = {}
    for name in all_func:
        func = all_func[name]
        d = get_str_deobf_function(name, func, verbosity)
        if d is None:
            continue
        func.metadata = d
        funcs_map[name] = d
    return funcs_map

def string_escape(s: str) -> str:
    s = s.replace("\\", "\\\\")     # must be first
    s = s.replace('"', "'")         # substitute with a single quote
    s = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    out = []
    for c in s:
        if c.isprintable():
            out.append(c)
        else:
            cp = ord(c)
            out.append("\\x%02x" % cp if cp <= 0xff else
                       "\\u%04x" % cp if cp <= 0xffff else
                       "\\U%08x" % cp)
    return "".join(out)
