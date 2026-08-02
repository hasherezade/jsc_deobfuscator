#!/usr/bin/env python3
# JSC Deobfuscator - static deobfuscation of View8 pseudocode generated from
# compiled V8 JavaScript bytecode.
#
# Copyright (C) 2026 Aleksandra "Hasherezade" Doniec @ Check Point Research
# SPDX-License-Identifier: GPL-2.0-or-later
#
''' Replace variables with their literal values, including Scope array references.
'''
import argparse
import os
import ast
import re
import json
from collections import defaultdict
from enum import IntFlag

from View8.Parser.shared_function_info import save_functions_to_file, load_functions_from_file
from View8.Simplify.global_scope_replace import replace_global_scope, find_assignment_op
from View8.view8_util import *

g_Verbosity = 0
g_HideDefs = True

###
# Commons

def split_rhs_lhs(line: str):
    op_indx = find_assignment_op(line)
    if op_indx is None:
        return (None, line)
    return (line[:op_indx+1], line[op_indx+1:])

###
# Merge dictionaries

def merge_fill_none_inplace(base: dict, incoming: dict) -> None:
    for k, v in incoming.items():
        if k not in base or (base[k] is None and v is not None):
            base[k] = v

def merge_fill_none_remove_conflicts(base: dict, incoming: dict) -> dict:
    result = base.copy()

    for k, v in incoming.items():
        if k not in result:
            # new key: just add
            result[k] = v

        else:
            existing = result[k]

            # fill None
            if existing is None and v is not None:
                result[k] = v

            # conflict: both non-None and different -> remove key
            elif existing is not None and v is not None and existing != v:
                result.pop(k)
    return result

###
# Local replacements:

def collect_lines_with_reg(func, reg, start_index, end_index):
    """
    Collect the lines containing a reference to the given register
    """
    linesIndx = []
    indx = start_index
    pattern = reg 
    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break
        if end_index and indx >= end_index:
            break
        line = func.code[indx].decompiled.strip()
        if not pattern in line:
            continue
        linesIndx.append(indx)
    return linesIndx

def hide_lines(func, linesIndx):
    """
    Hide all lines with the defined indexes
    """
    for i in linesIndx:
        func.code[i].visible = False

def fill_in_dict(func, reg, reg_dict, start_index, end_index, verbosity):
    """
    Fill in a dictionary with values defined by register.

    Returns a pair containing:
      * indexes of lines where the actual definitions were found
      * a key -> definition-line mapping used to preserve metadata when values
        are propagated and the original definitions are hidden
    """
    linesIndx = collect_lines_with_reg(func, reg, start_index, end_index)
    defLineIndx = []
    definition_by_key = {}
    pattValFunc =r'^(r\d+)\["([^"]+)"\]\s*=\s*(func_[A-Za-z0-9_]+)$' # example: r3["mUOue"] = func_mUOue_0x1446826034c9
    pattValStr = r'^(r\d+)\["([^"]+)"\]\s*=\s*("([^"\\]*(\\.[^"\\]*)*)")$' # example: r3["exsQh"] = "string"
    for i in linesIndx:
        line = func.code[i].decompiled.strip()
        if g_Verbosity > 3:
            print(line)
        match = re.match(pattValStr, line)
        if not match:
            match = re.match(pattValFunc, line)
        if match:
            reg1 = match.group(1)
            val = match.group(2)
            defined = match.group(3)
            if reg1 == reg and val in reg_dict.keys():
                reg_dict[val] = defined
                definition_by_key[val] = func.code[i]
                defLineIndx.append(i)
    if g_Verbosity > 3:
        print(reg_dict)
    return defLineIndx, definition_by_key

def find_reg_passing_line(func, rhs_reg, start_indx, verbosity):
    """
    Find the line where the value of the given register is assigned to a different variable.
    Returns index of the line.
    """
    pattern = f" = {rhs_reg}" # i.e. `r4 = r6`
    indx = start_indx
    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break
        line = func.code[indx].decompiled.strip()
        if line.endswith(pattern):
            return indx
    return None


def find_definition_line(func, start_index, verbosity):
    """
    Find the line in which a structure is assigned to a register.
    Example: `r6 = new {"jXwxF": null, "Hpory": null }`
    """
    patternDef = re.compile(r'^(r\d+)\s*=\s*new\s*({.*})$')
    indx = start_index
    reg_dict = None
    reg = None
    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break
        line = func.code[indx].decompiled
        match = re.match(patternDef, line.strip()) # example: `r6 = new {"jXwxF": null, "Hpory": null }`
        if match:
            reg = match.group(1)
            obj_str = match.group(2)
            try:
                reg_dict = parse_js_object(obj_str)
            except Exception as e:
                if verbosity > 3:
                    print(f"[!] Failed to parse scope definition, Error: {e}, Line {line.strip()}")
                continue
            if not reg_dict:
                if verbosity > 3:
                    print(f"ERR cannot parse: {line}")
                continue
            return (indx, (reg, reg_dict))
    return (None, (None, None))

###
# Replace the values from dictionary with corresponding literals. 
# For example: `r12 = r5["jRhVT"]` -> `r12 = func_EqualsStrict_0x93e23cfb039`

def replace_with_assigned(
    func,
    start_index,
    reg,
    reg_dict,
    verbosity,
    definition_by_key=None,
):
    """
    Replace occurrences of reg["key"] with mapped literal values,
    but never touch the LHS of an assignment.
    Example:
    `r12 = r5["jRhVT"]` -> `r12 = func_EqualsStrict_0x93e23cfb039`
    func: function that will be processed
    start_index: line index in the function from which the replacement should start
    reg: the register used to reference the value from the dict (i.e. r5)
    reg_dict: dict of the values (i.e. "jRhVT" -> func_EqualsStrict_0x93e23cfb039, ...)
    """
    missing_keys = 0
    definition_by_key = definition_by_key or {}

    # Imported lazily to avoid the existing deobf_commons -> deobf_scope2
    # import cycle during module initialization.
    from deobf_commons import propagate_string_metadata, sync_string_metadata

    # match only THIS reg
    pat = re.compile(rf'{re.escape(reg)}\["([^"]+)"\]')

    indx = start_index
    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break

        obj = func.code[indx]
        line = obj.decompiled
        if not line or reg not in line:
            continue

        assign_i = find_assignment_op(line)

        if assign_i is None:
            lhs = ""
            rhs = line
            join = ""
        else:
            lhs = line[:assign_i + 1]   # include '='
            rhs = line[assign_i + 1:]
            join = ""  # kept for clarity

        propagated = []

        def repl(m):
            nonlocal missing_keys
            key = m.group(1)

            if key not in reg_dict:
                return m.group(0)

            val = reg_dict[key]
            if val is None:
                if verbosity:
                    print(f"Line: {line.strip()} Requested undefined key: {reg}[\"{key}\"]")
                missing_keys += 1
                return m.group(0)

            if not isinstance(val, (str, int, float)):
                if verbosity:
                    print(f"Line: {line.strip()} Invalid value type: {type(val)}")
                missing_keys += 1
                return m.group(0)

            propagated.append((key, str(val)))
            return str(val)

        new_rhs = pat.sub(repl, rhs)
        new_line = lhs + join + new_rhs

        if new_line != line:
            obj.decompiled = new_line

            # The dictionary definition may be hidden after propagation. Copy
            # only decoded-string metadata belonging to the exact value that
            # was substituted into this target line.
            for key, propagated_value in propagated:
                source_obj = definition_by_key.get(key)
                if source_obj is not None:
                    propagate_string_metadata(
                        source_obj,
                        obj,
                        propagated_value,
                    )
            sync_string_metadata(obj)

            if verbosity:
                print(f"Repl: {line.strip()} -> {new_line.strip()}")

    return missing_keys
###

def _propagate_local_dict_in_func(func, start_index, verbosity):
    """
    Propagate local dicts definitions within the function. Returns index to continue search.
    Example:
< 	r7 = new {"HnzNw": null, "WkPGC": null, "wnCtj": null, "WdRxQ": null}
< 	r7["HnzNw"] = func_EqualsStrict_0x93e23cf2f41
[...]
< 	r1 = r7
< 		r7 = r1["HnzNw"]
---
> 		r7 = func_EqualsStrict_0x93e23cf2f41
    """
    (start_index, (reg, reg_dict)) = find_definition_line(func, start_index, verbosity)
    if start_index is None:
        return None

    end_index = find_reg_passing_line(func, reg, start_index, verbosity)
    if end_index is None:
        return start_index # dict is not assigned further

    if verbosity:
        print(f"Found dict: {reg_dict}")

    last_line = func.code[end_index].decompiled.strip()
    patternRegToReg = re.compile(r'^(r\d+)\s*=\s*(r\d+)$')
    match = re.match(patternRegToReg, last_line)
    if not match:
        return # this is not a reg to reg definition (i.e. r4 = r6)
    regTo = match.group(1)
    all_found = len(reg_dict.keys())
    defLineIndx, definition_by_key = fill_in_dict(
        func,
        reg,
        reg_dict,
        start_index,
        end_index,
        verbosity,
    )
    if not defLineIndx:
        return end_index
    all_solved = len(defLineIndx)
    is_solved = (all_found == all_solved)
    if verbosity and not is_solved:
        print(f"Not all solved! Solved: {all_solved} vs needed: {all_found}")
    missing_keys = replace_with_assigned(
        func,
        end_index,
        regTo,
        reg_dict,
        verbosity,
        definition_by_key,
    )
    missing_keys += replace_with_assigned(
        func,
        end_index,
        reg,
        reg_dict,
        verbosity,
        definition_by_key,
    )
    if verbosity:
        print(f"Function: {func.name}; Is solved: {is_solved}; Missing keys: {missing_keys}")
        print(f"Defined: {reg}; Solved: {all_solved}; Assigned: {last_line}; Reg to: `{regTo}`")
        print(f"Content: {reg_dict}")

    if not missing_keys:
        # hide the lines with the original definitions:
        defLineIndx.append(start_index)
        defLineIndx.append(end_index)
        hide_lines(func, defLineIndx)
    if verbosity:
        print("---\n")
    return end_index

def _propagate_local_dicts(func, verbosity):
    i = 0
    while i < len(func.code):
        i = _propagate_local_dict_in_func(func, i, verbosity)
        if i is None:
            break
        i += 1

def propagate_local_dicts(functions, verbosity):
    """
    Propagate local dicts definitions in all functions.
    """
    for func_name, func in functions.items():
        _propagate_local_dicts(func, g_Verbosity)


# Define an Enum class
class ScopeDef(IntFlag):
    DIRECT = 1
    VIA_REG = 2
    ALL = DIRECT | VIA_REG

def search_object_definition(reg, func, last_indx):
    """Search and parse dicts defined by registers. The search starts backwards from the given `last_indx`
    :param str reg: The register where the dict definition will be stored
    :param SharedFunctionInfo func: The function where to search
    :param int last_indx: The index from which the search backward will start
    Returns parsed dict filled with appropriate values.
    Example:
    `r6 = new {"jXwxF": null, "Hpory": null }`
    That are further filled like:
    `r6["jXwxF"] = func_jXwxF_0x2f95374f4061`
	`r6["Hpory"] = func_Hpory_0x2f95374f4319`
    The last_indx is the index where the complete dict was assigned to another variable.
    `Scope[5][6] = r6`
    """
    indx = last_indx
    if g_Verbosity > 3:
        print(f"Searching from: {indx}")
    patt_str = reg + '\\s*=\\s*new\\s*({.*})'
    patternDef = rf'{patt_str}'
    patt_str2 = reg + '\\["([^"]+)"\\] = '

    defLineIndx = None
    linesIndx = []
    const_dict = None
    definition_by_key = {}

    while True:
        indx = next_visible_line(func, indx, True)
        if indx is None:
            break
        
        line = func.code[indx].decompiled.strip()
        if not reg in line:
            continue

        match = re.match(patternDef, line.strip()) # example: `r6 = new {"jXwxF": null, "Hpory": null }`
        if match:
            obj_str = match.group(1)
            const_dict = parse_js_object(obj_str)
            if not const_dict:
                return None
            defLineIndx = indx
            if g_Verbosity > 3:
                print(const_dict)
            break
        linesIndx.append(indx)
    
    if not const_dict:
        return None
    
    all_solved = 0
    all_found = len(const_dict.keys())
    pattVal1 =r'^(r\d+)\["([^"]+)"\]\s*=\s*([A-Za-z0-9_]+)$' # example: r3["mUOue"] = func_mUOue_0x1446826034c9
    pattVal2 = r'^(r\d+)\["([^"]+)"\]\s*=\s*"([^"]*)"$' # example: r3["exsQh"] = "string"
    for i in linesIndx:
        line = func.code[i].decompiled.strip()
        if g_Verbosity > 3:
            print(line)
        match = re.match(pattVal1, line)
        if not match:
            match = re.match(pattVal2, line)
        if match:
            reg1 = match.group(1)
            val = match.group(2)
            defined = match.group(3)
            if reg1 == reg and val in const_dict.keys():
                const_dict[val] = defined
                definition_by_key[val] = func.code[i]
                all_solved += 1
                if g_HideDefs:
                    func.code[i].visible = False
    if g_Verbosity > 3:
        print(const_dict)
    # hide the definition only if all values were solved
    if g_HideDefs:
        if all_solved == all_found:
            func.code[defLineIndx].visible = False
            func.code[last_indx].visible = False
    return const_dict, definition_by_key

class ScopeResolver:
    """Handles resolution of Scope[x][y] references"""
    def __init__(self):
        self.scope_data = {}  # {scope_id: {index: value_dict}}
        self.scope_sources = {}  # same shape, values are key -> source line

    def parse_scope_assignment_reg(self, func, line_indx):
        """
        Parse scope assignments via register like:
        `Scope[4391][25] = r6`
        Where the dict is first filled by the register, i.e.
        `r6 = new {"jXwxF": null, "Hpory": null }`
        `r6["jXwxF"] = func_jXwxF_0x2f95374f4061`
        `r6["Hpory"] = func_Hpory_0x2f95374f4319`
        """
        line = func.code[line_indx].decompiled
        pattern = r'Scope\[(\d+)\]\[(\d+)\]\s*=\s*(r\d+)$'
        match = re.match(pattern, line.strip())
        if not match:
            return None
            
        scope_id = int(match.group(1))
        index = int(match.group(2))
        reg = match.group(3)
        if g_Verbosity > 2:
            print(f"{func.name} Definition: {line.strip()} Reg: {reg}")
        try:
            result = search_object_definition(reg, func, line_indx)
            if not result:
                return None
            filled_dict, definition_by_key = result
            return scope_id, index, filled_dict, definition_by_key
        except Exception as e:
            if g_Verbosity > 3:
                print(f"[!] Failed to parse scope definition, Error: {e}")
            return None
        return None

    def parse_scope_assignment_direct(self, func, line_indx):
        """
        Parse direct scope assignments like: 
        `Scope[4391][25] = new {"w": 78}`
        """
        line = func.code[line_indx].decompiled
        pattern = r'^Scope\[(\d+)\]\[(\d+)\]\s*=\s*new\s*({.*})$'
        match = re.match(pattern, line.strip())
        if not match:
            return None

        scope_id = int(match.group(1))
        index = int(match.group(2))
        obj_str = match.group(3)
        if g_Verbosity > 3:
            print(f"Definition: {line.strip()}")
        
        try:
            # Parse the JavaScript object
            const_dict = parse_js_object(obj_str)
            if g_HideDefs:
                func.code[line_indx].visible = False
            definition_by_key = {
                key: func.code[line_indx]
                for key in const_dict.keys()
            }
            return scope_id, index, const_dict, definition_by_key
        except Exception as e:
            if g_Verbosity > 3:
                print(f"[!] Failed to parse scope object: {obj_str}, Error: {e}")
            return None

    def parse_scope_assignment(self, func, index, def_type:ScopeDef):
        """
        Parse scope assignments of particular type. Format: Scope[x][y] = dict()
        Scopes can be defined direct (inline) or via register.
        """
        res = None
        if def_type & ScopeDef.DIRECT:
            res = self.parse_scope_assignment_direct(func, index)
            if res:
                return res
        if def_type & ScopeDef.VIA_REG:
            res = self.parse_scope_assignment_reg(func, index)
        return res

    def add_scope_data(
        self,
        scope_id,
        index,
        value_dict,
        definition_by_key=None,
    ):
        """Add scope data to the internal storage"""

        definition_by_key = definition_by_key or {}
        if scope_id not in self.scope_data:
            self.scope_data[scope_id] = {}
            self.scope_sources[scope_id] = {}
        if value_dict is None:
            return
        if index not in self.scope_data[scope_id].keys():
            # Add new value
            self.scope_data[scope_id][index] = value_dict
            self.scope_sources[scope_id][index] = dict(definition_by_key)
            if g_Verbosity > 2:
                print(f"    Added Scope[{scope_id}][{index}] = {value_dict}")
            return
        curr_value = self.scope_data[scope_id][index]
        if curr_value == value_dict:
            # Repeated identical definition
            curr_sources = self.scope_sources[scope_id].setdefault(index, {})
            for key, source_obj in definition_by_key.items():
                curr_sources.setdefault(key, source_obj)
            return

        merged = merge_fill_none_remove_conflicts(curr_value, value_dict)
        self.scope_data[scope_id][index] = merged

        curr_sources = self.scope_sources[scope_id].setdefault(index, {})
        merged_sources = {
            key: source_obj
            for key, source_obj in curr_sources.items()
            if key in merged
        }
        for key, source_obj in definition_by_key.items():
            if key not in merged:
                continue
            if key not in curr_value or curr_value.get(key) is None:
                merged_sources[key] = source_obj
            else:
                merged_sources.setdefault(key, source_obj)
        self.scope_sources[scope_id][index] = merged_sources

        if g_Verbosity > 1:
            print(f"Redefinition: Scope[{scope_id}][{index}] = {curr_value} vs {value_dict}")
            print(f"    Updated Scope[{scope_id}][{index}] = {self.scope_data[scope_id][index]}")
    
    def resolve_scope_reference(self, scope_ref):
        """Resolve scope references like -Scope[4390][2]["w"]"""
        # Match patterns like Scope[number][number]["key"]
        pattern = r'Scope\[(\d+)\]\[(\d+)\]\["([^"]+)"\]'
        match = re.search(pattern, scope_ref)
        
        if not match:
            return None
            
        scope_id = int(match.group(1))
        index = int(match.group(2))
        key = match.group(3)
        
        # Check if we have this scope data
        if (scope_id in self.scope_data and
            index in self.scope_data[scope_id] and 
            key in self.scope_data[scope_id][index]):
            return self.scope_data[scope_id][index][key]
        
        return None

    def resolve_scope_reference_with_source(self, scope_ref):
        """Resolve a scope reference and return its concrete source line."""
        pattern = r'Scope\[(\d+)\]\[(\d+)\]\["([^"]+)"\]'
        match = re.search(pattern, scope_ref)
        if not match:
            return None, None

        scope_id = int(match.group(1))
        index = int(match.group(2))
        key = match.group(3)
        value = self.resolve_scope_reference(scope_ref)
        if value is None:
            return None, None

        source_obj = (
            self.scope_sources
            .get(scope_id, {})
            .get(index, {})
            .get(key)
        )
        return value, source_obj
    
    def inline_scope_references_in_line(self, line):
        """Replace all scope references in a line with their literal values"""
        if not line:
            return line, False, []
            
        modified_line = line
        has_changes = False
        propagated = []
        
        # Pattern to match Scope[number][number]["key"]
        pattern = r'Scope\[\d+\]\[\d+\]\["[^"]+"\]'
        
        # Debug: Check if pattern matches anything in the line
        matches = re.findall(pattern, line)
        if matches and g_Verbosity > 2:
            print(f"    Found Scope references in line: {matches}")
        
        def replace_match(match):
            nonlocal has_changes
            scope_ref = match.group(0)
            value, source_obj = self.resolve_scope_reference_with_source(
                scope_ref
            )
            
            if g_Verbosity > 2:
                print(f"    Trying to resolve: {scope_ref} -> {value}")
            
            if value is not None:
                if isinstance(value, str):
                    has_changes = True
                    if not value.startswith("func_"):
                        value = f'"{value}"'
                    propagated.append((source_obj, value))
                    return f'{value}'
                elif isinstance(value, (int, float)):
                    has_changes = True
                    propagated.append((source_obj, str(value)))
                    return str(value)
                else:
                    if g_Verbosity > 2:
                        print(f"SKIPPING: {scope_ref} = {value} = {type(value)}")
                if g_Verbosity > 2:
                    print(f"    Could not resolve: {scope_ref}")
            return scope_ref
        
        modified_line = re.sub(pattern, replace_match, modified_line)
        return modified_line, has_changes, propagated

# Global scope resolver instance
g_ScopeResolver = ScopeResolver()

def find_and_print_func(functions, name):
    func = functions[name]
    indx = 0

    for line_obj in func.code:
        line = line_obj.decompiled
        print(f"{indx} : {line}")
        indx += 1
    return None


def parse_js_object(js_obj_str):
    """Convert JS object string to JSON-compatible format"""
    js_obj_str = js_obj_str.strip()
    # Handle both quoted and unquoted keys
    js_obj_str = re.sub(r'([{\s,])([a-zA-Z0-9_]+):', r'\1"\2":', js_obj_str)
    return json.loads(js_obj_str)

def inline_constants_in_line(line, const_dicts, const_sources=None):
    """Replace all variable property accesses in a line with their literal values"""
    if not line:
        return line, False, []

    const_sources = const_sources or {}
    
    modified_line = line
    has_changes = False
    propagated = []
    
    # Process all known variables
    for var_name, const_dict in const_dicts.items():
        # Pattern to match var_name["key"] or var_name['key']
        # But NOT when it's on the left side of an assignment
        pattern = re.compile(rf'(?<!=\s){re.escape(var_name)}\[[\'"]([^\'"]+)[\'"]\](?!\s*=)')
        
        def replace_match(match):
            nonlocal has_changes
            key = match.group(1)
            if key in const_dict:
                val = const_dict[key]
                if isinstance(val, (str, int, float)):
                    has_changes = True
                    replacement = (
                        f'"{val}"' if isinstance(val, str) else str(val)
                    )
                    source_obj = const_sources.get(var_name, {}).get(key)
                    propagated.append((source_obj, replacement))
                    return replacement
            return match.group(0)
        
        modified_line = pattern.sub(replace_match, modified_line)
    
    return modified_line, has_changes, propagated

# ---------------------------------------------------------------------------
# helper: replace variables but keep string literals intact
# ---------------------------------------------------------------------------

def _replace_outside_strings(text: str, repl_map: dict[str, str]) -> str:
    """
    Replace variable names in `repl_map` with their mapped values,
    but ONLY when they appear outside quoted string literals.
    Works efficiently for large mappings using a single-pass regex.

    Example:
        _replace_outside_strings('func(r1, "O$r1")', {'r1': '1000'})
        -> 'func(1000, "O$r1")'
    """
    if not repl_map:
        return text

    # 1. Extract string literals using non-identifier placeholders
    str_re = re.compile(r'(["\'])(?:\\.|(?!\1).)*\1')
    extracted = []

    def stash(match: re.Match) -> str:
        idx = len(extracted)
        extracted.append(match.group(0))
        return f"@@STR:{idx}@@"  # non-identifier placeholder

    tmp = str_re.sub(stash, text)

    # 2. Build a single regex matching any variable key, with identifier-safe lookarounds
    # Sort by length descending to avoid partial matches (e.g., r1 before r10)
    sorted_vars = sorted(repl_map.keys(), key=len, reverse=True)
    pattern = rf"(?<![A-Za-z0-9_])({'|'.join(map(re.escape, sorted_vars))})(?![A-Za-z0-9_])"
    repl_regex = re.compile(pattern)

    # 3. Replace dynamically using a lambda
    def replace_match(m: re.Match) -> str:
        return repl_map[m.group(0)]

    tmp = repl_regex.sub(replace_match, tmp)

    # 4. Restore string literals
    for idx, s in enumerate(extracted):
        tmp = tmp.replace(f"@@STR:{idx}@@", s)

    return tmp

# ---------------------------------------------------------------------------
# inline_mapped_variables
# ---------------------------------------------------------------------------

def inline_mapped_functions(line, val_mappings):
    """
    Replace *register* placeholders used as function names (e.g. r5(...))
    with the literal function names stored in `val_mappings`, while leaving
    any occurrences inside string literals untouched.
    """
    if not line or not val_mappings:
        return line, False

    has_changes = False
    active_map = {}

    # Build a replacement map only for variables that actually look like calls
    for var_name, value in val_mappings.items():
        # Quick pre-check: need the token followed by '(' outside strings
        call_pat = rf"\b{re.escape(var_name)}\s*\("
        if re.search(call_pat, line):
            active_map[var_name] = value  # remember for batch replacement

    if active_map:
        # For calls we must keep the '(' that follows the var-name.
        # Build a custom map that appends '(' to the replacement:
        call_map = {k: f"{v}(" for k, v in active_map.items()}

        # Temporarily make the '(' part of the key so we don’t touch assignments.
        # We do this by first transforming the line so every "var_name(" token
        # becomes "var_name__LP__" – then we run the outside-string replacement,
        # then restore '('.
        tmp = line
        for var in call_map:
            tmp = re.sub(rf"\b{re.escape(var)}\s*\(", f"{var}__LP__", tmp)

        replaced = _replace_outside_strings(tmp, {f"{k}__LP__": v for k, v in call_map.items()})
        replaced = replaced.replace("__LP__", "(")

        if replaced != line:
            line = replaced
            has_changes = True
            if g_Verbosity > 2:
                for v, lit in call_map.items():
                    print(f"    Func. Replaced call: {v} -> {lit[:-1]}")  # strip '(' in log

    return line, has_changes
###

def find_func_calls(line):

    if not hasattr(find_func_calls, "_func_name_re"):
        find_func_calls._func_name_re = re.compile(r'func_[\w#$]+')

    FUNC_NAME_RE = find_func_calls._func_name_re
    results = []

    for m in FUNC_NAME_RE.finditer(line):
        i = m.end()
        if i >= len(line) or line[i] != '(':
            continue

        depth = 1                 # already inside one '('
        in_str = None
        start = i + 1

        for j in range(i + 1, len(line)):
            c = line[j]

            if in_str:
                if c == in_str and line[j - 1] != '\\':
                    in_str = None
            else:
                if c in ('"', "'"):
                    in_str = c
                elif c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
                    if depth == 0:
                        args = line[start:j]
                        results.append((m.group(), args))
                        break

    return results or None


def find_first_func_call(line):
    res = find_func_calls(line)
    return res[0] if res else None

def inline_mapped_variables(name, line, val_mappings, func_arg_to_fill):
    """Replace function-variable calls with their literal values, but
       leave occurrences inside string literals untouched.
    """
    if not line or not val_mappings:
        return line, False

    m_call = find_first_func_call(line)
    if not m_call:
        return line, False

    func_name, args_list = m_call

    if func_name not in func_arg_to_fill:
        return line, False

    pattern_num_in_brackets = re.compile(r'^\((\-?\d+)\)$')

    has_changes = False
    new_args = args_list

    # build a mapping only for variables actually present in the arg list
    active_map = {}
    for var_name, value in val_mappings.items():
        if var_name not in args_list:
            continue

        m_num = pattern_num_in_brackets.match(value)
        if m_num:
            value = m_num.group(1)  # strip parentheses around numeric literal

        active_map[var_name] = value

    if active_map:
        replaced = _replace_outside_strings(new_args, active_map)
        if replaced != new_args:
            new_args = replaced
            has_changes = True

    if has_changes:
        # splice back the updated argument list
        line = line.replace(args_list, new_args, 1)

    return line, has_changes

def find_and_process_func_variables(functions, name, func_arg_to_fill, verbosity):
    """Process a function to replace function variable calls with literal function names"""
    func = functions[name]
    val_mappings = {}  # {var_name: value}
    changes_count = 0
    
    if verbosity > 2:
        print(f"[*] Processing function variables in: {name}")
    
    val_assign_pattern = re.compile(r'^\s*(r\d+)\s*=') # any assignment to a register
    func_pattern = re.compile(r'(func_[\w#$]+)\s*$')
    num_pattern = re.compile(r'(\d+)|(\(-\d+\))$')
    exclusion_pattern = re.compile(r'(ACCU|r\d+|a\d+)$')

    #func_assign_pattern = re.compile(r'^\s*(r\d+)\s*=\s*(func_\w+)\s*$')

    # Walk thought the lines of the function
    for line_obj in func.code:
        line = line_obj.decompiled
        if not line:
            continue

        # Check for any assignment and remove existing
        assign_match = re.match(val_assign_pattern, line)#(r\d+)
        if assign_match:
            var_name = assign_match.group(1)
            if var_name in val_mappings:
                if verbosity > 2:
                    print(f"    Removing {var_name} from function mappings")
                val_mappings[var_name] = None
                del val_mappings[var_name]

            lhs, rhs = split_rhs_lhs(line)
            rhs = rhs.strip()
            # Check if this line assigns a function to a variable, example: r5 = func_o_0x3bdf26d956a9
            if not re.match(exclusion_pattern, rhs) and (re.match(num_pattern, rhs) or re.match(func_pattern, rhs)):
                val_mappings[var_name] = rhs
                if verbosity > 1:
                    print(f"    Found value mapping: {var_name} -> {rhs} in:\n\t{line.strip()}")

        orig_line = line
        is_changed = False
        # Try to replace function variable calls in this line
        line, line_changed = inline_mapped_functions(line, val_mappings)
        if line_changed:
            is_changed = True
        if func_arg_to_fill and len(func_arg_to_fill):
            line, line_changed = inline_mapped_variables(name, line, val_mappings, func_arg_to_fill)
            if line_changed:
                is_changed = True
            
        if is_changed:
            changes_count += 1
            if verbosity:
                print(f"[V] Before:\n{orig_line}")
            line_obj.decompiled = line
            if verbosity:
                print(f"[V] After:\n{line}\n")
    return changes_count

def find_and_process_scope_assignments(functions, def_type:ScopeDef):
    """
    First pass: Find and process all Scope assignments across all functions.
    The assignments are in form of dicts, and they are added to the global resolver.
    """
    global g_Verbosity, g_ScopeResolver
    
    if g_Verbosity > 1:
        print("[*] First pass: Processing Scope assignments...")
    
    assignments_found = 0
    
    for func_name, func in functions.items():
        for i in range(len(func.code)):
            line = func.code[i].decompiled
            if not line:
                continue
                
            # Check if this line defines a Scope assignment
            result = g_ScopeResolver.parse_scope_assignment(func, i, def_type)
            if result:
                scope_id, index, value_dict, definition_by_key = result
                g_ScopeResolver.add_scope_data(
                    scope_id,
                    index,
                    value_dict,
                    definition_by_key,
                )
                assignments_found += 1
    
    if g_Verbosity > 0:
        print(f"[+] Found {assignments_found} Scope assignments")
    
    return assignments_found > 0

def find_and_process_func(functions, name, replace_local, verbosity):
    """Process a function to inline constant object property accesses and Scope references"""
    global g_ScopeResolver
    func = functions[name]
    const_dicts = {}  # {var_name: {key: val, ...}}
    const_sources = {}  # {var_name: {key: definition line, ...}}
    changes_count = 0
    line_prefix = 'S' if not replace_local else 'L'
    
    if verbosity > 2:
        print(f"[*] Processing function: {name}")
    
    for line_obj in func.code:
        line = line_obj.decompiled
        if not line:
            continue
        if replace_local:
            # Check if this line defines a constant object: r0 = new { ... }
            obj_match = re.match(r'^\s*(\w+)\s*=\s*new\s*({.*})\s*$', line)
            if obj_match:
                var_name = obj_match.group(1)
                js_obj_str = obj_match.group(2)
                
                try:
                    const_dict = parse_js_object(js_obj_str)
                    const_dicts[var_name] = const_dict
                    const_sources[var_name] = {
                        key: line_obj for key in const_dict.keys()
                    }
                    continue  # Don't process this line for replacements
                except Exception as e:
                    if verbosity > 2:
                        print(f"[!] Failed to parse constant object in line: {line}")
                        print(f"    Error: {e}")
                    continue
            
        # Try to inline constants and scope references in this line
        new_line = line
        line_changed = False
        propagated = []
        if replace_local:
            # First, replace regular constant property accesses
            if const_dicts:
                new_line, changed, propagated = inline_constants_in_line(
                    new_line,
                    const_dicts,
                    const_sources,
                )
                line_changed = line_changed or changed
        else: 
            # Replace Scope references
            new_line, changed, propagated = (
                g_ScopeResolver.inline_scope_references_in_line(new_line)
            )
            line_changed = line_changed or changed
        
        if line_changed:
            changes_count += 1
            if verbosity:
                print(f"[{line_prefix}] Before:\n{line}")
            line_obj.decompiled = new_line

            # Imported lazily to avoid the existing deobf_commons ->
            # deobf_scope2 import cycle during module initialization.
            from deobf_commons import (
                propagate_string_metadata,
                sync_string_metadata,
            )
            for source_obj, propagated_value in propagated:
                if source_obj is not None:
                    propagate_string_metadata(
                        source_obj,
                        line_obj,
                        propagated_value,
                    )
            sync_string_metadata(line_obj)

            if verbosity:
                print(f"[{line_prefix}] After:\n{new_line}\n")
    return changes_count

###

def _replace_functions_via_registers(func, verbosity):
    """
    Replace register-indirect function calls with direct calls.
    """

    patternAssign = r'^(r\d+)\s*='
    patternDef    = r'^(r\d+)\s*=\s*(func_[A-Za-z0-9_]+)$'
    patternCall   = r'\b(r\d+)\s*\(([^()]*)\)'  # FIXED: non-greedy, no nesting break

    reg_to_func = {}
    assign_lines = {}
    hide_assign_lines = True

    replaced = 0
    i = 0
    while True:
        i = next_visible_line(func, i)
        if i is None:
            break

        line = func.code[i].decompiled
        assign_reg = None
        # ----------------------------------------------------
        # Assignment
        # ----------------------------------------------------
        m_assign = re.match(patternAssign, line.strip())
        if m_assign:
            assign_reg = m_assign.group(1)

            m_def = re.match(patternDef, line.strip())
            if m_def:
                reg = m_def.group(1)
                func_name = m_def.group(2)
                reg_to_func[reg] = func_name
                assign_lines[reg] = i
                if verbosity > 1:
                    print(f"Added: {reg} -> {func_name}")
                continue

        # ----------------------------------------------------
        # Replacement loop until stable
        # ----------------------------------------------------
        def repl(m):
            reg = m.group(1)
            args = m.group(2)
            if reg in reg_to_func and reg_to_func[reg]:

                if hide_assign_lines:
                    assign_indx = assign_lines[reg]
                    func.code[assign_indx].visible = False

                return f"{reg_to_func[reg]}({args})"
            return m.group(0)

        new_line = line
        while True:
            updated = re.sub(patternCall, repl, new_line)
            if updated == new_line:
                break
            new_line = updated

        if new_line != line:
            if verbosity:
                print(f"[REPL] `{line.strip()}` -> `{new_line.strip()}`")
            func.code[i].decompiled = new_line
            replaced += 1

        # Reset the assignment at the end of the line:
        if assign_reg is not None:
            reg_to_func[assign_reg] = None

    return replaced


def replace_functions_via_registers(functions, verbosity):
    """
    Replace register-indirect function calls with direct calls.
    Example:
        r7 = func_zfDyL_0x739cb09b591
        r2 = r7(uu)
    becomes:
        r7 = func_zfDyL_0x739cb09b591
        r2 = func_zfDyL_0x739cb09b591(uu)
    """
    assignments_found = 0
    for func_name, func in functions.items():
        if _replace_functions_via_registers(func, verbosity):
            assignments_found += 1
            if verbosity:
                print(f"[REPLACED IN FUNC] {func_name}")
    return assignments_found


def deobf_scope_rounds(all_func, scope_def, verbosity):
    """
    Process scope replacement recursively (one layer my reveal another)
    """
    repl_rounds = 0
    is_stop = False
    total_replaced = 0

    while not is_stop:
        print(f"Replacement round: {repl_rounds}")
        find_and_process_scope_assignments(all_func, scope_def)
        replaced = 0
        for name in all_func:
            if find_and_process_func(all_func, name, False, verbosity):
                replaced += 1
        total_replaced += replaced
        if not replaced:
            is_stop = True
        repl_rounds += 1
    return total_replaced


def deobf_scope_default(all_func, verbosity):
    total_repl = deobf_scope_rounds(all_func, ScopeDef.ALL, verbosity)
    if not total_repl:
        return False
    return True
###

def propagate_variables_default(all_func, scope_level, verbosity):
    if scope_level == 0:
        return False

    is_changed1 = False
    if replace_global_scope(all_func, verbosity):
        is_changed1 = True
    print(f"Replace global scope done. Changed: {is_changed1}")

    is_changed2 = False
    if scope_level > 1:
        scope_def = ScopeDef.DIRECT
        find_and_process_scope_assignments(all_func, scope_def)
        for name in all_func:
            if find_and_process_func(all_func, name, False, verbosity):
                is_changed2 = True
        print(f"Propagating values by scopes: Done. Changed: {is_changed2}")

        is_changed3 = False
        if scope_level > 2:
            is_changed = False
            for name in all_func:
                if find_and_process_func(all_func, name, True, verbosity):
                    is_changed3 = True
            print(f"Propagating values by local variables. Done. Changed: {is_changed3}")

        is_changed4 = False
        for name in all_func:
            if find_and_process_func_variables(all_func, name, None, verbosity):
                is_changed4 = True
        print(f"Propagating func variables: Done. Changed: {is_changed4}")
    
    if is_changed1 or is_changed2 or is_changed3 or is_changed4:
        return True
    return False
###

def filter_functions(all_func, func_name):
    filtered = find_functions_by_name(all_func, func_name)
    if not func_name in filtered:
        print(f"Function {func_name} was not found. Found {len(filtered)} similar names.")
        for key in filtered.keys():
            print(key)
    return filtered

def main():
    global g_Verbosity, g_HideDefs
    parser = argparse.ArgumentParser(description="JSCeal scope deobf - replace variables with literal values")
    parser.add_argument('--inp', '-i', help="The input file name. It must be a serialized View8 output.", default=None, required=True)
    parser.add_argument('--out', '-o', help="The output file name.", default=None)
    parser.add_argument('--export_format', '-e', nargs='+', choices=['v8_opcode', 'translated', 'decompiled', 'serialized'], 
                        help="Specify the export format(s). Options are 'v8_opcode', 'translated', and 'decompiled'. Multiple options can be combined.", 
                        default=['serialized', 'decompiled'])
    parser.add_argument('--func', help="A function to be analyzed (cleaned).", default=None, required=False)
    parser.add_argument('--verbosity', '-v', help="Verbosity level (0-3)", default=0, type=int, required=False)
    parser.add_argument('--replace-funcs', help="Enable function variable replacement", default=0, type=int, required=False)
    parser.add_argument('--replace-vars', help="Enable variable replacement", default=0, type=int, required=False)
    parser.add_argument('--replace-scope', help="Enable Scope array replacement", default=0, type=int, required=False)
    parser.add_argument('--propagate', help="Propagate local struct definitions", default=0, type=int, required=False)
    parser.add_argument('--scope', help="Propagate scope arguments.", default=0, type=int, required=False)

    args = parser.parse_args()
    
    if not os.path.isfile(args.inp):
        raise FileNotFoundError(f"The input file {args.inp} does not exist.")

    if args.verbosity:
        g_Verbosity = args.verbosity

    vars_replaced = False
    funcs_replaced = False
    scope_replaced = False
    structs_propagated = False

    print(f"Reading from serialized, already decompiled input: {args.inp}")
    all_func = load_functions_from_file(args.inp)

    if args.scope:
        scope_level = args.scope
        if propagate_variables_default(all_func, scope_level, g_Verbosity):
            scope_replaced = True

    # Process all Scope assignments if enabled 
    # scope replacement must be done globally, before function filter is applied:
    scope_def = ScopeDef.ALL
    if args.replace_scope:
        print(f"[+] Replace Scope")
        if deobf_scope_rounds(all_func, scope_def, g_Verbosity):
            scope_replaced = True

    # if selected, narrow down processing to the selected functions
    if args.func:
        filtered = filter_functions(all_func, args.func)
        if len(filtered) == 0:
            return
        print(f"Deobfuscating filtered")
        all_func = filtered

    if args.propagate:
        print("[+] Propagate local definitions of structs")
        propagate_local_dicts(all_func, g_Verbosity)
        structs_propagated = True

    if args.replace_vars:
        print(f"[+] Replace Vars")
        for name in all_func:
            if find_and_process_func(all_func, name, True, g_Verbosity):
                vars_replaced = True
            
    # Process all functions for function variable replacement
    if args.replace_funcs:
        print(f"[+] Replace Funcs")
        for name in all_func:
            if find_and_process_func_variables(all_func, name, None, g_Verbosity):
                funcs_replaced = True

    if not funcs_replaced and not vars_replaced and not scope_replaced and not structs_propagated:
        print("No changes applied")
        return

    if scope_replaced:
        print("[+] Scope arguments propagated")
    
    if funcs_replaced:
        print("[+] Functions replaced")

    if vars_replaced:
        print("[+] Vars replaced")

    if args.func:
        print_funcs(all_func)
    
    # The output may be saved into a file:
    if args.out:
        export_to_file(args.out, all_func, args.export_format)
    print(f"Done.")


if __name__ == "__main__":
    main()
