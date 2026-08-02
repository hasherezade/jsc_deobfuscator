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
import copy

from View8.Parser.shared_function_info import save_functions_to_file, load_functions_from_file
from View8.Parser.shared_function_info import CodeLine
from deobf_commons import *
from View8.view8_util import *

g_Verbosity = 0


###

def count_indent(s):
    """
    Count indentation at the start of the line (tabs or spaces)
    until the first non-whitespace character or line end.
    """
    indent = 0
    for ch in s:
        if ch in (" ", "\t"):
            indent += 1
        else:
            break
    return indent

def remove_leading_tabs(s, count):
    """
    Decrease the indentation: remove the given number of tabs.
    """
    i = 0
    removed = 0
    while i < len(s) and removed < count and s[i] == "\t":
        i += 1
        removed += 1
    return s[i:]

def add_indent(line, x):
    """
    Add x tabs as indentation to the beginning of the line.
    """
    return "\t" * x + line


def negate_condition(condition):
    """
    Negate a View8 pseudocode condition while keeping the result readable.

    View8 commonly prints negation as a leading ``!`` (including its custom
    comparison form, e.g. ``!r7 === "0"``).  Removing that leading marker is
    the clean inverse.  Otherwise, wrap the complete expression so operator
    precedence is preserved.
    """
    condition = condition.strip()
    if condition.startswith("!(") and condition.endswith(")"):
        return condition[2:-1].strip()
    if condition.startswith("!"):
        return condition[1:].strip()
    return f"!({condition})"

def find_code_pattern(func, pattern1, start_indx=0):
    """
    Check if the function has the code line with the defined pattern.
    Return (index,match) if found, (None,None) otherwise.
    """
    for i in range(start_indx,len(func.code)):
        current_obj = func.code[i]
        if (not current_obj.visible or not current_obj.decompiled):
            continue
        line = current_obj.decompiled
        match = re.search(pattern1, line)
        if match:
            return (i, match)
    return (None, None)


def find_code_line(func, line_patt, exact, start_indx=0):
    """
    Check if the function has the code line as defined. 
    If `exact` is selected, the line must have identical padding/tabulation. Otherwise, the padding is stripped.
    Return `index` if found, `None` otherwise.
    """
    for i in range(start_indx,len(func.code)):
        current_obj = func.code[i]
        if (not current_obj.visible or not current_obj.decompiled):
            continue
        line = current_obj.decompiled
        if exact:
            if line == line_patt:
                return i
        else:
            if line.strip() == line_patt.strip():
                return i
    return None


def rfind_code_line(func, line_patt, exact, start_indx, stop_indx):
    """
    Check if the function has the code line as defined - reverse search. 
    If `exact` is selected, the line must have identical padding/tabulation. Otherwise, the padding is stripped.
    Return `index` if found, `None` otherwise.
    """
    for i in range(stop_indx, start_indx, -1):
        current_obj = func.code[i]
        if (not current_obj.visible or not current_obj.decompiled):
            continue
        line = current_obj.decompiled
        if exact:
            if line == line_patt:
                return i
        else:
            if line.strip() == line_patt.strip():
                return i
    return None

###


def print_lines(func, start_indx, end_indx, indent, line_no=True, skip_invisible=True):
    for i in range(start_indx, end_indx):
        current_obj = func.code[i]
        if (not current_obj.decompiled):
            continue
        if (not current_obj.visible and skip_invisible):
            continue
        line = current_obj.decompiled
        line = remove_leading_tabs(line, indent)
        if line_no:
            print(f"{i}: {line}")
        else:
            print(f"{line}")

def find_all_chunks_endings(func, start_indx, end_indx):
    endings_list = dict()
    ending1 = "}"
    ending2 = "break"
    for i in range(end_indx, start_indx, (-1)):
        current_obj = func.code[i]
        if (not current_obj.visible or not current_obj.decompiled):
            continue
        line = current_obj.decompiled
        indent = None
        if (line.strip() == ending2):
            indent = count_indent(line)
            endings_list[indent] = i
        elif (line.strip() == ending1):
            indent = count_indent(line)
            endings_list[indent] = i
        else:
            continue
    
    for k in endings_list.keys():
        indx = endings_list[k]
        if g_Verbosity > 2:
            print(f"Indent: {k} Chunk ending at: {indx}")
    return endings_list

def find_all_chunks_starts(func, start_indx, chunks):
    prev_indx = start_indx
    while (True):
        patternI = re.compile(r'if \(!r\d+ === \"(\d+)\"\)')
        (indx, match) = find_code_pattern(func, patternI, prev_indx + 1)
        if indx is None: 
            break
        prev_indx = indx
        line = func.code[indx].decompiled
        indent = count_indent(line)
        if indent is None:
            continue
        num = int(match.group(1)) + 1
        pair = (indent, indx)
        chunks[num] = pair
        if g_Verbosity > 2:
            print(f"{num} : Indent: {indent} Chunk begin at: {indx} ")
    return chunks


def get_cff_order_line(func, start_indx=0):
    """
    Find the line where the string defining the order of CFF chunks is set.
    Returns a pair (index, match) is found or (None, None) otherwise.
    """
    pattern1 = re.compile(r'"(\d+(?:\|\d+)+)"')
    for i in range(start_indx, len(func.code)):
        current_obj = func.code[i]
        if (not current_obj.visible or not current_obj.decompiled):
            continue
        line = current_obj.decompiled.strip()
        match = re.search(pattern1, line)
        if not match:
            continue
        return (i, match)
    return (None, None)

def fetch_reg_and_var(line, rhs=False):
    """
    Fetch register and key from lines such as:
    r8["ZOMBf"] = VAL` or `VAR = r8["ZOMBf"]` -> register: `r8`, key: `["ZOMBf"]`
    Returns a paie (register,key) or (None,None) if not found.
    """
    if rhs:
        pattern1 = re.compile(r' = (r\d+)(\["[^"]+"\])')
        pattern2 = re.compile(r' = (r\d+)')
    else:
        pattern1 = re.compile(r'(r\d+)(\["[^"]+"\]) = ')
        pattern2 = re.compile(r'(r\d+) = ')

    match = re.match(pattern1, line)
    if match:
        register = match.group(1)
        key = match.group(2)
        return (register, key)

    match = re.match(pattern2, line)
    if match:
        register = match.group(1)
        return (register, None)
    return (None, None)

def find_order_split_lines(func, target, start_indx):
    """
    Find lines where the order of chunks is split before processing.
    """
    refs = set()
    (register, key) = fetch_reg_and_var(target)
    if not register:
        print(f"Can't split: {target}")
        return None
    #if not key:
    #    print(f"Split {target} by a single register: {register}")
    i = None
    if key:
        for i in range(start_indx, len(func.code)):
            if not func.code[i].visible or not func.code[i].decompiled:
                continue
            line = func.code[i].decompiled.strip()
            if key in line:
                refs.add(i)
                break
        i = next_visible_line(func, i, False)
        line = func.code[i].decompiled.strip()
        if "\"split\"" in line:
            refs.add(i)
        i = next_visible_line(func, i, False)
        line = func.code[i].decompiled.strip()
        if "\"|\"" in line:
            refs.add(i)
    else:
        for i in range(start_indx, len(func.code)):
            if not func.code[i].visible or not func.code[i].decompiled:
                continue
            line = func.code[i].decompiled.strip()
            if "\"split\"" in line and register in line:
                #print(f"Split in line: {i}: {line}")
                refs.add(i)
                break
        i = next_visible_line(func, i, False)
        line = func.code[i].decompiled.strip()
        #print(f"Next: {line}")
        if "\"|\"" in line:
            refs.add(i)
    return refs

def hide_line(func, line_indx):
    if line_indx >= len(func.code):
        return False
    func.code[line_indx].visible = False
    return True

def nop_out_line(func, line_indx):
    if line_indx >= len(func.code):
        return False
    current_obj = func.code[line_indx]
    func.code[line_indx] = CodeLine("", line_indx, "", "", "nop")
    func.code[line_indx].visible = False
    return True

def nop_out_range(func, start, stop):
    for i in range(start, stop):
        if not nop_out_line(func, i):
            break
###

class CffLoop:
    def __init__(self, func_name, start, end, indent):
        self.func_name = func_name
        self.start = start
        self.end = end
        self.indent = indent
        self.prolog_lines = set()

    def print(self, func=None):
        print(f"{self.func_name} : CFF Order")
        for i in self.prolog_lines:
            print_lines(func, i, i+1, self.indent)

        print(f"{self.func_name} : Loop start Index: {self.start} End: {self.end}")
        if func is not None:
            print_lines(func, self.start, self.end, self.indent)

    def patch(self, func, code_lines):
        # hide lines of the dispatcher
        for i in self.prolog_lines:
            hide_line(func, i)

        # erase the current loop content:
        nop_out_range(func, self.start, self.end)

        #fill in collected lines on the place:
        lIndx = 0
        for i in range(self.start, self.end):
            if lIndx >= len(code_lines):
                break
            
            func.code[i] = code_lines[lIndx]
            lIndx += 1

class CffChunk:
    def __init__(
        self, num, start, end, indent, output_indent=0,
        promote_indices=None, skip_indices=None
    ):
        self.num = num
        self.start = start
        self.end = end
        # Indentation of the chunk in the original nested dispatcher.
        self.indent = indent
        # Indentation at which the chunk is emitted after the dispatcher loop
        # is removed. This is normally the indentation of the removed while.
        self.output_indent = output_indent
        # Some state-entry operations were hidden by View8 after linear
        # propagation.  When the state is moved, such operations may become
        # semantically necessary again.  Only explicitly verified target-entry
        # moves are promoted, and only their redundant immediate reload is
        # skipped.
        self.promote_indices = set(promote_indices or ())
        self.skip_indices = set(skip_indices or ())
        self.has_cont = False

    def print(self, func, line_no=True):
        print(f"\n# Num: {self.num}")
        print_lines(func, self.start, self.end, self.indent, False)

    def collect(self, func, code_lines):
        loop_indent = None
        added_indent = 0
        # Indentation levels of synthetic blocks opened to compensate for
        # branch-local continues targeting the removed CFF dispatcher loop.
        synthetic_block_indents = []
        i = self.start
        while (i < self.end):
            if i in self.skip_indices:
                i += 1
                continue

            source_obj = func.code[i]
            if i in self.promote_indices:
                current_obj = copy.deepcopy(source_obj)
                current_obj.visible = True
                current_obj.set_metadata("RecoveredCffTargetMove", True)
            else:
                current_obj = source_obj

            line = current_obj.decompiled or ""

            # Empty CodeLine placeholders are common after earlier filters
            # hide or fold dispatcher instructions.  Rebasing an empty string
            # with add_indent() would turn it into a tab-only, visible line,
            # which the exporter then prints as a large blank gap.  These
            # placeholders carry no source-level content and must not be
            # emitted as part of the reconstructed chunk.
            if not line.strip():
                i += 1
                continue

            curr_indent = count_indent(line)

            # Rebase the chunk from its original nesting depth to the
            # indentation of the removed dispatcher loop. Preserve relative
            # indentation inside nested source-level blocks.
            current_obj.decompiled = remove_leading_tabs(line, self.indent)
            current_obj.decompiled = add_indent(
                current_obj.decompiled, self.output_indent + added_indent
            )
            if "while" in line:
                loop_indent = count_indent(line)
            elif loop_indent is not None and curr_indent == loop_indent and line.strip() == "}":
                loop_indent = None # the loop is closed

            targets_cff_loop = (loop_indent is None) or (curr_indent <= loop_indent)

            # View8 represents a conditional jump to the next dispatcher
            # iteration as a single line, e.g. `if (ACCU) continue`. Once the
            # dispatcher loop is removed, the remainder of the current chunk
            # must execute only when the condition is false. Express this
            # directly by negating the condition and guarding the remainder.
            inline_continue = re.match(r'^\s*if\s*\((.*)\)\s+continue\s*$', line)
            if inline_continue and targets_cff_loop:
                self.has_cont = True
                ind = self.output_indent + curr_indent - self.indent + added_indent
                negated = negate_condition(inline_continue.group(1))

                current_obj.decompiled = add_indent(f"if ({negated})", ind)
                code_lines.append(current_obj)
                code_lines.append(CodeLine("", current_obj.line_num, "", "", add_indent("{", ind)))

                synthetic_block_indents.append(ind)
                added_indent += 1
                i += 1
                continue

            # A standalone continue inside a braced conditional targets the
            # main CFF loop. Remove it and wrap the remaining chunk statements
            # in the corresponding `else` branch.
            if "continue" == line.strip() and targets_cff_loop:
                self.has_cont = True
                nextI = next_visible_line(func, i, False)
                if nextI is not None:
                    nextLine = func.code[nextI].decompiled
                    if nextLine.strip() == "}":
                        ind = (
                            self.output_indent
                            + count_indent(nextLine)
                            + added_indent
                            - self.indent
                        )
                        code_lines.append(CodeLine("", nextI + 1, "", "", add_indent("}", ind)))
                        code_lines.append(CodeLine("", nextI + 2, "", "", add_indent("else", ind)))
                        code_lines.append(CodeLine("", nextI + 3, "", "", add_indent("{", ind)))
                        synthetic_block_indents.append(ind)
                        added_indent += 1
                        i = nextI + 1
                        continue
            # Lines collected while a synthetic CFF guard is active are
            # semantically conditional remnants of the dispatcher chunk.
            # Keep that provenance so later dead-assignment cleanup does not
            # erase them merely because the reconstructed order contains a
            # use of the register before this definition.
            if synthetic_block_indents:
                current_obj.set_metadata("CffGuardedRemainder", True)

            code_lines.append(current_obj)
            i += 1

        # Close synthetic else blocks from the inside out.
        for close_ind in reversed(synthetic_block_indents):
            code_lines.append(CodeLine("", 0, "", "", add_indent("}", close_ind)))
        return code_lines
###



def normalize_collected_brace_indentation(code_lines, verbosity=0):
    """
    Align each standalone closing brace with the standalone opening brace it
    closes.  CFF chunks are collected from different original nesting levels,
    so a structurally correct closing brace can retain one extra dispatcher
    indentation level after rebasing.

    This pass changes indentation only.  It neither inserts nor removes braces,
    and unmatched braces are left untouched so structural failures remain
    visible instead of being silently guessed away.
    """
    opening_indents = []

    for obj in code_lines:
        if not obj.visible or not obj.decompiled:
            continue

        text = obj.decompiled.strip()
        if text == "{":
            opening_indents.append(count_indent(obj.decompiled))
            continue

        if text != "}" or not opening_indents:
            continue

        expected_indent = opening_indents.pop()
        current_indent = count_indent(obj.decompiled)
        if current_indent == expected_indent:
            continue

        if verbosity > 2:
            print(
                f"CFF: rebasing closing brace indentation "
                f"{current_indent} -> {expected_indent}"
            )
        obj.decompiled = add_indent("}", expected_indent)

    if opening_indents and verbosity > 2:
        print(
            f"CFF: {len(opening_indents)} unmatched opening brace(s) remain "
            "after indentation normalization"
        )

    return code_lines


def _line_offset(line_obj):
    """Return a numeric bytecode offset from a CodeLine, if available."""
    try:
        return int(line_obj.line_num)
    except (TypeError, ValueError):
        return None


def _jump_target(line_obj):
    """Extract the absolute bytecode target printed in a V8 jump instruction."""
    instruction = line_obj.v8_instruction or ""
    match = re.search(r'@\s*(-?\d+)\)', instruction)
    if not match:
        return None
    return int(match.group(1))


def _previous_visible_index(func, before, lower_bound):
    """Find the previous visible, non-empty CodeLine index before ``before``."""
    i = before - 1
    while i >= lower_bound:
        obj = func.code[i]
        if obj.visible and obj.decompiled is not None:
            return i
        i -= 1
    return None


def _first_meaningful_indent(func, start, end):
    """Return the indentation of the first visible state-body statement."""
    for i in range(start, end):
        obj = func.code[i]
        if not obj.visible or not obj.decompiled:
            continue
        text = obj.decompiled.strip()
        if text in {"", "continue", "break", "}"}:
            continue
        return count_indent(obj.decompiled)
    return None


def _is_state_comparison_jump(line_obj):
    """
    Return True only for conditional jumps that can terminate a dispatcher
    equality test.  In particular, reject Jump/JumpConstant/JumpLoop: an
    unconditional dispatcher continue may sit immediately after the final
    comparison and must never overwrite that state's real target.
    """
    instruction = (line_obj.v8_instruction or "").strip()
    return re.match(
        r'^JumpIf(?:True|False)(?:Constant)?\b', instruction
    ) is not None


def _recover_hidden_target_move(func, start, end):
    """
    Recover a state-entry ``Mov src, dst`` that View8 hid after folding the
    immediately following ``Ldar dst`` into ``ACCU = src``.

    In the original linear order the hidden assignment may look redundant.
    After CFF states are reordered, however, later states can depend on ``dst``.
    Only the exact, mechanically verifiable pair below is recovered:

        Mov src, dst      (hidden, decompiled as ``dst = src``)
        Ldar dst          (visible, decompiled as ``ACCU = src``)

    Returns ``(promote_indices, skip_indices)``.
    """
    if start >= end:
        return set(), set()

    target = func.code[start]
    if target.visible or not target.decompiled:
        return set(), set()

    inst_match = re.match(
        r'^Mov\s+(.+?),\s*((?:r|a)\d+)\s*$',
        (target.v8_instruction or "").strip(),
    )
    decomp_match = re.match(
        r'^\s*((?:r|a)\d+)\s*=\s*(.+?)\s*$',
        target.decompiled,
    )
    if not inst_match or not decomp_match:
        return set(), set()

    destination = inst_match.group(2)
    if decomp_match.group(1) != destination:
        return set(), set()
    rhs = decomp_match.group(2).strip()

    next_index = start + 1
    while next_index < end:
        obj = func.code[next_index]
        if obj.visible and obj.decompiled and obj.decompiled.strip():
            break
        next_index += 1
    if next_index >= end:
        return set(), set()

    reload_obj = func.code[next_index]
    reload_inst = (reload_obj.v8_instruction or "").strip()
    reload_text = (reload_obj.decompiled or "").strip()
    if not re.match(rf'^Ldar\s+{re.escape(destination)}\b', reload_inst):
        return set(), set()
    if reload_text != f"ACCU = {rhs}":
        return set(), set()

    return {start}, {next_index}


def _trim_dispatcher_tail(func, start, end, body_indent):
    """
    Trim only the dispatcher transfer and dispatcher-chain braces.

    A genuine closing brace belonging to a source-level if/loop has the same
    indentation as the first statement of the state body and must be kept.
    Dispatcher-chain braces are shallower than the body.
    """
    while end > start:
        prev = _previous_visible_index(func, end, start)
        if prev is None:
            return start
        obj = func.code[prev]
        text = (obj.decompiled or "").strip()
        indent = count_indent(obj.decompiled or "")

        if text == "":
            end = prev
            continue
        if text in {"continue", "break"} and indent <= body_indent:
            end = prev
            continue
        if text == "}" and indent < body_indent:
            end = prev
            continue
        break
    return end


def find_chunks_by_jump_targets(func, loop_start, loop_end, loop_indent):
    """
    Recover CFF state bodies from the bytecode targets of dispatcher comparison
    jumps.  Bytecode metadata is used only for state-to-body anchors; emitted
    content remains the already-transformed CodeLine objects.
    """
    state_targets = {}
    condition_indent = {}
    # Most dispatcher comparisons are rendered as ``if (!rN === "K")``.
    # The terminal comparison is commonly rendered positively as
    # ``if (rN === "K") continue``.  Both forms carry the same authoritative
    # bytecode target for the matching state's body.
    pattern = re.compile(
        r'^\s*if\s*\(\s*!?\s*r\d+\s*===\s*["\'](\d+)["\']\s*\)'
        r'(?:\s+continue)?\s*$'
    )

    for i in range(loop_start, loop_end):
        obj = func.code[i]
        if not obj.decompiled or not _is_state_comparison_jump(obj):
            continue
        match = pattern.search(obj.decompiled)
        if not match:
            continue
        target = _jump_target(obj)
        if target is None:
            continue
        state = int(match.group(1))

        # One comparison belongs to each state. Keep the first conditional
        # anchor and never let a later control-transfer line replace it.
        if state in state_targets:
            continue
        state_targets[state] = target
        condition_indent[state] = count_indent(obj.decompiled)

    if not state_targets:
        return {}

    offset_to_index = {}
    for i in range(loop_start, loop_end):
        offset = _line_offset(func.code[i])
        if offset is not None and offset not in offset_to_index:
            offset_to_index[offset] = i

    starts = {}
    for state, target in state_targets.items():
        if target not in offset_to_index:
            # Fail closed and let the legacy indentation collector try. Do not
            # approximate a bytecode boundary from a transformed neighboring
            # line.
            return {}
        starts[state] = offset_to_index[target]

    ordered_starts = sorted((index, state) for state, index in starts.items())
    cff_chunks = {}

    for position, (start, state) in enumerate(ordered_starts):
        raw_end = (
            ordered_starts[position + 1][0]
            if position + 1 < len(ordered_starts)
            else loop_end
        )

        promote_indices, skip_indices = _recover_hidden_target_move(
            func, start, raw_end
        )
        if promote_indices:
            body_indent = count_indent(func.code[start].decompiled or "")
        else:
            body_indent = _first_meaningful_indent(func, start, raw_end)

        if body_indent is None:
            # A state consisting only of continue/break and dispatcher braces
            # is intentionally empty.
            fallback_indent = max(
                loop_indent + 1,
                condition_indent.get(state, loop_indent + 1),
            )
            cff_chunks[state] = CffChunk(
                state, start, start, fallback_indent, output_indent=loop_indent
            )
            continue

        end = _trim_dispatcher_tail(func, start, raw_end, body_indent)
        cff_chunks[state] = CffChunk(
            state, start, end, body_indent, output_indent=loop_indent,
            promote_indices=promote_indices, skip_indices=skip_indices
        )

    return cff_chunks

def _get_block_last_line(func, end_indx):
    """
    Find the last line of the single CFF block (chunk).
    """
    while (not func.code[end_indx].visible):
        end_indx -= 1
        continue
    if (func.code[end_indx].decompiled.strip() == ""):
        end_indx = next_visible_line(func, end_indx, True)
    if (func.code[end_indx].decompiled.strip() == "}"):
        end_indx = next_visible_line(func, end_indx, True)
    if (func.code[end_indx].decompiled.strip() == "break"):
        end_indx = next_visible_line(func, end_indx, True)
    if (func.code[end_indx].decompiled.strip() == "continue"):
        end_indx = next_visible_line(func, end_indx, True)
    return end_indx

def _get_loop_last_line(func, end_indx):
    """
    Find the last line of the CFF while loop.
    """
    while (not func.code[end_indx].visible):
        end_indx += 1
        continue
    line = func.code[end_indx].decompiled.strip()
    if (func.code[end_indx].decompiled.strip() == "}"):
        end_indx = next_visible_line(func, end_indx, False)
    if (line == "break"):
        end_indx = next_visible_line(func, end_indx, False)
        end_indx += 1
    return end_indx

def _find_loop_start(func, split_index):
    global g_Verbosity
    patternW = re.compile(r'while \(true\)')
    patternL1 = re.compile(r'r\d+\s*=\s*Number\(r\d+\)')
    patternL2 = re.compile(r'r\d+\s*=\s*\(Number\(r\d+\)\s*\+\s*1\)')
    patternL3 = re.compile(r'r\d+\s*=\s*r\d+\[r\d+\]')
    bogus_lines = ['if (![]) break', 'if (![]) continue' ]
    startI = split_index
    while True:
        (loopStartIndex,_) = find_code_pattern(func, patternW, startI)
        if loopStartIndex is None:
            return None
        #print(f"Loop start candidate: {loopStartIndex}")
        oIndex = next_visible_line(func, loopStartIndex, False)
        line = func.code[oIndex].decompiled.strip()
        if line != "{":
            return None

        # get valuable line, skip bogus:
        while True:
            oIndex = next_visible_line(func, oIndex, False)
            if oIndex is None:
                return None
            line = func.code[oIndex].decompiled.strip()
            if line not in bogus_lines:
                break
            if g_Verbosity:
                print("CFF: skipping bogus lines")

        match = re.match(patternL1, line)
        if match:
            oIndex = next_visible_line(func, oIndex, False)
            line = func.code[oIndex].decompiled.strip()
            match = re.match(patternL2, line)
            if match:
                oIndex = next_visible_line(func, oIndex, False)
                line = func.code[oIndex].decompiled.strip()
                match = re.match(patternL3, line)
                if match:
                    #print("Match ok")
                    return loopStartIndex
        print(f"Match NOT ok: {line}")
        startI = loopStartIndex + 1

    return None

def deobfuscate_flattened(func, verbosity):
    """
    Parse the content of the flattened function, and rewrite the code to deobfuscate it.
    """
    # get the line defining the order:
    (oIndex, match) = get_cff_order_line(func)
    if (oIndex is None) or (match is None):
        return
    oLine = func.code[oIndex].decompiled.strip()
    refs = find_order_split_lines(func, oLine, oIndex+1)
    if not refs:
        print(f"Can't find CFF markers in the function: {func.name}")
        return
    refs.add(oIndex)
    if verbosity:
        print(refs)
    # parse the order:
    parts = match.group(1).split("|")  # i.e. ['3', '2', '1', '0', '4']
    order = [int(x) for x in parts]
    if len(order) == 0:
        return
    # find the beginning of the loop
    chunks = dict()
    loopStartIndex = _find_loop_start(func,oIndex)
    if loopStartIndex is None:
        print(f"Can't find CFF loop in the function: {func.name}")
        return
    line = func.code[loopStartIndex].decompiled
    sIndent = count_indent(line)

    chunks[0] = (sIndent, loopStartIndex)
    # find the end of the loop
    loopEndIndx = find_code_line(func, add_indent("}", sIndent), True, loopStartIndex)
    if loopEndIndx is None:
        print(f"Failed to find the loop end {func.name}")
        return

    my_cff = CffLoop(func.name, loopStartIndex, _get_loop_last_line(func, loopEndIndx), sIndent)
    my_cff.prolog_lines.update(refs)
    if verbosity > 1:
        my_cff.print(func)
    
    # Prefer the authoritative bytecode jump targets.  The old indentation-
    # based collector is retained as a fallback for legacy serialized inputs
    # that do not carry V8 instructions or bytecode offsets.
    cff_chunks = find_chunks_by_jump_targets(func, loopStartIndex, loopEndIndx, sIndent)

    if not cff_chunks:
        find_all_chunks_starts(func, loopStartIndex, chunks)
        endings_list = find_all_chunks_endings(func, loopStartIndex, loopEndIndx)
        endings_list[sIndent] = loopEndIndx # the end of the loop

        cff_chunks = dict()
        for num in chunks.keys():
            (indent, indx) = chunks[num]
            if indent not in endings_list.keys():
                continue
            end_indx = endings_list[indent]
            start_pos = indx
            if (indent+1) in endings_list.keys():
                start_pos = endings_list[indent+1]
            if func.code[start_pos].decompiled.strip() == "}":
                start_pos += 1
            end_indx = _get_block_last_line(func, end_indx)
            cff_chunks[num] = CffChunk(
                num, start_pos, end_indx + 1, indent, output_indent=sIndent
            )

    if verbosity > 1:
        print("## Ordered:")

    is_ok = True
    code_lines  = []
    for num in order:
        if num not in cff_chunks.keys():
            print(f"The chunk {num} is missing from the collection")
            is_ok = False
            continue
        if (verbosity > 1):
            cff_chunks[num].print(func)
        cff_chunks[num].collect(func, code_lines)

    if not is_ok:
        print(f"Failed to patch the function: {func.name}")
        return

    normalize_collected_brace_indentation(code_lines, verbosity)
    my_cff.patch(func, code_lines)
    if verbosity > 1:
        print("## Patched the loop")
        my_cff.print(func)
    

def find_flattened(functions, verbosity=0):
    """
    Find all the flattened functions. Set metadata of the found function.
    Returns a dict in a format: function_name -> function_object
    """
    with_patt = set()
    flattened = dict()
    pattern1 = re.compile(r'(\"\d+(?:\|\d+)+\")')
    pattern2 = re.compile(r'while \(true\)')
    for func_name, func in functions.items():
        (index,match) = find_code_pattern(func, pattern1)
        if index is None:
            continue
        with_patt.add(func_name)
        func.code[index].set_metadata("CffOrder", match.group(1))
        index, match = find_code_pattern(func, pattern2)
        if index is None:
            continue
        flattened[func_name] = func
        func.metadata = "Flattened"
    for func_name in with_patt:
        if func_name not in flattened.keys():
            print(f"Unresolved: {func_name}")
    return flattened


def deobf_unflat_default(all_func, verbosity, return_changed=False):
    flattened = find_flattened(all_func)
    for func_name, func in flattened.items():
        deobfuscate_flattened(func, verbosity)
    if return_changed:
        return set(flattened)
    return len(flattened)


def main():
    global g_Verbosity
    global str_array
    parser = argparse.ArgumentParser(description="JSCeal deobf. - CFF unflattener")
    parser.add_argument('--inp', '-i', help="The input file name. It must be a serialized View8 output.", default=None, required=True)
    parser.add_argument('--out', '-o', help="The output file name.", default=None)
    parser.add_argument('--export_format', '-e', nargs='+', choices=['v8_opcode', 'translated', 'decompiled', 'serialized'], 
                        help="Specify the export format(s). Options are 'v8_opcode', 'translated', and 'decompiled'. Multiple options can be combined.", 
                        default=['serialized', 'decompiled'])
    parser.add_argument('--func', help="A function to be displayed.", default=None, required=False)
    parser.add_argument('--verbosity', '-v', help="Verbosity level (0-3)", default=0, type=int, required=False)
    args = parser.parse_args()
    
    g_Verbosity = args.verbosity
    
    if not os.path.isfile(args.inp):
        raise FileNotFoundError(f"The input file {args.inp} does not exist.")

    print(f"Reading from serialized, already decompiled input: {args.inp}")
    all_func = load_functions_from_file(args.inp)
    flattened = find_flattened(all_func)

    # print a single selected function:
    if args.func:
        func_name = args.func
        filtered = find_functions_by_name(all_func, func_name)
        if func_name in flattened.keys():
            func = flattened[func_name]
            print_func(func_name, func)
            deobfuscate_flattened(func, 2)
        else:
            print(f"Function {func_name} was not found among the flattened functions.")
        print(f"Done.")
        return

    #print_funcs(flattened, False)
    for func_name, func in flattened.items():
        #print_func(func_name, func)
        deobfuscate_flattened(func, g_Verbosity)
    if (g_Verbosity):
        print_funcs(flattened, show_all=False,show_line_num=False)

    if args.out:
        export_to_file(args.out, all_func, args.export_format)
    print(f"Done.")


if __name__ == "__main__":
    main()
