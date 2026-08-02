#!/usr/bin/env python3
# JSC Deobfuscator - static deobfuscation of View8 pseudocode generated from
# compiled V8 JavaScript bytecode.
#
# Copyright (C) 2026 Aleksandra "Hasherezade" Doniec @ Check Point Research
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''
JSC Deobfuscator
Renames requested function with a selected LLM
'''

import argparse
import os
import re
import requests
import json
import csv
import math
import time

from View8.Parser.shared_function_info import save_functions_to_file, load_functions_from_file
from deobf_commons import *
from View8.view8_util import export_to_file, find_functions_by_name, print_func, rename_functions_in_code
from View8.view8 import *

g_Verbosity = 0

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-5.4-mini",
    "ollama": "mistral",
}

DEFAULT_TEMPERATURES = {
    "anthropic": None,
    "openai": 0.0,
    "ollama": 0.1,
}

# Default output cap for the Anthropic backend. The previous hardcoded 1024 was
# too small for batch mode (a CSV row per function) and, on models with thinking
# on by default, could be consumed entirely by reasoning tokens.
DEFAULT_ANTHROPIC_MAX_TOKENS = 4096

# Thinking mode sent to the Anthropic API:
#   "disabled" - portable off switch. Accepted by Sonnet 4.6, Sonnet 5, Opus 4.x.
#                Required on Sonnet 5, where adaptive thinking is ON by default.
#   "adaptive" - let the model decide. Supported on Sonnet 4.6 / Sonnet 5 / Opus 4.6+.
#   "default"  - omit the field entirely (pre-patch behaviour).
DEFAULT_ANTHROPIC_THINKING = "disabled"

# Models that reject any explicit temperature / top_p / top_k with HTTP 400,
# regardless of whether thinking is active.
ANTHROPIC_FIXED_SAMPLING = (
    "claude-sonnet-5",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-fable-5",
    "claude-mythos-5",
)

# Models where thinking cannot be switched off at all; sending
# {"type": "disabled"} to them is an error, so the field is omitted.
ANTHROPIC_ALWAYS_THINKING = (
    "claude-fable-5",
    "claude-mythos-5",
    "claude-mythos-preview",
)


def resolve_model_name(backend: str, model: str | None) -> str:
    """Return the explicitly selected model or the backend default."""
    return model or DEFAULT_MODELS[backend]


def sanitize_filename_component(value: str) -> str:
    """Convert an arbitrary model identifier into a portable filename part."""
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return sanitized or "model"


# Maximum character count for function bodies sent to Claude API in a single request
# This prevents hitting API rate limits and ensures manageable request sizes
RATE_LIMIT = 30000

### 

class APIError(Exception):
    pass

###

def clean_llm_output(text: str) -> str:
    # remove triple quotes artifacts
    text = text.replace('"""', '"')

    # collapse repeated quotes
    text = text.replace('""', '"').strip()
    return text

def is_valid_name(name: str) -> bool:
    name = name.strip()

    if not name:
        return False

    if "unknown" in name.lower():
        return False

    if len(name) < 4:
        return False

    if not name[0].isalpha():
        return False

    if "func_" in name:
        return False

    # reject mixed garbage like RylYE patterns
    if sum(c.islower() for c in name) < 2:
        return False

    return True

class LLMClient:
    def __init__(self, backend, model=None, ollama_url=None, api_key=None, temperature=None,
                 thinking=DEFAULT_ANTHROPIC_THINKING, max_tokens=DEFAULT_ANTHROPIC_MAX_TOKENS):
        self.backend = backend
        self.model = model
        self.ollama_url = ollama_url
        self.api_key = api_key
        self.temperature = temperature
        self.thinking = thinking
        self.max_tokens = max_tokens

    def _model_startswith(self, prefixes) -> bool:
        return (self.model or "").startswith(prefixes)

    def ask(self, prompt: str) -> str:
        if self.backend == "anthropic":
            return self._ask_anthropic(prompt)
        if self.backend == "openai":
            return self._ask_openai(prompt)
        elif self.backend == "ollama":
            return self._ask_ollama(prompt)
        else:
            raise ValueError(f"Unknown backend: {self.backend}")

    def _ask_anthropic(self, prompt):
        if not self.api_key:
            raise ValueError("Missing ANTHROPIC_API_KEY")
        
        url = "https://api.anthropic.com/v1/messages"

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }

        data = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}]
        }

        # Thinking defaults differ across models: Sonnet 5 has adaptive thinking ON
        # unless told otherwise, while Sonnet 4.6 and older have it OFF. Sending
        # {"type": "disabled"} explicitly is accepted by both, so one payload works
        # for the whole range and the full max_tokens budget goes to the answer.
        if self.thinking != "default" and not self._model_startswith(ANTHROPIC_ALWAYS_THINKING):
            data["thinking"] = {"type": self.thinking}

        # Sonnet 5 / Opus 4.7+ reject an explicit temperature with HTTP 400.
        if self.temperature is not None and not self._model_startswith(ANTHROPIC_FIXED_SAMPLING):
            data["temperature"] = self.temperature

        response = requests.post(url, headers=headers, json=data, timeout=60)
        resp = response.json()

        if "error" in resp:
            raise APIError(resp["error"]["message"])

        if g_Verbosity > 2:
            print(resp)

        # Thinking blocks (when enabled) carry an empty "thinking" field plus a
        # signature, so filter by type instead of assuming content[0] is the answer.
        text = "\n".join(
            b.get("text", "") for b in resp.get("content", [])
            if b.get("type") == "text"
        )

        if resp.get("stop_reason") == "max_tokens":
            usage = resp.get("usage", {})
            details = usage.get("output_tokens_details", {})
            msg = (f"Response truncated at max_tokens={self.max_tokens} "
                   f"(output={usage.get('output_tokens')}, "
                   f"thinking={details.get('thinking_tokens')}). "
                   f"Increase --max_tokens.")
            if not text.strip():
                raise APIError(msg)
            print(f"WARNING: {msg} Keeping the partial output.")

        if not text.strip():
            raise APIError(
                f"No text block in the response (stop_reason={resp.get('stop_reason')})"
            )

        return text

    def _ask_openai(self, prompt: str) -> str:
        from openai import OpenAI

        if not self.api_key:
            raise ValueError("Missing OPENAI_API_KEY")

        client = OpenAI(api_key=self.api_key)

        request_args = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
        }
        if self.temperature is not None:
            request_args["temperature"] = self.temperature

        response = client.chat.completions.create(**request_args)
        return response.choices[0].message.content

    def _ask_ollama(self, prompt):
        options = {
            "num_ctx": 4096,
            "top_p": 0.8,
            "repeat_penalty": 1.2
        }
        if self.temperature is not None:
            options["temperature"] = self.temperature

        response = requests.post(
            f"{self.ollama_url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "options": options,
                "stream": False
            },
            timeout=400
        )
        data = response.json()
        return data["message"]["content"]
##

def _ask_ai(prompt):
    return llm.ask(prompt)

def ask_ai_rename(func_body):
    prompt = f"You are analyzing decompiled JavaScript functions.\n\
Task:\n\
Return ONLY a single valid function name in camelCase.\n\
Rules:\n\
- The name must describe actual behavior\n\
- Do NOT invent abstract identifiers\n\
- Do NOT reuse unknown patterns and meaningless names\n\
- If unsure, output: unknownFunction\n\
Output format:\n\
ONE WORD ONLY\n\
NO punctuation\n\
NO explanations\n\
Function:\n\n```{func_body}```"
    return _ask_ai(prompt)

def ask_ai_analyze_function(func_name: str, func_body: str):
    prompt = f"""You are analyzing one function recovered from compiled V8 JavaScript bytecode.
The input is View8 pseudocode, not runnable JavaScript and not the original source.

Analyze only the supplied function. Do not invent missing behavior. Distinguish direct
evidence from inference, and preserve unresolved calls or values instead of guessing them.

Return Markdown with exactly these sections:

## Suggested name
One camelCase function name, or `unknownFunction` when the behavior is unclear.

## Summary
A concise description of the function's purpose.

## Inputs
Explain each argument and any important values read through globals or scope. Mark uncertain
types or meanings explicitly.

## Return value
Describe the returned value and the conditions under which it is returned.

## Side effects and external interactions
List state changes, file, registry, network, process, cryptographic, UI, or other external
operations. Write `None identified` when there are none.

## Step-by-step logic
Explain the control flow in execution order.

## Cleaned pseudocode
Rewrite the function into readable pseudocode while preserving its observed semantics.
Do not claim that the result is runnable JavaScript.

## Evidence and uncertainties
Identify the strings, APIs, paths, calls, and data flow supporting the interpretation, and
state what remains unresolved.

Original function identifier: {func_name}

Function body:
```javascript
{func_body}
```"""
    return _ask_ai(prompt)

def ask_ai_rename_multi(func_bodies):
    prompt = f"You are given an output of JSC decompilation. Clean body of each function in your memory. Rename the given functions to the relevant names. Each name should be one word, camel-case. Don't add comments. As the output, list the original name mapped to the new name, as CSV. Answer only with the CSV, nothing more, no explanations. The function bodies are given below:\n```{func_bodies}```"
    return _ask_ai(prompt)

def get_func_body(func, func_name=None):
    content = []
    content.append(func.create_function_header())
    i = 0
    for i in range(len(func.code)):
        line_obj = func.code[i]
        if not line_obj.decompiled:
            continue
        if not line_obj.visible:
            continue
        line = line_obj.decompiled
        content.append(line)
    return "\n".join(content)

def get_func_name_via_ai(func, verbosity=0):
    body = get_func_body(func)
    new_name = ask_ai_rename(body)
    if verbosity > 2:
        print(body.replace(func.name, new_name))
    return new_name


def apply_names_to_text(text: str, renamed_dict: dict[str, str]) -> str:
    """Apply cached full function names to one text fragment without mutating the corpus."""
    if not renamed_dict:
        return text

    func_identifier = re.compile(r'func_[A-Za-z0-9_$]+_0x[0-9a-fA-F]+')
    return func_identifier.sub(lambda match: renamed_dict.get(match.group(0), match.group(0)), text)


def analyze_func_via_ai(func_name: str, func, renamed_dict: dict[str, str] | None = None) -> str:
    body = get_func_body(func)
    body = apply_names_to_text(body, renamed_dict or {})
    if len(body) >= RATE_LIMIT:
        raise ValueError(
            f"Function {func_name} is too large for detailed analysis: "
            f"{len(body)} characters (limit: {RATE_LIMIT - 1})"
        )
    return ask_ai_analyze_function(func_name, body)


def save_analysis(path: str, analysis: str):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(analysis)
        if not analysis.endswith('\n'):
            f.write('\n')


def parse_csv(data):
    parsed_dict = {}
    for row in csv.reader(data.splitlines()):
        if len(row) != 2:
            # Skip lines with only a key or incomplete
            continue
        key, value = row
        key = key.strip().strip('`').strip()
        value = value.strip().strip('`').strip()
        if not key or key.lower() in {"old", "old_name", "original", "original_name"}:
            continue
        parsed_dict[key] = value
    return parsed_dict


def _extract_full_func_name(text: str) -> str | None:
    """Return a View8-style function identifier embedded in LLM text, if any."""
    if not text:
        return None
    matches = re.findall(r'func_[A-Za-z0-9_$]+_0x[0-9a-fA-F]+', text)
    if matches:
        # Prefer the last match; it handles rows like: function func_x_0x123(a0)
        return matches[-1]
    return None


def canonicalize_llm_old_name(raw_name: str, functions: dict, expected_names: set[str] | None = None) -> str | None:
    """
    Normalize the left-hand side returned by the LLM.

    In batch mode Claude occasionally returns variants such as:
      * function func_x_0x123(a0)
      * `func_x_0x123`
      * func_func_x_0x123
      * x_0x123

    The renamer must map those back to the exact key present in `functions`,
    otherwise valid rows are lost as "name not found".
    """
    if expected_names is None:
        expected_names = set(functions.keys())

    name = (raw_name or '').strip().strip('`').strip().strip('"').strip("'")
    if not name:
        return None

    if name.startswith('function '):
        name = name[len('function '):].strip()
    if '(' in name:
        name = name.split('(', 1)[0].strip()
    name = name.rstrip(':;,')

    candidates = []
    embedded = _extract_full_func_name(name)
    if embedded:
        candidates.append(embedded)
    candidates.append(name)

    if name.startswith('func_func_'):
        # LLM sometimes prepends an extra func_ to an already View8-style name.
        candidates.append(name[len('func_'):])

    if not name.startswith('func_'):
        candidates.append('func_' + name)

    # If the address is intact, use it as the anchor. This recovers cases where
    # the textual prefix/mid-part was damaged but the 0x... suffix survived.
    m_addr = re.search(r'(0x[0-9a-fA-F]+)$', name)
    if m_addr:
        addr = m_addr.group(1)
        for real_name in expected_names:
            if real_name.endswith('_' + addr):
                candidates.append(real_name)
        for real_name in functions.keys():
            if real_name.endswith('_' + addr):
                candidates.append(real_name)

    seen = set()
    for cand in candidates:
        if not cand or cand in seen:
            continue
        seen.add(cand)
        if cand in expected_names and cand in functions:
            return cand
        if cand in functions:
            return cand

    return None


def get_funcs_names_dict_via_ai(func_bodies_str, verbosity=0):
    new_names_csv = clean_llm_output(ask_ai_rename_multi(func_bodies_str))
    if verbosity:
        print(f"Resp: {new_names_csv}")
    result = parse_csv(new_names_csv)
    if len(result) == 0:
        return None
    return result

def normalize_new_mid(new_mid: str) -> str:
    """Normalize the right-hand side returned by the LLM/CSV to a bare semantic name."""
    new_mid = (new_mid or '').strip().strip('`').strip().replace('"', '').replace("'", "")
    if new_mid.startswith('function '):
        new_mid = new_mid[len('function '):].strip()
    if '(' in new_mid:
        new_mid = new_mid.split('(', 1)[0].strip()

    # If the value is already a full View8-style name, keep only its middle part.
    m_new_full = re.match(r'^func_(.+?)_(0x[0-9a-fA-F]+)$', new_mid)
    if m_new_full:
        new_mid = m_new_full.group(1)
    elif new_mid.startswith('func_'):
        new_mid = new_mid[len('func_'):]

    # If the model returned name_0xaddr without the leading func_, drop the addr.
    new_mid = re.sub(r'_0x[0-9a-fA-F]+$', '', new_mid)

    # Keep only safe identifier chars.
    new_mid = re.sub(r'[^A-Za-z0-9_]', '', new_mid)
    return new_mid or 'unknown'


def build_new_full(old_full: str, new_mid: str) -> str:
    """Build a stable View8-style full function name.

    `new_mid` is supposed to be just the semantic middle part, but LLMs and
    cached CSVs sometimes contain a full name such as `func_parseFoo_0x123`.
    Without normalization this becomes `func_parseFoo_0x123_0x123` or other
    malformed names.
    """
    m_old = re.match(r'^func_(.+?)_(0x[0-9a-fA-F]+)$', old_full)
    if not m_old:
        return old_full

    old_addr = m_old.group(2)
    new_mid = normalize_new_mid(new_mid)
    return f"func_{new_mid}_{old_addr}"

def replace_name_in_function(func, old_full: str, new_full: str):
    indx = -1
    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break

        line = func.code[indx].decompiled

        # Replace only exact identifier occurrences
        new_line = re.sub(rf'\b{re.escape(old_full)}\b', new_full, line)

        if new_line != line:
            func.code[indx].decompiled = new_line
            if g_Verbosity > 1:
                print(f"REPL: `{line}` -> `{new_line}`")


def propagate_name(functions, call_tree, old_name, new_name, verbosity):
    for name in call_tree:
        if old_name in call_tree[name]:
            func = functions[name]
            if verbosity:
                print(f"Function: {name} is using {old_name} -> {new_name}")
            replace_name_in_function(func, old_name, new_name)


def erase_from_call_tree(func_name: str, call_tree: dict[str, set[str]]):
    call_tree.pop(func_name, None)
    for name in call_tree.keys():
        if func_name in call_tree[name]:
            call_tree[name].discard(func_name)

def resolve_funcs_by_ai(functions, min_ref_subset, call_tree, blacklisted: set[str], batch_mode, verbosity=0):

    if len(min_ref_subset) == 0:
        return None

    total_len = 0
    selected_funcs = []

    for func_name in sorted(min_ref_subset):

        if func_name not in functions:
            # The call tree should only contain real function keys, but be defensive
            # in case it was built from partially renamed input.
            print(f"WARNING: call tree key not found in functions: {func_name}")
            erase_from_call_tree(func_name, call_tree)
            continue

        func = functions[func_name]
        body = get_func_body(func)
        curr_len = len(body)

        if curr_len >= RATE_LIMIT:
            blacklisted.add(func_name)
            erase_from_call_tree(func_name, call_tree)
            print(f"Blacklisted the function that exceeded the rate: {func_name} Len: {curr_len}")
            if verbosity > 2:
                print_func(func_name, func)

            continue

        if total_len + curr_len > RATE_LIMIT:
            if total_len > (RATE_LIMIT / 2):
                break
            continue

        total_len += curr_len
        selected_funcs.append((func_name, func, body))

        #
        # For local models we intentionally process
        # one function at a time.
        #
        if not batch_mode:
            break

    if not selected_funcs:
        return None

    #
    # SINGLE-FUNCTION MODE
    #
    if not batch_mode:
        func_name, func, _ = selected_funcs[0]
        if verbosity:
            print(f"Resolving: {func_name}")

        retry_count = 0
        max_retries = 5

        while retry_count < max_retries:
            try:
                new_name = get_func_name_via_ai(func, verbosity)
                return { func_name: new_name }
            
            except APIError as e:
                print(f"API error: {e}")
                if "rate limit" in str(e).lower():
                    retry_count += 1
                    if retry_count >= max_retries:
                        print(f"Max retries ({max_retries}) reached. Giving up.")
                        raise
                    seconds = 60 * (2 ** (retry_count - 1))
                    print(f"Rate limit hit. Waiting {seconds} seconds before retry {retry_count}/{max_retries}...")
                    time.sleep(seconds)
                else:
                    raise
        return None

    #
    # BATCH MODE
    #
    func_bodies_str = "\n".join(body for _, _, body in selected_funcs)

    if verbosity:
        print(f"Inp Len: {len(func_bodies_str)}")

    retry_count = 0
    max_retries = 5

    while retry_count < max_retries:
        try:
            return get_funcs_names_dict_via_ai(func_bodies_str)
        
        except APIError as e:
            print(f"API error: {e}")

            if "rate limit" in str(e).lower():
                retry_count += 1

                if retry_count >= max_retries:
                    print(f"Max retries ({max_retries}) reached. Giving up.")
                    raise

                seconds = 60 * (2 ** (retry_count - 1))
                print(f"Rate limit hit. Waiting {seconds} seconds before retry {retry_count}/{max_retries}...")
                time.sleep(seconds)
            else:
                raise
    return None


def find_min_ref(call_tree):
    min_ref = None
    for name in call_tree:
        curr_ref = len(call_tree[name])
        if min_ref is None:
            min_ref = curr_ref
            continue
        if curr_ref < min_ref:
            min_ref = curr_ref
    return min_ref


def run_renaming_round(functions, call_tree, renamed_dict, blacklisted, csv_file, batch_mode, verbosity):

    def _rename_function(functions: dict[str, SharedFunctionInfo], old_name: str, new_name:str):
        func = functions[old_name]
        func.name = new_name

    min_ref = find_min_ref(call_tree)
    if verbosity:
        print(f"Min ref: {min_ref}")

    min_ref_subset = set()
    for name in call_tree:
        if len(call_tree[name]) == min_ref:
            min_ref_subset.add(name)

    # rename the remaining
    mini_dict = resolve_funcs_by_ai(functions, min_ref_subset, call_tree, blacklisted, batch_mode, verbosity)
    if not mini_dict:
        return 0

    if verbosity:
        print(mini_dict)

    count = 0
    used_old_names = set()
    for raw_name in mini_dict.keys():
        name = canonicalize_llm_old_name(raw_name, functions, min_ref_subset)
        if not name:
            print(f"WARNING: name not found: {raw_name}")
            continue
        if name in used_old_names:
            if verbosity:
                print(f"WARNING: duplicate LLM row for: {name} (raw: {raw_name})")
            continue
        used_old_names.add(name)
        new_mid = normalize_new_mid(mini_dict[raw_name])
        if not is_valid_name(new_mid):
            blacklisted.add(name)
            erase_from_call_tree(name, call_tree)
            if g_Verbosity:
                print(f"Blacklisted function due to invalid name: {new_mid} -> {name}")
            continue
        new_name = build_new_full(name, new_mid)
        renamed_dict[name] = new_name
        _rename_function(functions, name, new_name)
        
        propagate_name(functions, call_tree, name, new_name, verbosity)
        erase_from_call_tree(name, call_tree)

        write_to_csv(csv_file, name, new_name)
        count += 1
    return count

def write_to_csv(csv_file, old_name, new_name):
    """
    Save the resolved functions to the CSV file.
    """
    if not csv_file:
        return False

    try:
        parent = os.path.dirname(os.path.abspath(csv_file))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([old_name, new_name])
        return True
    except Exception as e:
        print(f"Error writing to CSV file {csv_file}: {e}")
    return False

def read_from_csv(csv_file, renamed_dict, all_func):
    found_funcs = 0
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            # Process rows
            for row in reader:
                if len(row) != 2:
                    print(f"Warning: Skipping malformed row: {row}")
                    continue
                
                old_name, new_name = row
                old_name = old_name.strip().strip('`').strip()
                new_name = new_name.strip().strip('`').strip()
                canonical_old = canonicalize_llm_old_name(old_name, all_func)
                if canonical_old in all_func.keys():
                    found_funcs += 1
                    renamed_dict[canonical_old] = build_new_full(canonical_old, new_name)

            if not found_funcs:
                raise Exception(f"The list of functions does not fit the file")
                return False

    except FileNotFoundError:
        print(f"Error: CSV file '{csv_file}' not found")
        return False
        
    except Exception as e:
        print(f"Error loading from CSV: {e}")
        return False
    return True

def discard_resolved(call_tree, renamed_dict, verbosity=0):
    names_set = set(call_tree.keys())
    # filter out already resolved:
    for name in names_set:
        if name in renamed_dict.keys():
            if verbosity > 1:
                print(f"Already renamed: {name} -> {renamed_dict[name]}")
            erase_from_call_tree(name, call_tree)
            continue
             
def rename_funcs_from_call_tree(functions, call_tree, renamed_dict, csv_file, batch_mode, verbosity):
    print(f"Call tree size: {len(call_tree)}")
    blacklisted = set()
    while True:
        try:
            resolved = run_renaming_round(functions, call_tree, renamed_dict, blacklisted, csv_file, batch_mode, verbosity)
        except Exception as e:
            print(e)
            break
        print(f"Remaining call tree size: {len(call_tree)} Resolved {resolved}")
        if len(call_tree) == 0:
            break

    # Now do the replacements in all the functions:
    rename_functions_in_code(functions, renamed_dict, g_Verbosity)
    return renamed_dict

###

ANY_FUNC = re.compile(r'(func_[A-Za-z0-9_$]+)')
ANY_FUNC_CALLS = re.compile(r'(func_[A-Za-z0-9_$]+)\(')

def _browse_func_refs(func_name, func, called_set, calls_only=True, searched_meta_tag = None, searched_meta_value = None):
    added = 0
    indx = -1
    while True:
        indx = next_visible_line(func, indx)
        if indx is None:
            break
        line = func.code[indx].decompiled

        # filter out the lines that don't match expected metadata:
        if searched_meta_tag:
            meta = func.code[indx].get_metadata(searched_meta_tag)
            if not meta:
                continue
            if searched_meta_value and meta != searched_meta_value:
                continue

        #print (f"Func call in line: {line}")
        if calls_only:
            matches = ANY_FUNC_CALLS.findall(line)
        else:
            matches = ANY_FUNC.findall(line)
        for called_name in matches:
            if called_name == func_name:
                continue
            called_set.add(called_name)
            added += 1
    return added

def collect_call_set(functions, funcs_set: set[str], call_tree: dict[str, set[str]], calls_only=True):
    for func_name in funcs_set:
        if func_name not in functions.keys():
            continue
        func = functions[func_name]
        #skip function that are already mapped
        if func_name in call_tree.keys():
            continue
        # skip functions that have been hidden
        if func.visible == False:
            continue
        call_tree[func_name] = set()
        if not _browse_func_refs(func_name, func, call_tree[func_name], calls_only):
            continue
        collect_call_set(functions, call_tree[func_name], call_tree, calls_only)

def browse_functions_references(functions, calls_only=True):
    call_tree = {}
    start_name = get_start_function(functions)
    if not start_name:
        return
    if g_Verbosity > 1:
        print(f"Start func: {start_name}")
    init_func = functions[start_name]
    called_set = set()
    _browse_func_refs(start_name, init_func, called_set, calls_only)
    collect_call_set(functions, called_set, call_tree, calls_only)
    return call_tree
   

def initialize_llm_client(args, model_name):
    """Create the selected LLM client only when an API request is required."""
    api_key = args.api_key

    if args.llm_backend == "openai":
        if api_key is None:
            api_key = os.getenv("OPENAI_API_KEY")
        if api_key is None:
            print("OpenAI Key missing")
            return None

    if args.llm_backend == "anthropic":
        if api_key is None:
            api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key is None:
            print("Anthropic Key missing")
            return None

    temperature = args.temperature
    if temperature is None:
        temperature = DEFAULT_TEMPERATURES[args.llm_backend]

    return LLMClient(
        backend=args.llm_backend,
        model=model_name,
        ollama_url=args.ollama_url,
        api_key=api_key,
        temperature=temperature,
        thinking=args.thinking,
        max_tokens=args.max_tokens,
    )


def main():
    global g_Verbosity
    global llm

    parser = argparse.ArgumentParser(description="JSCeal deobfuscator: request the function name via LLM.")

    parser.add_argument('--inp', '-i', help="The input file name. It must be a serialized View8 output.", default=None, required=True)
    parser.add_argument('--out', '-o', help="The output file name.", default=None)
    parser.add_argument('--export_format', '-e', nargs='+', choices=['v8_opcode', 'translated', 'decompiled', 'serialized'], 
                        help="Specify the export format(s). Options are 'v8_opcode', 'translated', and 'decompiled'. Multiple options can be combined.", 
                        default=['serialized', 'decompiled'])
    parser.add_argument(
        '--csv', '-c',
        help=(
            "A CSV with renamed functions. If omitted, defaults to "
            "<input_name>.renamed_funcs.<basic|greedy>.<model>.csv."
        ),
        default=None,
        required=False,
    )
    parser.add_argument(
        '--func',
        help="Analyze exactly one function in detail. Requires its full function identifier.",
        default=None,
        required=False,
    )
    parser.add_argument(
        '--analysis-out',
        help="Optional Markdown output file for the detailed --func analysis.",
        default=None,
        required=False,
    )
    parser.add_argument('--greedy', help="Collect all function references (not only calls)", default=False, action="store_true", required=False)
    parser.add_argument('--verbosity', '-v', help="Verbosity level (0-3)", default=0, type=int, required=False)
    parser.add_argument('--bulk', help="Resolve functions in batches rather than one by one (faster, but may be less precise). Disabled for local models.", default=1, type=int, required=False)
    parser.add_argument(
        '--apply-csv-only',
        action='store_true',
        help=(
            "Apply names from --csv and export the result without building a call tree "
            "or making any LLM/API requests."
        ),
    )
    parser.add_argument("--llm_backend", choices=["anthropic", "ollama", "openai"], default="anthropic", help="Which LLM backend to use")
    parser.add_argument("--model", default=None, help="Model name (depends on backend)")
    parser.add_argument(
        "--temperature",
        type=float,
        default=None,
        help=(
            "Sampling temperature. If omitted, preserves the backend's current "
            "default: OpenAI 0, Ollama 0.1, and no explicit value for Anthropic."
        ),
    )
    parser.add_argument(
        "--thinking",
        choices=["disabled", "adaptive", "default"],
        default=DEFAULT_ANTHROPIC_THINKING,
        help=(
            "Anthropic thinking mode. 'disabled' (default) works on Sonnet 4.6 and "
            "Sonnet 5 alike and is required on Sonnet 5, where thinking is otherwise "
            "on by default. 'default' omits the field and uses the model's own default."
        ),
    )
    parser.add_argument(
        "--max_tokens",
        type=int,
        default=DEFAULT_ANTHROPIC_MAX_TOKENS,
        help="Anthropic max output tokens (includes thinking tokens when thinking is on).",
    )
    parser.add_argument("--api_key", default=None)
    parser.add_argument("--ollama_url", default="http://localhost:11434", help="Ollama base URL")
    args = parser.parse_args()

    if args.apply_csv_only and not args.csv:
        parser.error("--apply-csv-only requires --csv")
    if args.apply_csv_only and args.func:
        parser.error("--apply-csv-only cannot be combined with --func")
    if args.analysis_out and not args.func:
        parser.error("--analysis-out requires --func")
    if args.func and args.out:
        parser.error("--out exports View8 data and cannot be combined with --func; use --analysis-out")

    if not args.apply_csv_only:
        if args.max_tokens < 1:
            parser.error("--max_tokens must be a positive integer")

        if args.temperature is not None:
            if not math.isfinite(args.temperature) or args.temperature < 0:
                parser.error("--temperature must be a finite, non-negative number")
            if args.llm_backend == "anthropic":
                if args.temperature > 1:
                    parser.error("Anthropic temperature must be between 0 and 1")
                if resolve_model_name("anthropic", args.model).startswith(ANTHROPIC_FIXED_SAMPLING):
                    parser.error(
                        f"{resolve_model_name('anthropic', args.model)} does not accept an "
                        "explicit --temperature; omit it to use the model default"
                    )
    
    g_Verbosity = args.verbosity
    model_name = resolve_model_name(args.llm_backend, args.model)

    batch_mode = False
    if args.bulk:
        batch_mode = True
    if args.llm_backend == "ollama":
        batch_mode = False

    calls_only = True
    if args.greedy:
        calls_only = False

    if not os.path.isfile(args.inp):
        raise FileNotFoundError(f"The input file {args.inp} does not exist.")
    
    print(f"Reading from serialized, already decompiled input: {args.inp}")
    all_func = load_functions_from_file(args.inp)

    # Analyze exactly one selected function. Fuzzy matches are suggestions only;
    # they never trigger API requests.
    if args.func:
        func_name = args.func
        if func_name not in all_func:
            filtered = find_functions_by_name(all_func, func_name)
            print(f"Function {func_name} was not found. Found {len(filtered)} similar names:")
            for key in filtered.keys():
                print(key)
            return

        renamed_dict = {}
        if args.csv:
            print(f"Reading the CSV file for function-name context: \"{args.csv}\"...")
            if not read_from_csv(args.csv, renamed_dict, all_func):
                raise RuntimeError(f"Could not load applicable names from: {args.csv}")
            print(f"Loaded: {len(renamed_dict)} contextual names from: \"{args.csv}\"")

        llm = initialize_llm_client(args, model_name)
        if llm is None:
            return

        ai_start = time.perf_counter()
        analysis = analyze_func_via_ai(func_name, all_func[func_name], renamed_dict)
        elapsed_sec = time.perf_counter() - ai_start
        elapsed_min = elapsed_sec / 60.0

        print(analysis)
        if args.analysis_out:
            save_analysis(args.analysis_out, analysis)
            print(f"Saved detailed analysis to: \"{args.analysis_out}\"")

        print(f"Retrieved. Total time: {elapsed_sec} s. = {elapsed_min} min")
        print("Done.")
        return

    csv_file = args.csv
    if csv_file is None:
        input_stem, _ = os.path.splitext(args.inp)
        rename_mode = "greedy" if args.greedy else "basic"
        safe_model_name = sanitize_filename_component(model_name)
        csv_file = (
            f"{input_stem}.renamed_funcs."
            f"{rename_mode}.{safe_model_name}.csv"
        )

    renamed_dict = {}

    print(f"Reading the CSV file: \"{csv_file}\"...")
    csv_loaded = read_from_csv(csv_file, renamed_dict, all_func)
    if args.apply_csv_only and not csv_loaded:
        raise RuntimeError(f"Could not load applicable names from: {csv_file}")

    # The normal mode needs the original identifiers in its dependency graph.
    # Build that graph before applying cached names to the function corpus.
    call_tree = None
    if not args.apply_csv_only:
        call_tree = browse_functions_references(all_func, calls_only) or {}

    if csv_loaded:
        applied = rename_functions_in_code(all_func, renamed_dict, args.verbosity)
        print(f"Loaded: {len(renamed_dict)} names from: \"{csv_file}\"")
        if args.apply_csv_only:
            print(f"Applied: {applied} function names")
    else:
        print(f"Loaded: 0 names from: \"{csv_file}\"; continuing with an empty rename cache")

    if args.apply_csv_only:
        if args.out:
            export_to_file(args.out, all_func, args.export_format)
        print(f"Done.")
        return

    call_tree_size = len(call_tree)
    discard_resolved(call_tree, renamed_dict, args.verbosity)
    print(f"Initial call tree size: {call_tree_size}; after removing resolved: {len(call_tree)}")

    if len(call_tree.keys()):
        # Do not require an API key or construct a client until the loaded CSV
        # leaves unresolved functions that actually need an LLM request.
        llm = initialize_llm_client(args, model_name)
        if llm is None:
            return

        ai_start = time.perf_counter()
        
        rename_funcs_from_call_tree(all_func, call_tree, renamed_dict, csv_file, batch_mode, args.verbosity)
        
        elapsed_sec = time.perf_counter() - ai_start
        elapsed_min = elapsed_sec / 60.0
        print(f"Renaming finished. Total time: {elapsed_sec} s. = {elapsed_min} min")

        if renamed_dict and csv_file:
            print(f"Saved the renamed list to: \"{csv_file}\"")

    # The output may be saved into a file:
    if args.out:
        export_to_file(args.out, all_func, args.export_format)
    print("Done.")

if __name__ == "__main__":
    main()
