# JSC Deobfuscator

This tool is dedicated to statically deobfuscating compiled V8 JavaScript bytecode that was protected with [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator).

It operates on pseudocode produced by [View8](https://github.com/suleram/View8), rather than on the original JavaScript source. The project was developed and tested on JSCeal payloads.

The filters are pattern-driven and intended primarily as a research toolkit and reference implementation. The tool is **not** a general-purpose JavaScript deobfuscator, does not reconstruct the original source code, and does not produce runnable JavaScript. Its output remains View8 pseudocode intended for static inspection, searching, comparison, and function-tree export.

📖 [Read Wiki](https://github.com/hasherezade/jsc_deobfuscator/wiki)

## Safety notes

- View8 serialized files use Python `pickle`. Loading a malicious or untrusted `.pkl` file can execute code. Only load serialized files that you generated locally with View8.
- LLM-generated function names are hypotheses. Verify every important name against the function body, strings, APIs, paths, and data flow.

## Requirements

- Python 3.10 or newer;
- Python dependencies from `requirements.txt`;
- a V8 disassembler compatible with the exact V8 version used by the payload;
- the `brotli` command-line utility for the Linux batch unpacking workflow;
- Node.js only when using the included Brotli decompression fallback;
- an API key or a reachable local model server when generating new LLM-assisted names. Applying an existing rename CSV does not require an LLM backend.

Create an isolated Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

The OpenAI backend in `deobf_ai.py` additionally requires the OpenAI Python package:

```bash
python3 -m pip install openai
```

The Anthropic backend uses the HTTP API through `requests`. The Ollama backend expects a reachable Ollama server.

## Deobfuscating JSCeal

### 1. Decompress the payload

The original JSCeal `app.jsc` payload is Brotli-compressed. On Linux, it can be decompressed with the `brotli` utility:

```bash
brotli -d app.jsc -o app.decompressed.jsc
```

The batch workflow under `scripts/` performs this step with `scripts/unpack_all.sh`.

On Windows, or when the `brotli` command-line utility is unavailable, the included Node.js helper can be used as a fallback. It only decompresses the input and does not execute it:

```powershell
node Utils/decompress-jsc.js app.jsc
```

It writes:

```text
app.jsc.decompressed.jsc
```

### 2. Disassemble the V8 code cache

V8 code cache is version-specific. Use a disassembler built for the same V8 version as the payload.

The JSCeal samples used during development were based on V8 `10.2.154.26`. Default disassemblers from an unrelated V8 build will not work correctly.

The source tree contains the disassembler source and required V8 patches under:

```text
Utils/disasm/v8dasm.cpp
Utils/disasm/patches/
```

A prebuilt Linux binary is distributed with the project release, while the source tree contains the source and patches needed to rebuild it. Detailed description is available on the project [Wiki](https://github.com/hasherezade/jsc_deobfuscator/wiki/Building-V8-Disasm). After obtaining or building the matching `v8dasm`, run:

```bash
/path/to/v8dasm app.decompressed.jsc > app.jsc.disasm.txt
```

### 3. Decompile the disassembly with View8

Feed the disassembled file to `view8.py` and produce both serialized output for further processing and human-readable pseudocode:

```bash
mkdir -p decompiled

python3 View8/view8.py \
  --input_format disassembled \
  --inp app.jsc.disasm.txt \
  --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
```

This produces:

```text
decompiled/app.dec.txt
decompiled/app.dec.pkl
```

The `--normalize` option makes generated function identifiers reproducible across repeated disassembly and decompilation runs.

### 4. Apply all deobfuscation passes

There are separate filters for the individual obfuscation layers. They can be applied together to the serialized View8 output with `deobf_all.py`:

```bash
mkdir -p deobfuscated

python3 deobf_all.py \
  --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

The default string filter is variant 2, used by the majority of analyzed JSCeal payloads. To select the simpler string scheme explicitly, add:

```text
--str_deobf 1
```

Typical outputs are:

```text
deobfuscated/app.deobf.txt
deobfuscated/app.deobf.pkl
deobfuscated/app.deobf.txt.strings.txt
decompiled/app.dec.resolved_funcs.csv
```

The resolved-functions CSV is a sample-specific cache. When it is absent, the string pass recovers the required decoder configuration, writes the CSV, and continues deobfuscating strings in the same run. Later runs reuse the cache and are normally faster.

Do not reuse a resolved-functions CSV with a different decompiled payload.

### 5. Rename functions with an LLM

After all structural deobfuscation filters have been applied, `deobf_ai.py` can propose names that describe function behavior. It supports Anthropic, OpenAI, and Ollama backends.

Pass the model explicitly so that runs remain reproducible.

#### Anthropic

```bash
export ANTHROPIC_API_KEY='...'

python3 deobf_ai.py \
  --inp deobfuscated/app.deobf.pkl \
  --out deobfuscated/app.renamed.txt \
  --llm_backend anthropic \
  --model '<model-id>' \
  --export_format decompiled serialized
```

#### OpenAI

```bash
export OPENAI_API_KEY='...'

python3 deobf_ai.py \
  --inp deobfuscated/app.deobf.pkl \
  --out deobfuscated/app.renamed.txt \
  --llm_backend openai \
  --model '<model-id>' \
  --export_format decompiled serialized
```

#### Ollama

```bash
python3 deobf_ai.py \
  --inp deobfuscated/app.deobf.pkl \
  --out deobfuscated/app.renamed.txt \
  --llm_backend ollama \
  --model '<local-model>' \
  --ollama_url http://localhost:11434 \
  --export_format decompiled serialized
```

In the default mode, the renamer builds a direct-call tree starting from the entry function and renames only functions reached through calls. Add `--greedy` to include all visible function references, including callbacks and assigned handlers.

#### Resume from a rename CSV

The generated two-column CSV acts as a cache and allows an interrupted run to continue. Select an existing cache explicitly with `--csv`:

```bash
python3 deobf_ai.py \
  --inp deobfuscated/app.deobf.pkl \
  --out deobfuscated/app.renamed.txt \
  --csv deobfuscated/app.deobf.renamed_funcs.greedy.example-model.csv \
  --llm_backend anthropic \
  --model '<model-id>' \
  --greedy \
  --export_format decompiled serialized
```

In the normal mode, the CSV is treated as a potentially partial cache. Cached names are applied first, functions already covered by the cache are removed from the selected call or reference tree, and the LLM is invoked only for functions that remain unresolved. If the CSV completely covers that tree, no API key or LLM connection is required. If it covers only part of the tree, the selected backend is initialized and the newly generated mappings are appended to the same CSV.

Use the same tree mode that was used when the CSV was created. A CSV produced from a `--greedy` run normally needs `--greedy` again if the goal is to continue that run rather than only reuse the direct-call subset.

#### Apply an existing CSV without an LLM

Use `--apply-csv-only` when the CSV already contains the labels you want to apply, including reviewed, edited, imported, or rebased mappings:

```bash
python3 deobf_ai.py \
  --inp deobfuscated/app.deobf.pkl \
  --out deobfuscated/app.renamed.txt \
  --csv renamed_functions.normalized.csv \
  --apply-csv-only \
  --export_format decompiled serialized
```

This mode:

- requires an explicit `--csv`;
- loads and applies the matching names without constructing a call or reference tree;
- makes no LLM or API requests and does not require an API key;
- does not append new rows to the CSV;
- cannot be combined with `--func`.

Rows whose original function identifier does not exist in the input are ignored. The command fails when the CSV contains no mappings applicable to the loaded file.

#### Analyze one function in detail

Use `--func` with the exact full function identifier to request a focused semantic analysis of one deobfuscated function:

```bash
python3 deobf_ai.py \
  --inp deobfuscated/app.deobf.pkl \
  --func func_example_0x100001234 \
  --llm_backend anthropic \
  --model '<model-id>'
```

The analysis includes a proposed name, behavior summary, inputs and return value, side effects, step-by-step logic, cleaned pseudocode, supporting evidence, and unresolved uncertainties. Supplying `--csv` adds cached semantic names as context for references inside the selected function without modifying the loaded corpus. Use `--analysis-out analysis/function.md` to save the report as Markdown. Fuzzy matches are printed only as suggestions; the requested function identifier must match exactly.

Use `--help` for options controlling temperature, batching, Anthropic thinking mode, token limits, and custom CSV paths.

LLM-generated names are navigation aids, not evidence. Always verify them against the deobfuscated body.

### 6. Work with the output

Deobfuscated JSCeal output is usually very large. Load the serialized output back into View8 and split it into smaller function trees.

At this stage, add `--scope 0`. Scope propagation has already been performed by the deobfuscator, and repeating it may propagate values incorrectly.

A tree based on declarer relationships:

```bash
python3 View8/view8.py \
  --input_format serialized \
  --inp deobfuscated/app.deobf.pkl \
  --out trees/declarers \
  --export_format decompiled \
  --tree start \
  --scope 0
```

A compact direct-call overview:

```bash
python3 View8/view8.py \
  --input_format serialized \
  --inp deobfuscated/app.deobf.pkl \
  --out trees/calls \
  --export_format decompiled \
  --tree start \
  --scope 0 \
  --split_mode calls \
  --inline_depth 1 \
  --split_depth 5
```

A broader reference tree, including callbacks and assigned handlers:

```bash
python3 View8/view8.py \
  --input_format serialized \
  --inp deobfuscated/app.deobf.pkl \
  --out trees/references \
  --export_format decompiled \
  --tree start \
  --scope 0 \
  --split_mode references \
  --inline_depth 1 \
  --split_depth 3
```

## String deobfuscation

Different JSC files may use different string-obfuscation modes.

The simplest observed mode uses index shifting and is handled by `deobf_str1.py`. The most common JSCeal mode uses Base64, RC4, chunked strings, and transformed indexes; it is handled by `deobf_str2.py`.

The complete pipeline selects variant 2 by default. The filters can also be run independently for testing.

### `deobf_str2.py`

Use `--help` to display all available modes and options:

```bash
python3 deobf_str2.py --help
```

A direct string-deobfuscation run can be started with:

```bash
python3 deobf_str2.py \
  --inp decompiled/app.dec.pkl \
  --out work/app.strings.txt \
  --export_format decompiled serialized
```

During the run, the script identifies the string-decoder functions, loads any valid cached configurations, resolves missing ones, saves the resulting CSV, and decodes the strings. A second run is not required.

When `deobf_str2.py` is used directly, its default CSV name is `resolved_funcs.csv`. Select a sample-specific path with `--csv` or `-c`:

```bash
python3 deobf_str2.py \
  --inp decompiled/app.dec.pkl \
  --out work/app.strings.txt \
  --csv decompiled/app.dec.resolved_funcs.csv \
  --export_format decompiled serialized \
  --verbosity 1
```

When chaining individual filters, preserve serialized output between stages so that later passes can continue operating on View8 objects.

## Default pipeline

`deobf_all.py` applies the following stages in order:

1. local-variable and scope-value propagation;
2. string reconstruction;
3. scope and dictionary propagation;
4. control-flow unflattening;
5. refresh of strings exposed by unflattening;
6. proxy-call and operation-wrapper replacement;
7. global-value propagation;
8. conservative local-temporary cleanup;
9. final refresh of newly exposed string-decoder calls.

LLM-assisted function renaming is optional and is run separately after structural deobfuscation.

## Batch helper scripts

The repository includes a complete helper workflow under `scripts/`. All scripts are kept in one directory and source the same centralized configuration.

```text
scripts/config.sh                         shared tool and workspace paths
scripts/copy_payloads.sh                  collect and MD5-name JSCeal app.jsc files
scripts/unpack_all.sh                     Brotli decompression
scripts/disasm_all.sh                     batch V8 disassembly
scripts/decompile_all.sh                  batch View8 decompilation
scripts/deobfuscate_all.sh                batch deobfuscation with a combined log
scripts/run_unattended.sh                 detached deobfuscation and validation
scripts/collect_output.sh                 collect decoder caches and string listings
```

The supplied `scripts/config.sh` contains paths from an example environment:

```bash
JSC_DEOBF_ROOT="$HOME/jsc_deobfuscator"
V8DASM="$HOME/code/v8/v8dasm"
```

Edit that file once to configure the installation path, matching V8 disassembler, workspace directories, external commands, log paths, and harvest layout. The workspace defaults to the directory from which the helper script is launched.

Every value can also be overridden through an environment variable. `JSC_HELPER_CONFIG` can select a different configuration file.

A typical batch run is:

```bash
scripts/copy_payloads.sh
scripts/unpack_all.sh
scripts/disasm_all.sh
scripts/decompile_all.sh
scripts/deobfuscate_all.sh
scripts/collect_output.sh
```

The scripts preserve conventions used for the JSCeal corpus, including treating discovered `app.jsc` files as Brotli-compressed payloads and naming them by MD5. Review [`scripts/README.md`](scripts/README.md) before applying the workflow to unrelated samples.

### Unattended corpus run

For a long batch, `scripts/run_unattended.sh` launches deobfuscation with `nohup`, writes timestamped log, PID, and status files, and validates each generated output for unresolved references to cached string-decoder functions:

```bash
scripts/run_unattended.sh
```

Selected samples can be supplied explicitly:

```bash
scripts/run_unattended.sh \
  decompiled/sample1.dec.pkl \
  decompiled/sample2.dec.pkl
```

## Repository layout

```text
View8/                         View8 decompiler and function-tree exporter
Utils/decompress-jsc.js        Brotli decompression fallback for Windows
Utils/disasm/v8dasm.cpp        V8 disassembler source
Utils/disasm/patches/          V8 patches required by the disassembler
Utils/check_unresolved_decoder_references.py
                               output validation helper
deobf_all.py                   complete default deobfuscation pipeline
deobf_str1.py                  simple string-index-shift filter
deobf_str2.py                  RC4/Base64 string filter with index recovery
deobf_scope2.py                scope and dictionary propagation
deobf_unflattener.py           control-flow unflattening
deobf_replace_ops.py           proxy and operation-wrapper replacement
deobf_globals.py               global propagation
deobf_inline_temporaries.py    conservative final cleanup
deobf_ai.py                    optional LLM-assisted function renaming
scripts/                       configurable batch and validation helpers
```

## Running individual filters

Every major pass can be executed separately for testing. Run the selected script with `--help` to see its complete interface:

```bash
python3 deobf_str1.py --help
python3 deobf_str2.py --help
python3 deobf_scope2.py --help
python3 deobf_unflattener.py --help
python3 deobf_replace_ops.py --help
python3 deobf_globals.py --help
python3 deobf_inline_temporaries.py --help
```

## Known limitations

- The deobfuscation logic recognizes patterns observed in JSCeal and related `javascript-obfuscator` output. New variants may require additional detectors or transformations.
- Ambiguous control flow is deliberately left unchanged rather than rewritten speculatively.
- View8 output is pseudocode and may use notation that is not valid JavaScript.
- V8 code-cache and disassembly formats are tied to specific V8 versions.
- String-decoder caches are sample-specific.
- LLM-assisted names can be wrong even when they sound plausible.

## Validation

The pipeline has been regression-tested against the JSCeal corpus used in the accompanying research. Basic release checks include:

```bash
python3 -m compileall -q .
python3 deobf_all.py --help
python3 deobf_str2.py --help
python3 deobf_ai.py --help
python3 View8/view8.py --help
```

For each corpus sample, verify that the run:

- completes successfully;
- writes both `.pkl` and `.txt` output;
- produces the decoded-string listing;
- produces or reuses the expected resolved-functions CSV;
- leaves no unresolved decoder references in visible output.

The unattended helper script automates the final decoder-reference validation.

## Credits

- View8 was originally created by Moshe Marelus.
- The deobfuscation pipeline was developed through analysis of JSCeal.
- String and control-flow transformations target patterns generated by `javascript-obfuscator`.

## License

The JSC Deobfuscator source code authored for this project is licensed under
the GNU General Public License, version 2 or (at your option) any later version
(`GPL-2.0-or-later`). See [LICENSE](LICENSE) for the complete license text.

Copyright (C) 2026 Aleksandra "Hasherezade" Doniec @ Check Point Research.

The `View8` submodule is a separate project. Third-party-derived disassembler
material under `Utils/disasm/` retains its existing provenance and is not
relicensed by the copyright notice above.
