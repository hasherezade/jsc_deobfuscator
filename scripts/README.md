# Helper scripts

The helper scripts automate the JSCeal research workflow and batch processing
with View8 and JSC Deobfuscator. All scripts and their shared configuration are
kept in this directory.

## Configuration

Edit `config.sh` before the first run. The supplied defaults reproduce the
example environment:

```bash
JSC_DEOBF_ROOT="$HOME/jsc_deobfuscator"
V8DASM="$HOME/code/v8/v8dasm"
```

The workspace defaults to the directory from which a script is launched. The
following directories are created below it as needed:

```text
payloads/
unpacked/
disassembled/
decompiled/
deobfuscated/
harvest/
```

The configuration also centralizes the Python, Brotli and MD5 commands, output
directories, the decoder-reference checker, and log paths.

A value may be overridden for one invocation without editing the file:

```bash
V8DASM=/opt/v8/v8dasm scripts/disasm_all.sh
WORK_DIR=/data/jsceal scripts/decompile_all.sh
```

A completely different configuration file can be selected with
`JSC_HELPER_CONFIG`:

```bash
JSC_HELPER_CONFIG=/data/jsceal/config.sh scripts/deobfuscate_all.sh
```

## Scripts

### `copy_payloads.sh`

Searches `SOURCE_DIR` recursively for files named `app.jsc`, calculates each
MD5, and copies it to:

```text
payloads/<md5>.jsc.br
```

This naming assumes that the discovered JSCeal payloads are Brotli-compressed.
An alternative source directory may be passed as the only argument.

### `unpack_all.sh`

Decompresses all `payloads/*.jsc.br` files into `unpacked/` using the
`BROTLI` command configured in `config.sh`. One or more explicit input files
may be passed as arguments. This is the normal decompression step for the
Linux batch workflow.

### `disasm_all.sh`

Disassembles all `unpacked/*.jsc` files with the configured matching V8
binary and writes `disassembled/*.jsc.disasm.txt`. Partial output is removed
when the disassembler fails.

### `decompile_all.sh`

Decompiles all `disassembled/*.jsc.disasm.txt` files with View8 and writes:

```text
decompiled/<sample>.dec.txt
decompiled/<sample>.dec.pkl
```

### `deobfuscate_all.sh`

Deobfuscates all `decompiled/*.dec.pkl` files and writes results under
`deobfuscated/`. A combined log is written to the configured `DEOBF_LOG` path.

### `run_unattended.sh`

Starts a detached batch deobfuscation run with `nohup`, then validates every
corresponding output with `check_unresolved_decoder_references.py`. It accepts
the same optional `.dec.pkl` file list as `deobfuscate_all.sh`; without
arguments, it processes the configured `DECOMPILED_DIR`.

A run creates three timestamped files under `RUN_LOG_DIR` (default: `logs/`):

```text
jsc-deobfuscation-run-<timestamp>.log
jsc-deobfuscation-run-<timestamp>.pid
jsc-deobfuscation-run-<timestamp>.status
```

The status file is written when processing ends. `0` means that deobfuscation
produced every expected output and no unresolved decoder reference was found.
A nonzero value indicates a command, output-generation, or validation failure.
Existing text outputs are moved aside before the run so that stale files cannot
hide a failed deobfuscation. They are restored when a replacement is not
produced and retained beside the run log when further inspection is useful.

The consolidated run log can be followed with `tail -f`. The normal
`DEOBF_LOG` written by `deobfuscate_all.sh` is retained as well.

### `collect_output.sh`

Collects each resolved-functions CSV and its decoded-string listing under
`harvest/<hash-prefix>/`. The default prefix length is five characters and can
be changed with `HARVEST_PREFIX_LENGTH` in `config.sh`.

## Typical workflow

Run the scripts from the workspace containing the research corpus:

```bash
/path/to/jsc_deobfuscator/scripts/copy_payloads.sh
/path/to/jsc_deobfuscator/scripts/unpack_all.sh
/path/to/jsc_deobfuscator/scripts/disasm_all.sh
/path/to/jsc_deobfuscator/scripts/decompile_all.sh
/path/to/jsc_deobfuscator/scripts/deobfuscate_all.sh
/path/to/jsc_deobfuscator/scripts/collect_output.sh
```

The batch scripts also accept one or more explicit input files, making it
possible to rerun only selected samples.

## Unattended deobfuscation and validation

For a long corpus run, use the detached launcher instead of invoking
`deobfuscate_all.sh` directly:

```bash
/path/to/jsc_deobfuscator/scripts/run_unattended.sh
```

Selected samples can be supplied explicitly:

```bash
/path/to/jsc_deobfuscator/scripts/run_unattended.sh \
    decompiled/sample1.dec.pkl \
    decompiled/sample2.dec.pkl
```
