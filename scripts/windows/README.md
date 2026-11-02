# Helper scripts (Windows)

These Windows Batch scripts automate the JSCeal bulk-processing workflow on Windows
using only `cmd.exe` for orchestration.

The workflow uses the following workspace layout:

```text
payloads\
unpacked\
disassembled\
decompiled\
deobfuscated\
harvest\
```

The workspace defaults to the directory from which the scripts are launched.
Paths and commands can be changed in `config.bat` or overridden through
environment variables before launching a script.

## Requirements

The complete workflow requires:

- Windows with `cmd.exe`
- Python 3
- the JSC Deobfuscator repository
- View8 and its Python dependencies
- a `v8dasm.exe` build matching the V8 version of the payload
- for Brotli decompression, either:
  - Node.js and the repository helper `Utils\decompress-jsc.js` (**default**), or
  - an external `brotli.exe` CLI

The V8 code cache is version-specific. A disassembler built for one V8 version
is not expected to accept arbitrary caches produced by another version.

## Configuration

Edit `config.bat` before the first run. The most important variables are:

```bat
set "JSC_DEOBF_ROOT=%USERPROFILE%\jsc_deobfuscator"
set "V8DASM=%USERPROFILE%\bin\v8dasm.exe"
set "PYTHON=python"
set "NODE=node"
set "DECOMPRESS_METHOD=js"
```

The default paths derived from `JSC_DEOBF_ROOT` are:

```text
View8\view8.py
Utils\decompress-jsc.js
deobf_all.py
Utils\check_unresolved_decoder_references.py
```

You can also override a value for a single shell session before running a
script, for example:

```bat
set "V8DASM=D:\v8-10.2.154.26\v8dasm.exe"
disasm_all.bat
```

## Brotli decompression on Windows

`brotli.exe` is **not** a standard Windows command, so the batch scripts do not
assume that it exists.

### Option 1: use `Utils\decompress-jsc.js` (recommended)

The repository already contains a small Node.js helper that performs Brotli
decompression without executing the recovered V8 cache:

```text
Utils\decompress-jsc.js
```

This is the default Windows backend:

```bat
set "DECOMPRESS_METHOD=js"
set "NODE=node"
```

Install Node.js if it is not already present, make sure `node.exe` is on
`PATH`, and run:

```bat
unpack_all.bat
```

Internally the helper writes `<input>.decompressed.jsc`; `unpack_all.bat` moves
that result into the normal `unpacked\<sample>.jsc` location used by the rest
of the pipeline.

You can also call the helper directly:

```bat
node Utils\decompress-jsc.js payload.jsc.br
```

### Option 2: use the native Brotli CLI

Google's Brotli project provides the command-line implementation, but Windows
does not ship it by default. The official project documents building/installing
Brotli from source with CMake or installing it through vcpkg.

Project and releases:

- https://github.com/google/brotli
- https://github.com/google/brotli/releases

For example, with vcpkg:

```bat
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
vcpkg install brotli
```

Or build the official sources with CMake/Visual Studio and place the resulting
`brotli.exe` somewhere on `PATH` (or set `BROTLI` to its full path).

Then configure:

```bat
set "DECOMPRESS_METHOD=brotli"
set "BROTLI=C:\Tools\brotli\brotli.exe"
```

and run:

```bat
unpack_all.bat
```

## Typical workflow

From the directory that will contain the workspace folders:

```bat
copy_payloads.bat C:\path\to\extracted_samples
unpack_all.bat
disasm_all.bat
decompile_all.bat
deobfuscate_all.bat
collect_output.bat
```

The first step is optional. If you already have Brotli-compressed payloads,
place them in `payloads\` using the `.jsc.br` suffix and start from
`unpack_all.bat`.

## Scripts

### `copy_payloads.bat`

Recursively searches a source directory for files named `app.js*`, calculates
an MD5 using the built-in `certutil` utility, and copies each payload to:

```text
payloads\<md5>.jsc.br
```

Usage:

```bat
copy_payloads.bat C:\samples\campaign
```

This helper targets the Brotli-only JSCeal generation represented by the
original batch workflow. Newer JSCeal variants may add encryption before the
Brotli layer; those payloads must be decrypted/extracted first.

### `unpack_all.bat`

Decompresses all:

```text
payloads\*.jsc.br
```

into:

```text
unpacked\*.jsc
```

The backend is selected with `DECOMPRESS_METHOD` in `config.bat`:

```text
js       Utils\decompress-jsc.js via Node.js
brotli   external brotli.exe
```

You can also pass one or more files explicitly:

```bat
unpack_all.bat payloads\a.jsc.br payloads\b.jsc.br
```

### `disasm_all.bat`

Runs the configured matching V8 disassembler over `unpacked\*.jsc` and writes:

```text
disassembled\<sample>.jsc.disasm.txt
```

The output-file argument of `v8dasm.exe` is used directly. This avoids Windows
console/redirection text transformations and preserves the byte-oriented text
format expected by View8.

Explicit files are also supported:

```bat
disasm_all.bat unpacked\sample.jsc
```

### `decompile_all.bat`

Runs View8 with:

```text
--input_format disassembled
--normalize
--export_format decompiled serialized
```

The human-readable output is written under `decompiled\`; View8 also creates
the serialized `.dec.pkl` files consumed by the deobfuscator.

### `deobfuscate_all.bat`

Processes `decompiled\*.dec.pkl` with `deobf_all.py` and writes results under:

```text
deobfuscated\
```

A fresh batch log is written to:

```text
deobf.log.txt
```

Because plain `cmd.exe` has no built-in equivalent of Unix `tee`, detailed
Python/deobfuscator output is redirected to this log rather than duplicated to
both the console and log file.

### `collect_output.bat`

Collects each sample's resolved-functions CSV and, when present, its recovered
string listing into `harvest\` directories grouped by a short sample prefix.
The prefix length is controlled by:

```bat
set "HARVEST_PREFIX_LENGTH=5"
```

## Notes

- Run the scripts from `cmd.exe`; they do not require PowerShell.
- Quote paths containing spaces when passing explicit arguments.
- The scripts stop on the first failed sample rather than silently continuing.
- `v8dasm.exe` must match the V8 version of the cached bytecode.
- The Brotli-only workflow does not decrypt newer AES-encrypted JSCeal payloads.
  Recover the raw Brotli/code-cache layer first and then enter this pipeline.
