# Building the V8 13 disassembler

## Target

The disassembler targets V8 code cache produced by:

- Node.js v24.11.0
- V8 13.6.233.10-node.28
- Windows x64

## Tested build environment

- Windows
- Visual Studio 2022
- VS Clang 19.1.5
- NASM 3.02
- Python 3.10.x
- Git >= 2.42.0

## Build

Clone Node.js and check out the required version:

```powershell
git clone https://github.com/nodejs/node.git
cd node
git checkout v24.11.0
```

Apply the V8 patches:

```powershell
git apply <path>\v8_base_patch.diff
git apply <path>\v8_string_patch.diff
```

Create:

```text
tools\v8dasm\
```

Copy:

```text
v8dasm_node24.cpp
```

to:

```text
tools\v8dasm\v8dasm_node24.cpp
```

Apply the Node build patch:

```powershell
git apply <path>\node_gyp_add_v8dasm.diff
```

Build:

```powershell
.\vcbuild.bat release x64 vs2022
```

The resulting executable is:

```text
Release\v8dasm.exe
```

## Usage

The disassembler expects a raw V8 code-cache file. It validates and consumes
the cache, then prints the contained V8 bytecode and related metadata without
executing the cached program.

Preferred usage on Windows:

```powershell
.\Release\v8dasm.exe app.jsc app.jsc.disasm.txt
```

Standard output can also be used:

```powershell
.\Release\v8dasm.exe app.jsc > app.jsc.disasm.txt
```

The explicit output-file argument is recommended under PowerShell to avoid
native-output transcoding.

## Notes

The older JSCeal generation could be handled with a disassembler built directly
from the matching V8 source. For the V8 13 generation, matching the V8 version
alone was not sufficient.

In our tests, the cache was accepted by the matching Windows Node.js runtime,
but rejected by an independently built Linux Node.js runtime using the same V8
version. Because of this, the disassembler is built inside the matching Node.js
source tree and uses Node's generated startup snapshot.

The analyzed samples use:

```text
--no-lazy
--no-flush-bytecode
```

The disassembler reproduces these flags.

The patches do not disable V8 code-cache validation. The cache must still be
accepted by the matching runtime before its contents are printed.
