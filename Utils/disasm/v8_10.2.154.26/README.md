# Building the V8 10 disassembler

## Target

The disassembler targets V8 code cache compatible with:

- V8 10.2.154.26
- x64

A pre-built version is available in the project releases.

# Building on Linux

The steps below describe the original Linux build procedure.

The Windows build uses the same patched V8 source, but requires additional
compatibility steps because this V8 branch expects an older Windows toolchain.
A Windows walk-through is provided below.

## Build environment

Required tools:

- `depot_tools`
- Ninja
- CMake
- LLVM/Clang
- Python 3
- Git

## Preparing the build tools

Clone `depot_tools`:

```bash
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
```

Add it to `PATH`, for example:

```bash
export PATH=/home/tester/code/depot_tools:$PATH
```

Install Ninja. If the system package does not work with the V8 build, it can be
built from source:

```bash
git clone https://github.com/ninja-build/ninja.git
cd ninja
git checkout release

./configure.py --bootstrap
cmake -Bbuild-cmake
cmake --build build-cmake
./build-cmake/ninja_test
```

Add Ninja to `PATH`, for example:

```bash
export PATH="/home/tester/code/depot_tools:/home/tester/code/ninja:$PATH"
```

## Building V8

Fetch V8 and check out the required version:

```bash
fetch v8
cd v8
git checkout 10.2.154.26
gclient sync
```

Apply the patches from this directory:

```bash
git apply <path>/v8_base_patch.diff
git apply <path>/v8_string_patch.diff
```

Generate the build configuration:

```bash
python3 tools/dev/v8gen.py x64.release
```

Edit:

```text
out.gn/x64.release/args.gn
```

and use:

```text
dcheck_always_on = false
is_component_build = false
is_debug = false
target_cpu = "x64"
use_custom_libcxx = false
v8_monolithic = true
v8_use_external_startup_data = false

v8_static_library = true
v8_enable_disassembler = true
v8_enable_object_print = true
v8_enable_pointer_compression = false
```

Build the V8 monolithic library:

```bash
ninja -C out.gn/x64.release v8_monolith
```

## Building v8dasm

Copy `v8dasm.cpp` from this directory to the root of the V8 source tree.

Build it with Clang:

```bash
clang++ v8dasm.cpp -g -std=c++20 \
  -Iinclude \
  -Lout.gn/x64.release/obj \
  -lv8_libbase \
  -lv8_libplatform \
  -lv8_monolith \
  -o v8dasm
```

The resulting file is the `v8dasm` ELF executable.

## Usage

```bash
./v8dasm app.jsc > app.jsc.disasm.txt
```

# Building on Windows

The Windows build uses the same V8 10.2.154.26 source and common disassembly
patches. Two additional Windows patches are provided (available in the `win` subdirectory):

- `v8_windows_build_monolith.diff` - adds the GN compatibility change needed for the Windows static-library build.
- `v8_windows_build_disasm.diff` - adds the GN target for `v8dasm.exe`.

The tested configuration uses:

- Visual Studio 2022 Community
- MSVC 14.29 (`v142`)
- x64 target
- V8 10.2.154.26

## Preparing the environment

Install Visual Studio 2022 with the **Desktop development with C++** workload and the MSVC 14.29 (`v142`) toolset. 
You can do it from the menu of Visual Studio: `Tools` -> `Get Tools and Features` and from `Individual components` select: `MSVC v142 - VS 2019 C++ x64/x86 build tools`.

Install/clone `depot_tools`. Example:

```
cd C:\src
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
```

Add it to `PATH`:

```powershell
$env:PATH = "C:\src\depot_tools;$env:PATH"
```

Make sure the Windows toolchain is set to `0`:

```powershell
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = "0"
```

Fetch V8 and check out the required version:

```powershell
fetch v8
cd v8
git checkout 10.2.154.26
gclient sync
```

## Selecting MSVC 14.29

Edit:

```text
build\toolchain\win\setup_toolchain.py
```

In the section that builds the argument list passed to `vcvarsall.bat`, add the
SDK/toolset selection before `_LoadEnvFromBat` is called:

```python
if target_store:
    args.append('store')

args.append('10.0.20348.0')
args.append('-vcvars_ver=14.29')

variables = _LoadEnvFromBat(args)
return _ExtractImportantEnvironment(variables)
```

The `10.0.20348.0` SDK version above is the version used in the tested setup.
It can be adjusted to one available on the system. The important compatibility
requirement for this V8 branch is selecting MSVC 14.29.

## Building the V8 monolith

Apply the common V8 disassembly patches and the Windows monolith-build patch:

```powershell
git apply <path>\v8_base_patch.diff
git apply <path>\v8_string_patch.diff
git apply <path>\v8_windows_build_monolith.diff
```

Patch files should retain LF line endings. It is recommended to enforce this in
the repository:

```gitattributes
*.diff text eol=lf
*.patch text eol=lf
```

Generate the build configuration:

```powershell
python3 tools/dev/v8gen.py x64.release
```

Edit:

```text
out.gn\x64.release\args.gn
```

and use:

```text
dcheck_always_on = false
is_component_build = false
is_debug = false
target_cpu = "x64"
use_custom_libcxx = false
v8_monolithic = true
v8_use_external_startup_data = false

v8_static_library = true
v8_enable_disassembler = true
v8_enable_object_print = true
v8_enable_pointer_compression = false

treat_warnings_as_errors = false
```

Regenerate the Ninja files:

```powershell
gn gen out.gn\x64.release
```

Build the monolithic library:

```powershell
ninja -C out.gn\x64.release v8_monolith
```

The resulting library is:

```text
out.gn\x64.release\obj\v8_monolith.lib
```

## Building v8dasm on Windows

Copy `v8dasm.cpp` from this directory into the V8 source tree:

```powershell
Copy-Item <path>\v8dasm.cpp .\samples\v8dasm.cpp
```

Apply the separate disassembler-target patch:

```powershell
git apply <path>\v8_windows_build_disasm.diff
```

Regenerate the build files:

```powershell
gn gen out.gn\x64.release
```

Build the disassembler:

```powershell
ninja -C out.gn\x64.release v8dasm
```

The resulting executable is:

```text
out.gn\x64.release\v8dasm.exe
```

## Usage on Windows

`v8dasm` accepts an optional output-file argument. On Windows, using it is
recommended instead of PowerShell stdout redirection:

```powershell
.\out.gn\x64.release\v8dasm.exe `
    app.jsc `
    app.jsc.disasm.txt
```

Avoid using PowerShell `>` redirection for the disassembly output. Depending on
the PowerShell version/environment, native stdout redirection may transcode the
file. Writing the output directly from `v8dasm.exe` preserves the byte-oriented
format expected by View8.

# Notes

The disassembler must be built for the V8 version compatible with the analyzed
code cache. This directory contains the patches prepared for V8 10.2.154.26.

`v8_base_patch.diff` is based on the disassembler patch from the
[j4k0xb View8 fork](https://github.com/j4k0xb/View8), adapted to apply to the
V8 10.2.154.26 source tree.

`v8_string_patch.diff` fixes string printing in V8 disassembly. V8's
`String::PrintUC16` operates on UTF-16 code units; the patch prevents non-ASCII
values from being passed through byte-oriented `std::isprint()` handling and
prints them using escaped representations instead.

`v8_windows_build_monolith.diff` contains the GN compatibility change needed
for the Windows static-library build.

`v8_windows_build_disasm.diff` adds the `v8dasm` GN executable target used by
the Windows build.

The V8 10 base patch also relaxes some serialized-code sanity checks used during
cache deserialization. Use this build only with code cache expected to be
compatible with V8 10.2.154.26.
