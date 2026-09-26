# Building the V8 10 disassembler

## Target

The disassembler targets V8 code cache compatible with:

- V8 10.2.154.26
- x64

A pre-built version is available in the project releases.

## Build environment

The steps below describe building on Linux, which was the tested configuration. 
A Windows build should work analogously, but was not tested as part of this project.

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

## Notes

The disassembler must be built for the V8 version compatible with the analyzed
code cache. This directory contains the patches prepared for V8 10.2.154.26.

`v8_base_patch.diff` is based on the disassembler patch from the
[j4k0xb View8 fork](https://github.com/j4k0xb/View8), adapted to apply to the
V8 10.2.154.26 source tree.

`v8_string_patch.diff` fixes string printing in V8 disassembly. V8's
`String::PrintUC16` operates on UTF-16 code units; the patch prevents non-ASCII
values from being passed through byte-oriented `std::isprint()` handling and
prints them using escaped representations instead.

The V8 10 base patch also relaxes some serialized-code sanity checks used during
cache deserialization. Use this build only with code cache expected to be
compatible with V8 10.2.154.26.
