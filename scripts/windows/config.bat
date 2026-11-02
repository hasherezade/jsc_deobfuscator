@echo off
rem Central configuration for the Windows batch helper scripts.
rem
rem Edit the defaults below to match your installation and workspace.
rem Environment variables that are already defined are preserved.

if not defined JSC_DEOBF_ROOT set "JSC_DEOBF_ROOT=%USERPROFILE%\jsc_deobfuscator"
if not defined VIEW8 set "VIEW8=%JSC_DEOBF_ROOT%\View8\view8.py"
if not defined DEOBF_ALL set "DEOBF_ALL=%JSC_DEOBF_ROOT%\deobf_all.py"
if not defined CHECK_UNRESOLVED set "CHECK_UNRESOLVED=%JSC_DEOBF_ROOT%\Utils\check_unresolved_decoder_references.py"
if not defined DECOMPRESS_JSC set "DECOMPRESS_JSC=%JSC_DEOBF_ROOT%\Utils\decompress-jsc.js"

rem Matching V8 disassembler. Adjust to the build matching the payload's V8 version.
if not defined V8DASM set "V8DASM=%USERPROFILE%\bin\v8dasm.exe"

rem External commands.
if not defined PYTHON set "PYTHON=python"
if not defined NODE set "NODE=node"
if not defined BROTLI set "BROTLI=brotli.exe"

rem Decompression backend:
rem   js      - use Utils\decompress-jsc.js through Node.js (recommended/default)
rem   brotli  - use an external brotli.exe CLI
if not defined DECOMPRESS_METHOD set "DECOMPRESS_METHOD=js"

rem Workspace. Relative workflow paths are anchored here.
if not defined WORK_DIR set "WORK_DIR=%CD%"
if not defined SOURCE_DIR set "SOURCE_DIR=%WORK_DIR%"
if not defined PAYLOADS_DIR set "PAYLOADS_DIR=%WORK_DIR%\payloads"
if not defined UNPACKED_DIR set "UNPACKED_DIR=%WORK_DIR%\unpacked"
if not defined DISASSEMBLED_DIR set "DISASSEMBLED_DIR=%WORK_DIR%\disassembled"
if not defined DECOMPILED_DIR set "DECOMPILED_DIR=%WORK_DIR%\decompiled"
if not defined DEOBFUSCATED_DIR set "DEOBFUSCATED_DIR=%WORK_DIR%\deobfuscated"
if not defined HARVEST_DIR set "HARVEST_DIR=%WORK_DIR%\harvest"
if not defined DEOBF_LOG set "DEOBF_LOG=%WORK_DIR%\deobf.log.txt"

if not defined HARVEST_PREFIX_LENGTH set "HARVEST_PREFIX_LENGTH=5"
exit /b 0
