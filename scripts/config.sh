#!/usr/bin/env bash

# Central configuration for the helper scripts.
#
# The tool paths below represent an example environment.
# Edit this file once if your installation or workspace differs.
# Every value may also be overridden through an environment variable.

# JSC Deobfuscator installation.
: "${JSC_DEOBF_ROOT:=$HOME/jsc_deobfuscator}"
: "${VIEW8:=$JSC_DEOBF_ROOT/View8/view8.py}"
: "${DEOBF_ALL:=$JSC_DEOBF_ROOT/deobf_all.py}"
: "${CHECK_UNRESOLVED:=$JSC_DEOBF_ROOT/Utils/check_unresolved_decoder_references.py}"

# Matching V8 disassembler. This default is provided as an example setup.
: "${V8DASM:=$HOME/code/v8/v8dasm}"

# External commands.
: "${PYTHON:=python3}"
: "${BROTLI:=brotli}"
: "${MD5SUM:=md5sum}"

# Workspace. Relative workflow paths are anchored here.
# By default, this is the directory from which a helper script is launched.
: "${WORK_DIR:=$PWD}"
: "${SOURCE_DIR:=$WORK_DIR}"
: "${PAYLOADS_DIR:=$WORK_DIR/payloads}"
: "${UNPACKED_DIR:=$WORK_DIR/unpacked}"
: "${DISASSEMBLED_DIR:=$WORK_DIR/disassembled}"
: "${DECOMPILED_DIR:=$WORK_DIR/decompiled}"
: "${DEOBFUSCATED_DIR:=$WORK_DIR/deobfuscated}"
: "${HARVEST_DIR:=$WORK_DIR/harvest}"
: "${DEOBF_LOG:=$WORK_DIR/deobf.log.txt}"
: "${RUN_LOG_DIR:=$WORK_DIR/logs}"

# collect_output.sh groups artifacts by this many leading hash characters.
: "${HARVEST_PREFIX_LENGTH:=5}"
