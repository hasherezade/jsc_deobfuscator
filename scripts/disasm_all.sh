#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${JSC_HELPER_CONFIG:-$SCRIPT_DIR/config.sh}"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Configuration file not found: $CONFIG_FILE" >&2
    exit 1
fi
# shellcheck source=config.sh
source "$CONFIG_FILE"

if [[ ! -x "$V8DASM" ]]; then
    echo "V8 disassembler is not executable: $V8DASM" >&2
    echo "Edit V8DASM in $CONFIG_FILE." >&2
    exit 1
fi

mkdir -p "$DISASSEMBLED_DIR"

if (( $# > 0 )); then
    files=("$@")
else
    shopt -s nullglob
    files=("$UNPACKED_DIR"/*.jsc)
    shopt -u nullglob
fi

if (( ${#files[@]} == 0 )); then
    echo "No .jsc files found in: $UNPACKED_DIR" >&2
    exit 1
fi

for file in "${files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "File not found: $file" >&2
        exit 1
    fi

    filename="$(basename -- "$file")"
    output_file="$DISASSEMBLED_DIR/${filename}.disasm.txt"
    temporary_file="${output_file}.tmp.$$"

    echo "Processing: $file"
    echo "Output:     $output_file"

    if "$V8DASM" "$file" > "$temporary_file"; then
        mv -- "$temporary_file" "$output_file"
    else
        status=$?
        rm -f -- "$temporary_file"
        echo "Disassembly failed for: $file" >&2
        exit "$status"
    fi
done

echo "All payloads disassembled successfully."
