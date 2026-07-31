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

if [[ ! -f "$VIEW8" ]]; then
    echo "View8 entry point not found: $VIEW8" >&2
    echo "Edit VIEW8 or JSC_DEOBF_ROOT in $CONFIG_FILE." >&2
    exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python command not found: $PYTHON" >&2
    exit 1
fi

mkdir -p "$DECOMPILED_DIR"

if (( $# > 0 )); then
    files=("$@")
else
    shopt -s nullglob
    files=("$DISASSEMBLED_DIR"/*.jsc.disasm.txt)
    shopt -u nullglob
fi

if (( ${#files[@]} == 0 )); then
    echo "No .jsc.disasm.txt files found in: $DISASSEMBLED_DIR" >&2
    exit 1
fi

for file in "${files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "File not found: $file" >&2
        exit 1
    fi

    filename="$(basename -- "$file")"
    base="${filename%.jsc.disasm.txt}"
    output_file="$DECOMPILED_DIR/${base}.dec.txt"

    echo "Processing: $file"
    echo "Output:     $output_file"

    "$PYTHON" "$VIEW8" \
        --input_format disassembled \
        --inp "$file" \
        --normalize \
        --out "$output_file" \
        --export_format decompiled serialized

done

echo "All files decompiled successfully."
