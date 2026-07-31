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

if [[ ! -f "$DEOBF_ALL" ]]; then
    echo "Deobfuscator entry point not found: $DEOBF_ALL" >&2
    echo "Edit DEOBF_ALL or JSC_DEOBF_ROOT in $CONFIG_FILE." >&2
    exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python command not found: $PYTHON" >&2
    exit 1
fi

mkdir -p "$DEOBFUSCATED_DIR"
mkdir -p "$(dirname -- "$DEOBF_LOG")"
: > "$DEOBF_LOG"

if (( $# > 0 )); then
    files=("$@")
else
    shopt -s nullglob
    files=("$DECOMPILED_DIR"/*.dec.pkl)
    shopt -u nullglob
fi

if (( ${#files[@]} == 0 )); then
    echo "No .dec.pkl files found in: $DECOMPILED_DIR" \
        | tee -a "$DEOBF_LOG" >&2
    exit 1
fi

timestamp() {
    "$PYTHON" -c 'from datetime import datetime; print(datetime.now().astimezone().isoformat(timespec="seconds"))'
}

for file in "${files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "File not found: $file" \
            | tee -a "$DEOBF_LOG" >&2
        exit 1
    fi

    filename="$(basename -- "$file")"
    base="${filename%.dec.pkl}"
    output_file="$DEOBFUSCATED_DIR/${base}.deobf.txt"

    {
        echo "============================================================"
        echo "Processing: $file"
        echo "Output:     $output_file"
        echo "Started:    $(timestamp)"

        "$PYTHON" -u "$DEOBF_ALL" \
            --inp "$file" \
            --out "$output_file"

        echo "Finished:   $file"
        echo "Completed:  $(timestamp)"
    } 2>&1 | tee -a "$DEOBF_LOG"
done

echo "All files deobfuscated successfully." | tee -a "$DEOBF_LOG"
