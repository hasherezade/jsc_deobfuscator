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

if ! command -v "$BROTLI" >/dev/null 2>&1; then
    echo "Brotli command not found: $BROTLI" >&2
    exit 1
fi

mkdir -p "$UNPACKED_DIR"

if (( $# > 0 )); then
    files=("$@")
else
    shopt -s nullglob
    files=("$PAYLOADS_DIR"/*.jsc.br)
    shopt -u nullglob
fi

if (( ${#files[@]} == 0 )); then
    echo "No .jsc.br files found in: $PAYLOADS_DIR" >&2
    exit 1
fi

for file in "${files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "File not found: $file" >&2
        exit 1
    fi

    filename="$(basename -- "$file")"
    output_file="$UNPACKED_DIR/${filename%.br}"

    echo "Processing: $file"
    echo "Output:     $output_file"
    "$BROTLI" -d -k -f "$file" -o "$output_file"
done

echo "All payloads decompressed successfully."
