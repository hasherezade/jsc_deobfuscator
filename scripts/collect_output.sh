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

if [[ ! "$HARVEST_PREFIX_LENGTH" =~ ^[1-9][0-9]*$ ]]; then
    echo "HARVEST_PREFIX_LENGTH must be a positive integer." >&2
    exit 1
fi

mkdir -p "$HARVEST_DIR"

shopt -s nullglob
csv_files=("$DECOMPILED_DIR"/*.dec.resolved_funcs.csv)
shopt -u nullglob

if (( ${#csv_files[@]} == 0 )); then
    echo "No resolved-functions CSV files found in: $DECOMPILED_DIR" >&2
    exit 1
fi

for csv in "${csv_files[@]}"; do
    base="$(basename -- "$csv")"
    sample="${base%.dec.resolved_funcs.csv}"
    prefix="${sample:0:HARVEST_PREFIX_LENGTH}"
    output_dir="$HARVEST_DIR/$prefix"

    mkdir -p "$output_dir"
    cp -- "$csv" "$output_dir/"

    strings_file="$DEOBFUSCATED_DIR/${sample}.deobf.txt.strings.txt"
    if [[ -f "$strings_file" ]]; then
        cp -- "$strings_file" "$output_dir/"
    else
        echo "Warning: missing $strings_file" >&2
    fi
done

echo "Collected output under: $HARVEST_DIR"
