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

if (( $# > 1 )); then
    echo "Usage: $0 [source-directory]" >&2
    exit 1
fi

source_root="${1:-$SOURCE_DIR}"

if [[ ! -d "$source_root" ]]; then
    echo "Source directory not found: $source_root" >&2
    exit 1
fi
if ! command -v "$MD5SUM" >/dev/null 2>&1; then
    echo "MD5 command not found: $MD5SUM" >&2
    exit 1
fi

mkdir -p "$PAYLOADS_DIR"
found=0

while IFS= read -r -d '' file; do
    md5="$($MD5SUM "$file" | awk '{print $1}')"
    destination="$PAYLOADS_DIR/${md5}.jsc.br"
    cp -v -- "$file" "$destination"
    found=1
done < <(find "$source_root" -type f -name 'app.jsc' -print0)

if (( found == 0 )); then
    echo "No app.jsc files found under: $source_root" >&2
    exit 1
fi

echo "Payloads copied to: $PAYLOADS_DIR"
