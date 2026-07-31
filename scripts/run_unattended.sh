#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${JSC_HELPER_CONFIG:-$SCRIPT_DIR/config.sh}"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Configuration file not found: $CONFIG_FILE" >&2
    exit 1
fi
CONFIG_FILE="$(cd -- "$(dirname -- "$CONFIG_FILE")" && pwd)/$(basename -- "$CONFIG_FILE")"
# shellcheck source=config.sh
source "$CONFIG_FILE"

if [[ ! -x "$SCRIPT_DIR/deobfuscate_all.sh" ]]; then
    echo "Batch deobfuscation script not executable: $SCRIPT_DIR/deobfuscate_all.sh" >&2
    exit 1
fi
if [[ ! -f "$CHECK_UNRESOLVED" ]]; then
    echo "Decoder-reference checker not found: $CHECK_UNRESOLVED" >&2
    echo "Edit CHECK_UNRESOLVED or JSC_DEOBF_ROOT in $CONFIG_FILE." >&2
    exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python command not found: $PYTHON" >&2
    exit 1
fi

if (( $# > 0 )); then
    input_files=("$@")
else
    shopt -s nullglob
    input_files=("$DECOMPILED_DIR"/*.dec.pkl)
    shopt -u nullglob
fi

if (( ${#input_files[@]} == 0 )); then
    echo "No .dec.pkl files found in: $DECOMPILED_DIR" >&2
    exit 1
fi
for file in "${input_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "File not found: $file" >&2
        exit 1
    fi
done

mkdir -p "$RUN_LOG_DIR"
stamp="$($PYTHON -c 'from datetime import datetime; print(datetime.now().strftime("%Y-%m-%dT%H%M%S"))')"
run_base="$RUN_LOG_DIR/jsc-deobfuscation-run-$stamp"
run_log="$run_base.log"
pid_file="$run_base.pid"
status_file="$run_base.status"
backup_dir="$run_base.previous"

nohup bash -c '
set -uo pipefail

script_dir=$1
config_file=$2
status_file=$3
backup_dir=$4
shift 4
input_files=("$@")

# Record an exit status even when the worker terminates unexpectedly.
trap '\''rc=$?; printf "%s\n" "$rc" > "$status_file"'\'' EXIT

# shellcheck disable=SC1090
source "$config_file"

deobf_failed=0
validation_failed=0
missing_output=0

# Move the previous text outputs aside. This prevents a stale successful file
# from hiding a deobfuscation failure that returned exit status 0.
mkdir -p "$backup_dir"
for input in "${input_files[@]}"; do
    filename=$(basename -- "$input")
    base=${filename%.dec.pkl}
    output="$DEOBFUSCATED_DIR/${base}.deobf.txt"
    if [[ -e "$output" ]]; then
        mv -- "$output" "$backup_dir/${base}.deobf.txt"
    fi
done

printf "Started: %s\n" \
    "$("$PYTHON" -c '\''from datetime import datetime; print(datetime.now().astimezone().isoformat(timespec="seconds"))'\'')"
printf "Inputs:  %s\n" "${#input_files[@]}"
echo

"$script_dir/deobfuscate_all.sh" "${input_files[@]}" || deobf_failed=1

echo
printf "%s\n" "============================================================"
echo "Validating generated output"

for input in "${input_files[@]}"; do
    filename=$(basename -- "$input")
    base=${filename%.dec.pkl}
    output="$DEOBFUSCATED_DIR/${base}.deobf.txt"
    csv="${input%.pkl}.resolved_funcs.csv"

    echo
    printf "%s\n" "------------------------------------------------------------"
    echo "Input:  $input"
    echo "Output: $output"
    echo "CSV:    $csv"

    if [[ ! -s "$output" ]]; then
        echo "ERROR: Expected non-empty output was not produced." >&2
        missing_output=1
        previous="$backup_dir/${base}.deobf.txt"
        if [[ -e "$previous" ]]; then
            mv -- "$previous" "$output"
            echo "Restored the previous output after the failed run."
        fi
        continue
    fi
    if [[ ! -s "$csv" ]]; then
        echo "ERROR: Resolved-functions CSV was not produced." >&2
        validation_failed=1
        continue
    fi

    "$PYTHON" "$CHECK_UNRESOLVED" \
        --output "$output" \
        --csv "$csv" || validation_failed=1
done

echo
printf "%s\n" "============================================================"
echo "Deobfuscation command failures: $deobf_failed"
echo "Missing output files:           $missing_output"
echo "Validation failures:            $validation_failed"
result=$((deobf_failed || missing_output || validation_failed))
if (( result == 0 )); then
    rm -rf -- "$backup_dir"
elif find "$backup_dir" -mindepth 1 -print -quit | grep -q .; then
    echo "Previous outputs retained in: $backup_dir"
else
    rmdir "$backup_dir" 2>/dev/null || true
fi

printf "Completed: %s\n" \
    "$("$PYTHON" -c '\''from datetime import datetime; print(datetime.now().astimezone().isoformat(timespec="seconds"))'\'')"

exit "$result"
' bash "$SCRIPT_DIR" "$CONFIG_FILE" "$status_file" "$backup_dir" "${input_files[@]}" \
    > "$run_log" 2>&1 < /dev/null &

pid=$!
printf '%s\n' "$pid" > "$pid_file"

printf 'Started as PID %s\n' "$pid"
printf 'Log:        %s\n' "$run_log"
printf 'PID file:   %s\n' "$pid_file"
printf 'Status:     %s (created when the run finishes)\n' "$status_file"
printf '\nFollow the run with:\n  tail -f %q\n' "$run_log"
