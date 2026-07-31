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
run_base="$RUN_LOG_DIR/jsc-deobfuscation-cold-warm-$stamp"
run_log="$run_base.log"
pid_file="$run_base.pid"
status_file="$run_base.status"

nohup bash -c '
set -uo pipefail

script_dir=$1
config_file=$2
status_file=$3
shift 3
input_files=("$@")

# Record an exit status even when the worker terminates unexpectedly.
trap '\''rc=$?; printf "%s\n" "$rc" > "$status_file"'\'' EXIT

# shellcheck disable=SC1090
source "$config_file"

timestamp()
{
    "$PYTHON" -c \
        '\''from datetime import datetime; print(datetime.now().astimezone().isoformat(timespec="seconds"))'\''
}

clear_deobfuscated_dir()
{
    case "${DEOBFUSCATED_DIR:-}" in
        ""|"/"|"."|"..")
            echo "ERROR: Refusing to clear unsafe DEOBFUSCATED_DIR: ${DEOBFUSCATED_DIR:-<empty>}" >&2
            return 1
            ;;
    esac

    mkdir -p -- "$DEOBFUSCATED_DIR"
    find "$DEOBFUSCATED_DIR" \
        -mindepth 1 -maxdepth 1 \
        -exec rm -rf -- {} +
}

remove_resolved_function_csvs()
{
    local input csv

    echo "Removing resolved-function CSV caches for the cold run:"
    for input in "${input_files[@]}"; do
        csv="${input%.pkl}.resolved_funcs.csv"
        if [[ -e "$csv" ]]; then
            echo "  removing: $csv"
            rm -f -- "$csv"
        else
            echo "  already absent: $csv"
        fi
    done
}

run_and_validate()
{
    local phase=$1
    local deobf_failed=0
    local validation_failed=0
    local missing_output=0
    local input filename base output csv
    local result

    echo
    printf "%s\n" "################################################################"
    printf "### %s ###\n" "$phase"
    printf "%s\n" "################################################################"
    printf "Started: %s\n" "$(timestamp)"
    printf "Inputs:  %s\n" "${#input_files[@]}"
    echo

    "$script_dir/deobfuscate_all.sh" "${input_files[@]}" || deobf_failed=1

    echo
    printf "%s\n" "============================================================"
    echo "Validating generated output: $phase"

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
    echo "$phase summary"
    echo "Deobfuscation command failures: $deobf_failed"
    echo "Missing output files:           $missing_output"
    echo "Validation failures:            $validation_failed"
    printf "Completed: %s\n" "$(timestamp)"

    result=$((deobf_failed || missing_output || validation_failed))
    return "$result"
}

printf "Started two-pass run: %s\n" "$(timestamp)"
printf "Inputs:               %s\n" "${#input_files[@]}"

echo
echo "Preparing run without cache..."
clear_deobfuscated_dir || exit 1
remove_resolved_function_csvs

cold_failed=0
run_and_validate "RUN NO CACHE" || cold_failed=1

if (( cold_failed != 0 )); then
    echo
    echo "Run without cache failed validation; run with cache will not be started." >&2
    exit 1
fi

echo
echo "Preparing run with cache..."
echo "Keeping the CSV caches generated by the cold run."
echo "Deleting every item from: $DEOBFUSCATED_DIR"
clear_deobfuscated_dir || exit 1

hot_failed=0
run_and_validate "RUN WITH CACHE" || hot_failed=1

echo
printf "%s\n" "################################################################"
echo "Two-pass summary"
echo "Run without cache failures: $cold_failed"
echo "Run with cache failures: $hot_failed"
echo "Final output directory contains only the run-with-cache artifacts:"
echo "  $DEOBFUSCATED_DIR"
printf "Completed two-pass run: %s\n" "$(timestamp)"

result=$((cold_failed || hot_failed))
exit "$result"
' bash "$SCRIPT_DIR" "$CONFIG_FILE" "$status_file" "${input_files[@]}" \
    > "$run_log" 2>&1 < /dev/null &

pid=$!
printf '%s\n' "$pid" > "$pid_file"

printf 'Started as PID %s\n' "$pid"
printf 'Log:        %s\n' "$run_log"
printf 'PID file:   %s\n' "$pid_file"
printf 'Status:     %s (created when both runs finish)\n' "$status_file"
printf '\nFollow both runs with:\n  tail -f %q\n' "$run_log"
