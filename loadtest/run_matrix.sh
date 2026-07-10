#!/bin/bash
# Run ws_load.py across a baseline matrix of client counts and print a
# one-line summary per config. Useful for "before / after" comparisons when
# you change bus/fan-out code.
#
# Usage:
#   ./loadtest/run_matrix.sh                            # default matrix
#   URL=http://remote:8092 ./loadtest/run_matrix.sh     # point elsewhere
#   CLIENTS="1 10 50"  ./loadtest/run_matrix.sh         # custom list
#   DURATION=30 ./loadtest/run_matrix.sh                # longer hold

set -eu
URL="${URL:-http://127.0.0.1:8092}"
DURATION="${DURATION:-10}"
CLIENTS="${CLIENTS:-1 5 20 50 100}"
STAGGER="${STAGGER:-20}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"
if [ -x "$SCRIPT_DIR/../.venv/bin/python" ]; then
    PY="$SCRIPT_DIR/../.venv/bin/python"
fi

printf "%-8s %-14s %-12s %-14s %-14s %-12s\n" \
    "clients" "connected_ok" "msgs_total" "ttfm_med_ms" "gap_med_ms" "dropped"
printf -- "%.s-" {1..76}; echo

for n in $CLIENTS; do
    out="$(
      "$PY" "$SCRIPT_DIR/ws_load.py" \
        --url "$URL" \
        --clients "$n" \
        --duration "$DURATION" \
        --stagger-ms "$STAGGER"
    )" || true
    ok=$(echo "$out"      | "$PY" -c "import sys,json; d=json.load(sys.stdin); print(d['connected_ok'])"     2>/dev/null || echo "-")
    tot=$(echo "$out"     | "$PY" -c "import sys,json; d=json.load(sys.stdin); print(d['msgs_total'])"       2>/dev/null || echo "-")
    ttfm=$(echo "$out"    | "$PY" -c "import sys,json; d=json.load(sys.stdin); print(d['ttfm_median_ms'])"   2>/dev/null || echo "-")
    gap=$(echo "$out"     | "$PY" -c "import sys,json; d=json.load(sys.stdin); print(d['gap_median_of_medians_ms'])" 2>/dev/null || echo "-")
    dropped=$(echo "$out" | "$PY" -c "import sys,json; d=json.load(sys.stdin); print(d.get('bus_delta',{}).get('dropped','-'))" 2>/dev/null || echo "-")
    printf "%-8s %-14s %-12s %-14s %-14s %-12s\n" "$n" "$ok" "$tot" "$ttfm" "$gap" "$dropped"
done
