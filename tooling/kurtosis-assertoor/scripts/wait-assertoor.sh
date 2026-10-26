#!/usr/bin/env bash
#
# Waits for every assertoor test run to finish and fails unless all of them
# succeeded.
#
# Usage: wait-assertoor.sh <assertoor-url> <expected-test-count> [timeout-minutes] [out-dir]
#
# The URL is what `kurtosis port print <enclave> assertoor http` prints. Writes
# <out-dir>/test_runs.json, one run-<id>.json per run (with per-task results),
# and <out-dir>/failed.txt naming every run that did not succeed. A run that
# is still going at the deadline counts as failed, as does a run that never
# showed up.

set -euo pipefail

URL="${1:?assertoor url required}"
EXPECTED="${2:?expected test count required}"
TIMEOUT_MIN="${3:-100}"
OUT="${4:-assertoor-results}"

mkdir -p "$OUT"
: > "$OUT/failed.txt"
deadline=$((SECONDS + TIMEOUT_MIN * 60))
runs='[]'

while :; do
    # Assertoor takes a moment to listen after kurtosis reports it started.
    if fetched=$(curl -sf --max-time 10 "$URL/api/v1/test_runs" | jq -c '.data'); then
        runs="$fetched"
        total=$(jq 'length' <<<"$runs")
        active=$(jq '[.[] | select(.status == "pending" or .status == "running")] | length' <<<"$runs")
        echo "[$(date -u +%H:%M:%S)] $total/$EXPECTED runs seen, $active active:" \
            "$(jq -r '[.[] | "\(.name)=\(.status)"] | join(", ")' <<<"$runs")"
        if [ "$total" -ge "$EXPECTED" ] && [ "$active" -eq 0 ]; then
            break
        fi
    else
        echo "[$(date -u +%H:%M:%S)] assertoor not answering yet"
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "::error::timed out after ${TIMEOUT_MIN} minutes waiting for assertoor tests"
        break
    fi
    sleep 30
done

echo "$runs" > "$OUT/test_runs.json"
for id in $(jq -r '.[].run_id' <<<"$runs"); do
    curl -sf --max-time 30 "$URL/api/v1/test_run/$id/details" > "$OUT/run-$id.json" || true
done

jq -r '.[] | select(.status != "success") | "\(.name) (\(.status))"' <<<"$runs" > "$OUT/failed.txt"
total=$(jq 'length' <<<"$runs")
if [ "$total" -lt "$EXPECTED" ]; then
    echo "only $total of $EXPECTED test runs appeared" >> "$OUT/failed.txt"
fi

echo
jq -r '.[] | "\(.status)\t\(.name)\t\((.stop_time - .start_time))s"' <<<"$runs"
if [ -s "$OUT/failed.txt" ]; then
    echo "Failed:"
    cat "$OUT/failed.txt"
    exit 1
fi
echo "All $total assertoor tests passed"
