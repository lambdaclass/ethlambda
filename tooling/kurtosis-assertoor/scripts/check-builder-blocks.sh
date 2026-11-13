#!/usr/bin/env bash
#
# Waits until ethlambda has built blocks through the builder (Commit-Boost) and
# fails if that does not happen in time.
#
# Usage: check-builder-blocks.sh <enclave> <timeout-minutes> <output-dir>
#
# Reads Prometheus metrics through `kurtosis port print <enclave> <service>
# metrics`, and succeeds once every condition below holds:
#
#   ethlambda beacon node (participant 3)
#     lean_beacon_builder_registrations_total{outcome="forwarded"}  >= 1
#     lean_beacon_builder_payload_source_total{source="builder"}    >= 1
#   ethlambda validator client of participant 3
#     ethlambda_validator_builder_registrations_sent_total          >= 1
#     ethlambda_validator_blinded_blocks_proposed_total             >= 1
#   ethlambda validator client of participant 2 (on a lighthouse beacon node)
#     ethlambda_validator_blinded_blocks_proposed_total             >= 1
#
# On every exit, writes each ethlambda service's builder metric lines to
# <output-dir>/<service>.prom, and the conditions still unmet to
# <output-dir>/failed.txt. A condition unmet at the deadline fails the check.

set -euo pipefail

ENCLAVE="${1:?enclave name required}"
TIMEOUT_MIN="${2:?timeout in minutes required}"
OUT="${3:?output directory required}"

# Service names follow ethereum-package: cl-<n>-<cl>-<el>, and vc-<n>-<el>-<cl>
# with -<vc> appended when the validator client differs from the beacon node.
CL3="cl-3-ethlambda-geth"
VC2="vc-2-geth-lighthouse-ethlambda"
VC3="vc-3-geth-ethlambda"
SERVICES=("$CL3" "$VC2" "$VC3")

# service|series (name, with its labels when the metric is labelled)|description
CONDITIONS=(
    "$CL3|lean_beacon_builder_registrations_total{outcome=\"forwarded\"}|beacon node forwarded a registration"
    "$CL3|lean_beacon_builder_payload_source_total{source=\"builder\"}|beacon node served a builder payload"
    "$VC3|ethlambda_validator_builder_registrations_sent_total|validator client of participant 3 sent a registration"
    "$VC3|ethlambda_validator_blinded_blocks_proposed_total|validator client of participant 3 proposed a blinded block"
    "$VC2|ethlambda_validator_blinded_blocks_proposed_total|validator client of participant 2 proposed a blinded block"
)

mkdir -p "$OUT"
deadline=$((SECONDS + TIMEOUT_MIN * 60))
: > "$OUT/failed.txt"

# Prints a service's metrics, or nothing while it is unreachable.
scrape() {
    local addr
    addr=$(kurtosis port print "$ENCLAVE" "$1" metrics 2>/dev/null) || return 0
    curl -sf --max-time 10 "${addr#*://}/metrics" 2>/dev/null || true
}

# Prints the sum of a series over the given exposition text, 0 if absent. A
# selector with labels matches that exact `name{labels}` token; a bare name
# matches the metric under any labels.
value_of() {
    awk -v sel="$2" '
        index(sel, "{") { if ($1 == sel) sum += $NF; next }
        { split($1, p, "{"); if (p[1] == sel) sum += $NF }
        END { printf "%d\n", sum }
    ' <<<"$1"
}

# Writes each service's builder-related series to <output-dir>/<service>.prom.
dump_metrics() {
    local service
    for service in "${SERVICES[@]}"; do
        scrape "$service" \
            | grep -E '^(lean_beacon_builder_|ethlambda_validator_.*(blinded|registration))' \
            > "$OUT/$service.prom" || true
    done
}

# Prints one line per condition and returns 1 if any is unmet.
evaluate() {
    local entry svc series desc value unmet=0
    for entry in "${CONDITIONS[@]}"; do
        IFS='|' read -r svc series desc <<<"$entry"
        value=$(value_of "$(scrape "$svc")" "$series")
        if [ "$value" -ge 1 ]; then
            echo "ok      $svc $series = $value ($desc)"
        else
            echo "unmet   $svc $series = $value ($desc)"
            unmet=1
        fi
    done
    return "$unmet"
}

finish() {
    dump_metrics
    echo "Builder metrics written to $OUT"
}
trap finish EXIT

status=1
while :; do
    if summary=$(evaluate); then
        status=0
        break
    fi
    echo "[$(date -u +%H:%M:%S)] builder conditions not met yet:"
    grep '^unmet' <<<"$summary" | sed 's/^/    /'
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "::error::timed out after ${TIMEOUT_MIN} minutes waiting for builder blocks"
        break
    fi
    sleep 30
done

echo
echo "$summary"
grep '^unmet' <<<"$summary" > "$OUT/failed.txt" || true
if [ "$status" -ne 0 ]; then
    echo "Failed:"
    cat "$OUT/failed.txt"
    exit 1
fi
echo "ethlambda built blocks through the builder"
