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
# After every evaluation, writes the conditions still unmet to
# <output-dir>/failed.txt, so a run cut short still says what was missing. On
# every exit, writes each ethlambda service's builder metric lines to
# <output-dir>/<service>.prom.
#
# Exits 1 if a condition is unmet at the deadline, and 2 at once if the check
# cannot run: kurtosis or curl is missing, or a service has no `metrics` port
# (ethereum-package renamed it, or the participants were reordered).

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
: > "$OUT/failed.txt"

for tool in kurtosis curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "::error::$tool is not on PATH"
        echo "setup   $tool is not on PATH" > "$OUT/failed.txt"
        exit 2
    fi
done

# One evaluation's scrapes, a file per service.
SNAPSHOT=$(mktemp -d)

# Prints a service's metrics address as host:port. `kurtosis port print` answers
# `<application protocol>://<host>:<port>`, or `<host>:<port>` for a port with
# no application protocol; anything around the host and port is dropped, and
# curl's default (http) is what the metrics port speaks.
metrics_address() {
    local addr
    addr=$(kurtosis port print "$ENCLAVE" "$1" metrics) || return
    addr="${addr#*://}"
    printf '%s\n' "${addr%%/*}"
}

# Prints a service's metrics, or nothing while it is unreachable. The address is
# looked up on every scrape, since a restarted service can come back on another
# host port.
scrape() {
    local addr
    addr=$(metrics_address "$1" 2>/dev/null) || return 0
    curl -sf --max-time 10 "$addr/metrics" 2>/dev/null || true
}

# Scrapes every service once, so one evaluation reads each service as of one
# moment rather than once per condition.
take_snapshot() {
    local service
    for service in "${SERVICES[@]}"; do
        scrape "$service" > "$SNAPSHOT/$service.prom"
    done
}

# Prints the sum of a series in the given exposition file, 0 if absent. A
# selector with labels matches that exact `name{labels}` token; a bare name
# matches the metric under any labels. Every series checked is a counter, so the
# sum is truncated to an integer for the shell's `-ge`: truncating rather than
# rounding keeps a value below 1 from meeting a `>= 1` condition, and `%.0f`
# prints a large or exponent-notation value (`1e+06`) whole, which `%d` need not.
value_of() {
    awk -v sel="$2" '
        index(sel, "{") { if ($1 == sel) sum += $NF; next }
        { split($1, p, "{"); if (p[1] == sel) sum += $NF }
        END { printf "%.0f\n", int(sum) }
    ' "$1"
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
    take_snapshot
    for entry in "${CONDITIONS[@]}"; do
        IFS='|' read -r svc series desc <<<"$entry"
        if [ ! -s "$SNAPSHOT/$svc.prom" ]; then
            echo "unmet   $svc $series: no metrics, the service did not answer ($desc)"
            unmet=1
            continue
        fi
        value=$(value_of "$SNAPSHOT/$svc.prom" "$series")
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
    rm -rf "$SNAPSHOT"
    echo "Builder metrics written to $OUT"
}
trap finish EXIT

# `kurtosis run` has started every service by the time this runs, so each one
# must already have a metrics port. A service the package named differently
# would otherwise read as "not met yet" until the deadline, not as the setup
# problem it is.
missing=0
for service in "${SERVICES[@]}"; do
    if ! err=$(metrics_address "$service" 2>&1 >/dev/null); then
        echo "::error::$service has no metrics port in enclave $ENCLAVE: ${err:-kurtosis port print failed}"
        echo "setup   $service has no metrics port in enclave $ENCLAVE" >> "$OUT/failed.txt"
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    echo "Check the service names above against \`kurtosis enclave inspect $ENCLAVE\`."
    exit 2
fi

deadline=$((SECONDS + TIMEOUT_MIN * 60))
status=1
while :; do
    summary=$(evaluate) && status=0
    grep '^unmet' <<<"$summary" > "$OUT/failed.txt" || true
    if [ "$status" -eq 0 ]; then
        break
    fi
    echo "[$(date -u +%H:%M:%S)] builder conditions not met yet:"
    sed 's/^/    /' "$OUT/failed.txt"
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "::error::timed out after ${TIMEOUT_MIN} minutes waiting for builder blocks"
        break
    fi
    sleep 30
done

echo
echo "$summary"
if [ "$status" -ne 0 ]; then
    echo "Failed:"
    cat "$OUT/failed.txt"
    exit 1
fi
echo "ethlambda built blocks through the builder"
