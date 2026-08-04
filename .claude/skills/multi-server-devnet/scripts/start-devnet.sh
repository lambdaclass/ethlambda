#!/bin/bash
# Launch a full INDEPENDENT single-host devnet on THIS host (fresh start, no
# checkpoint sync — every node boots from the genesis already in /config).
# Nodes 0..NODES-1, ports gossip 9000+n / api 5052+n / metrics 9200+n.
# Aggregators: nodes 0..SUBNETS-1, node k aggregates subnet k.
# Three-layer naming: node identity = node_N (node-id, node_N.key, data-dir,
# genesis validator name); container/display = <client>_N (docker name, cAdvisor
# `name`, promtail `node`); ports = index N. All genesis artifacts key off node_N.
#
# Usage (on host):  start-devnet.sh <NODES> <SUBNETS> [N:client ...]
#   NODES     validators on this server
#   SUBNETS   ATTESTATION_COMMITTEE_COUNT (= number of aggregators)
#   N:client  optional: run node N as client in zeam|ream|qlean|gean|lantern|grandine
#             (everything else runs ethlambda)
set -u
NODES=$1; SUBNETS=$2; shift 2
# Paths are env-overridable (same as cs-restart.sh) so the launch can be
# exercised against a fixture dir without touching the real devnet.
GENESIS=${GENESIS:-/opt/lean-quickstart/genesis}
DATA=${DATA:-/opt/lean-quickstart/data}
# Per-container limits, env-overridable (same pattern as the *_IMG vars below).
# No CPU caps: block production is latency-bound on the leanVM Type-2 merge
# (~6.5s per packed attestation), not CPU-bound, so caps only starved nodes
# without taming the cost. (History: --cpus 1.5/8 were added 2026-06-18 after a
# non-finality spiral drove 32 nodes to load 50 on 16 cores; removed 2026-06-24.)
# Memory is uniform across roles: 8g RAM / 16g RAM+swap / 2g reservation.
MEM="${MEM:---memory 8g --memory-swap 16g --memory-reservation 2g}"
MEM_AGG="${MEM_AGG:---memory 8g --memory-swap 16g --memory-reservation 2g}"
# Cap Docker json-file stdout logs (default driver is unbounded -> filled 936G disks).
# 200m x 5 = 1 GiB max per container. Applied to every `docker run` below.
# History: started 100m x 3 (300 MiB); bumped to 600m x 10 (6 GiB) on 2026-06-17 so a
# multi-hour stall stayed inspectable via `docker logs` (300 MiB only held ~7-15h).
# Reduced to 1 GiB on 2026-06-29 once the central Loki (7d retention) took over that
# role: the long-term stall record now lives in Loki/Grafana, so the local json-file is
# just a hot buffer for `docker logs --tail` + a promtail-outage cushion (~a day at this
# rate). promtail ships via the Docker daemon API, so this rotation never races it.
# Env-overridable (same pattern as MEM above).
LOGOPT="${LOGOPT:---log-opt max-size=200m --log-opt max-file=5}"
LOG=/tmp/start-devnet.log
log(){ echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"; }
: > "$LOG"

ETH_IMG=${ETH_IMG:-ghcr.io/lambdaclass/ethlambda:devnet5}
# Extra CLI flags appended to every ethlambda node (env-overridable). Used to
# inject experiment-only flags like --disable-duty-sync-gate without hardcoding.
EXTRA_ETH_FLAGS=${EXTRA_ETH_FLAGS:-}
ZEAM_IMG=${ZEAM_IMG:-blockblaz/zeam:devnet5}
REAM_IMG=${REAM_IMG:-ghcr.io/reamlabs/ream:latest-devnet5}
QLEAN_IMG=${QLEAN_IMG:-qdrvm/qlean-mini:devnet-5-amd64}
GEAN_IMG=${GEAN_IMG:-ghcr.io/geanlabs/gean:devnet5}
LANTERN_IMG=${LANTERN_IMG:-bitminemavan/lantern:devnet5}
GRANDINE_IMG=${GRANDINE_IMG:-sifrai/lean:devnet-5}

CLIENTS="ethlambda zeam ream qlean gean lantern grandine"

# map node index -> canary client (empty = ethlambda)
declare -A CANARY
for spec in "$@"; do
  n=${spec%%:*}; client=${spec#*:}
  case "$n" in ''|*[!0-9]*) log "ERROR: bad node index in spec '$spec'"; exit 1;; esac
  case " $CLIENTS " in *" $client "*) ;; *) log "ERROR: unknown client '$client' in spec '$spec' (want: $CLIENTS)"; exit 1;; esac
  CANARY[$n]=$client
done

# --- preflight: the two mistakes that cost a whole devnet ---------------------
cfg_val(){ sudo awk -v k="$1:" '$1==k{print $2}' "$GENESIS/config.yaml" 2>/dev/null; }
GT=$(cfg_val GENESIS_TIME); GACC=$(cfg_val ATTESTATION_COMMITTEE_COUNT)
[ -n "$GT" ] || { log "ERROR: no GENESIS_TIME in $GENESIS/config.yaml -- is the genesis shipped?"; exit 1; }
# SUBNETS drives the aggregator set and every client's --attestation-committee-count.
# If it disagrees with the genesis the chain was built with, nodes compute a different
# subnet map than the aggregators listen on and votes vanish.
if [ -n "$GACC" ] && [ "$GACC" != "$SUBNETS" ]; then
  log "ERROR: SUBNETS=$SUBNETS but the genesis says ATTESTATION_COMMITTEE_COUNT=$GACC."
  log "  Pass $GACC (or ship the genesis you meant to run)."
  exit 1
fi
# A node that resumes an old DB against a NEW genesis forks onto its own chain
# (the genesis-time landmine). Fresh start => data dirs must be empty.
stale=$(sudo find "$DATA" -mindepth 2 -maxdepth 2 -path "$DATA/node_*" -print -quit 2>/dev/null)
if [ -n "$stale" ] && [ -z "${ALLOW_STALE_DATA:-}" ]; then
  log "ERROR: leftover node data under $DATA (e.g. $stale)."
  log "  Wipe it first:  sudo rm -rf $DATA/node_*"
  log "  Do that BEFORE generating genesis -- it is the one step that scales with chain"
  log "  age, so it must not run against the GENESIS_TIME countdown."
  log "  To relaunch on the EXISTING chain instead, use cs-restart.sh (checkpoint sync),"
  log "  or override with ALLOW_STALE_DATA=1 if you know the data matches this genesis."
  exit 1
fi
gt_delta=$((GT - $(date +%s)))
if [ "$gt_delta" -lt -3600 ]; then
  log "WARNING: GENESIS_TIME is $(( -gt_delta / 60 ))min in the PAST with empty data dirs --"
  log "  nodes will boot thousands of slots behind and sit in the sync gate. Stale genesis dir?"
fi

log "=== start-devnet NODES=$NODES SUBNETS=$SUBNETS canaries=[$*] GT=$GT (genesis in ${gt_delta}s) ==="

for n in $(seq 0 $((NODES-1))); do
  G=$((9000+n)); A=$((5052+n)); M=$((9200+n))
  client=${CANARY[$n]:-ethlambda}
  NAME=node_$n            # node identity: node-id, node_N.key, data-dir (client-agnostic)
  CNAME=${client}_$n      # container / display name (docker, cAdvisor `name`, promtail `node`)
  # remove any prior container for this node index, whatever client it ran
  cids=$(sudo docker ps -aq --filter "name=_${n}$"); [ -n "$cids" ] && sudo docker rm -f $cids >/dev/null 2>&1
  sudo mkdir -p "$DATA/$NAME"
  # aggregator if node index < SUBNETS; subnet covered = its own index
  aggflags=""; lim="$MEM"
  if [ "$n" -lt "$SUBNETS" ]; then
    lim="$MEM_AGG"; aggflags="--is-aggregator"
    [ "$client" != qlean ] && aggflags="$aggflags --aggregate-subnet-ids $n"
  fi
  case "$client" in
    ethlambda)
      sudo docker run -d --restart unless-stopped --name "$CNAME" --network host $lim $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$NAME":/data "$ETH_IMG" \
        --genesis /config/config.yaml --validators /config/annotated_validators.yaml \
        --bootnodes /config/nodes.yaml --validator-config /config/validator-config.yaml \
        --hash-sig-keys-dir /config/hash-sig-keys --data-dir /data \
        --gossipsub-port "$G" --node-id "$NAME" --node-key /config/"$NAME".key \
        --http-address 0.0.0.0 --api-port "$A" --metrics-port "$M" \
        --attestation-committee-count "$SUBNETS" $aggflags $EXTRA_ETH_FLAGS >/dev/null \
        && log "$NAME ethlambda started${aggflags:+ (agg subnet $n)}" || log "FAIL $NAME ethlambda";;
    zeam)
      # console_log_level=info exposes zeam's own duty publishes (attestation /
      # block) on stdout so the duty-timing profiler (reads `docker logs`) can see
      # them; the file sink stays warn (not captured). Costs more stdout volume,
      # bounded here by the json-log rotation in $LOGOPT.
      sudo docker run -d --restart unless-stopped --name "$CNAME" --network host $lim $LOGOPT \
        --security-opt seccomp=unconfined \
        -v "$GENESIS":/config -v "$DATA/$NAME":/data "$ZEAM_IMG" \
        --log_file_active_level warn --console_log_level info \
        node --custom-genesis /config --validator-config genesis_bootnode --data-dir /data \
        --node-id "$NAME" --node-key /config/"$NAME".key --metrics-enable \
        --api-port "$A" --metrics-port "$M" --attestation-committee-count "$SUBNETS" \
        $aggflags --db-backend lmdb >/dev/null \
        && log "$NAME zeam started${aggflags:+ (agg)}" || log "FAIL $NAME zeam";;
    ream)
      sudo docker run -d --restart unless-stopped --name "$CNAME" --network host $lim $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$NAME":/data "$REAM_IMG" \
        --data-dir /data lean_node --network /config/config.yaml \
        --validator-registry-path /config/annotated_validators.yaml \
        --bootnodes /config/nodes.yaml \
        --node-id "$NAME" --node-key /config/"$NAME".key --socket-port "$G" \
        --metrics --metrics-address 0.0.0.0 --metrics-port "$M" \
        --http-address 0.0.0.0 --http-port "$A" \
        --attestation-committee-count "$SUBNETS" $aggflags >/dev/null \
        && log "$NAME ream started${aggflags:+ (agg)}" || log "FAIL $NAME ream";;
    qlean)
      sudo docker run -d --restart unless-stopped --name "$CNAME" --network host $lim $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$NAME":/data "$QLEAN_IMG" \
        --genesis-dir /config --data-dir /data --node-id "$NAME" \
        --node-key /config/"$NAME".key \
        --listen-addr /ip4/0.0.0.0/udp/"$G"/quic-v1 \
        --metrics-host 0.0.0.0 --metrics-port "$M" \
        --api-host 0.0.0.0 --api-port "$A" \
        --attestation-committee-count "$SUBNETS" $aggflags -linfo >/dev/null \
        && log "$NAME qlean started${aggflags:+ (agg)}" || log "FAIL $NAME qlean";;
    gean)
      sudo docker run -d --restart unless-stopped --name "$CNAME" --network host $lim $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$NAME":/data "$GEAN_IMG" \
        --custom-network-config-dir /config \
        --gossipsub-port "$G" --node-id "$NAME" --node-key /config/"$NAME".key \
        --http-address 0.0.0.0 --api-port "$A" --metrics-port "$M" \
        --attestation-committee-count "$SUBNETS" $aggflags >/dev/null \
        && log "$NAME gean started${aggflags:+ (agg)}" || log "FAIL $NAME gean";;
    lantern)
      sudo docker run -d --restart unless-stopped --name "$CNAME" --network host $lim $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$NAME":/data "$LANTERN_IMG" \
        --data-dir /data --genesis-config /config/config.yaml \
        --nodes-path /config/nodes.yaml --genesis-state /config/genesis.ssz \
        --validator_config /config \
        --node-id "$NAME" --node-key-path /config/"$NAME".key \
        --listen-address /ip4/0.0.0.0/udp/"$G"/quic-v1 \
        --http-port "$A" --metrics-port "$M" \
        --hash-sig-key-dir /config/hash-sig-keys --attestation-committee-count "$SUBNETS" \
        --devnet 12345678 $aggflags >/dev/null \
        && log "$NAME lantern started${aggflags:+ (agg)}" || log "FAIL $NAME lantern";;
    grandine)
      sudo docker run -d --restart unless-stopped --name "$CNAME" --network host $lim $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$NAME":/data "$GRANDINE_IMG" \
        --genesis /config/config.yaml --validator-registry-path /config/annotated_validators.yaml \
        --bootnodes /config/nodes.yaml --node-id "$NAME" --node-key /config/"$NAME".key \
        --port "$G" --address 0.0.0.0 --http-address 0.0.0.0 --http-port "$A" \
        --metrics --metrics-address 0.0.0.0 --metrics-port "$M" \
        --hash-sig-key-dir /config/hash-sig-keys --attestation-committee-count "$SUBNETS" \
        $aggflags >/dev/null \
        && log "$NAME grandine started${aggflags:+ (agg)}" || log "FAIL $NAME grandine";;
    *) log "ERROR unknown client '$client' for $NAME";;
  esac
done
log "=== all $NODES nodes launched ==="
