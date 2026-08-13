#!/bin/bash
# HOST-side: launch an ethlambda node RANGE of a CROSS-SERVER devnet (fresh start,
# no checkpoint sync -- every node boots from the genesis already in /config).
# The skill's start-devnet.sh assumes one host owns nodes 0..NODES-1; a chain split
# across hosts needs each host to own a slice, and aggregator->subnet mapping is no
# longer "node k -> subnet k" (eth-5 owns nodes 32-63 but subnets 4-7), so the
# aggregators are passed explicitly.
#
# Usage (on host): start-range.sh <START> <END> <SUBNETS> [N:subnet ...]
#   START END   inclusive node index range this host owns (e.g. 0 31 / 32 63)
#   SUBNETS     ATTESTATION_COMMITTEE_COUNT (checked against the genesis on disk)
#   N:subnet    node N aggregates subnet `subnet` (e.g. 0:0 1:1 / 36:4 37:5)
#
# Ports: gossip 9000+n, api 5052+n, metrics 9200+n (global index, no per-host base).
# Naming: identity node_N (node-id, node_N.key, data-dir, genesis validator name);
# container ethlambda_N (docker name, cAdvisor `name`, promtail `node`).
set -u
START=$1; END=$2; SUBNETS=$3; shift 3

GENESIS=${GENESIS:-/opt/lean-quickstart/genesis}
DATA=${DATA:-/opt/lean-quickstart/data}
ETH_IMG=${ETH_IMG:-ghcr.io/lambdaclass/ethlambda:devnet5}
MEM="${MEM:---memory 8g --memory-swap 16g --memory-reservation 2g}"
LOGOPT="${LOGOPT:---log-opt max-size=200m --log-opt max-file=5}"
EXTRA_ETH_FLAGS=${EXTRA_ETH_FLAGS:-}
LOG=/tmp/start-range.log
log(){ echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"; }
: > "$LOG"

# map node index -> aggregated subnet id
declare -A AGG
for spec in "$@"; do
  n=${spec%%:*}; s=${spec#*:}
  case "$n" in ''|*[!0-9]*) log "ERROR: bad node index in agg spec '$spec'"; exit 1;; esac
  case "$s" in ''|*[!0-9]*) log "ERROR: bad subnet in agg spec '$spec'"; exit 1;; esac
  [ "$n" -ge "$START" ] && [ "$n" -le "$END" ] || { log "ERROR: agg node $n outside range $START-$END"; exit 1; }
  [ "$s" -lt "$SUBNETS" ] || { log "ERROR: subnet $s >= SUBNETS=$SUBNETS"; exit 1; }
  AGG[$n]=$s
done

# --- preflight (same failures start-devnet.sh guards, adapted to a range) ------
cfg_val(){ sudo awk -v k="$1:" '$1==k{print $2}' "$GENESIS/config.yaml" 2>/dev/null; }
GT=$(cfg_val GENESIS_TIME); GACC=$(cfg_val ATTESTATION_COMMITTEE_COUNT)
GVC=$(cfg_val VALIDATOR_COUNT)
[ -n "$GT" ] || { log "ERROR: no GENESIS_TIME in $GENESIS/config.yaml -- is the genesis shipped?"; exit 1; }
if [ -n "$GACC" ] && [ "$GACC" != "$SUBNETS" ]; then
  log "ERROR: SUBNETS=$SUBNETS but genesis says ATTESTATION_COMMITTEE_COUNT=$GACC"; exit 1
fi
if [ -n "$GVC" ] && [ "$END" -ge "$GVC" ]; then
  log "ERROR: END=$END but genesis only has VALIDATOR_COUNT=$GVC"; exit 1
fi
# pubkey size must match the binary's PUBLIC_KEY_SIZE or the node dies parsing genesis
# (52B = pre-leanVM-main / leanSig, 64 hex; 32B = leanVM-main, 104 hex incl. quotes).
PKHEX=$(sudo grep -m1 -o 'attestation_pubkey: "[0-9a-f]*"' "$GENESIS/config.yaml" 2>/dev/null | sed 's/.*"\(.*\)"/\1/')
log "genesis pubkey size: $(( ${#PKHEX} / 2 )) bytes (image $ETH_IMG must agree)"
for n in $(seq "$START" "$END"); do
  if [ -n "$(sudo find "$DATA/node_$n" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ] \
     && [ -z "${ALLOW_STALE_DATA:-}" ]; then
    log "ERROR: leftover data in $DATA/node_$n -- a node resuming an old DB against a NEW"
    log "  genesis forks onto its own chain. Wipe first: sudo rm -rf $DATA/node_*"
    log "  (override with ALLOW_STALE_DATA=1 only if the data matches THIS genesis)"
    exit 1
  fi
done
gt_delta=$((GT - $(date +%s)))
[ "$gt_delta" -lt -3600 ] && log "WARNING: GENESIS_TIME is $(( -gt_delta / 60 ))min in the PAST with empty data dirs"

log "=== start-range $START-$END SUBNETS=$SUBNETS aggs=[$*] IMG=$ETH_IMG GT=$GT (in ${gt_delta}s) ==="

for n in $(seq "$START" "$END"); do
  G=$((9000+n)); A=$((5052+n)); M=$((9200+n))
  NAME=node_$n; CNAME=ethlambda_$n
  cids=$(sudo docker ps -aq --filter "name=_${n}$"); [ -n "$cids" ] && sudo docker rm -f $cids >/dev/null 2>&1
  sudo mkdir -p "$DATA/$NAME"
  aggflags=""
  if [ -n "${AGG[$n]:-}" ]; then aggflags="--is-aggregator --aggregate-subnet-ids ${AGG[$n]}"; fi
  sudo docker run -d --restart unless-stopped --name "$CNAME" --network host $MEM $LOGOPT \
    -v "$GENESIS":/config -v "$DATA/$NAME":/data "$ETH_IMG" \
    --genesis /config/config.yaml --validators /config/annotated_validators.yaml \
    --bootnodes /config/nodes.yaml --validator-config /config/validator-config.yaml \
    --hash-sig-keys-dir /config/hash-sig-keys --data-dir /data \
    --gossipsub-port "$G" --node-id "$NAME" --node-key /config/"$NAME".key \
    --http-address 0.0.0.0 --api-port "$A" --metrics-port "$M" \
    --attestation-committee-count "$SUBNETS" $aggflags $EXTRA_ETH_FLAGS >/dev/null \
    && log "$NAME started${aggflags:+ (agg subnet ${AGG[$n]})}" || log "FAIL $NAME"
done
log "=== launched $((END-START+1)) nodes; aggregators: ${!AGG[*]} ==="
