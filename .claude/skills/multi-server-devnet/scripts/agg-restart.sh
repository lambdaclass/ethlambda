#!/bin/bash
# Checkpoint-sync restart of specific ethlambda AGGREGATOR nodes on ONE devnet's
# host, preserving the aggregator role (--is-aggregator --aggregate-subnet-ids)
# and letting you swap the IMAGE (e.g. to canary a PR build on an aggregator).
# Same safety rules as cs-restart.sh: always checkpoint-sync (keep-DB resume
# panics), 60s gossip backoff for nodes that were running, crash logs saved.
# Ports per node n: gossip 9000+n, api 5052+n, metrics 9200+n (no BASE offset).
# Each aggregator node n covers the single subnet n (override with SUBNET).
#
# IMPORTANT: CS_PORT must be a healthy NON-aggregator same-devnet node (do not
# checkpoint-sync an aggregator from the aggregator you are restarting).
#
# Usage (on host):  IMAGE=ghcr.io/lambdaclass/ethlambda:pr421-amd64 \
#                   agg-restart.sh <CS_PORT> <node>...
set -u
CS=$1; shift; NODES="$*"
IMAGE=${IMAGE:?set IMAGE to the aggregator image to run}
GENESIS=${GENESIS:-/opt/lean-quickstart/genesis}
DATA=${DATA:-/opt/lean-quickstart/data}
MEMLIMITS=${MEMLIMITS:-"--memory 8g --memory-swap 16g --memory-reservation 2g"}
LOGOPT=${LOGOPT:-"--log-opt max-size=200m --log-opt max-file=5"}  # 1 GiB hot buffer; Loki (7d) holds the long-term record
CRASH=/opt/lean-quickstart/crash-logs
LOG=/tmp/agg-restart.log
TS=$(date +%Y%m%d-%H%M%S)
log(){ echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"; }

sudo mkdir -p "$CRASH"; : > "$LOG"
log "=== agg-restart cs_port=$CS nodes=[$NODES] image=$IMAGE ==="
for n in $NODES; do
  name=node_$n; cname=ethlambda_$n; G=$((9000+n)); A=$((5052+n)); M=$((9200+n))
  # aggregator node n covers subnet n by default (one aggregator per subnet)
  subnet=${SUBNET:-$n}
  # find the node's current container by index (its client prefix may differ)
  cid=$(sudo docker ps -aq --filter "name=_${n}$")
  [ -n "$cid" ] && sudo sh -c "docker logs $cid > '$CRASH/node_${n}-${TS}.log' 2>&1" && log "saved $CRASH/node_${n}-${TS}.log"
  existed=no; [ -n "$cid" ] && existed=yes
  [ -n "$cid" ] && sudo docker rm -f $cid >/dev/null 2>&1
  sudo rm -rf "$DATA/$name"/* 2>/dev/null
  if [ "$existed" = yes ]; then log "stopped node_$n container; 60s gossip backoff"; sleep 60; fi
  sudo docker run -d --restart unless-stopped --name "$cname" --network host $MEMLIMITS $LOGOPT \
    -v "$GENESIS":/config -v "$DATA/$name":/data "$IMAGE" \
    --genesis /config/config.yaml --validators /config/annotated_validators.yaml \
    --bootnodes /config/nodes.yaml --validator-config /config/validator-config.yaml \
    --hash-sig-keys-dir /config/hash-sig-keys --data-dir /data \
    --gossipsub-port "$G" --node-id "$name" --node-key /config/"$name".key \
    --http-address 0.0.0.0 --api-port "$A" --metrics-port "$M" \
    --is-aggregator --aggregate-subnet-ids "$subnet" \
    --checkpoint-sync-url "http://127.0.0.1:$CS/lean/v0/states/finalized" >/dev/null
  log "started $cname (node_$n) [AGGREGATOR subnet $subnet] image=$IMAGE (checkpoint sync from :$CS)"
done
log "=== agg-restart done ==="
