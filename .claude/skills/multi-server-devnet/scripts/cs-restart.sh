#!/bin/bash
# Checkpoint-sync restart of specific ethlambda nodes on ONE devnet's host, in
# place. Recover crashed/frozen/split nodes WITHOUT resetting the chain.
# ALWAYS uses checkpoint sync (keep-DB resume panics: store.rs:566 "safe target
# exists"). Keeps the mandatory 60s gossip backoff for nodes that were running,
# so they re-graft cleanly (skip it and they attest but aggregators never hear
# them -> finality stalls below the 2/3 threshold).
# Ports per node n: gossip 9000+n, api 5052+n, metrics 9200+n (no BASE offset).
#
# Usage (on host):  cs-restart.sh <CS_PORT> <node>...
#   CS_PORT  api port of a HEALTHY same-devnet node to checkpoint-sync from
#            (use an aggregator's api port; it stays up). e.g. 5052
#   node...  node indices to restart
set -u
CS=$1; shift; NODES="$*"
IMAGE=${IMAGE:-ghcr.io/lambdaclass/ethlambda:devnet5}
GENESIS=${GENESIS:-/opt/lean-quickstart/genesis}
DATA=${DATA:-/opt/lean-quickstart/data}
MEMLIMITS=${MEMLIMITS:-"--memory 8g --memory-swap 16g --memory-reservation 2g"}
LOGOPT=${LOGOPT:-"--log-opt max-size=200m --log-opt max-file=5"}  # 1 GiB hot buffer; Loki (7d) holds the long-term record
CRASH=/opt/lean-quickstart/crash-logs
LOG=/tmp/cs-restart.log
TS=$(date +%Y%m%d-%H%M%S)
log(){ echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"; }

sudo mkdir -p "$CRASH"; : > "$LOG"
log "=== cs-restart cs_port=$CS nodes=[$NODES] ==="
for n in $NODES; do
  name=node_$n; cname=ethlambda_$n; G=$((9000+n)); A=$((5052+n)); M=$((9200+n))
  # find the node's current container by index (may be a canary being reset to ethlambda)
  cid=$(sudo docker ps -aq --filter "name=_${n}$")
  # preserve any crash log (sudo sh -c so the redirect runs as root)
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
    --checkpoint-sync-url "http://127.0.0.1:$CS/lean/v0/states/finalized" >/dev/null
  log "started $cname (node_$n, checkpoint sync from :$CS)"
done
log "=== cs-restart done ==="
