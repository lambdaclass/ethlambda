#!/bin/bash
# Convert nodes of an INDEPENDENT single-host devnet to other lean clients
# (rolling, checkpoint sync, 60s gossip backoff). devnet5 images.
# Node identity stays node_N (node-id, node_N.key, data-dir — genesis keys off it);
# only the container name changes to <client>_N to reflect the running client.
# Ports per node n: gossip 9000+n, api 5052+n, metrics 9200+n (no BASE offset).
# ACC (this devnet's SUBNETS / ATTESTATION_COMMITTEE_COUNT) is read from the
# genesis on disk; set ACC=<n> only to override it. A wrong ACC gives the node a
# different subnet map than the chain, so its votes go to a subnet nobody
# aggregates -- never guess it.
# An :agg node covers the single subnet n % ACC (qlean auto-derives, no flag).
# Specs are validated BEFORE anything is removed: a typo used to be discovered
# after the container and its data were already gone, leaving the node down.
# Args: CS_PORT tuple...   tuple = N:client[:agg]   client in zeam|ream|qlean|gean|lantern|grandine
set -u
GENESIS=${GENESIS:-/opt/lean-quickstart/genesis}
DATA=${DATA:-/opt/lean-quickstart/data}
CRASH=${CRASH:-/opt/lean-quickstart/crash-logs}
LOG=/tmp/convert.log
TS=$(date +%Y%m%d-%H%M%S)
CLIENTS="zeam ream qlean gean lantern grandine"
ZEAM_IMG=${ZEAM_IMG:-blockblaz/zeam:devnet5}
REAM_IMG=${REAM_IMG:-ghcr.io/reamlabs/ream:latest-devnet5}
QLEAN_IMG=${QLEAN_IMG:-qdrvm/qlean-mini:devnet-5-amd64}
LANTERN_IMG=${LANTERN_IMG:-bitminemavan/lantern:devnet5}
GEAN_IMG=${GEAN_IMG:-ghcr.io/geanlabs/gean:devnet5}
GRANDINE_IMG=${GRANDINE_IMG:-sifrai/lean:devnet-5}
MEMLIMITS=${MEMLIMITS:-"--memory 8g --memory-swap 16g --memory-reservation 2g"}  # override per client if needed
# Cap Docker json-file stdout logs. 200m x 5 = 1 GiB/container; central Loki (7d) holds
# the long-term record, so this is just a hot buffer for `docker logs` (see start-devnet.sh).
# EVERY client run must carry this: the default json-file driver is unbounded and has
# filled a host disk before.
LOGOPT=${LOGOPT:-"--log-opt max-size=200m --log-opt max-file=5"}

CS=$1; shift
log(){ echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"; }

: > "$LOG"
# ACC must match the chain. Read it from the genesis this host is running unless
# the caller overrode it.
if [ -z "${ACC:-}" ]; then
  ACC=$(sudo awk '/^ATTESTATION_COMMITTEE_COUNT:/{print $2}' "$GENESIS/config.yaml" 2>/dev/null)
fi
case "${ACC:-}" in
  ''|*[!0-9]*|0) log "ERROR: ACC unknown (no ATTESTATION_COMMITTEE_COUNT in $GENESIS/config.yaml) -- pass ACC=<subnets>"; exit 1;;
esac

# Validate every spec before touching a container: an unknown client or a
# non-numeric index used to surface only after the node was already destroyed.
for spec in "$@"; do
  n=${spec%%:*}; rest=${spec#*:}; client=${rest%%:*}
  case "$n" in ''|*[!0-9]*) log "ERROR: bad node index in spec '$spec'"; exit 1;; esac
  case " $CLIENTS " in *" $client "*) ;; *) log "ERROR: unknown client '$client' in spec '$spec' (want: $CLIENTS)"; exit 1;; esac
  case "$rest" in "$client"|"$client:agg") ;; *) log "ERROR: bad spec '$spec' (want N:client[:agg])"; exit 1;; esac
done

convert_node(){  # $1 = N:client[:agg]
  local spec=$1
  local n=${spec%%:*} rest=${spec#*:}
  local client=${rest%%:*} agg=no
  [[ "$rest" == *:agg ]] && agg=yes
  local name=node_$n         # node identity: node-id, node_N.key, data-dir (client-agnostic)
  local cname=${client}_$n   # container / display name reflecting the running client
  local G=$((9000+n)) A=$((5052+n)) M=$((9200+n))
  local CSURL="http://127.0.0.1:$CS/lean/v0/states/finalized"
  # qlean rejects --aggregate-subnet-ids; aggregators here cover one subnet each
  local aggflags=""
  if [ "$agg" = yes ]; then
    aggflags="--is-aggregator"
    [ "$client" != qlean ] && aggflags="$aggflags --aggregate-subnet-ids $((n % ACC))"
  fi

  # every container for this index (its client prefix may differ); keep one crash
  # log each -- converting away from a wedged canary is exactly when you want it
  local cids="" cid cnm
  while read -r cid cnm; do
    [ -n "$cid" ] || continue
    cids="${cids:+$cids }$cid"
    # Warn if we are removing this devnet's aggregator for the subnet without
    # putting one back: the subnet's votes then reach no aggregator and finality
    # quietly drops below ceil(2/3 . NODES).
    if [ "$agg" = no ] && sudo docker inspect -f '{{join .Config.Cmd " "}}' "$cid" 2>/dev/null \
         | grep -q -- '--is-aggregator'; then
      log "WARNING: $cnm was an AGGREGATOR and the new spec has no :agg -- subnet $((n % ACC)) loses its aggregator"
    fi
    cnm=$(printf '%s' "${cnm:-$cid}" | tr -c 'A-Za-z0-9_.-' '_')
    sudo sh -c "docker logs '$cid' > '$CRASH/${cnm}-${TS}.log' 2>&1" \
      && log "saved $CRASH/${cnm}-${TS}.log"
  done < <(sudo docker ps -a --filter "name=_${n}$" --format '{{.ID}} {{.Names}}')
  local existed=no; [ -n "$cids" ] && existed=yes
  [ "$existed" = yes ] && sudo docker rm -f $cids >/dev/null
  # wipe the dir itself, not `dir/*` (that glob is expanded unprivileged, so an
  # unreadable dir would silently leave the previous client's data in place --
  # wrong on-disk format for the new client). Recreate for the bind mount.
  sudo rm -rf "$DATA/$name"; sudo mkdir -p "$DATA/$name"
  if [ "$existed" = yes ]; then log "stopped node_$n container(s); 60s gossip backoff"; sleep 60; fi

  case "$client" in
    zeam)
      # console_log_level=info exposes zeam's own duty publishes (attestation /
      # block) on stdout so the duty-timing profiler (reads `docker logs`) can see
      # them; the file sink stays warn (not captured). That extra volume is exactly
      # why $LOGOPT must be here -- without it this is the one unbounded json log.
      sudo docker run -d --restart unless-stopped --name "$cname" --network host \
        --security-opt seccomp=unconfined $MEMLIMITS $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$name":/data \
        "$ZEAM_IMG" \
        --log_file_active_level warn --console_log_level info node \
        --custom-genesis /config --validator-config genesis_bootnode \
        --data-dir /data --node-id "$name" --node-key /config/"$name".key \
        --metrics-enable --api-port "$A" --metrics-port "$M" \
        --attestation-committee-count "$ACC" $aggflags \
        --checkpoint-sync-url "$CSURL" --db-backend lmdb >/dev/null
      ;;
    ream)
      sudo docker run -d --restart unless-stopped --name "$cname" --network host \
        $MEMLIMITS $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$name":/data \
        "$REAM_IMG" --data-dir /data lean_node \
        --network /config/config.yaml \
        --validator-registry-path /config/annotated_validators.yaml \
        --bootnodes /config/nodes.yaml \
        --node-id "$name" --node-key /config/"$name".key --socket-port "$G" \
        --metrics --metrics-address 0.0.0.0 --metrics-port "$M" \
        --http-address 0.0.0.0 --http-port "$A" \
        --attestation-committee-count "$ACC" $aggflags \
        --checkpoint-sync-url "$CSURL" >/dev/null
      ;;
    gean)
      sudo docker run -d --restart unless-stopped --name "$cname" --network host \
        $MEMLIMITS $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$name":/data \
        "$GEAN_IMG" \
        --custom-network-config-dir /config --data-dir /data \
        --gossipsub-port "$G" --node-id "$name" --node-key /config/"$name".key \
        --http-address 0.0.0.0 --api-port "$A" --metrics-port "$M" \
        --attestation-committee-count "$ACC" $aggflags \
        --checkpoint-sync-url "$CSURL" >/dev/null
      ;;
    qlean)
      sudo docker run -d --restart unless-stopped --name "$cname" --network host \
        $MEMLIMITS $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$name":/data \
        "$QLEAN_IMG" \
        --genesis-dir /config --data-dir /data \
        --node-id "$name" --node-key /config/"$name".key \
        --listen-addr /ip4/0.0.0.0/udp/"$G"/quic-v1 \
        --metrics-host 0.0.0.0 --metrics-port "$M" \
        --api-host 0.0.0.0 --api-port "$A" \
        --attestation-committee-count "$ACC" $aggflags \
        --checkpoint-sync-url "$CSURL" -linfo >/dev/null
      ;;
    lantern)
      sudo docker run -d --restart unless-stopped --name "$cname" --network host \
        $MEMLIMITS $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$name":/data \
        "$LANTERN_IMG" \
        --data-dir /data --genesis-config /config/config.yaml \
        --nodes-path /config/nodes.yaml --genesis-state /config/genesis.ssz \
        --validator_config /config \
        --node-id "$name" --node-key-path /config/"$name".key \
        --listen-address /ip4/0.0.0.0/udp/"$G"/quic-v1 \
        --http-port "$A" --metrics-port "$M" \
        --hash-sig-key-dir /config/hash-sig-keys \
        --attestation-committee-count "$ACC" --devnet 12345678 $aggflags \
        --checkpoint-sync-url "$CSURL" >/dev/null
      ;;
    grandine)
      sudo docker run -d --restart unless-stopped --name "$cname" --network host \
        $MEMLIMITS $LOGOPT \
        -v "$GENESIS":/config -v "$DATA/$name":/data \
        "$GRANDINE_IMG" \
        --genesis /config/config.yaml --validator-registry-path /config/annotated_validators.yaml \
        --bootnodes /config/nodes.yaml --node-id "$name" --node-key /config/"$name".key \
        --port "$G" --address 0.0.0.0 --http-address 0.0.0.0 --http-port "$A" \
        --metrics --metrics-address 0.0.0.0 --metrics-port "$M" \
        --hash-sig-key-dir /config/hash-sig-keys \
        --attestation-committee-count "$ACC" $aggflags \
        --checkpoint-sync-url "$CSURL" >/dev/null
      ;;
    *) log "ERROR unknown client '$client' for $name"; return 1;;
  esac
  log "converted $name -> $client$([ "$agg" = yes ] && echo ' [AGGREGATOR]')"
}

sudo mkdir -p "$CRASH"
log "=== convert start cs_port=$CS acc=$ACC specs=[$*] ==="
for spec in "$@"; do convert_node "$spec"; done
log "=== convert done ==="
