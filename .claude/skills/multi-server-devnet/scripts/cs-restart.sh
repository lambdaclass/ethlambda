#!/bin/bash
# Checkpoint-sync restart of ethlambda nodes on ONE devnet's host, in place.
# Recover crashed/frozen/split nodes, canary an image, or set the aggregator role
# WITHOUT resetting the chain. This is the ONLY restart path: a separate script
# per role drifts out of the one used every day, which is how the role handling
# got lost in the first place.
#
# ALWAYS uses checkpoint sync (a keep-DB resume can panic the consensus actor on
# older images -- `store.rs` `expect("safe target exists")` -- leaving the process
# up with consensus dead). Keeps the mandatory 60s gossip backoff for nodes that
# were running, so they re-graft cleanly (skip it and they attest but aggregators
# never hear them -> finality stalls below the 2/3 threshold). Saves one crash log
# per removed container.
# Ports per node n: gossip 9000+n, api 5052+n, metrics 9200+n (no BASE offset).
#
# THE AGGREGATOR ROLE IS PRESERVED BY DEFAULT. A node restarted without
# --is-aggregator stops storing gossip signatures, so its subnet's votes are never
# aggregated: attestations still verify, the logs look healthy, and the devnet
# quietly stops finalizing with attestation_count=0. So the topology flags
# (--is-aggregator / --aggregate-subnet-ids / --attestation-committee-count) are
# read off the container being replaced and passed through unless you ask
# otherwise. Experiment flags are deliberately NOT carried over -- a restart is
# where an experiment ends.
#
# Usage (on host):  cs-restart.sh <CS_PORT[,CS_PORT...]> <node>...
#   CS_PORT  api port of a HEALTHY same-devnet node to checkpoint-sync from
#            (an aggregator stays up -- use it; but do NOT point an aggregator at
#            itself). Comma-separate several for redundancy: ethlambda tries them
#            in order and only aborts if every one fails.
#   node...  node indices to restart, one at a time per host
#
# Env:
#   IMAGE    image to run (default ghcr.io/lambdaclass/ethlambda:devnet5). Set it
#            to canary a PR build on specific nodes, aggregators included.
#   AGG      role control:
#              unset   preserve the role the container already has   [default]
#              auto    apply the topology rule (node n aggregates subnet n while
#                      n < SUBNETS, otherwise non-aggregator). Needs SUBNETS.
#                      Use this to repair a node that lost its role.
#              <id>    force --is-aggregator on subnet <id> (promote). With more
#                      than one node this puts them ALL on <id> -- usually you
#                      want AGG=auto instead.
#              off     force non-aggregator (deliberate demotion).
#   SUBNETS  the devnet's committee count. Authoritative for
#            --attestation-committee-count, drives AGG=auto, and is the fallback
#            for the role when the container is already gone (nothing to read).
#   GENESIS, DATA, CRASH, MEMLIMITS, LOGOPT
set -u
CS=$1; shift; NODES="$*"
IMAGE=${IMAGE:-ghcr.io/lambdaclass/ethlambda:devnet5}
GENESIS=${GENESIS:-/opt/lean-quickstart/genesis}
DATA=${DATA:-/opt/lean-quickstart/data}
MEMLIMITS=${MEMLIMITS:-"--memory 8g --memory-swap 16g --memory-reservation 2g"}
LOGOPT=${LOGOPT:-"--log-opt max-size=200m --log-opt max-file=5"}  # 1 GiB hot buffer; Loki (7d) holds the long-term record
CRASH=${CRASH:-/opt/lean-quickstart/crash-logs}
LOG=/tmp/cs-restart.log
TS=$(date +%Y%m%d-%H%M%S)
log(){ echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"; }

: > "$LOG"
# Validate everything before touching a container: discovering a bad argument
# halfway through leaves nodes destroyed and not restarted.
for n in $NODES; do
  case "$n" in ''|*[!0-9]*) log "ERROR: bad node index '$n'"; exit 1;; esac
done
case "${AGG:-}" in
  ''|off|auto) ;;
  *[!0-9,]*) log "ERROR: AGG must be a subnet id, 'auto', or 'off' (got '$AGG')"; exit 1;;
esac
if [ "${AGG:-}" = auto ] && [ -z "${SUBNETS:-}" ]; then
  log "ERROR: AGG=auto needs SUBNETS=<committee count> to know which nodes aggregate"; exit 1
fi

# One URL per CS_PORT; ethlambda accepts a comma-separated list and falls over to
# the next when a peer is unreachable.
CSURL=""
for p in ${CS//,/ }; do
  CSURL="${CSURL:+$CSURL,}http://127.0.0.1:$p/lean/v0/states/finalized"
done

arg_value(){  # $1 = flag, $2 = full command line -> the token after the flag
  awk -v f="$1" '{for(i=1;i<=NF;i++) if($i==f) print $(i+1)}' <<<"$2" | head -1
}
resolve_role(){  # $1 = container id ("" if none), $2 = node index -> topology flags
  local cmd="" acc="" sub="" agg=no
  # ENTRYPOINT is the binary, so the node's run args are .Config.Cmd
  [ -n "$1" ] && cmd=$(sudo docker inspect -f '{{join .Config.Cmd " "}}' "$1" 2>/dev/null)
  if [ -n "$cmd" ]; then
    acc=$(arg_value --attestation-committee-count "$cmd")
    sub=$(arg_value --aggregate-subnet-ids "$cmd")
    case " $cmd " in
      *" --is-aggregator=false "*) agg=no ;;
      *" --is-aggregator "*|*" --is-aggregator=true "*) agg=yes ;;
    esac
  elif [ -n "${SUBNETS:-}" ] && [ "$2" -lt "$SUBNETS" ]; then
    agg=yes; sub=$2                       # nothing to read: fall back to the rule
  fi
  [ -n "${SUBNETS:-}" ] && acc=$SUBNETS   # explicit SUBNETS wins over the old value
  case "${AGG:-}" in
    off)  agg=no ;;
    auto) if [ "$2" -lt "$SUBNETS" ]; then agg=yes; sub=$2; else agg=no; fi ;;
    ?*)   agg=yes; sub=$AGG ;;
  esac
  # --aggregate-subnet-ids requires --is-aggregator (clap refuses to start otherwise)
  [ "$agg" = yes ] || sub=""
  printf '%s%s%s' "${acc:+ --attestation-committee-count $acc}" \
                  "${sub:+ --aggregate-subnet-ids $sub}" \
                  "$([ "$agg" = yes ] && echo ' --is-aggregator')"
}

sudo mkdir -p "$CRASH"
log "=== cs-restart cs=[$CS] nodes=[$NODES] image=$IMAGE role=${AGG:-preserve} ==="
for n in $NODES; do
  name=node_$n; cname=ethlambda_$n; G=$((9000+n)); A=$((5052+n)); M=$((9200+n))
  # A node index can have several containers (e.g. a stopped canary left over from
  # a conversion plus the running one) -- they all end in _$n. One crash log each:
  # passing several ids to `docker logs` (or letting the id list keep its newline
  # inside `sh -c "... > file"`) loses the log, which is the one artifact worth
  # having when debugging a crash.
  cids=""
  while read -r cid cnm; do
    [ -n "$cid" ] || continue
    cids="${cids:+$cids }$cid"
    cnm=$(printf '%s' "${cnm:-$cid}" | tr -c 'A-Za-z0-9_.-' '_')
    sudo sh -c "docker logs '$cid' > '$CRASH/${cnm}-${TS}.log' 2>&1" \
      && log "saved $CRASH/${cnm}-${TS}.log"
  done < <(sudo docker ps -a --filter "name=_${n}$" --format '{{.ID}} {{.Names}}')
  # decide the role from the most recent container BEFORE removing anything
  role=$(resolve_role "${cids%% *}" "$n")
  existed=no; [ -n "$cids" ] && existed=yes
  [ -n "$cids" ] && sudo docker rm -f $cids >/dev/null 2>&1
  # Wipe the whole dir, not `dir/*`: the glob is expanded by THIS (unprivileged)
  # shell, so an unreadable dir would silently leave the stale DB in place and the
  # node would come back on it. Recreate immediately -- docker must find it there.
  sudo rm -rf "$DATA/$name"; sudo mkdir -p "$DATA/$name"
  if [ "$existed" = yes ]; then log "stopped node_$n container(s); 60s gossip backoff"; sleep 60; fi
  sudo docker run -d --restart unless-stopped --name "$cname" --network host $MEMLIMITS $LOGOPT \
    -v "$GENESIS":/config -v "$DATA/$name":/data "$IMAGE" \
    --genesis /config/config.yaml --validators /config/annotated_validators.yaml \
    --bootnodes /config/nodes.yaml --validator-config /config/validator-config.yaml \
    --hash-sig-keys-dir /config/hash-sig-keys --data-dir /data \
    --gossipsub-port "$G" --node-id "$name" --node-key /config/"$name".key \
    --http-address 0.0.0.0 --api-port "$A" --metrics-port "$M" $role \
    --checkpoint-sync-url "$CSURL" >/dev/null
  log "started $cname (node_$n)${role:+ [$role]} (checkpoint sync from $CS)"
done
log "=== cs-restart done ==="
