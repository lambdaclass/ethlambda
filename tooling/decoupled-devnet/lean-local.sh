#!/usr/bin/env bash
# A local lean devnet running the decoupled consensus protocol: N ethlambda
# processes on 127.0.0.1, one validator each, peering over discv5 from node 0.
#
#   tooling/decoupled-devnet/lean-local.sh start   # keys, genesis, start nodes
#   tooling/decoupled-devnet/lean-local.sh status  # each node's decoupled view
#   tooling/decoupled-devnet/lean-local.sh stop
#
# Environment: N (nodes, default 4), DIR (work dir, default
# /tmp/ethlambda-decoupled-lean), BIN (ethlambda binary, default
# target/release-fast/ethlambda), SLOT_MS (default 4000), LOCK_PERIOD
# (Goldilocks' k, default 4), GENESIS_DELAY (seconds, default 30).
set -euo pipefail

N=${N:-4}
DIR=${DIR:-/tmp/ethlambda-decoupled-lean}
BIN=${BIN:-target/release-fast/ethlambda}
SLOT_MS=${SLOT_MS:-4000}
LOCK_PERIOD=${LOCK_PERIOD:-4}
GENESIS_DELAY=${GENESIS_DELAY:-30}

gossip_port() { echo $((9300 + $1)); }
discovery_port() { echo $((9400 + $1)); }
api_port() { echo $((5300 + $1)); }
metrics_port() { echo $((5400 + $1)); }

hex_of() { xxd -p -c 256 "$1" | tr -d '\n'; }

start() {
  rm -rf "$DIR"
  mkdir -p "$DIR/keys"
  "$BIN" keygen --num-validators "$N" --log-num-active-epochs 14 --output-dir "$DIR/keys" >/dev/null

  local genesis=$(( $(date +%s) + GENESIS_DELAY ))
  {
    echo "GENESIS_TIME: $genesis"
    echo "MILLISECONDS_PER_SLOT: $SLOT_MS"
    echo "DECOUPLED_CONSENSUS: true"
    echo "DECOUPLED_LOCK_PERIOD: $LOCK_PERIOD"
    echo "GENESIS_VALIDATORS:"
    for i in $(seq 0 $((N - 1))); do
      echo "  - attestation_pubkey: \"$(hex_of "$DIR/keys/validator_${i}_attester_key_pk.ssz")\""
      echo "    proposal_pubkey: \"$(hex_of "$DIR/keys/validator_${i}_proposer_key_pk.ssz")\""
    done
  } >"$DIR/config.yaml"

  : >"$DIR/annotated_validators.yaml"
  echo "validators:" >"$DIR/validator-config.yaml"
  for i in $(seq 0 $((N - 1))); do
    openssl rand -hex 32 | tr -d '\n' >"$DIR/node_$i.key"
    {
      echo "node_$i:"
      echo "  - index: $i"
      echo "    pubkey_hex: \"$(hex_of "$DIR/keys/validator_${i}_attester_key_pk.ssz")\""
      echo "    privkey_file: validator_${i}_attester_key_sk.ssz"
      echo "  - index: $i"
      echo "    pubkey_hex: \"$(hex_of "$DIR/keys/validator_${i}_proposer_key_pk.ssz")\""
      echo "    privkey_file: validator_${i}_proposer_key_sk.ssz"
    } >>"$DIR/annotated_validators.yaml"
    {
      echo "  - name: node_$i"
      echo "    privkey: \"0x$(cat "$DIR/node_$i.key")\""
    } >>"$DIR/validator-config.yaml"
  done

  launch 0
  local enr=""
  for _ in $(seq 1 50); do
    enr=$(grep -o 'enr:-[A-Za-z0-9_-]*' "$DIR/node_0.log" | head -1 || true)
    [ -n "$enr" ] && break
    sleep 0.2
  done
  [ -n "$enr" ] || { echo "node 0 printed no ENR; see $DIR/node_0.log" >&2; exit 1; }
  echo "- $enr" >"$DIR/bootnodes.yaml"
  for i in $(seq 1 $((N - 1))); do
    launch "$i"
  done
  echo "genesis at $(date -r "$genesis" '+%H:%M:%S'); logs in $DIR/node_*.log"
}

launch() {
  local i=$1
  local bootnodes=()
  if [ "$i" -ne 0 ]; then bootnodes=(--bootnodes "$DIR/bootnodes.yaml"); fi
  RUST_LOG=${RUST_LOG:-info} "$BIN" node \
    --genesis "$DIR/config.yaml" \
    --validators "$DIR/annotated_validators.yaml" \
    --validator-config "$DIR/validator-config.yaml" \
    --hash-sig-keys-dir "$DIR/keys" \
    --node-id "node_$i" \
    --node-key "$DIR/node_$i.key" \
    --data-dir "$DIR/data_$i" \
    --gossipsub-port "$(gossip_port "$i")" \
    --api-port "$(api_port "$i")" \
    --metrics-port "$(metrics_port "$i")" \
    --discovery.enable \
    --discovery.port "$(discovery_port "$i")" \
    --discovery.advertise-ip 127.0.0.1 \
    ${bootnodes[@]+"${bootnodes[@]}"} \
    >"$DIR/node_$i.log" 2>&1 &
  echo $! >"$DIR/node_$i.pid"
}

status() {
  for pidfile in "$DIR"/node_*.pid; do
    local i=${pidfile##*node_}
    i=${i%.pid}
    printf 'node_%s ' "$i"
    curl -s "http://127.0.0.1:$(api_port "$i")/lean/v0/decoupled/status" || echo "(no answer)"
    echo
  done
}

stop() {
  for pidfile in "$DIR"/node_*.pid; do
    kill -INT "$(cat "$pidfile")" 2>/dev/null || true
  done
}

case "${1:-}" in
  start) start ;;
  status) status ;;
  stop) stop ;;
  # Restart one node on its existing data directory, appending to its log.
  restart)
    mv "$DIR/node_$2.log" "$DIR/node_$2.log.$(date +%s)"
    launch "$2"
    ;;
  *) echo "usage: $0 start|status|stop|restart <i>" >&2; exit 2 ;;
esac
