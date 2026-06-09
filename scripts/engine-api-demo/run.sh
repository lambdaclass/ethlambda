#!/usr/bin/env bash
#
# Engine API integration demo: one ethlambda consensus node paired with one
# ethrex execution node over the Engine API. ethlambda builds a block every
# slot, asks ethrex to produce the execution payload, embeds it, and ethrex
# imports it — the chain advances and finalizes on both layers.
#
# This is a single-validator demo (finalizes solo). Usage:
#
#   scripts/engine-api-demo/run.sh           # start the demo
#   scripts/engine-api-demo/run.sh stop      # stop it
#
# Prerequisites:
#   - ethrex on PATH (v15+), or set ETHREX=/path/to/ethrex
#   - a dual-key (devnet5+) lean genesis bundle. By default the script looks in
#     lean-quickstart/local-devnet/genesis; generate one with:
#         cd lean-quickstart && ./generate-genesis.sh local-devnet/genesis
#     (requires the lean-quickstart `main` branch and Docker).
#   - cargo (to build ethlambda) unless SKIP_BUILD=1.
#
# Config via environment variables (defaults in parens):
#   ETHREX             (ethrex)            ethrex binary
#   LEAN_GENESIS_DIR   (lean-quickstart/local-devnet/genesis)
#   DATA_DIR           ($TMPDIR/ethlambda-el-demo)
#   GENESIS_OFFSET     (12)                seconds until genesis
#   AUTHRPC_PORT 8551  EL_HTTP_PORT 8545  API_PORT 5052  METRICS_PORT 5054
#   SKIP_BUILD         (unset)            set to 1 to skip `cargo build`
#
# No `set -e`: the script intentionally probes/kills ports that may be empty.

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/scripts/engine-api-demo"

ETHREX="${ETHREX:-ethrex}"
LEAN_GENESIS_DIR="${LEAN_GENESIS_DIR:-$REPO/lean-quickstart/local-devnet/genesis}"
DATA_DIR="${DATA_DIR:-${TMPDIR:-/tmp}/ethlambda-el-demo}"
EL_GENESIS="$HERE/genesis-el.json"
JWT="$DATA_DIR/jwt.hex"
GENESIS_OFFSET="${GENESIS_OFFSET:-12}"
AUTHRPC_PORT="${AUTHRPC_PORT:-8551}"
EL_HTTP_PORT="${EL_HTTP_PORT:-8545}"
API_PORT="${API_PORT:-5052}"
METRICS_PORT="${METRICS_PORT:-5054}"

ETHLAMBDA="$REPO/target/release/ethlambda"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; }

kill_ports() {
  for port in "$AUTHRPC_PORT" "$EL_HTTP_PORT" "$API_PORT" "$METRICS_PORT" 9000; do
    pid=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null; lsof -nP -iUDP:"$port" -t 2>/dev/null)
    [ -n "$pid" ] && kill $pid 2>/dev/null
  done
}

if [ "$1" = "stop" ]; then
  log "Stopping demo"
  kill_ports
  echo "stopped"
  exit 0
fi

# --- preflight ----------------------------------------------------------------
if ! command -v "$ETHREX" >/dev/null 2>&1; then
  err "ethrex not found (looked for '$ETHREX'). Install it or set ETHREX=/path/to/ethrex."
  exit 1
fi

if [ ! -f "$LEAN_GENESIS_DIR/config.yaml" ]; then
  err "lean genesis not found at $LEAN_GENESIS_DIR"
  err "Generate a dual-key bundle: (cd lean-quickstart && ./generate-genesis.sh local-devnet/genesis)"
  err "or point LEAN_GENESIS_DIR at an existing devnet5+ bundle."
  exit 1
fi
if ! ls "$LEAN_GENESIS_DIR"/hash-sig-keys/*attester*sk.ssz >/dev/null 2>&1; then
  err "lean genesis at $LEAN_GENESIS_DIR is not dual-key (no *_attester_key_sk.ssz)."
  err "ethlambda needs a devnet5+ bundle (separate attestation + proposal keys)."
  exit 1
fi

mkdir -p "$DATA_DIR"

if [ "$SKIP_BUILD" != "1" ]; then
  log "Building ethlambda (release) — set SKIP_BUILD=1 to skip"
  (cd "$REPO" && cargo build --release --bin ethlambda) || { err "build failed"; exit 1; }
fi
[ -x "$ETHLAMBDA" ] || { err "ethlambda binary not found at $ETHLAMBDA"; exit 1; }

[ -f "$JWT" ] || { log "Generating JWT secret"; openssl rand -hex 32 > "$JWT"; }

log "Stopping any previous demo processes"
kill_ports
sleep 1

# --- start ethrex -------------------------------------------------------------
log "Starting ethrex (EL): $("$ETHREX" --version 2>/dev/null | head -1)"
rm -rf "$DATA_DIR/ethrex-data"
"$ETHREX" --network "$EL_GENESIS" --datadir "$DATA_DIR/ethrex-data" \
          --authrpc.addr 127.0.0.1 --authrpc.port "$AUTHRPC_PORT" --authrpc.jwtsecret "$JWT" \
          --http.addr 127.0.0.1 --http.port "$EL_HTTP_PORT" --p2p.disabled --syncmode full \
          --log.level info > "$DATA_DIR/ethrex.log" 2>&1 &
echo "    ethrex pid $! (log: $DATA_DIR/ethrex.log)"

# wait for Auth-RPC + read the genesis block hash from the log
EL_GENESIS_HASH=""
for _ in $(seq 1 40); do
  if [ -z "$EL_GENESIS_HASH" ]; then
    EL_GENESIS_HASH=$(grep -aoE 'Genesis Block Hash: [0-9a-fA-F]+' "$DATA_DIR/ethrex.log" 2>/dev/null | head -1 | awk '{print $NF}')
  fi
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:$AUTHRPC_PORT" \
         -H 'content-type: application/json' --data '{}' 2>/dev/null)
  [ "$code" = "200" ] && [ -n "$EL_GENESIS_HASH" ] && break
  sleep 0.5
done
if [ -z "$EL_GENESIS_HASH" ]; then err "couldn't read ethrex genesis hash"; exit 1; fi
echo "    ethrex up — genesis hash 0x$EL_GENESIS_HASH"

# --- start ethlambda ----------------------------------------------------------
NEW_GT=$(( $(date +%s) + GENESIS_OFFSET ))
# re-stamp GENESIS_TIME so the chain starts shortly after launch
if sed --version >/dev/null 2>&1; then
  sed -i "s/^GENESIS_TIME:.*/GENESIS_TIME: $NEW_GT/" "$LEAN_GENESIS_DIR/config.yaml"
else
  sed -i '' "s/^GENESIS_TIME:.*/GENESIS_TIME: $NEW_GT/" "$LEAN_GENESIS_DIR/config.yaml"
fi

log "Starting ethlambda (CL) paired with ethrex"
rm -rf "$DATA_DIR/ethlambda-data"
"$ETHLAMBDA" \
    --genesis "$LEAN_GENESIS_DIR/config.yaml" \
    --validators "$LEAN_GENESIS_DIR/annotated_validators.yaml" \
    --bootnodes "$LEAN_GENESIS_DIR/nodes.yaml" \
    --validator-config "$LEAN_GENESIS_DIR/validator-config.yaml" \
    --hash-sig-keys-dir "$LEAN_GENESIS_DIR/hash-sig-keys" \
    --node-key "$LEAN_GENESIS_DIR/ethlambda_0.key" \
    --node-id ethlambda_0 --is-aggregator --data-dir "$DATA_DIR/ethlambda-data" \
    --api-port "$API_PORT" --metrics-port "$METRICS_PORT" \
    --execution-endpoint "http://127.0.0.1:$AUTHRPC_PORT" \
    --execution-jwt-secret "$JWT" \
    --execution-genesis-block-hash "0x$EL_GENESIS_HASH" \
    > "$DATA_DIR/ethlambda.log" 2>&1 &
echo "    ethlambda pid $! (log: $DATA_DIR/ethlambda.log)"

cat <<EOF

================  DEMO IS RUNNING  ================
Genesis in ~${GENESIS_OFFSET}s, then a block every 4s. Give it ~30s, then:

1. EL importing CL-built payloads (chain climbing; "miner" = configured fee recipient):
     curl -s -X POST http://127.0.0.1:$EL_HTTP_PORT -H 'content-type: application/json' \\
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}' \\
       | jq '.result | {number, hash, miner}'

2. ethlambda fork-choice UI (browser):
     open http://127.0.0.1:$API_PORT/lean/v0/fork_choice/ui

3. Both layers in lockstep:
     tail -f $DATA_DIR/ethlambda.log | grep -E 'proposer|finalized|head updated'
     tail -f $DATA_DIR/ethrex.log    | grep -E 'BLOCK|executed|Fork choice'

Stop:  scripts/engine-api-demo/run.sh stop
==================================================
EOF
