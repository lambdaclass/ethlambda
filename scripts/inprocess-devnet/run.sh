#!/usr/bin/env bash
#
# Standalone in-process ethrex devnet.
#
# Spins up an N-node ethlambda devnet where every node embeds its own ethrex
# execution layer (enabled by --el-genesis). Self-contained: it generates the
# validator keys, consensus genesis, ENRs and EL genesis itself, so it does NOT
# need a lean-quickstart checkout.
#
# Requirements: docker, yq. Everything else runs in containers.
#
#   ./run.sh                        # 3 nodes, 20 slots, then tear down
#   ./run.sh --nodes 1 --slots 10   # single node
#   ./run.sh --trace --keep         # EL trace logs, leave nodes running
#   ./run.sh --build                # build the node image from this repo first
#   ./run.sh --no-tx                # skip the transaction submission/inclusion check
#
set -euo pipefail

# ---------------------------------------------------------------- defaults ----
NODES=3
SLOTS=20
IMAGE="ghcr.io/lambdaclass/ethlambda:local"
WORKDIR=""
EL_GENESIS=""
ACTIVE_EPOCH=18
GENESIS_OFFSET=30          # seconds from launch until slot 0
SECONDS_PER_SLOT=4
TRACE=false
KEEP=false
BUILD=false
VERIFY=true
NO_EL=false
NO_TX=false
NO_EL_P2P=false

KEYGEN_IMAGE="blockblaz/hash-sig-cli:latest"
GENESIS_IMAGE="ethpandaops/eth-beacon-genesis:pk910-leanchain"

# Deterministic test node keys (secp256k1). Extend if you need more than 5 nodes.
PRIVKEYS=(
  "299550529a79bc2dce003747c52fb0639465c893e00b0440ac66144d625e066a"
  "bdf953adc161873ba026330c56450453f582e3c4ee6cb713644794bcfdd85fe5"
  "af27950128b49cda7e7bc9fcb7b0270f7a3945aa7543326f3bfdbd57d2a97a32"
  "c2bbdac5e876b3e9d4b8b6b8c2bbdac5e876b3e9d4b8b6b8c2bbdac5e876b3e9"
  "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ------------------------------------------------------------------- args -----
while [[ $# -gt 0 ]]; do
  case "$1" in
    --nodes)       NODES="$2"; shift 2 ;;
    --slots)       SLOTS="$2"; shift 2 ;;
    --image)       IMAGE="$2"; shift 2 ;;
    --workdir)     WORKDIR="$2"; shift 2 ;;
    --el-genesis)  EL_GENESIS="$2"; shift 2 ;;
    --trace)       TRACE=true; shift ;;
    --keep)        KEEP=true; shift ;;
    --build)       BUILD=true; shift ;;
    --no-tx)       NO_TX=true; shift ;;
    --no-el-p2p)   NO_EL_P2P=true; shift ;;
    --no-verify)   VERIFY=false; shift ;;
    --no-el)       NO_EL=true; shift ;;
    -h|--help)     sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done

WORKDIR="${WORKDIR:-$REPO_ROOT/.devnet-inprocess}"
GENESIS_DIR="$WORKDIR/genesis"
LOG_DIR="$WORKDIR/logs"

if (( NODES < 1 || NODES > ${#PRIVKEYS[@]} )); then
  echo "--nodes must be between 1 and ${#PRIVKEYS[@]}" >&2; exit 2
fi

step() { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

node_name() { echo "ethlambda_$1"; }

# -------------------------------------------------------------- preflight -----
step "Preflight"
command -v docker >/dev/null || die "docker not found"
docker info >/dev/null 2>&1 || die "docker daemon is not running"
command -v yq >/dev/null || die "yq not found (brew install yq)"
ok "docker + yq present"

if [[ "$BUILD" == true ]]; then
  step "Building node image ($IMAGE)"
  ( cd "$REPO_ROOT" && make docker-build DOCKER_TAG="${IMAGE##*:}" ) || die "image build failed"
  ok "image built"
fi
docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image $IMAGE not found — run with --build, or 'make docker-build DOCKER_TAG=local'"
ok "image $IMAGE present"

# The EL genesis MUST be Cancun: a Prague genesis expects a requests_hash that
# the Cancun-shaped ExecutionPayloadV3 cannot carry, and newPayload rejects
# every block ("Requests hash is not present").
EL_GENESIS="${EL_GENESIS:-$REPO_ROOT/crates/net/ethrex-engine/tests/fixtures/genesis.json}"
[[ -f "$EL_GENESIS" ]] || die "EL genesis not found: $EL_GENESIS"
if grep -q '"pragueTime"' "$EL_GENESIS"; then
  die "EL genesis $EL_GENESIS activates Prague; the in-process V3 path needs a Cancun genesis"
fi
ok "EL genesis is Cancun: $EL_GENESIS"

# --------------------------------------------------------------- teardown -----
teardown() {
  local names=()
  for ((i = 0; i < NODES; i++)); do names+=("$(node_name "$i")"); done
  step "Collecting logs"
  mkdir -p "$LOG_DIR"
  for n in "${names[@]}"; do
    docker logs "$n" > "$LOG_DIR/$n.log" 2>&1 || true
    [[ -s "$LOG_DIR/$n.log" ]] && ok "$LOG_DIR/$n.log ($(wc -l < "$LOG_DIR/$n.log" | tr -d ' ') lines)"
  done
  step "Stopping nodes"
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
  ok "removed"
}

# ------------------------------------------------------- fresh working dir ----
step "Preparing $WORKDIR"
rm -rf "$WORKDIR"
mkdir -p "$GENESIS_DIR" "$LOG_DIR"
# Remove any containers left over from a previous run (stale genesis would
# otherwise cause deserialization / UnknownSourceBlock errors).
for ((i = 0; i < NODES; i++)); do docker rm -f "$(node_name "$i")" >/dev/null 2>&1 || true; done
ok "clean"

# --------------------------------------------------- validator-config.yaml ----
# One aggregator is mandatory: without it attestation signatures are never
# stored for aggregation and the chain never finalizes.
step "Writing validator-config.yaml ($NODES node(s), node 0 aggregates)"
{
  echo "shuffle: roundrobin"
  echo "deployment_mode: local"
  echo "config:"
  echo "  activeEpoch: $ACTIVE_EPOCH"
  echo '  keyType: "hash-sig"'
  echo "validators:"
  for ((i = 0; i < NODES; i++)); do
    echo "  - name: \"$(node_name "$i")\""
    echo "    privkey: \"${PRIVKEYS[$i]}\""
    echo "    enrFields:"
    echo '      ip: "127.0.0.1"'
    echo "      quic: $((9001 + i))"
    echo "    metricsPort: $((8081 + i))"
    echo "    apiPort: $((15052 + i))"
    echo "    isAggregator: $([[ $i -eq 0 ]] && echo true || echo false)"
    echo "    count: 1"
  done
} > "$GENESIS_DIR/validator-config.yaml"
ok "$NODES validator(s)"

# --------------------------------------------------------- seed config.yaml ---
GENESIS_TIME=$(( $(date +%s) + GENESIS_OFFSET ))
{
  echo "GENESIS_TIME: $GENESIS_TIME"
  echo "ACTIVE_EPOCH: $ACTIVE_EPOCH"
  echo "VALIDATOR_COUNT: $NODES"
} > "$GENESIS_DIR/config.yaml"
ok "genesis time $GENESIS_TIME (slot 0 in ${GENESIS_OFFSET}s)"

# ------------------------------------------------------------ XMSS keygen -----
# --export-format ssz produces the DUAL-KEY manifest (attester_key_pubkey_hex +
# proposer_key_pubkey_hex), which is what lets us emit the two-key
# GENESIS_VALIDATORS entries the client requires.
step "Generating XMSS validator keys (slow: ~1s per key)"
docker pull -q "$KEYGEN_IMAGE" >/dev/null 2>&1 || warn "could not pull $KEYGEN_IMAGE, using local copy"
docker run --rm --pull=never \
  --user "$(id -u):$(id -g)" \
  -v "$GENESIS_DIR:/genesis" \
  "$KEYGEN_IMAGE" generate \
  --num-validators "$NODES" \
  --log-num-active-epochs "$ACTIVE_EPOCH" \
  --output-dir "/genesis/hash-sig-keys" \
  --export-format ssz >/dev/null || die "hash-sig keygen failed"

MANIFEST="$GENESIS_DIR/hash-sig-keys/validator-keys-manifest.yaml"
[[ -f "$MANIFEST" ]] || die "keygen produced no manifest at $MANIFEST"
grep -q "attester_key_pubkey_hex" "$MANIFEST" \
  || die "manifest is not dual-key; this client needs attestation_pubkey + proposal_pubkey"
ok "dual-key manifest for $NODES validator(s)"

# ------------------------------------------------- GENESIS_VALIDATORS entries --
step "Appending GENESIS_VALIDATORS to config.yaml"
{
  echo "GENESIS_VALIDATORS:"
  for ((i = 0; i < NODES; i++)); do
    AH=$(yq eval ".validators[$i].attester_key_pubkey_hex" "$MANIFEST")
    PH=$(yq eval ".validators[$i].proposer_key_pubkey_hex" "$MANIFEST")
    [[ "$AH" != "null" && "$PH" != "null" ]] || die "missing pubkeys for validator $i"
    echo "  - attestation_pubkey: \"${AH#0x}\""
    echo "    proposal_pubkey: \"${PH#0x}\""
  done
} >> "$GENESIS_DIR/config.yaml"
ok "dual-key entries written"

# --------------------------------------------- consensus genesis + ENRs -------
step "Generating consensus genesis, validators.yaml and ENRs"
docker pull -q "$GENESIS_IMAGE" >/dev/null 2>&1 || warn "could not pull $GENESIS_IMAGE, using local copy"
docker run --rm --pull=never \
  --user "$(id -u):$(id -g)" \
  -v "$WORKDIR:/data" \
  "$GENESIS_IMAGE" leanchain \
  --config "/data/genesis/config.yaml" \
  --mass-validators "/data/genesis/validator-config.yaml" \
  --state-output "/data/genesis/genesis.ssz" \
  --json-output "/data/genesis/genesis.json" \
  --nodes-output "/data/genesis/nodes.yaml" \
  --validators-output "/data/genesis/validators.yaml" \
  --config-output "/data/genesis/config.yaml" >/dev/null || die "genesis generation failed"

for f in config.yaml validators.yaml nodes.yaml genesis.json genesis.ssz; do
  [[ -s "$GENESIS_DIR/$f" ]] || die "genesis step did not produce $f"
done
ok "config.yaml validators.yaml nodes.yaml genesis.json genesis.ssz"

# ------------------------------------------- annotated_validators.yaml --------
# The client's --validators flag wants this file, NOT the genesis tool's
# validators.yaml (which is just node -> [validator index]). Each validator
# contributes two entries — attester and proposer — sharing one index, each
# naming its secret-key file inside hash-sig-keys/.
step "Writing annotated_validators.yaml"
{
  for ((i = 0; i < NODES; i++)); do
    echo "$(node_name "$i"):"
    for role in attester proposer; do
      PUB=$(yq eval ".validators[$i].${role}_key_pubkey_hex" "$MANIFEST")
      SK=$(yq eval ".validators[$i].${role}_key_privkey_file" "$MANIFEST")
      [[ "$PUB" != "null" && "$SK" != "null" ]] || die "manifest lacks $role key for validator $i"
      echo "  - index: $i"
      echo "    pubkey_hex: ${PUB#0x}"
      echo "    privkey_file: $SK"
    done
    echo
  done
} > "$GENESIS_DIR/annotated_validators.yaml"
ok "$((NODES * 2)) key entries ($NODES attester + $NODES proposer)"

# ------------------------------------------------------- node keys + EL --------
step "Writing node keys and EL genesis"
for ((i = 0; i < NODES; i++)); do
  echo "${PRIVKEYS[$i]}" > "$GENESIS_DIR/$(node_name "$i").key"
done
cp "$EL_GENESIS" "$GENESIS_DIR/el-genesis.json"
ok "$NODES node key(s) + el-genesis.json"

# ---------------------------------------------------------------- launch ------
# The EL hooks log at trace!, so they are invisible at the default INFO level.
# `el_integration` covers build/FCU/gossip-import; the "newPayload on own-built
# block" line lives in the parent `ethlambda_blockchain` module, so enable both.
RUST_LOG_VALUE="info"
[[ "$TRACE" == true ]] && RUST_LOG_VALUE="info,ethlambda_blockchain=trace"

step "Starting $NODES node(s) with an embedded execution layer"
# Execution-layer devp2p ports. Distinct from consensus gossip (9001+) and from
# the API/metrics ports; one value per node serves both RLPx and discv4.
el_p2p_port() { echo "$((30303 + $1))"; }
# Node 0's enode, harvested from its log once it is up and used as the single
# bootnode for the rest. Only node 0's is needed: discv4 finds the remainder of
# the mesh from there. It cannot be computed here because the execution-layer key
# is a keccak derivation of the consensus node key and bash cannot do secp256k1.
EL_BOOTNODE=""

for ((i = 0; i < NODES; i++)); do
  NAME="$(node_name "$i")"
  EL_ARGS=()
  if [[ "$NO_EL" == false ]]; then
    EL_ARGS+=(--el-genesis /config/el-genesis.json)
    if [[ "$NO_EL_P2P" == false ]]; then
      EL_ARGS+=(--el-p2p-port "$(el_p2p_port "$i")")
      [[ -n "$EL_BOOTNODE" ]] && EL_ARGS+=(--el-bootnodes "$EL_BOOTNODE")
    fi
  fi
  [[ $i -eq 0 ]] && EL_ARGS+=(--is-aggregator)

  # --network host: containers reach each other on 127.0.0.1 as the ENRs say.
  # Ports must therefore differ per node, which they do by construction above.
  # Deliberately NOT --rm: a crashed node must keep its logs for diagnosis.
  # `teardown` removes containers explicitly.
  docker run -d --pull=never \
    --name "$NAME" \
    --network host \
    -e "RUST_LOG=$RUST_LOG_VALUE" \
    -v "$GENESIS_DIR:/config" \
    -v "$WORKDIR/data/$NAME:/data" \
    "$IMAGE" \
    --genesis /config/config.yaml \
    --validators /config/annotated_validators.yaml \
    --bootnodes /config/nodes.yaml \
    --validator-config /config/validator-config.yaml \
    --hash-sig-keys-dir /config/hash-sig-keys \
    --node-id "$NAME" \
    --node-key "/config/$NAME.key" \
    --data-dir /data \
    --gossipsub-port "$((9001 + i))" \
    --http-address 0.0.0.0 \
    --metrics-port "$((8081 + i))" \
    --api-port "$((15052 + i))" \
    "${EL_ARGS[@]}" >/dev/null || die "failed to start $NAME"
  ok "$NAME (quic $((9001 + i)), api $((15052 + i)))$([[ $i -eq 0 ]] && echo ' [aggregator]')"

  # Harvest node 0's enode before starting the rest, so they can find it.
  if [[ $i -eq 0 && "$NO_EL" == false && "$NO_EL_P2P" == false ]]; then
    for _ in $(seq 1 40); do
      EL_BOOTNODE=$(docker logs "$NAME" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' |
        grep -o 'enode://[0-9a-fA-F]\{128\}@[0-9.]*:[0-9]*' | head -1 || true)
      [[ -n "$EL_BOOTNODE" ]] && break
      sleep 0.5
    done
    if [[ -n "$EL_BOOTNODE" ]]; then ok "EL bootnode: ${EL_BOOTNODE:0:26}...@${EL_BOOTNODE##*@}"
    else warn "no EL enode from $NAME; remaining nodes start without a bootnode"; fi
  fi
done

# Fail fast: a flag or config mistake kills nodes within a couple of seconds.
sleep 5
for ((i = 0; i < NODES; i++)); do
  NAME="$(node_name "$i")"
  if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    echo; docker logs "$NAME" 2>&1 | tail -20
    teardown; die "$NAME exited during startup (see output above)"
  fi
done
ok "all nodes alive"

if [[ "$KEEP" == true ]]; then
  step "Leaving nodes running (--keep)"
  echo "  logs:  docker logs -f $(node_name 0)"
  echo "  stop:  docker rm -f $(for ((i=0;i<NODES;i++)); do printf '%s ' "$(node_name "$i")"; done)"
  exit 0
fi

RUNTIME=$(( GENESIS_OFFSET + SLOTS * SECONDS_PER_SLOT ))
trap teardown EXIT

# Transactions can only be submitted while the nodes are up, and inclusion can
# only be read back from the API before teardown, so both happen mid-run.
if [[ "$NO_EL" == true || "$NO_TX" == true ]]; then
  step "Running for ~$SLOTS slots (${RUNTIME}s: ${GENESIS_OFFSET}s to genesis + ${SLOTS}×${SECONDS_PER_SLOT}s)"
  sleep "$RUNTIME"
else
  # Let genesis pass and a few blocks accumulate before submitting, so the
  # transaction lands in a normal steady-state block rather than block 1.
  SETTLE=$(( GENESIS_OFFSET + 4 * SECONDS_PER_SLOT ))
  step "Running to genesis + 4 slots (${SETTLE}s) before submitting a transaction"
  sleep "$SETTLE"

  # The same signed nonce-0 transfer the RPC tests post: 1 wei from the
  # genesis-funded 0xf39f...2266. Each run generates a fresh chain, so nonce 0
  # is always the right nonce.
  TX_FILE="$REPO_ROOT/crates/net/rpc/tests/fixtures/signed_transfer_nonce_0.hex"
  TX_RAW="$(tr -d '\n\r ' < "$TX_FILE")"
  TX_BODY="$(printf '0x%s' "${TX_RAW#0x}")"

  # Who to submit to. With execution-layer gossip the whole point is that it does
  # NOT have to be the next proposer, so submit to exactly one node and pick one
  # that is not about to propose — then a different proposer including it is proof
  # the transaction travelled. Without gossip, fan out instead, since a lone
  # mempool can only be drained by its own node's turn.
  SUBMIT_TARGETS=()
  if [[ "$NO_EL_P2P" == true ]]; then
    for ((i = 0; i < NODES; i++)); do SUBMIT_TARGETS+=("$i"); done
    step "Submitting a transaction to all $NODES node(s) (no EL gossip)"
  else
    # Proposers rotate round-robin by validator index, and this script gives node
    # i exactly validator i, so the proposer of slot s is s % NODES. Submit to the
    # node that *just* proposed: it is the furthest from proposing again (a full
    # NODES slots away), which maximises the chance that some other node includes
    # the transaction and the check is conclusive.
    HEAD_SLOT=$(curl -sS -m 5 "http://127.0.0.1:15052/lean/v0/node/syncing" 2>/dev/null |
      grep -o '"head_slot":"*[0-9]*' | grep -o '[0-9]*$' || true)
    HEAD_SLOT="${HEAD_SLOT:-0}"
    SUBMIT_TARGETS+=( "$(( HEAD_SLOT % NODES ))" )
    step "Submitting a transaction to one node only (head slot $HEAD_SLOT)"
  fi

  TX_ACCEPTED=0
  : > "$LOG_DIR/tx-submitters"
  for i in "${SUBMIT_TARGETS[@]}"; do
    RESP=$(curl -sS -m 5 -X POST \
      -H 'content-type: application/json' \
      -d "{\"raw\": \"$TX_BODY\"}" \
      "http://127.0.0.1:$((15052 + i))/lean/v0/admin/el/tx" 2>&1 || echo "REQUEST_FAILED")
    if [[ "$RESP" == *tx_hash* ]]; then
      TX_ACCEPTED=$(( TX_ACCEPTED + 1 ))
      echo "$i" >> "$LOG_DIR/tx-submitters"
      TX_HASH="${RESP#*\"tx_hash\":\"}"; TX_HASH="${TX_HASH%%\"*}"
      ok "$(node_name "$i") accepted it ($TX_HASH)"
    else
      warn "$(node_name "$i") rejected it: $RESP"
    fi
  done
  echo "$TX_ACCEPTED" > "$LOG_DIR/tx-accepted.count"
  echo "${#SUBMIT_TARGETS[@]}" > "$LOG_DIR/tx-targets.count"

  REMAINING=$(( RUNTIME - SETTLE ))
  step "Running the remaining ~$(( REMAINING / SECONDS_PER_SLOT )) slots (${REMAINING}s)"
  sleep "$REMAINING"

  # Find the block that carries it. The raw bytes are echoed verbatim in the
  # payload's `transactions` list, so a substring match is exact — no jq needed.
  step "Looking for the transaction on chain"
  TX_NEEDLE="$(printf '%s' "${TX_RAW#0x}" | tr 'A-Z' 'a-z')"
  : > "$LOG_DIR/tx-inclusion.json"
  for ((slot = SLOTS; slot >= 1; slot--)); do
    BLOCK=$(curl -sS -m 5 "http://127.0.0.1:15052/lean/v0/blocks/$slot" 2>/dev/null || true)
    if [[ "$(printf '%s' "$BLOCK" | tr 'A-Z' 'a-z')" == *"$TX_NEEDLE"* ]]; then
      printf '%s\n' "$BLOCK" > "$LOG_DIR/tx-inclusion.json"
      echo "$slot" > "$LOG_DIR/tx-inclusion.slot"
      ok "found in the block at slot $slot"
      break
    fi
  done
  [[ -s "$LOG_DIR/tx-inclusion.json" ]] || warn "not found in slots 1..$SLOTS"
fi

trap - EXIT
teardown

# ---------------------------------------------------------------- verify ------
[[ "$VERIFY" == false ]] && exit 0

step "Verifying"
AGG_LOG="$LOG_DIR/$(node_name 0).log"
strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }
# One integer, always. `grep -c` prints 0 *and* exits non-zero on no match, so a
# `|| echo 0` fallback would emit a second line and break the arithmetic below.
# Concatenating first also avoids grep's per-file counts.
count() { local n; n=$(cat "$LOG_DIR"/*.log 2>/dev/null | grep -c "$1" || true); echo "${n:-0}"; }
count1() { local n; n=$(grep -c "$1" "$2" 2>/dev/null || true); echo "${n:-0}"; }
FAIL=0

# 1. the embedded EL came up on every node
EL_UP=$(count "Embedded ethrex enabled")
if [[ "$NO_EL" == true ]]; then ok "consensus-only control run (no EL expected)"
elif [[ "$EL_UP" == "$NODES" ]]; then ok "in-process EL enabled on $EL_UP/$NODES node(s)"
else warn "in-process EL enabled on $EL_UP/$NODES node(s)"; FAIL=1; fi

# 2. blocks were produced (works with a single node, unlike the import path)
PRODUCED=$(count "Building block")
if (( PRODUCED > 0 )); then ok "blocks produced: $PRODUCED"
else warn "no blocks produced"; FAIL=1; fi

# 3. blocks arrived over gossip. Needs peers, so it is informational at --nodes 1:
#    a lone proposer never receives its own block back.
IMPORTED=$(count1 "Block imported" "$AGG_LOG")
if (( IMPORTED > 0 )); then ok "blocks imported from peers: $IMPORTED"
elif (( NODES == 1 )); then warn "no gossip imports (expected with --nodes 1)"
else warn "no blocks imported despite $NODES nodes"; FAIL=1; fi

# 4. finality. Needs ~30 slots, so informational on short runs.
FINAL=$(grep -h "Checkpoint finalized" "$AGG_LOG" 2>/dev/null | strip_ansi | tail -1 || true)
if [[ -n "$FINAL" ]]; then ok "${FINAL#*Checkpoint finalized }"
else warn "no finalization yet (needs ~30 slots; ran $SLOTS)"; fi

# 5. the EL actually built and executed payloads (trace-level: needs --trace)
if [[ "$NO_EL" == true ]]; then
  warn "consensus-only control run (--no-el): EL checks skipped"
elif [[ "$TRACE" == true ]]; then
  BUILT=$(count "Built execution payload")
  EXECD=$(count "EL executed payload")
  if (( BUILT > 0 )); then ok "EL payloads built: $BUILT"
  else warn "no EL payload builds"; FAIL=1; fi
  if (( EXECD > 0 )); then ok "EL payloads submitted for execution: $EXECD"
  else warn "no EL executions"; FAIL=1; fi
else
  warn "payload build/execute counts need --trace (they log at trace level)"
fi

# 6. the transaction went in and was executed. Reads the block captured mid-run,
#    since the API is gone by now.
if [[ "$NO_EL" == true || "$NO_TX" == true ]]; then
  warn "transaction check skipped"
else
  ACCEPTED=$(cat "$LOG_DIR/tx-accepted.count" 2>/dev/null || echo 0)
  TARGETS=$(cat "$LOG_DIR/tx-targets.count" 2>/dev/null || echo "$NODES")
  if (( ACCEPTED == TARGETS && TARGETS > 0 )); then ok "transaction accepted by $ACCEPTED/$TARGETS node(s) submitted to"
  else warn "transaction accepted by $ACCEPTED/$TARGETS node(s) submitted to"; FAIL=1; fi

  if [[ -s "$LOG_DIR/tx-inclusion.json" ]]; then
    INCL_SLOT=$(cat "$LOG_DIR/tx-inclusion.slot" 2>/dev/null || echo '?')
    ok "transaction included in the block at slot $INCL_SLOT"
    # Executing a transfer burns gas, so a zero here would mean the payload
    # carried the transaction without running it. `gasUsed` is a hex *string*
    # (`"0x5208"`) — every numeric payload field uses the hex_u64 serde helper —
    # so extract the hex and let bash convert it.
    GAS_HEX=$(tr ',' '\n' < "$LOG_DIR/tx-inclusion.json" |
      grep -o '"gasUsed":"0x[0-9a-fA-F]*"' | head -1 | grep -o '0x[0-9a-fA-F]*' || true)
    if [[ -n "$GAS_HEX" && "$GAS_HEX" != "0x0" ]]; then ok "gasUsed=$(( GAS_HEX )) in that block"
    else warn "gasUsed missing or zero in that block (got '${GAS_HEX:-none}')"; FAIL=1; fi

    # The point of execution-layer gossip: a node that never saw the submission
    # included it. `proposer_index` is a validator index and this script gives
    # node i validator i, so it names the node that built the block.
    if [[ "$NO_EL_P2P" == false ]]; then
      PROPOSER=$(tr ',' '\n' < "$LOG_DIR/tx-inclusion.json" |
        grep -o '"proposer_index":[0-9]*' | head -1 | grep -o '[0-9]*$' || true)
      SUBMITTERS=$(tr '\n' ' ' < "$LOG_DIR/tx-submitters" 2>/dev/null || true)
      if [[ -z "$PROPOSER" ]]; then
        warn "could not read proposer_index from the including block"; FAIL=1
      elif [[ " $SUBMITTERS " == *" $PROPOSER "* ]]; then
        # Inclusion is proven, propagation is not: the node that received the
        # transaction is the one that proposed. Not a failure — just no evidence
        # either way. The submit target is chosen to avoid this.
        warn "included by node $PROPOSER, which is also where it was submitted — gossip unproven"
      else
        ok "gossip proven: submitted to node(s) $SUBMITTERS, included by node $PROPOSER"
      fi
    fi
  else
    warn "transaction never made it into a block"; FAIL=1
  fi
fi

# 6b. the execution layers actually peered with each other
if [[ "$NO_EL" == false && "$NO_EL_P2P" == false ]]; then
  EL_P2P_UP=$(count "EL devp2p enabled")
  if (( EL_P2P_UP == NODES )); then ok "EL devp2p started on $EL_P2P_UP/$NODES node(s)"
  else warn "EL devp2p started on $EL_P2P_UP/$NODES node(s)"; FAIL=1; fi

  EL_P2P_FAIL=$(count "EL transaction gossip unavailable")
  if (( EL_P2P_FAIL > 0 )); then warn "EL devp2p failed to start on $EL_P2P_FAIL node(s)"; FAIL=1; fi
fi

# 7. red flags
BAD=$(( $(count "using synthetic payload") + $(count "EL rejected payload") ))
if (( BAD == 0 )); then ok "no synthetic fallbacks / rejected payloads"
else warn "EL failure lines: $BAD"; FAIL=1; fi

ERRS=$(count "panicked")
if (( ERRS == 0 )); then ok "no panics"; else warn "panics: $ERRS"; FAIL=1; fi

echo
if (( FAIL == 0 )); then
  printf '\033[1;32m✓ devnet run looks healthy\033[0m — logs in %s\n' "$LOG_DIR"
else
  printf '\033[1;33m! devnet ran but some checks did not pass\033[0m — inspect %s\n' "$LOG_DIR"
  exit 1
fi
