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
    --no-verify)   VERIFY=false; shift ;;
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
for ((i = 0; i < NODES; i++)); do
  NAME="$(node_name "$i")"
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
    --el-genesis /config/el-genesis.json \
    $([[ $i -eq 0 ]] && echo "--is-aggregator") >/dev/null || die "failed to start $NAME"
  ok "$NAME (quic $((9001 + i)), api $((15052 + i)))$([[ $i -eq 0 ]] && echo ' [aggregator]')"
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
step "Running for ~$SLOTS slots (${RUNTIME}s: ${GENESIS_OFFSET}s to genesis + ${SLOTS}×${SECONDS_PER_SLOT}s)"
trap teardown EXIT
sleep "$RUNTIME"
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
EL_UP=$(count "In-process ethrex execution engine enabled")
if [[ "$EL_UP" == "$NODES" ]]; then ok "in-process EL enabled on $EL_UP/$NODES node(s)"
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
if [[ "$TRACE" == true ]]; then
  BUILT=$(count "Built execution payload")
  EXECD=$(( $(count "newPayload on own-built block") + $(count "newPayload ok") ))
  if (( BUILT > 0 )); then ok "EL payloads built: $BUILT"
  else warn "no EL payload builds"; FAIL=1; fi
  if (( EXECD > 0 )); then ok "EL payloads submitted for execution: $EXECD"
  else warn "no EL executions"; FAIL=1; fi
else
  warn "payload build/execute counts need --trace (they log at trace level)"
fi

# 6. red flags
BAD=$(( $(count "falling back to synthetic") + $(count "getPayload failed") + $(count "rejected payload") ))
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
