#!/usr/bin/env bash
#
# Launch the 16-node ethlambda devnet with the transaction-capable image:
# embedded ethrex + the submit endpoint + execution-layer transaction gossip.
#
# Differs from start-devnet.sh in one structural way: node 0 starts alone first,
# its execution-layer enode is read out of its log, and the remaining nodes get
# that enode as --el-bootnodes. The enode cannot be computed in advance because
# the EL key is a keccak derivation of the consensus node key.
#
#   bash start-tx-devnet.sh NODES SUBNETS IMAGE
set -euo pipefail

NODES="${1:?usage: start-tx-devnet.sh NODES SUBNETS IMAGE}"
SUBNETS="${2:?}"
IMAGE="${3:?}"

G=/opt/lean-quickstart/genesis
D=/opt/lean-quickstart/data
EL_PORT_BASE=30303

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# Guard: the committee count baked into genesis must match what we launch with.
GEN_SUBNETS=$(sudo grep -oE 'ATTESTATION_COMMITTEE_COUNT: *[0-9]+' "$G/config.yaml" | grep -oE '[0-9]+')
[[ "$GEN_SUBNETS" == "$SUBNETS" ]] || die "genesis says $GEN_SUBNETS subnets, launching with $SUBNETS"
ok "subnets agree with genesis ($SUBNETS)"

[[ -f "$G/el-genesis.json" ]] || die "no $G/el-genesis.json"
sudo grep -q 'f39fd6e51aad88f6f4ce6ab8827279cfffb92266' "$G/el-genesis.json" \
  || die "el-genesis.json has no funded dev account; transactions would be unspendable"
ok "EL genesis carries the funded dev account"

launch() {                      # launch <index> [extra args...]
  local i="$1"; shift
  local name="ethlambda_$i"
  sudo mkdir -p "$D/node_$i"
  sudo docker run -d \
    --name "$name" \
    --restart unless-stopped \
    --network host \
    --memory 8g --memory-swap 16g --memory-reservation 2g \
    --log-opt max-size=100m --log-opt max-file=3 \
    -e RUST_LOG=info \
    -v "$G:/config" \
    -v "$D/node_$i:/data" \
    "$IMAGE" \
    --genesis /config/config.yaml \
    --validators /config/annotated_validators.yaml \
    --bootnodes /config/nodes.yaml \
    --validator-config /config/validator-config.yaml \
    --hash-sig-keys-dir /config/hash-sig-keys \
    --node-id "node_$i" \
    --node-key "/config/node_$i.key" \
    --data-dir /data \
    --gossipsub-port "$((9000 + i))" \
    --http-address 0.0.0.0 \
    --metrics-port "$((9200 + i))" \
    --api-port "$((5052 + i))" \
    --el-genesis /config/el-genesis.json \
    --el-p2p-port "$((EL_PORT_BASE + i))" \
    "$@" >/dev/null || die "failed to start $name"
}

# ---- node 0 first: it is the EL bootnode and an aggregator ----
launch 0 --is-aggregator --aggregate-subnet-ids 0
ok "ethlambda_0 started (aggregator, subnet 0)"

EL_BOOTNODE=""
for _ in $(seq 1 60); do
  EL_BOOTNODE=$(sudo docker logs ethlambda_0 2>&1 | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -o 'enode://[0-9a-fA-F]\{128\}@[0-9.]*:[0-9]*' | head -1 || true)
  [[ -n "$EL_BOOTNODE" ]] && break
  sleep 1
done
[[ -n "$EL_BOOTNODE" ]] || die "node 0 never logged an EL enode — check 'docker logs ethlambda_0'"
ok "EL bootnode harvested: ${EL_BOOTNODE:0:30}...@${EL_BOOTNODE##*@}"

# ---- the rest, seeded with node 0's enode ----
for ((i = 1; i < NODES; i++)); do
  EXTRA=()
  if (( i < SUBNETS )); then EXTRA+=(--is-aggregator --aggregate-subnet-ids "$i"); fi
  launch "$i" --el-bootnodes "$EL_BOOTNODE" "${EXTRA[@]}"
  ok "ethlambda_$i started$( (( i < SUBNETS )) && echo " (aggregator, subnet $i)")"
done

sleep 8
UP=$(sudo docker ps --format '{{.Names}}' | grep -c '^ethlambda_' || true)
if [[ "$UP" == "$NODES" ]]; then ok "all $NODES nodes alive"
else warn "only $UP/$NODES alive — check 'docker ps -a' and logs"; fi
echo "$EL_BOOTNODE" | sudo tee /opt/lean-quickstart/genesis/.el-bootnode >/dev/null
