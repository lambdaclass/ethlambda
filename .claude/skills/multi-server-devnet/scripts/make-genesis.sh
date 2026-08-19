#!/bin/bash
# OPERATOR-side: build ONE independent devnet's genesis dir.
# Produces a self-contained genesis (own GENESIS_TIME + genesis root) for a
# single host: NODES validators, SUBNETS committees, all ENRs pinned to
# 127.0.0.1 so this devnet never cross-discovers other servers' devnets.
# Aggregators are nodes 0..SUBNETS-1 (node k -> subnet k). Subnet of node n =
# n % SUBNETS. hash-sig keys for validators 0..NODES-1 are HARDLINKED from a
# canonical key set (keygen is the slow part; reuse it).
#
# Requires: yq, python3, docker, and lean-quickstart's generate-genesis.sh
# (set LQ to the lean-quickstart dir; default ~/lean_consensus/lean-quickstart).
#
# Usage: make-genesis.sh <OUTDIR> <NODES> <SUBNETS> <KEYS_DIR> <SRC_VCONFIG> [GT_OFFSET]
#   OUTDIR       genesis build dir to create (e.g. devnet-foo/genesis)
#   NODES        validator count
#   SUBNETS      ATTESTATION_COMMITTEE_COUNT
#   KEYS_DIR     canonical hash-sig-keys dir (has validator_<i>_{attester,proposer}_key_{pk,sk}.ssz
#                for i in 0..NODES-1 + validator-keys-manifest.yaml)
#   SRC_VCONFIG  a validator-config.yaml holding one 'privkey' per validator. Its
#                'name' prefix is irrelevant: privkeys are matched by the trailing
#                index (name '<anything>_<i>'), so an ethlambda_i or node_i source
#                both work.
#   GT_OFFSET    seconds from now until genesis (default 240)
#                generate-genesis.sh stamps GENESIS_TIME as now+offset EARLY (before
#                the per-validator config loop), so everything after it eats the
#                budget. Measured 2026-07-28 on a 32-node host:
#                  genesis generation after the stamp   13s (128 val) / 28s (256 val)
#                  ship + teardown + wipe + launch      93s / 105s
#                  gossip mesh formation (peers=N-1)    ~30s
#                => ~165s needed; 240 leaves ~75s margin. 600 wasted ~7min of wall
#                clock per restart, which is the whole reason this default dropped.
#                WIPE THE DATA DIRS BEFORE CALLING THIS: `rm -rf .../data/node_*` is
#                the one step that scales with chain age (54 GB took a big chunk of
#                that 93s), so doing it pre-stamp keeps the countdown predictable.
#                Raise the offset only if shipping to many hosts or over a slow link.
#
# Env: VALIDATORS_PER_NODE (default 1) validators hosted by each node. KEYS_DIR
#   must then hold NODES*VALIDATORS_PER_NODE key pairs, and the manifest is read
#   positionally, so its indices must run 0..NODES*VALIDATORS_PER_NODE-1.
#
# Node identity is the client-agnostic 'node_<i>' (node-id, node_<i>.key,
# data-dir, validator name). The client running a node is reflected only in its
# container name (<client>_<i>), set by start-devnet.sh/convert.sh, never here.
set -eu
OUTDIR=$1; NODES=$2; SUBNETS=$3; KEYS_DIR=$4; SRC_VCONFIG=$5; GT_OFFSET=${6:-240}
LQ=${LQ:-$HOME/lean_consensus/lean-quickstart}

mkdir -p "$OUTDIR/hash-sig-keys"

python3 - "$OUTDIR" "$NODES" "$SUBNETS" "$KEYS_DIR" "$SRC_VCONFIG" <<'PY'
import os, sys, yaml
outdir, nodes, subnets, keys_dir, src_vconfig = sys.argv[1:6]
nodes, subnets = int(nodes), int(subnets)
# Validators per node (env VALIDATORS_PER_NODE, default 1). generate-genesis.sh
# sums the per-row 'count' into VALIDATOR_COUNT and assigns node i the
# contiguous global indices [i*vpn, (i+1)*vpn).
# NOTE: the client derives a validator's attestation subnet from its own global
# index (`vid % ACC`, see p2p attestation_subscription_subnets), NOT from the
# 'subnet' row below -- so at vpn == subnets every node owns one validator in
# every subnet and subscribes to all of them. 'subnet' is metadata for the
# ansible/other-client path only.
vpn = int(os.environ.get('VALIDATORS_PER_NODE', '1'))
# Match privkeys by the trailing index so any source prefix (ethlambda_i / node_i)
# works; node identity emitted here is the client-agnostic node_<i>.
priv = {int(v['name'].rsplit('_', 1)[1]): v['privkey']
        for v in yaml.safe_load(open(src_vconfig))['validators']}
rows = []
for i in range(nodes):
    rows.append({
        'name': f'node_{i}', 'privkey': priv[i],
        'subnet': i % subnets,
        'enrFields': {'ip': '127.0.0.1', 'quic': 9000 + i},
        'metricsPort': 9200 + i, 'apiPort': 5052 + i,
        'isAggregator': i < subnets, 'count': vpn,
    })
cfg = {'shuffle': 'roundrobin', 'deployment_mode': 'ansible',
       'config': {'activeEpoch': 18, 'keyType': 'hash-sig',
                  'attestation_committee_count': subnets},
       'validators': rows}
header = (f"# {nodes}-node, {subnets}-subnet independent single-host devnet.\n"
          f"# {vpn} validator(s) per node -> {nodes * vpn} validators total;\n"
          f"# node i owns global validator indices {vpn}i..{vpn}i+{vpn - 1}.\n"
          f"# Subnet of node n = n % {subnets}; aggregators are nodes 0..{subnets-1}.\n"
          "# All ENRs pinned to 127.0.0.1 so this devnet is fully isolated.\n"
          "# Node identity is the client-agnostic node_<i> (node-id, node_<i>.key);\n"
          "# the client is reflected only in the container name (<client>_<i>).\n")
with open(f'{outdir}/validator-config.yaml', 'w') as f:
    f.write(header); yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
# hardlink keys 0..(nodes*vpn)-1 + manifest (one key pair per VALIDATOR, not per node)
names = ['validator-keys-manifest.yaml'] + [
    f'validator_{i}_{r}_key_{p}.ssz'
    for i in range(nodes * vpn) for r in ('attester', 'proposer') for p in ('pk', 'sk')]
linked = 0
for n in names:
    dst = f'{outdir}/hash-sig-keys/{n}'
    if not os.path.exists(dst):
        os.link(f'{keys_dir}/{n}', dst); linked += 1
print(f'validator-config + {linked} hardlinked key files ready')
PY

"$LQ/generate-genesis.sh" "$OUTDIR" --offset "$GT_OFFSET"

# generate-genesis.sh hands node i the contiguous index block [i*vpn,(i+1)*vpn),
# which at vpn == SUBNETS puts one of its validators in every subnet. Re-derive
# the assignment so each node holds validators from a single subnet instead
# (identity when VALIDATORS_PER_NODE=1).
python3 "$(dirname "$0")/subnet-align-validators.py" \
  "$OUTDIR" "$NODES" "$SUBNETS" "${VALIDATORS_PER_NODE:-1}"

echo "genesis ready: GT=$(grep ^GENESIS_TIME "$OUTDIR/config.yaml" | awk '{print $2}') ACC=$(grep ^ATTESTATION_COMMITTEE_COUNT "$OUTDIR/config.yaml" | awk '{print $2}') validators=$(grep -c attestation_pubkey "$OUTDIR/config.yaml")"
