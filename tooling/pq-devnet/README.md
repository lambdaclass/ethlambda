# PQ devnet

A local kurtosis devnet on the consensus-specs `pq` fork (pinned at
`b5d422b2`), active from genesis, with ethlambda next to Lighthouse's PQ
client. `network_params.yaml` runs an ethlambda beacon node that only
follows; `network_params_validators.yaml` gives it 16 of the 64 validators
behind ethlambda's own validator client. See
[`docs/beacon_pq.md`](../../docs/beacon_pq.md) for what ethlambda implements
of the fork.

> **With Lighthouse, not runnable at this pin yet.** `b5d422b2` changed the
> VRF tree (each leaf now commits to its slot's secret, and the tree is hashed
> with Keccak-256 over all `2^31` leaves). No published genesis generator or
> Lighthouse build registers roots under that rule, so every proposal splits
> the chain: see [Known limits](#known-limits). The Lighthouse steps below are
> the ones last run, at `a4d16c5b`. An ethlambda-only devnet runs at this pin
> on key files ethlambda writes itself: see [ethlambda alone](#ethlambda-alone).

## What runs

- **Genesis**: `ethpandaops/ethereum-genesis-generator:pq` (eth-beacon-genesis
  `284025a0`). Fulu, gloas and PQ at epoch 0, mainnet preset, 12 s slots.
  Every validator's leanXMSS key is `KeyGen(sha256("leanxmss-seed" || sk))`
  and its VRF seed `sha256("vrf-seed" || sk)`, `sk` its EIP-2333 signing key;
  ethereum-package ships the first 1000 keys of its default mnemonic. That
  generator's VRF tree is the one before `b5d422b2` (see Known limits). The
  EIP-7002, EIP-7251 and EIP-8282 request contracts are inert stubs.
- **Lighthouse**: `ethdreamer/lighthouse:pq`, which proves attestation
  aggregates with leanVM through a `leanvm-sidecar` (`lighthouse-pq-bn`).
- **ethlambda**: this repository's image with `leanvm-sidecar` added, started
  through `ethlambda-pq` (`bin/ethlambda/pq/ethlambda-pq`), which starts the
  sidecar and passes its socket as `--pq-prover-socket`. Without the sidecar
  ethlambda checks proofs with the specification's reference encoding, which
  rejects every Lighthouse block that carries attestations.
- **Execution**: geth (`ethereum/client-go:latest`).
- **Dora**: `ethpandaops/dora:pq`.

## Run it

```sh
# 1. The image, from the repository root (about 15 minutes).
docker build -f tooling/pq-devnet/Dockerfile -t ethlambda:pq-local .

# 2. The package: lambdaclass/ethereum-package's `add-ethlambda` (the
#    ethlambda launcher) merged with ethpandaops/ethereum-package's `pq` (the
#    PQ genesis and Lighthouse wiring), plus the launcher patch here.
git clone https://github.com/lambdaclass/ethereum-package.git ethereum-package
cd ethereum-package
git checkout 8159202d71cca5a1de086d8152d512c5b95465ca      # add-ethlambda
git fetch https://github.com/ethpandaops/ethereum-package.git \
  7fafe056d997b07ec70656b16e54389fa02ec506                  # pq
git merge --no-edit FETCH_HEAD
git apply <ethlambda>/tooling/pq-devnet/ethlambda-launcher.patch
cd ..

# 3. The devnet. kurtosis wants the package as an absolute path.
kurtosis run --enclave pq "$PWD/ethereum-package" \
  --args-file <ethlambda>/tooling/pq-devnet/network_params.yaml
```

Lighthouse's validator client derives its validators' leanXMSS keys at
startup, about two minutes for 64 on an 11-core machine, so the first slots
are missed. Lighthouse needs a supernode or 128 validators for PeerDAS, which
the params give it.

With `network_params_validators.yaml`, ethlambda's validator client derives
its 16 keys in under a minute. Lighthouse keeps 48 (75%), enough to finalize
alone, so a fault on ethlambda's side shows as missed duties rather than a
stalled chain.

## ethlambda alone

`network_params_ethlambda.yaml` runs two ethlambda beacon nodes, each with
an ethlambda validator client and 16 of the 32 validators, on a genesis whose
VRF roots follow `b5d422b2`. Lighthouse cannot join it (see Known limits).

```sh
# 1. The genesis key material, for the package's default mnemonic: each
#    validator's leanXMSS key and VRF root (<name>.bin, what the genesis
#    generator reads) and its VRF tree state (<name>.vrf, what validator
#    clients read). Every root hashes the whole tree: about 2.5 minutes a
#    validator on an 11-core Apple M3 Pro, one after another. Resumable.
ethlambda pq-keys --count 32 --output-dir keys   --mnemonic "giant issue aisle success illegal bike spike question tent bar rely arctic volcano long crawl hungry vocal artwork sniff fantasy very lucky have athlete"

# 2. Serve them where the enclave reaches the host.
(cd keys && python3 -m http.server 8641 --bind 127.0.0.1) &

# 3. The image and the package as above, then the devnet.
kurtosis run --enclave pq "$PWD/ethereum-package"   --args-file <ethlambda>/tooling/pq-devnet/network_params_ethlambda.yaml
```

- The generator must log `leanXMSS keys: 0 from cache, 32 fetched, 0
  derived`. A record the file lacks is derived under the generator's own,
  older VRF rule, and that validator's proposals then fail.
- Each validator client must log `Every validator's VRF tree is ready ...
  loaded=16 hashed=0`: `--vrf-state-url` gave every key its tree.
- **At least 32 validators** on the mainnet preset: gloas's `compute_ptc`
  asserts that every slot has an attester, so with fewer, epoch processing
  fails at the first epoch boundary (`compute_balance_weighted_selection:
  total > 0`) and the chain stops. The specification does the same.
- Deriving the leanXMSS keys takes a validator client about 40 seconds for
  16 keys, on every start, so the first slots after genesis can be missed.
  If more than four are, the beacon nodes call themselves syncing and refuse
  duties until no block has been seen for eight slots (the sync gate's stall
  rule). Raise `genesis_delay` (20 seconds by default) for more keys per
  client.
- Blobs: add a blob spammer on the enclave's network, for example
  `docker run -d --network kt-pq ethpandaops/spamoor:master blobs --privkey
  bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31 -h
  http://el-1-geth-ethlambda:8545 --throughput 1 --sidecars 2`, and look for
  `Published data column sidecars ... columns=128` beside `Produced a PQ
  block`.

## Known limits

- **The VRF tree changed under every other client.** At `b5d422b2` a VRF
  leaf is `keccak256("VRF_LEAF" || secret || le64(slot))` over the secret
  `keccak256("VRF_SECRET" || vrf_seed || le64(slot))`, and a reveal is the
  secret, not the leaf. When this was written:
  - `ethpandaops/eth-beacon-genesis`'s `pq` branch (`ff42fce0`, the
    `pq-full-vrf` image ethereum-package now defaults to) hashes all `2^31`
    leaves with Keccak-256, but each leaf is `keccak256(vrf_seed ||
    le64(slot))` itself, the rule `b5d422b2` replaced;
  - Lighthouse's PQ branch (`ethdreamer/lighthouse:pq` at `0c76c6e1`) uses the
    same leaf with only the first `2^20` leaves populated and the rest zero.

  A root either registers fails ethlambda's `is_valid_vrf_proof`, and
  ethlambda's reveals fail theirs, so the first block of either side is
  invalid to the other. The image at `284025a0` this devnet was last run with
  is older still (SHA-256). Until both move, run ethlambda alone against a
  genesis whose VRF roots are `compute_vrf_root` of each validator's seed,
  which `ethlambda_crypto::vrf::VrfTree::build` computes.
- **A validator's first start hashes its VRF trees.** About 100 seconds a key
  on an Apple M4 Max's 14 cores, one key after another, in the background:
  attestations start at once, proposals before a key's tree is ready are
  missed. The trees are kept under `<validators-dir>/pq_vrf_trees/`, so a
  restart reads them back.
- **Lighthouse does not serve PQ envelopes over req/resp.** Its `pq` branch
  answers `execution_payload_envelopes_by_{range,root}` with a gloas-shaped
  envelope under the PQ digest ("Pq payload envelope RPC decoding is not
  implemented" in its codec), which ethlambda refuses: it cannot decode as
  PQ's container and carries no leanXMSS signature. So an ethlambda node that
  falls behind cannot catch up from Lighthouse alone, since every FULL parent's
  envelope is fetched that way; it can from another ethlambda node. Gossip is
  unaffected.
- **Memory.** Every `leanvm-sidecar` warms up by proving twice and stays
  large. In Docker Desktop's default 8 GB VM, starting a second sidecar next
  to Lighthouse's has had the kernel kill Lighthouse's. Set `LEANVM_THREADS`
  (through `cl_extra_env_vars`) on ethlambda nodes that only verify.

## What to check

- Both beacon APIs report the same head root, and ethlambda's
  `lean_beacon_gossip_validation_total` is all `accept`: blocks, envelopes,
  aggregates (their leanVM proofs checked through the sidecar), attestations,
  payload attestations and proposer preferences.
- `lean_beacon_aggregate_total{outcome="applied"}` rises: PQ aggregates reach
  fork choice.
- ethlambda's execution client answers `VALID` for every envelope
  (`Execution payload envelope verified ... status=Valid`).
- Finality matches Lighthouse's.
- With ethlambda validators: every block ethlambda's validator client
  publishes (`Published a PQ block`) is canonical on Lighthouse, the ones
  after the first few carry attestations (`Packed PQ attestations`), and
  Lighthouse's `gossipsub_rejected_messages_per_topic_total` stays empty for
  ethlambda's attestations, PTC votes, blocks, envelopes and aggregates
  (`Proved a PQ aggregate`, `Published PQ aggregates`).
