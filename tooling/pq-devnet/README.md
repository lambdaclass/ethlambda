# PQ devnet

A local kurtosis devnet on the consensus-specs `pq` fork (pinned at
`2f43bc0f`, the pq-devnet-0 spec), active from genesis, with ethlambda next to Lighthouse's PQ
client. `network_params.yaml` runs an ethlambda beacon node that only
follows; `network_params_validators.yaml` gives it 16 of the 64 validators
behind ethlambda's own validator client. See
[`docs/beacon_pq.md`](../../docs/beacon_pq.md) for what ethlambda implements
of the fork.

> **Lighthouse must be on leanVM bindings v0.15.0 too.** pq-devnet-0 moved
> its signer, prover, verifier and sidecar to leanVM's bindings v0.15.0
> (`c5ee9d239`) at once, and a proof from the previous pin (`283686575c`)
> does not verify under it. ethlambda's image builds its sidecar at v0.15.0;
> use a Lighthouse `pq-devnet-0` image built after the move. Interop was
> last checked on 2026-11-20, at the previous pin.

## What runs

- **Genesis**: `ethpandaops/ethereum-genesis-generator:pq`. Fulu, gloas and
  PQ at epoch 0, mainnet preset, 12 s slots. Every validator's leanXMSS key
  is `KeyGen(sha256("leanxmss-seed" || sk))` and its VRF seed
  `sha256("vrf-seed" || sk)`, `sk` its EIP-2333 signing key; ethereum-package
  publishes the keys, VRF roots and VRF tree states of its default
  mnemonic's first 10000 validators, and the generator must log `0 derived`.
  The EIP-7002,
  EIP-7251 and EIP-8282 request contracts are inert stubs.
- **Lighthouse**: `ethpandaops/lighthouse:pq-devnet-0` (last run at
  `sha256:f571048f`), which proves attestation aggregates with leanVM through
  a `leanvm-sidecar` (`lighthouse-pq-bn`).
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
  87788250ac957609e4826705421d59ea924ba69f                  # pq
git merge --no-edit FETCH_HEAD
git apply <ethlambda>/tooling/pq-devnet/ethlambda-launcher.patch
cd ..

# 3. For network_params_validators.yaml: the package's published VRF tree
#    states, where ethlambda's validator client reaches the host.
(cd ethereum-package/static_files/xmss-keys \
  && python3 -m http.server 8642 --bind 127.0.0.1) &

# 4. The devnet. kurtosis wants the package as an absolute path.
kurtosis run --enclave pq "$PWD/ethereum-package" \
  --args-file <ethlambda>/tooling/pq-devnet/network_params.yaml
```

Lighthouse's validator client derives its validators' leanXMSS keys at
startup, about two minutes for 64 on an 11-core machine, so the first slots
are missed. Lighthouse needs a supernode or 128 validators for PeerDAS, which
the params give it.

With `network_params_validators.yaml`, ethlambda's validator client derives
its 16 keys in about a minute and must log `Every validator's VRF tree is
ready ... loaded=16 hashed=0`. Lighthouse keeps 48 (75%), enough to finalize
alone, so a fault on ethlambda's side shows as missed duties rather than a
stalled chain: judge ethlambda from Lighthouse's side (its blocks canonical,
`gossipsub_rejected_messages_per_topic_total` empty, validators 48 to 63
participating).

## ethlambda alone

`network_params_ethlambda.yaml` runs two ethlambda beacon nodes, each with
an ethlambda validator client and 16 of the 32 validators, on the package's
published keys and VRF states.

```sh
# The image and the package as above, the published VRF states served as in
# step 3, then the devnet. The plain image (`make docker-build`) and a package
# without the launcher patch run it too, the nodes then checking each other's
# proofs in the specification's reference encoding.
kurtosis run --enclave pq "$PWD/ethereum-package" \
  --args-file <ethlambda>/tooling/pq-devnet/network_params_ethlambda.yaml
```

- The generator must log `leanXMSS keys: 0 from cache, 32 fetched, 0
  derived`, and each validator client `Every validator's VRF tree is ready
  ... loaded=16 hashed=0`.
- For another mnemonic, or past the 10000 validators the package publishes,
  `ethlambda pq-keys --mnemonic ... --count N --output-dir keys` writes the
  same two files (`<name>.bin`, the leanXMSS keys and VRF roots the generator
  reads through `xmss_pubkey_url`, and `<name>.vrf`, the states validator
  clients read). Every root hashes the whole tree, minutes a validator;
  resumable.
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

- **Without VRF tree states, a validator's first start hashes its trees.**
  Minutes a key on all cores, one key after another, in a pool of their own
  so attestations, aggregates and PTC votes are signed meanwhile; a proposal
  before its key's tree is ready is missed. `--vrf-state-url` (the package's
  published file, or the `.vrf` file `ethlambda pq-keys` writes) avoids it,
  and the trees are kept under `<validators-dir>/pq_vrf_trees/`, so a restart
  reads them back.
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
