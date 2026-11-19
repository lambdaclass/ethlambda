# PQ devnet

A local kurtosis devnet on the consensus-specs `pq` fork (pinned at
`a4d16c5b`), active from genesis, with ethlambda next to Lighthouse's PQ
client. See [`docs/beacon_pq.md`](../../docs/beacon_pq.md) for what ethlambda
implements of the fork.

## What runs

- **Genesis**: `ethpandaops/ethereum-genesis-generator:pq` (eth-beacon-genesis
  `284025a0`). Fulu, gloas and PQ at epoch 0, mainnet preset, 12 s slots.
  Every validator's leanXMSS key is `KeyGen(sha256("leanxmss-seed" || sk))`
  and its VRF seed `sha256("vrf-seed" || sk)`, `sk` its EIP-2333 signing key;
  ethereum-package ships the first 1000 keys of its default mnemonic. The
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

## Known limits

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
