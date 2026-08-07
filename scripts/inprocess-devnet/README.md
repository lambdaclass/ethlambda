# Standalone in-process ethrex devnet

`run.sh` spins up an N-node ethlambda devnet where **every node embeds its own
ethrex execution layer** (enabled by `--el-genesis`). There are no separate EL
containers.

It is self-contained: it generates the validator keys, consensus genesis, ENRs and
node keys itself, so it does **not** need a `lean-quickstart` checkout. (Harness
drift there was the single largest source of false failures while building this —
see `docs/ethrex-inprocess-integration.md`.)

## Requirements

- `docker` (running) and `yq`. Everything else runs in containers:
  - `blockblaz/hash-sig-cli` — XMSS validator keys
  - `ethpandaops/eth-beacon-genesis:pk910-leanchain` — genesis, ENRs, validator assignment
- A node image. Use `--build`, or `make docker-build DOCKER_TAG=local` beforehand.

## Usage

```bash
./run.sh                          # 3 nodes, 20 slots, teardown + verify
./run.sh --build                  # build the node image first
./run.sh --nodes 1 --slots 10     # single node
./run.sh --trace                  # enable EL trace logs (needed to count payloads)
./run.sh --keep                   # leave the nodes running
```

| Flag | Default | Meaning |
|---|---|---|
| `--nodes N` | 3 | Node count (1–5). Node 0 is the aggregator. |
| `--slots N` | 20 | Slots to run before teardown. |
| `--trace` | off | Turn on EL trace logging so payload builds/executions are countable. |
| `--keep` | off | Skip teardown and leave the containers up. |
| `--build` | off | Build the node image before starting. |
| `--image REF` | `ghcr.io/lambdaclass/ethlambda:local` | Node image to run. |
| `--el-genesis PATH` | repo Cancun fixture | EL genesis JSON. Must be Cancun. |
| `--workdir DIR` | `.devnet-inprocess/` | Where genesis, data and logs go (recreated each run). |
| `--no-verify` | off | Skip the post-run checks. |

## What it verifies

After the run it checks the log evidence and exits non-zero if something looks wrong:

- the in-process EL came up on every node,
- blocks were produced, and (with peers) imported over gossip,
- finality advanced — needs roughly 30 slots,
- with `--trace`: EL payloads were **built** and **submitted for execution**,
- zero synthetic fallbacks, rejected payloads, or panics.

Reference healthy run — `./run.sh --nodes 3 --slots 32 --trace`:

```
✓ in-process EL enabled on 3/3 node(s)
✓ blocks produced: 40
✓ blocks imported from peers: 27
✓ finalized_slot=37 justified_slot=38
✓ EL payloads built: 40
✓ EL payloads submitted for execution: 120
✓ no synthetic fallbacks / rejected payloads
✓ no panics
```

## Notes

- **The EL genesis must be Cancun.** A Prague genesis makes ethrex demand a
  `requests_hash` that the Cancun-shaped `ExecutionPayloadV3` cannot carry, and
  `newPayload` then rejects every block. The script refuses to start if it sees
  `pragueTime`.
- **The EL hooks log at `trace!`**, so without `--trace` a healthy run prints
  nothing about payload builds — which is indistinguishable from an EL that never
  ran. Failures log at `warn!`, so silence there is the reliable INFO-level signal.
- **`--nodes 1` cannot show gossip imports.** A lone proposer never receives its
  own block back, so that check is informational in single-node mode.
- `--network host` is used so containers reach each other on `127.0.0.1` as the
  ENRs advertise; ports are therefore distinct per node by construction.
