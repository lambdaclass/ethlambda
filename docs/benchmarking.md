# Benchmarking block building

`ethlambda benchmark` measures block building the way the node performs it when
it proposes, against a reproducible synthetic workload, with no devnet running.

Block building is otherwise only observable through the Prometheus histograms a
live node exports. Those are noisy, depend on whatever the network happened to
be doing, and cannot be diffed against a baseline — which makes them a poor
instrument for tracking performance. The benchmark
trades network realism for repeatability: the same parameters produce the same
blocks every run, so two reports differ only where the code differs.

## Running it

```bash
make bench                                  # defaults, mock crypto
BENCH_ARGS="synthetic" make bench           # real XMSS/leanVM crypto
BENCH_ARGS="synthetic --iterations 50" make bench
```

`make bench` is a thin wrapper. The binary takes the same arguments directly:

```bash
ethlambda benchmark synthetic --num-validators 8 --iterations 10 --key-cache ~/.cache/ethlambda-bench-keys
ethlambda benchmark synthetic --mock-crypto --num-validators 8 --iterations 10
```

Without `--mock-crypto` the run uses real cryptography end to end: seed-derived
XMSS keys, real attestation signatures aggregated into leanVM type-1 proofs, and
the proposer's real seal (block-root signature, singleton type-1 wrap, type-2
merge), with every built block imported through the verifying `on_block` path.
A default real run takes a few minutes; `--key-cache` saves the seed-derived
keys so reruns skip key generation. A default mock run finishes in well under a
second, which is why CI can afford to run one on every pull request.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--num-validators` | `8` | Validators in the synthetic genesis |
| `--warmup-slots` | `8` | Unmeasured slots built first, so measured builds run on a state with realistic historical roots and justifications |
| `--iterations` | `10` | Measured builds, one block each |
| `--proofs-per-data` | `1` | Aggregates seeded per `AttestationData`, mimicking committee aggregators over disjoint validator subsets |
| `--seed` | `42` | Seed for the validator set and its XMSS keys; fixes the whole run |
| `--key-cache <dir>` | — | Cache the seed-derived XMSS keys on disk (keyed by leansig revision, seed, validator index and run length). Real crypto only |
| `--mock-crypto` | off | Placeholder proofs instead of real XMSS/leanVM signatures, and no seal. Measures selection, compaction and the state transition only |
| `--enable-proposer-aggregation` | off | Mirrors the node flag: collapse same-data proofs via recursive leanVM aggregation |
| `--max-attestations-per-block` | `3` | Mirrors the node flag: distinct `AttestationData` per block |
| `--format` | `human` | `human` or `json` |
| `--output <path>` | — | Also write the JSON report to a file |

Logs go to stderr and the report to stdout, so `--format json` pipes straight
into `jq`.

## What it measures

Each iteration enters `produce_block_with_signatures` and then `seal_block` —
the same functions `BlockChainServer::propose_block` calls — and the harness
reports the phases inside them:

| Phase | Work |
| --- | --- |
| `select_payloads` | Choosing which attestations go in the block |
| `compact` | Collapsing or picking among proofs for the same data; with `--enable-proposer-aggregation` this is a real recursive leanVM aggregation |
| `stf_simulate` | The state transition that seals `state_root` |
| `sign_proposer` | The proposer's XMSS signature over the block root (real crypto only) |
| `wrap_proposer` | Wrapping that signature into a singleton type-1 proof (real crypto only) |
| `merge_type2` | Merging every type-1 proof into the block's type-2 proof (real crypto only) |
| `overhead` | The rest of the measured span: tick processing, attestation promotion, fork-choice head, pool clone, pubkey resolution |
| `wall` | The whole span |

`overhead` is `wall` minus the sum of the phases, so the columns add up by
construction. In mock mode there is nothing to sign with, so the seal is skipped
and its three phases are absent.

Deliberately **outside** the measured span, matching the boundary of the node's
own `lean_block_building_time_seconds` metric: gossip publish, the
slot-alignment sleep, and importing the block that was just built. The import
still happens between iterations — otherwise every iteration would build on the
same head and `process_slots` would get more expensive as the run went on. Two
such costs are reported anyway, because they are real crypto worth watching:

| Column | Work |
| --- | --- |
| `aggregate` | Producing the slot's pool entries: every validator's attestation signature plus their type-1 aggregation. Aggregator-side work a proposer never does; zero in mock mode |
| `import` | Importing the built block; in real mode this includes verifying its type-2 proof |

Phase times come from the sample sums of the existing
`lean_block_proposal_attestation_build_phase_seconds` histogram, read before and
after each build. Histogram sums accumulate raw f64 seconds, so the difference
between two readings is the elapsed phase time and bucket boundaries play no
part. Nothing is added to the hot path for the benchmark's benefit. The harness
asserts each phase was observed exactly once per build and fails the run
otherwise, because a mis-attributed report is worse than no report.

## Reading a report

```
Block-building benchmark — synthetic workload (real crypto)
  validators=2 warmup_slots=1 iterations=2 proofs_per_data=1 seed=42
  enable_proposer_aggregation=false max_attestations_per_block=3
  ethlambda/v0.1.0/aarch64-apple-darwin/rustc-v1.97.1 leansig=15cbdd43 leanvm=e2592df4 os=macos arch=aarch64 threads=14

  iter           compact      merge_type2  select_payloads    sign_proposer     stf_simulate    wrap_proposer   overhead       wall  aggregate     import         root
  1              0.001ms        550.641ms          0.007ms          0.461ms          0.011ms         65.127ms    0.103ms  616.350ms  103.548ms   19.205ms   0x77465b33
  2              0.001ms       1175.326ms          0.015ms          2.024ms          0.015ms         73.124ms    0.119ms 1250.623ms   94.691ms   20.472ms   0xf7e48c73

  phase              count        min       mean        p50        p90        max
  compact                2    0.001ms    0.001ms    0.001ms    0.001ms    0.001ms
  merge_type2            2  550.641ms  862.983ms 1175.326ms 1175.326ms 1175.326ms
  ...
  wall                   2  616.350ms  933.487ms 1250.623ms 1250.623ms 1250.623ms

  outside the measured span:
  aggregate              2   94.691ms   99.119ms  103.548ms  103.548ms  103.548ms
  import                 2   19.205ms   19.838ms   20.472ms   20.472ms   20.472ms
```

Every measured iteration gets its own row, and the summary follows below it.
Outliers are never discarded: XMSS signing and OTS window advancement produce
legitimate heavy tails, and hiding them would misrepresent the thing being
measured. A coefficient of variation above 10% is flagged so a noisy run is not
mistaken for a result.

Percentiles are nearest-rank, without interpolation. Sample counts here are
small, so an actual observed value is more informative than a blend of two
neighbours.

The `root` column is the block root of each built block. It is what makes a
before/after comparison trustworthy: if an optimization leaves the root
sequence unchanged, it changed only speed and not which attestations were
selected. If the roots move, the change altered block contents and the timing
comparison means something different than intended.

## Comparing two runs

Same seed and same parameters produce identical root sequences, so a baseline
and a candidate can be diffed directly. The header line exists to tell you when
they *cannot* be compared:

- `leansig` and `leanvm` are the resolved revisions the binary was built
  against, read from `Cargo.lock` at build time. leanSig tracks a moving branch
  and leanVM performs the signature aggregation, so either one moving changes
  the measured crypto. Real-mode roots also depend on the seed-derived keys, so
  the same seed on the same leansig revision reproduces the same signatures and
  the same roots.
- `os`, `arch` and `threads` change results across machines.

Two reports that disagree on any of those are not measuring the same thing.

## Limitations

- **Synthetic workloads only.** Replaying a real datadir is not implemented, so
  results reflect a synthetic chain rather than a deep production state.
- **Short-lived keys.** Real-mode XMSS keys are generated for exactly the slots
  the run signs, so key generation is cheap but the OTS window advancement a
  long-lived validator key performs every 65,536 slots is never exercised.
- **Mock mode skips the seal.** Without keys there is nothing to sign, so the
  three seal phases only appear in real runs.

## In CI

The Test job runs a short mock benchmark and asserts the JSON report's shape
(`schema_version`, one sample per iteration). It costs seconds, and it means a
change to the report contract cannot land unnoticed.
