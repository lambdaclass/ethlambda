# Plan: `ethlambda benchmark` — offline block-building benchmark sub-command

## Context

The README roadmap lists **"Optimize block building" (issue #465)** as the top near-term
priority, but block building is only observable today through Prometheus histograms on a
live devnet — there is no reproducible, offline way to measure it or to compare an
optimization against a baseline. This adds an `ethlambda benchmark` sub-command that
drives the exact production proposer code path against controlled workloads.

Fixed scope decisions: offline harness; synthetic **and** replay-from-datadir workloads;
real XMSS/leanVM crypto by default with a mock fast mode.

## What gets measured

The proposer pipeline as executed at interval 4, entered through the same functions the
actor calls:

```
produce_block_with_signatures (crates/blockchain/src/store.rs:788)   ← already public
  ├─ preamble: on_tick → interval 0, promote attestations,
  │            fork-choice head, pool deep-clone      → reported as derived "build_overhead"
  └─ build_block: select_payloads → compact → stf_simulate
seal_block (extracted from crates/blockchain/src/lib.rs:504-631, see refactor)
  └─ sign → wrap_proposer_type1 (leanVM) → merge_type_2 (leanVM)
```

**Excluded** (same boundary as the node's own `time_block_building` metric): gossip
publish, slot-alignment sleep, block import.

**Phase capture with zero hot-path changes**: the existing
`lean_block_proposal_attestation_build_phase_seconds` HistogramVec accumulates exact f64
sums, observed exactly once per phase per build — the harness deltas per-label sums
between iterations (prometheus 0.14 exposes `get_sample_sum()`, readable in-process).
Guards: assert per-phase count advanced by exactly 1, and warn if `wall − Σphases`
exceeds 2%.

**Statistics**: warmup 3 + 10 iterations (defaults, configurable); min/mean/p50/p90/max +
CV>10% warning per phase; raw samples always exported; outliers never auto-discarded
(XMSS rejection-sampling and OTS window advancement produce legitimate tails). Each
iteration records `block.hash_tree_root()` — diffing root sequences between baseline and
optimized runs proves an optimization changed only speed, not attestation selection.

## CLI (verified on clap 4.6.1)

Every existing flat invocation (devnet skills, Dockerfile, lean-quickstart) parses
byte-for-byte unchanged.

- `cli.rs`: add `#[command(subcommand_negates_reqs = true,
  args_conflicts_with_subcommands = true)]` + `command: Option<Command>`; the 7 required
  args become `Option<T>` with `#[arg(long, required = true)]` (mandatory — non-Option
  fields break `ethlambda benchmark` even with `negates_reqs`). Missing-arg error
  messages for the node path are unchanged; mixed `--genesis x benchmark` is rejected.
- `main.rs`: early branch right after parse (mirrors the HIVE test-driver early-return);
  node path unwraps the Options in one helper.

```
ethlambda benchmark synthetic  --num-validators 8 --warmup-slots 8
                               --proofs-per-data 1 --seed 42 [--key-cache-dir <dir>]  # cache: M2
ethlambda benchmark replay     --data-dir <path> --genesis config.yaml [--no-copy]
                               [--validators … --hash-sig-keys-dir … --node-id …]  # enables seal
common:  --iterations 10 --mock-crypto --enable-proposer-aggregation
         --max-attestations-per-block 3 --format human|json --output <path>
```

Implementation refinements (M1): there is no `--pool-datas` knob — the pool
accumulates one distinct `AttestationData` per elapsed slot naturally, exactly
as on a live node, and per-sample `pool_entries` makes the growth visible.
`--proofs-per-data` defaults to 1 (a single full-coverage aggregate per data,
what a committee aggregator emits) so justification/finalization advance every
slot; higher values exercise multi-proof selection but stall justification
without proposer aggregation — the real coverage cost of that node flag.
Warmup slots double as chain advancement, so there is no separate warmup-
iterations knob.

Known pre-existing issue (unrelated): `lean-quickstart/client-cmds/ethlambda-cmd.sh`
still uses `--custom-network-config-dir`, removed in #321 — needs an upstream fix.

## Harness design (`bin/ethlambda/src/benchmark/{mod,keys,corpus,report}.rs`)

- **Iteration model**: slots advance monotonically, proposer rotates `slot % N` (matches
  round-robin `is_proposer`); each built block is imported via
  `on_block_without_verification` so the empty-slot gap stays constant; the pool is
  re-seeded per iteration in fixed seeded order (insertion order pins proof choice).
- **Keys**: seeded in-process keygen, cached on disk keyed by (leansig rev, seed, index,
  role). Minimal-window keygen costs ~1s/key in release (verified empirically; the window
  floors at 131,072 epochs — ample for thousands of bench slots; the 2^32 lifetime is
  fixed in the type and unaffected). Arbitrary N, no Docker, no fixture download.
- **Synthetic corpus**: `State::from_genesis` + `InMemoryBackend`; K warmup blocks; pool
  = attestations from the last `--pool-datas` slots × `--proofs-per-data` real type-1
  proofs via `aggregate_signatures` (built outside the timed span, progress on stderr).
- **`--mock-crypto`**: empty proofs, forces the `keep_best` path (clap `conflicts_with
  --enable-proposer-aggregation`, since `compact` invokes the real prover), seal skipped
  and reported as null-not-zero. Runs in seconds → CI smoke test.
- **Replay (v1 scope)**: copies the datadir before opening (mandatory — `on_tick`/head
  updates write Metadata per interval and RocksDB has no read-only mode; `--no-copy`
  opt-out with a warning). Loads via `Store::from_db_state`, builds at head+1. Pools are
  in-memory-only and unrecoverable from disk, so v1 replay measures selection + STF +
  state-root realism on real deep states; supplying the node's key trio additionally
  enables the seal phases. Type-2 splitting / pool recording = deferred future work.
- **Report**: human table + `--format json` (stdout pipe-clean, logs to stderr) with
  `schema_version`, environment (CPU model, cores, OS, ethlambda rev via vergen, leansig
  lock rev via a small `build.rs` Cargo.lock parse — leansig tracks the moving `devnet4`
  branch), full params + seed, per-iteration raw samples. One configuration per process
  invocation (global cumulative histograms, rayon/prover state).

## The one library refactor

Extract `crates/blockchain/src/lib.rs:504-631` (proposer sign → type-1 wrap → pubkey
resolution → type-2 merge) into `pub fn seal_block(...) -> Result<SignedBlock,
SealBlockError>` in the blockchain crate; `propose_block` calls it. Justified: the
benchmark cannot reach these phases otherwise (a bin-side copy would drift), it collapses
six repeated error-return-with-metric blocks into one `match` (net-negative LOC), and
adding `sign`/`wrap_proposer_type1`/`merge_type_2` labels to the existing phase histogram
gives production dashboards the currently-untimed expensive steps issue #465 targets.
Verbatim move, own commit, devnet smoke before merge. `build_block` stays `pub(crate)`.

## Milestones

| | Deliverable | Files |
|---|---|---|
| **M1** — CLI + mock end-to-end | `ethlambda benchmark synthetic --mock-crypto` runs in seconds; table + JSON; flat-invocation compat tests; `make bench`; CI smoke step in the existing Test job. Includes one small library fix found by the determinism gate: `extend_proofs_greedily` kept its candidate set in a `HashSet`, so equal-coverage proof ties were broken by randomized hash order and block contents differed run to run — ties now break to the lowest pool index | `cli.rs`, `main.rs`, `benchmark/{mod,corpus,report}.rs`, `build.rs` (leansig rev), `Makefile`, `ci.yml`, `block_builder.rs` (tie-break) |
| **M2** — real crypto | `seal_block` extraction (first commit) + 3 new phase labels; seeded keygen + cache; real type-1 pools; all 7 phases measured; first baseline JSON recorded | `crates/blockchain/src/{seal.rs,lib.rs,metrics.rs}`, `benchmark/keys.rs`, `types/src/signature.rs` (keygen wrapper) |
| **M3** — replay + docs | replay mode against a devnet-runner datadir; `docs/benchmarking.md` + `SUMMARY.md` + README roadmap line | `benchmark/corpus.rs`, docs |

One PR per milestone; `make fmt/lint/test` before each; M2 additionally gated by a devnet
smoke via `test-branch.sh`.

## Verification

- clap `try_parse_from` tests: flat invocation parses, missing-arg errors preserved,
  `benchmark` parses without node args, mixed invocation rejected.
- Determinism: two same-seed runs produce identical per-iteration block-root sequences.
- Accounting: Σphases ≥ 98% of wall per iteration, per-phase count deltas == 1.
- CI mock smoke: `benchmark synthetic --mock-crypto --num-validators 4 --iterations 3
  --format json | jq -e '.schema_version == 1'`.

## Main risks

- Real-mode setup cost: iterations × pool proofs of leanVM proving → default real run
  takes minutes (mitigated: mock mode, small defaults, ETA logging, key cache).
- `seal_block` extraction touches consensus-critical `propose_block` — verbatim
  extraction, careful review of the six error branches, devnet smoke.
- Cross-run comparability: rayon-parallel proving is machine/load-sensitive and leansig
  is a moving branch — the env block in every report is the guard, not a fix.
