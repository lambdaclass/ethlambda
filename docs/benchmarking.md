# Benchmarking

`ethlambda benchmark` measures two things the node does in production, each
against a reproducible offline workload, with no devnet running:

- **`synthetic`**: block building, the way the node performs it when it
  proposes, on a synthetic in-memory chain built for the run.
- **`import`**: block import, replaying a corpus of real blocks through the
  node's own import path. See [Import workload](#import-workload) below.

Both are otherwise only observable through the Prometheus histograms a live
node exports. Those are noisy, depend on whatever the network happened to be
doing, and cannot be diffed against a baseline, which makes them a poor
instrument for tracking performance. Each benchmark trades some realism for
repeatability: the same parameters (or the same corpus) produce the same
result every run, so two reports differ only where the code differs.

## Synthetic workload (block building)

### Running it

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
| `--key-cache <dir>` | — | Cache the seed-derived XMSS keys on disk (keyed by leanVM revision, seed, validator index and run length). Real crypto only |
| `--mock-crypto` | off | Placeholder proofs instead of real XMSS/leanVM signatures, and no seal. Measures selection, compaction and the state transition only |
| `--enable-proposer-aggregation` | off | Mirrors the node flag: collapse same-data proofs via recursive leanVM aggregation |
| `--max-attestations-per-block` | `3` | Mirrors the node flag: distinct `AttestationData` per block |
| `--format` | `human` | `human` or `json` |
| `--output <path>` | — | Also write the JSON report to a file |

Logs go to stderr and the report to stdout, so `--format json` pipes straight
into `jq`.

### What it measures

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

### Reading a report

```
Block-building benchmark — synthetic workload (real crypto)
  validators=2 warmup_slots=1 iterations=2 proofs_per_data=1 seed=42
  enable_proposer_aggregation=false max_attestations_per_block=3
  ethlambda/v0.1.0/aarch64-apple-darwin/rustc-v1.97.1 leanvm=48a90420 os=macos arch=aarch64 threads=14

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
Outliers are never discarded: XMSS signing and its Merkle-subtree cache misses produce
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

### Comparing two runs

Same seed and same parameters produce identical root sequences, so a baseline
and a candidate can be diffed directly. The header line exists to tell you when
they *cannot* be compared:

- `leanvm` is the resolved revision the binary was built against, read from
  `Cargo.lock` at build time. leanVM owns the whole signature stack (XMSS and
  aggregation), so a rev bump changes the measured crypto. Real-mode roots also
  depend on the seed-derived keys, so the same seed on the same leanVM revision
  reproduces the same signatures and the same roots.
- `os`, `arch` and `threads` change results across machines.

Two reports that disagree on any of those are not measuring the same thing.

### Limitations

- **Synthetic chain, not a production state.** This workload builds on a
  genesis constructed for the run, not a deep chain. The [import
  workload](#import-workload) below covers real production states instead, by
  replaying real blocks rather than building synthetic ones.
- **Short-lived keys.** Real-mode XMSS keys are generated for exactly the slots
  the run signs, so key generation is cheap but the OTS window advancement a
  long-lived validator key performs every 65,536 slots is never exercised.
- **Mock mode skips the seal.** Without keys there is nothing to sign, so the
  three seal phases only appear in real runs.

### In CI

The Test job runs a short mock benchmark and asserts the JSON report's shape
(`schema_version`, one sample per iteration). It costs seconds, and it means a
change to the report contract cannot land unnoticed.

## Import workload

`ethlambda benchmark import` measures block import: the state transition,
attestation processing, persistence and fork-choice work a node does for every
block it receives, whether proposed locally or gossiped in. It replays a
corpus of real blocks through the node's own import path, offline.

### Why a corpus

Measuring import on a live mainnet follower is possible, but the numbers it
produces are hard to trust:

- Each comparison leg needs a restart, so a run costs about ten minutes before
  a single block is measured.
- The denominator moves between legs. How much of that ten minutes was spent
  actually importing, versus holding a block for data availability or waiting
  on a column fetch, differs run to run with whatever the network happened to
  be doing.
- A live follower's process is not only importing. It is simultaneously
  serving gossip, req/resp, discovery and column custody, all competing for
  the same CPU the import path is trying to use.

The work being measured, one block's state transition and its consequences, is
deterministic. Capturing a range of real blocks once and replaying it offline
removes all three problems: no restart between legs, no held-block noise in
the denominator, and nothing else running in the process.

### The two phases

**`fetch`** pulls a slot range from a running beacon node's standard Beacon
API into a corpus directory: a manifest, the anchor state and block the range
builds on, and one SSZ file per non-empty slot from the anchor to the end of
the range. The anchor sits on the first slot of an epoch (see
[Requirements and limits](#requirements-and-limits)), so the blocks between it
and `--from` are fetched too, and recorded as warm-up blocks the replay imports
without sampling. It prints a progress line to stderr every hundred slots.

A 404 from the Beacon API means an empty slot, a slot past the source's head, or
one before its history, and `fetch` cannot tell those apart from the status
alone. So it refuses a `--to` past the source's head, and checks that every
block names the previous one as its parent: a block missing from the middle of
the range, or a reorg between two requests, stops the fetch instead of turning
into a replay that fails many minutes later. A fetch that fails removes the
corpus directory if it was the one that created it.

```bash
ethlambda benchmark import fetch \
  --url http://127.0.0.1:5052 \
  --from 9123456 --to 9133456 \
  --corpus ./corpus/9123456-9133456 \
  --network mainnet
```

**`replay`** drives that corpus's blocks, in manifest order, through
`BlockChainServer::import_block` on a freshly bootstrapped RocksDB store, and
reports per-block, per-phase timings for the blocks in the range. Each block
prints a progress line to stderr as it imports, since a mainnet block takes
seconds and a long corpus would otherwise run silent for hours.

```bash
ethlambda benchmark import replay \
  --corpus ./corpus/9123456-9133456 \
  --data-dir ./replay-data \
  --network mainnet \
  --format json --output report.json
```

### What is measured

The measured span is one `BlockChainServer::import_block` call per block, the
same `on_block` entry a live node's own cascade uses. That covers the state
transition, block-borne attestation processing, state persistence to RocksDB,
and the beacon head recomputation: `on_block` recomputes the head itself after
every import rather than waiting for a tick to do it, so that cost is inside
the span too.

Per-block, per-phase numbers come from the `lean_block_import_phase_seconds`
histogram, read before and after each import the same way the synthetic
workload reads its own histogram. A replayed block reports under
`source="replay"`, a label no node ever writes, so it reaches the histogram
without passing for a gossip or sync arrival. The phases are the
`BLOCK_IMPORT_PHASES` labels: `decode`, `queue`, `defer`, `admit`, `guards`,
`preamble`, `parent_wait`, `cascade_wait`, `da_check`, `columns_wait`, `engine`,
`verify_struct`, `verify_crypto`, `stf`, `writer_wait`, `db_write`, `fc_head`,
`block_atts`; plus the per-arrival sections that are not spans around the others, `prune`,
`get_head` and `fcu`, since each `import_block` call is one arrival. `get_head`
is where the head recomputation after every import is charged.

On beacon, `writer_wait` is the importer's blocking hand-off of the post-state
to the storage crate's background writer, which waits while the writer's queue
is full. It happens inside `fork_choice::on_block`, so `stf` excludes it: `stf`
is state-transition work and the two phases do not overlap. When blocks import
faster than the writer persists them, the wait shows up here rather than in
`stf`.

### What is excluded, and why

Replay runs nothing that a corpus already answers for:

- **No execution client**, so `engine` reports a near-zero section with nothing
  to call and `fcu` never runs. On a live follower paired with one, `engine` was
  31ms p50, about 0.5% of an import; a replay's numbers are complete without it.
- **An empty custody set**, so `columns_wait` never runs and no block is ever
  held waiting on data availability. A corpus supplies every block directly;
  there are no columns to wait for.
- **No gossip, req/resp or discovery.** `replay` drives `import_block`
  directly on the caller's task: no mailbox, no tick loop, no p2p, so none of
  that traffic competes with import for CPU.

A phase that did not run on a given block is **absent from that block's
report, not zero**. That is what keeps a phase that genuinely took no time
distinguishable from one that never ran at all.

### Requirements and limits

- **The anchor sits on the first slot of an epoch.** Fork choice makes the
  anchor its finalized checkpoint at the anchor state's own epoch, and every
  import walks back to that epoch's first slot to find the checkpoint's block.
  From an anchor past that slot the walk steps below the anchor, onto a block
  the store never held, and the first import fails with
  `spec assertion failed: root in store.blocks`. So `fetch` anchors on the
  block at the first slot of the epoch holding `--from - 1`, stepping back an
  epoch at a time while that slot is empty, and fetches that block's own
  post-state. `replay` refuses a corpus whose anchor is anywhere else, which
  only a corpus fetched before this rule can have.
- **The source node must still hold a state at the anchor slot.** Most beacon
  nodes serve only recent states, so an old range fails at `fetch` with a 404
  naming the state endpoint it tried.
- **The range is deliberately not capped.** `fetch` streams: the anchor state
  is the only state it ever holds, decoded once to read the genesis
  fingerprint, written to disk and dropped before the block loop starts, and
  each block is written as its response completes rather than accumulated. A
  long range costs disk and time, not memory.
- **A replay's RAM floor is the store's own state cache.** `replay` shares the
  same `STATE_CACHE_CAPACITY`-bounded LRU every node runs with. With the
  registry and balances in persistent trees, cached states share every
  unchanged subtree, so the cache costs far less than its capacity times one
  state: a 128-block mainnet replay at 2.4M validators measured 2.9 GiB of RSS
  once every block was in, against 11.6 GiB when each state held flat copies.
  That ceiling belongs to the store, not to this harness.
- **`--network` selects the decoder, not just a genesis check.**
  `decode_block` resolves each block's fork from its own slot through that
  network's fork schedule, so replaying against the wrong network can decode a
  block at the wrong fork. The manifest records the genesis validators root
  the corpus was fetched against, and `replay` refuses a mismatch against
  `--network` before decoding a single block.

### How to A/B two revisions

Fetch one corpus, then replay it twice, once per revision, against separate
`--data-dir`s:

```bash
ethlambda benchmark import replay --corpus ./corpus/9123456-9133456 \
  --data-dir ./replay-baseline --format json --output baseline.json

ethlambda benchmark import replay --corpus ./corpus/9123456-9133456 \
  --data-dir ./replay-candidate --format json --output candidate.json
```

The corpus is the fixed input both legs share, so `baseline.json` and
`candidate.json` differ only where the code differs. `--format json --output
<file>` is what makes that diffable; the human table on stdout is for reading
a single run, not for diffing two.

### Determinism

Two replays of one corpus, on the same revision, import identical block roots
in the same order. Each sample's `block_root` is a per-block checksum for
exactly that: if a change alters the sequence of roots a corpus produces, it
changed what got imported, not just how fast, and a timing comparison against
that run means something different than intended.
