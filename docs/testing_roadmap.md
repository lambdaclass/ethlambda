# Testing and Verification Roadmap

The goal is to test ethlambda the way FoundationDB, TigerBeetle, Dropbox, etcd
and AWS test their systems: run the real logic under simulated time and a
seeded, adversarial network, check invariants on every step, and keep every
failing seed as a regression test. The highest-ROI first step is a **seeded
in-process chain-logic simulator**. It drives N in-memory lean stores through
`on_tick` and gossip that a seeded scheduler delays, drops, reorders and
partitions. Most of the seams it needs already exist (see
[What makes it testable](#what-makes-it-testable)), and most of the incidents
under [Gaps](#gaps-tied-to-real-incidents) are timing and ordering bugs of the
kind such a simulator finds.

Priorities and phases on this page are proposals, open for discussion. Code
references are `path:line` at `c3f5f566`.

## What exists today

| Suite | What it catches | Deterministic? | Where it runs |
|---|---|---|---|
| leanSpec `forkchoice_spectests`, `signature_spectests` (`crates/blockchain/Cargo.toml:54,63`), `stf_spectests` (`crates/blockchain/state_transition/Cargo.toml:116`), `ssz_spectests` (`crates/common/types/Cargo.toml:42`) | Divergence from leanSpec fork choice, STF, signature verification, SSZ | Yes | **Nowhere.** All four are `test = false` because the released fixtures still carry the old leanVM key format. CI only clippies them (`.github/workflows/ci.yml:65`) |
| Beacon consensus-spec-tests (`beacon-spec-tests` feature, `make test-beacon-{mainnet,minimal}`) | Beacon STF, fork choice and crypto divergence from consensus-specs | Yes | CI `beacon-spec-tests` job, both presets |
| Hive test driver (`crates/net/rpc/src/test_driver.rs`, `HIVE_LEAN_TEST_DRIVER=1`) | leanSpec fixtures replayed over HTTP by Hive's lean simulator | Yes | Hive, outside this repo |
| proptest: `crates/common/ssz-tree/tests/model.rs`, `crates/storage/src/beacon_state_delta.rs:177` | SSZ tree against a reference model (`libssz_types`); state-delta round trips | Seeded, with a checked-in regressions file | `make test` |
| `#[tokio::test(start_paused = true)]` (`bin/ethlambda/src/main.rs:2681`) | Checkpoint-sync retry and DB-resume windows under paused time | Yes | `make test` |
| `daily_ci.yml` | The same two test halves as CI, reported to Slack | As above | Daily, 12:00 UTC |
| `era_replay.yml` | Beacon STF divergence on real mainnet/hoodi eras ([Era Replay](./era_replay.md)) | Yes | Push to main touching STF/types paths |
| `kurtosis_assertoor.yml` | Beacon node and validator client next to lighthouse: stability, proposals, sync | No | Push to main |
| Shadow build (`shadow-integration` feature, `shadow/README.md`) | Runs the real binary under the Shadow simulator for [lean-shadow-fuzzer](https://github.com/kamilsa/lean-shadow-fuzzer) | Shadow is deterministic per seed | External; `-shadow` images built by `docker_publish.yaml`. No scheduled run here |

Nothing exercises **several lean nodes' chain logic together under controlled
time and message order** in CI, and nothing checks process-level lifecycle
(signals, resource limits).

## What makes it testable

- **Fork-choice time arrives as data.** `store::on_tick(store, timestamp_ms, has_proposal)`
  (`crates/blockchain/src/store.rs:379`) converts a timestamp into intervals;
  nothing inside reads the clock. A simulator can feed any time sequence.
- **The swarm sits behind a channel adapter.** `SwarmHandle` sends
  `SwarmCommand`s over an mpsc channel, and events come back as a stream
  (`crates/net/p2p/src/swarm_adapter.rs:23,112,247`). `SwarmHandle::capturing()`
  (`:241`, `#[cfg(test)]`) already lets a test read what was sent.
- **Storage is a trait with an in-memory backend.** `StorageBackend`
  (`crates/storage/src/api/traits.rs:10`) has `InMemoryBackend`
  (`crates/storage/src/backend/in_memory.rs:26`) next to RocksDB, and the test
  driver already builds stores on it.
- **Crypto can be stubbed.** `on_block_without_verification`
  (`crates/blockchain/src/store.rs:640`); `benchmark synthetic --mock-crypto`
  (`bin/ethlambda/src/benchmark/mod.rs:169`); `dummy_sig()` in aggregation tests
  (`crates/blockchain/src/aggregation.rs:1781`); Shadow's fake-proof backend
  (`crates/common/crypto/src/shadow_cost.rs`).
- **Keys are reproducible.** `ValidatorSecretKey::generate_from_seed`
  (`crates/common/crypto/src/signature.rs:154`).

What makes it hard:

- **No clock trait.** `unix_now_ms()` (`crates/common/types/src/time.rs:14`) reads
  `SystemTime` directly, from 19 sites in `crates/blockchain/src/lib.rs` and
  others in p2p (e.g. 11 in `gossipsub/handler.rs`). The actor's tick
  scheduling mixes this wall clock with tokio's monotonic sleep, which is
  exactly where 3210931f came from.
- **Unseeded randomness.** Peer choice uses `rand::thread_rng()`
  (`crates/net/p2p/src/req_resp/handlers.rs:1000,1156`).
- **A process-global prover thread.** `prover_queue()` spawns one
  `leanvm-prover` thread for the life of the process
  (`crates/common/crypto/src/lib.rs:131`), so in-process nodes share it.
- **Global metrics.** Metrics are `LazyLock` statics (208 in
  `crates/blockchain/src/metrics.rs` alone), so N in-process nodes write the
  same series, and metric-based assertions cannot tell nodes apart.

## Gaps tied to real incidents

| Commit | What broke | What would have caught it |
|---|---|---|
| a2f65803 | Ticks were scheduled on the unix-epoch 800 ms grid, not genesis's, so every interval fired 600 ms late on the default config | Kani/property test on `ms_until_next_interval`; simulator with a non-aligned genesis |
| 514e21a7 | `on_tick` overran its interval (inline proving, ~1.3 s) and the next interval's duty was skipped: a proposer never attested on its own slot, so 1-2 node devnets could not justify | Simulator with injected duty latency; liveness check "every validator attests each slot" |
| 3210931f | Wall clock drifting behind the monotonic clock re-ran an interval's duties (`StateSlotIsNewer` on re-proposal) | Clock-jump tests on the tick actor |
| 67a69ab2 | devnet4: during a finalization stall, fallback pruning deleted states while blocks stayed, so the `has_state` idempotency check let blocks be re-processed forever (100% CPU, ~3.5 GB logs per node) | Simulator with a long partition (finality stall) and a "no block imported twice" monitor |
| 32e3972a | Fork-choice votes were derived from bounded proof buffers, so FIFO eviction dropped live votes from fork-choice weight | Reference-model test of vote tracking; simulator at high attestation volume |
| 65c0bf77 | Beacon: unrealized justifications lived only in memory, so after a restart `get_head` failed every tick and the head froze | Metamorphic restart-from-DB test |
| 6168a0e7 | Hoodi: the missing-ancestor walk stopped at an already-imported block, so a dropped block was never re-requested and ~900 blocks stayed parked for three hours | Reference model of the pending-block fetch set; "every pending root gets an outcome" monitor |
| 64a6bce9 | Two req/resp paths left a root in `pending_root_requests` forever, so it could never be fetched again | Same monitor; failpoints on error responses |
| d2593f88 | Checkpoint sync failed fast on one timeout and the process exited (flaky Hive starts) | Failpoint on checkpoint sync |
| afc491b2 | devnet-5 aggregators with `--prover-arena` were OOM-killed about every 40 minutes: each proving thread pinned an arena slab | Soak with an RSS budget |
| 1d7902da | Release feedback: `docker stop` force-killed after 10 s while a clean shutdown took 14.3 s, losing state; clean Ctrl+C logged a P2P `ERROR` | Process-level shutdown test with a time budget and a clean-log assertion |

## Techniques

Each entry: what it is, precedent, the ethlambda target, effort, and the
acceptance criterion.

### Seeded in-process chain-logic simulator (flagship)

- **What:** N lean `Store`s on `InMemoryBackend`, one simulated clock driving
  `on_tick`, blocks and attestations delivered through a seeded scheduler that
  delays, drops, duplicates, reorders and partitions. Signatures stubbed via
  `on_block_without_verification`. Each run is a pure function of its seed.
- **Precedent:** [FoundationDB simulation](https://apple.github.io/foundationdb/testing.html), [TigerBeetle VOPR](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/internals/vopr.md).
- **Target:** `crates/blockchain` store functions plus validator duties, above
  the swarm. No libp2p and no actor.
- **Invariants:** safety (no two conflicting finalized checkpoints across nodes;
  finalized slot never decreases); liveness (finalization resumes within K slots
  after a partition heals with >2/3 honest connected); no block imported twice.
- **Effort:** 2-3 weeks for a first version. Needs the duty path callable
  without the actor, and a clock parameter where duties call `unix_now_ms()`.
- **Done when:** runs in CI on a fixed seed set plus a few hundred random seeds
  nightly; a failing seed reproduces locally from one command; at least one
  incident above (514e21a7 or 67a69ab2) is reproduced by reverting its fix.

### Re-enable the leanSpec runners

- **What:** regenerate or bump to fixtures with the current leanVM key format
  and drop `test = false` from the four runners.
- **Precedent:** every consensus client runs its spec tests on every PR.
- **Effort:** days, gated on a leanSpec fixture release.
- **Done when:** `make test` runs all four and CI fails on a fork-choice fixture
  mismatch.

### Kani on slot and justification math

- **What:** bounded proofs of `slot_is_justifiable_after`
  (`crates/blockchain/state_transition/src/lib.rs:629`; no overflow, agrees with
  a naive square/pronic definition), `ms_until_next_interval`
  (`crates/blockchain/src/lib.rs:208`; result in `1..=interval`, lands on a
  genesis-aligned boundary, the property a2f65803 broke), and
  `on_tick`'s timestamp-to-interval conversion.
- **Precedent:** AWS runs [Kani harnesses on Firecracker](https://model-checking.github.io/kani-verifier-blog/2023/08/31/using-kani-to-validate-security-boundaries-in-aws-firecracker.html) in CI.
- **Effort:** about a week. **Done when:** a `kani` CI job proves the harnesses.

### TLA+ / Apalache model of 3SF-mini justification and finality

- **What:** a model of justification and finalization with justifiable-slot
  rules, checked for accountable safety. Start from Konnov et al.,
  [arXiv:2501.07958](https://arxiv.org/abs/2501.07958), which translated 3SF's
  executable Python specification to TLA+ and checked accountable safety with
  Apalache (exhaustively up to 7 checkpoints and 24 votes).
- **Target:** [3SF-mini](./3sf_mini.md) as ethlambda implements it, then trace
  validation against simulator runs.
- **Effort:** weeks. **Done when:** the model checks in CI at small bounds and
  simulator traces replay in it.

### Metamorphic tests

- **What:** the same block set in any arrival order gives the same head and
  finalized checkpoint; a node restarted from its DB gives the same head as one
  that never stopped (the property 65c0bf77 lacked).
- **Effort:** days on the simulator's harness. **Done when:** both run per seed.

### Reference models

- **What:** proptest a simple model against `justified_slots_ops`
  (`set_justified`, `shift_window`,
  `crates/blockchain/state_transition/src/justified_slots_ops.rs:45,72`) and
  against the pending-block / `pending_root_requests` bookkeeping (6168a0e7,
  64a6bce9), as `ssz-tree/tests/model.rs` already does for SSZ.
- **Effort:** days each. **Done when:** random op sequences agree with the
  model after every step.

### Failpoints

- **What:** named fault sites (e.g. the `fail` crate) in the aggregation
  worker, RocksDB writes, swarm-loop exit, and checkpoint-sync fetch.
- **Effort:** days. **Done when:** each site has a test asserting the node
  either recovers or exits with a clear error, never hangs.

### Process-level shutdown test

- **What:** start the binary, send SIGINT and SIGTERM, assert exit within a
  budget with a clean log and a DB that resumes. On `main` only SIGINT is
  handled (`tokio::signal::ctrl_c()`, `bin/ethlambda/src/main.rs:988`), so
  SIGTERM uses the default action and kills the node in about 0.01 s with no
  graceful shutdown (measured during the `spawned-v0.7` work); the README works
  around it with `--stop-signal SIGINT`. The `spawned-v0.7` branch handles
  SIGTERM and bounds shutdown with an 8 s deadline.
- **Effort:** days. **Done when:** CI kills a running node both ways and checks
  time, exit code, log level and a successful resume.

### Single-CPU runs

- **What:** run the test suite and a short devnet under `taskset -c 0` (or a
  1-CPU container) to surface starvation between the actor, the
  `spawn_blocking` aggregation worker and the prover thread.
- **Effort:** a CI job. **Done when:** a nightly 1-CPU devnet finalizes.

### Clock-jump tests

- **What:** feed the store and the tick actor wall-clock jumps forward and
  backward and monotonic/wall drift (3210931f, a2f65803). Requires a clock
  parameter in place of `unix_now_ms()` on the tick path.
- **Done when:** no interval's duties run twice or are skipped under drift.

### Soak with resource budgets

- **What:** multi-hour devnet with aggregators and `--prover-arena`, asserting
  RSS, FD and DB-size ceilings (afc491b2).
- **Done when:** a nightly soak fails on budget breach, not only on crash.

### TSAN / LSan

- **What:** nightly `-Zsanitizer=thread` and `leak` runs of the node test half.
- **Done when:** clean, with any suppressions listed and justified.

### Log-based invariant monitors

- **What:** a checker over devnet and Shadow logs: slot monotonicity, tick
  lateness under a bound, every pending root reaching an outcome (64a6bce9,
  6168a0e7), no block imported twice (67a69ab2). `tooling/event-monitor` is a
  natural home.
- **Done when:** every Kurtosis, Shadow and soak run ends with the monitor.

### Nightly Shadow runs with seeds

- **What:** a scheduled multi-node Shadow run of the `-shadow` image with a
  recorded seed, partitions and latency, plus the log monitors.
- **Precedent:** lean-shadow-fuzzer already drives ethlambda under Shadow.
- **Done when:** nightly, failing seeds filed with a repro command.

### Kurtosis/Assertoor and Attacknet-style chaos for lean devnets

- **What:** extend `kurtosis_assertoor.yml`, today beacon-only, to a lean
  devnet; add [Attacknet](https://github.com/crytic/attacknet)-style faults (partitions, clock skew, container kills).
- **Done when:** a lean devnet job runs on main with at least one fault scenario.

### spawned-test fault injection and lifecycle monitors

- **What:** after the spawned v0.7 upgrade (branch `spawned-v0.7`), use
  `spawned-test` mocks (already replacing hand-written protocol stubs there),
  supervision fault injection, and lifecycle monitors that assert every actor
  stops within the shutdown deadline.
- **Done when:** a test panics each restartable actor and checks the node keeps
  importing.

### Antithesis (optional)

- **What:** hosted deterministic hypervisor that explores fault schedules
  against the real containers. Worth evaluating once the in-process simulator
  and Shadow runs stop finding bugs.

## Phased plan

**Phase 1: now, on `main`.**

| Item | Acceptance |
|---|---|
| Re-enable the leanSpec runners | All four run in `make test` |
| Chain-logic simulator | Fixed seeds in CI, random seeds nightly, one incident reproduced |
| Kani slot math | CI job proves the three harnesses |
| Shutdown test | SIGINT and SIGTERM both covered; SIGTERM expected to fail until Phase 2 |
| Nightly Shadow | Scheduled seeded run with log monitors |
| Single-CPU | Nightly 1-CPU devnet finalizes |
| Soak | Nightly run with RSS/FD/DB budgets |

**Phase 2: with spawned v0.7** (`spawned-v0.7` branch, canary on fede256).

| Item | Acceptance |
|---|---|
| `ActorSystem` shutdown deadline | SIGTERM test passes within 8 s |
| Supervision fault injection | Restartable actors panicked in tests; import continues |
| spawned-test mocks | Done on the branch |
| Lifecycle monitors | Every actor stop observed within the deadline |

**Phase 3.**

| Item | Acceptance |
|---|---|
| Actor-level exploration once spawned ships `explore` | Low value while ethlambda runs two main actors (`BlockChain`, `P2P`); revisit if that grows |
| TLA+ 3SF-mini model | Checks in CI; simulator traces validate against it |

## Shared with ethrex

- **Storage pattern:** the same backend-trait-plus-in-memory approach makes
  restart and failpoint tests portable between the two clients.
- **Discovery:** ethlambda runs ethrex's discv5 `DiscoveryServer`
  (`crates/net/p2p/src/discovery/mod.rs:21`), so discovery tests belong upstream.
- **Harness:** both build on spawned; its testing harness and monitors serve
  both.

Related plans: [ethrex testing and verification roadmap (ethrex#7517)](https://github.com/lambdaclass/ethrex/pull/7517),
[spawned: Database-grade testing program](https://github.com/lambdaclass/spawned/blob/main/ROADMAP.md#database-grade-testing-program),
[spawned: systematic testing research](https://github.com/lambdaclass/spawned/blob/main/docs/research/systematic-testing.md).

## Sources

- Konnov, Kukovec, Pani, Saltini, Tran, *Exploring Automatic Model-Checking of the Ethereum specification*: <https://arxiv.org/abs/2501.07958>
- FoundationDB, *Simulation and Testing*: <https://apple.github.io/foundationdb/testing.html>
- TigerBeetle, *VOPR*: <https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/internals/vopr.md>
- Kani on AWS Firecracker: <https://model-checking.github.io/kani-verifier-blog/2023/08/31/using-kani-to-validate-security-boundaries-in-aws-firecracker.html>
- Attacknet: <https://github.com/crytic/attacknet>
- Shadow network simulator: <https://shadow.github.io/>
- lean-shadow-fuzzer: <https://github.com/kamilsa/lean-shadow-fuzzer>
- ethrex PR #7517: <https://github.com/lambdaclass/ethrex/pull/7517>
- spawned ROADMAP and research note: links above
