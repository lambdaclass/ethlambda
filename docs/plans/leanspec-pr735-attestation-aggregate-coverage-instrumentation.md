# Attestation Aggregate Coverage — Instrumentation (zeam #876 port)

## Goal

Following Mega's PR #386 review ("We still need to emit the metrics"), port the
producer side of [zeam #876](https://github.com/blockblaz/zeam/pull/876) on top
of the registration-only metrics from PR #386. After this PR, all 18 series
declared in `init()` get real per-slot updates from chain activity.

## Source-of-truth: zeam #876

Reference for every design choice. Emission lives in three call sites:

| # | zeam call site | Sections emitted | When |
| - | -------------- | ---------------- | ---- |
| 1 | `acceptNewAttestationsUnlocked` (snapshot) + `formatAggregationCoverageReport` (emit) in `forkchoice.zig`, fired from `chain.zig::printSlot` for `slot - 1` | `timely`, `late`, `block`, `combined`, `diff_validators` | Once per slot, at the slot boundary, reporting on the previous slot |
| 2 | `logBlockProposalPayloadCoverage` in `forkchoice.zig`, fired from the end of `aggregate` | `proposal_payloads`, `proposal_gossip`, `proposal_combined` | Once per block proposal |
| 3 | `logNewPayloadsCoverageForAggregation` in `forkchoice.zig`, fired from `chain.zig` right before fork-choice `aggregate` runs | `agg_start_new` | Once per slot, at the aggregation start (interval 2 in ethlambda) |

zeam's `latest_block_aggregated_payloads` is observability-only: block-extracted
proofs are stored in **both** `latest_known_aggregated_payloads` (for fork
choice) **and** in `latest_block_aggregated_payloads` (for the report). We
mirror that exactly.

## Mapping zeam → ethlambda

| zeam concept | ethlambda location | Notes |
| ------------ | ------------------ | ----- |
| `forkchoice.zig` state (payload maps) | `crates/storage/src/store.rs` (`Store::known_payloads`, `Store::new_payloads`, `Store::gossip_signatures`) | All in-memory, behind `Mutex` |
| `latest_known_aggregated_payloads` | `Store::known_payloads` (existing) | Snapshot via `Store::known_aggregated_payloads()` |
| `latest_new_aggregated_payloads` | `Store::new_payloads` (existing) | No public snapshot today; add `new_aggregated_payloads()` |
| `latest_block_aggregated_payloads` | **New** `Store::block_payloads` + slot tracker | Reset when block-slot changes |
| `saved_pre_merge_new_coverage` | **New** `Store::saved_pre_merge_new_coverage` | Captured before each promote |
| `acceptNewAttestationsUnlocked` (the merge) | `crates/blockchain/src/store.rs::accept_new_attestations` (calls `store.promote_new_aggregated_payloads()`) | Snapshot taken just before the call |
| `aggregate` (block proposal) | `crates/blockchain/src/store.rs::build_block` | Fire at the end |
| `chain.zig::printSlot` (per-slot report) | `crates/blockchain/src/lib.rs::on_tick` at `interval == 0` | Fires once per slot for `slot - 1` |
| `chain.zig` aggregation start | `BlockChainServer::start_aggregation_session` in `lib.rs` (interval 2) | Fire before `snapshot_aggregation_inputs` |
| `config.spec.attestation_committee_count` | **New** field on `BlockChainServer`, threaded through `BlockChain::spawn` | Currently only known to P2P; needs threading |
| `config.genesis.numValidators()` | `store.head_state().validators.len()` | Already accessible |
| `computeSubnetId(vid, committee_count)` | `vid % committee_count` (matches `crates/net/p2p/src/lib.rs:241`) | Inline; no helper needed |
| `AggregationBits` participants | `AggregatedSignatureProof::participants` (global validator-index bits) | `validator_indices(bits)` already iterates set bits as u64 IDs |

## New code surface

### Helpers — `crates/blockchain/src/coverage.rs` (new file)

```rust
//! Per-slot attestation aggregate coverage computation.

use ethlambda_types::{
    attestation::{AggregationBits, validator_indices},
    block::AggregatedSignatureProof,
};

/// Per-validator + per-subnet presence used by every coverage section.
#[derive(Debug, Clone)]
pub struct Coverage {
    pub seen: Vec<bool>,        // len = validator_count
    pub has_subnet: Vec<bool>,  // len = committee_count
    pub committee_count: u64,
}

impl Coverage {
    pub fn new(validator_count: usize, committee_count: usize) -> Self { ... }

    /// OR in another coverage (for `combined` rollups).
    pub fn merge_from(&mut self, other: &Self) { ... }

    /// Mark validators set in `bits`; their subnets are derived from `index % committee_count`.
    pub fn add_bits(&mut self, bits: &AggregationBits) { ... }

    /// Mark validators set in any of `proofs` for one attestation entry.
    pub fn add_proofs(&mut self, proofs: &[AggregatedSignatureProof]) { ... }

    pub fn count_seen(&self) -> usize { ... }
    pub fn count_subnets(&self) -> usize { ... }
}

/// (a_only, b_only) symmetric-difference validator counts.
pub fn diff_counts(a: &Coverage, b: &Coverage) -> (usize, usize) { ... }

/// Push `seen`/`subnets` for one section to Prometheus.
pub fn record_section(section: &str, coverage: &Coverage) {
    crate::metrics::set_attestation_aggregate_coverage_validators(section, "combined", coverage.count_seen() as i64);
    crate::metrics::set_attestation_aggregate_coverage_subnets(section, coverage.count_subnets() as i64);
}

pub fn record_diff(block_only: usize, timely_only: usize) { ... }
```

No log-line emission in this PR (zeam's `info!` chain-status line is
separately useful but not required to satisfy "emit the metrics"; we keep
the surface focused). If we want it later it's one helper away.

### Store state additions — `crates/storage/src/store.rs`

```rust
/// Coverage snapshot of `latest_new_aggregated_payloads` captured just before a promote().
/// Read once per slot during the post-block coverage report.
#[derive(Debug, Clone)]
pub struct SavedPreMergeCoverage {
    pub slot: u64,
    pub seen: Vec<bool>,
    pub has_subnet: Vec<bool>,
}

// Inside Store {}
block_payloads: Mutex<AggregatedPayloadsBuffer>,
block_payloads_slot: Mutex<Option<u64>>,
saved_pre_merge_new_coverage: Mutex<Option<SavedPreMergeCoverage>>,
```

New public methods:

```rust
// New payload snapshot (mirrors known_aggregated_payloads)
pub fn new_aggregated_payloads(&self) -> HashMap<H256, (AttestationData, Vec<AggregatedSignatureProof>)>;

// Block payload tracking — resets when block-slot changes
pub fn insert_block_aggregated_payloads_batch(
    &mut self,
    block_slot: u64,
    entries: Vec<(HashedAttestationData, AggregatedSignatureProof)>,
);
pub fn block_aggregated_payloads(&self) -> HashMap<H256, (AttestationData, Vec<AggregatedSignatureProof>)>;
pub fn block_aggregated_payloads_slot(&self) -> Option<u64>;

// Pre-merge snapshot — get/set
pub fn save_pre_merge_new_coverage(&self, snapshot: SavedPreMergeCoverage);
pub fn pre_merge_new_coverage(&self) -> Option<SavedPreMergeCoverage>;
```

### Metric setters — `crates/blockchain/src/metrics.rs`

```rust
pub fn set_attestation_aggregate_coverage_validators(section: &str, subnet: &str, value: i64) {
    LEAN_ATTESTATION_AGGREGATE_COVERAGE_VALIDATORS
        .with_label_values(&[section, subnet])
        .set(value);
}

pub fn set_attestation_aggregate_coverage_subnets(section: &str, value: i64) {
    LEAN_ATTESTATION_AGGREGATE_COVERAGE_SUBNETS
        .with_label_values(&[section])
        .set(value);
}

pub fn set_attestation_aggregate_coverage_diff_validators(direction: &str, value: i64) {
    LEAN_ATTESTATION_AGGREGATE_COVERAGE_DIFF_VALIDATORS
        .with_label_values(&[direction])
        .set(value);
}
```

### Threading `attestation_committee_count` to `BlockChain`

Three call-site updates:

1. `BlockChainServer` gains `attestation_committee_count: u64` field.
2. `BlockChain::spawn(...)` gains an `attestation_committee_count: u64` parameter.
3. `bin/ethlambda/src/main.rs` already resolves it (line 183-192); just pass it into `BlockChain::spawn`.

This is a small public-API change; we add a `// breaking change` note to `RELEASE.md`'s next-release section if one exists.

## Emission sites

### 1. Pre-merge snapshot — `accept_new_attestations`

In `crates/blockchain/src/store.rs::accept_new_attestations`, BEFORE the
`store.promote_new_aggregated_payloads()` call:

```rust
fn accept_new_attestations(
    store: &mut Store,
    committee_count: u64,
    log_tree: bool,
) {
    // Snapshot the new-payload coverage right before the merge.
    if let Some(snapshot) = snapshot_new_payloads(store, committee_count) {
        store.save_pre_merge_new_coverage(snapshot);
    }
    store.promote_new_aggregated_payloads();
    // ... existing code ...
}
```

`snapshot_new_payloads()`:
1. Returns `None` if `validator_count == 0 || committee_count == 0 || new_payloads` is empty.
2. Reads the slot from the first entry's `AttestationData.slot`.
3. Builds a `Coverage` over `new_payloads`.
4. Returns `SavedPreMergeCoverage { slot, seen, has_subnet }`.

### 2. Block payloads buffer — `on_block_core`

In `crates/blockchain/src/store.rs::on_block_core` at line 527, **replace**:

```rust
store.insert_known_aggregated_payloads_batch(known_entries);
```

with the dual-write:

```rust
let known_entries_for_block = known_entries.clone();
store.insert_known_aggregated_payloads_batch(known_entries);
store.insert_block_aggregated_payloads_batch(block.slot, known_entries_for_block);
```

The `.clone()` is necessary because `Vec<(HashedAttestationData, AggregatedSignatureProof)>`
isn't `Copy` and both buffers need ownership. `insert_block_aggregated_payloads_batch`
resets the buffer when `block_slot` differs from the previous insert's slot.

### 3. Per-slot coverage report — `on_tick` interval 0

In `crates/blockchain/src/lib.rs::on_tick`, after `store::on_tick` runs at
`interval == 0`:

```rust
if interval == 0 && slot > 0 {
    coverage::emit_post_block_report(
        &self.store,
        self.attestation_committee_count,
        slot - 1,
    );
}
```

`emit_post_block_report(slot)`:
1. Read `validator_count` from `store.head_state().validators.len()`. Bail if zero.
2. Build `Coverage`s for:
   - `timely`: `store.pre_merge_new_coverage()` if `Some` and `.slot == slot`, else empty.
   - `late`: from `store.new_aggregated_payloads()` filtered to `data.slot == slot`.
   - `block`: from `store.block_aggregated_payloads()` if `block_payloads_slot() == Some(slot)`, else empty.
   - `combined`: union of the above three.
3. `record_section(...)` for each.
4. `diff_counts(block, timely)` → `record_diff(block_only, timely_only)`.

### 4. Aggregation-start coverage — `start_aggregation_session`

In `crates/blockchain/src/lib.rs::start_aggregation_session`, at the top
(before the prior-session join and `snapshot_aggregation_inputs`):

```rust
coverage::emit_agg_start_new(
    &self.store,
    self.attestation_committee_count,
    slot,
);
```

Computes coverage from `store.new_aggregated_payloads()` and emits
`agg_start_new`. Bails silently on zero counts.

### 5. Block proposal coverage — `build_block`

The most invasive of the five. zeam's `logBlockProposalPayloadCoverage`
classifies validators selected into the block as:

- **payloads**: covered by some entry in `latest_known_aggregated_payloads` for that `AttestationData`
- **gossip**: in the final selection but NOT covered by any known payload (i.e., came from gossip-only)
- **combined**: final block coverage

In `crates/blockchain/src/store.rs::build_block`, just before the
`Ok((block, signatures, post_checkpoints))` return, compute the three
coverages and emit. Code lives in `coverage.rs`:

```rust
pub fn emit_proposal_coverage(
    store: &Store,
    committee_count: u64,
    selected: &[(AggregatedAttestation, AggregatedSignatureProof)],
) {
    // For each (att, _proof) in selected:
    //   final.add_bits(att.aggregation_bits)
    //   For each existing payload proof matching att.data in known_payloads:
    //     payload_coverage.add_bits(proof.participants)
    //
    // Then for each validator v set in final:
    //   if payload_coverage.seen[v] → proposal_payloads.set(v)
    //   else                        → proposal_gossip.set(v)
}
```

Lookup: `store.existing_proofs_for_data(&data_root)` returns
`(new_proofs, known_proofs)` (line 1135 in `storage/src/store.rs`); we use
`known_proofs` only (matches zeam's `latest_known_aggregated_payloads`).

## Testing

### Unit tests for `coverage.rs`

In a `#[cfg(test)] mod tests {}` block in `crates/blockchain/src/coverage.rs`:

- `Coverage::add_bits` marks expected validators and derives correct subnets.
- `Coverage::merge_from` is OR-correct.
- `diff_counts` returns symmetric-difference counts for hand-built sets.
- `record_section` and `record_diff` round-trip through `prometheus::gather()`
  (use a scoped check that the metric family's sample value matches).

Target: ~6-8 unit tests, all in-process, no actor wiring needed.

### Integration touch-tests

Modify existing on_block tests in `crates/blockchain/src/store.rs::tests` (the
`tests` module starting around line 1443):

- After inserting a block, assert that `store.block_aggregated_payloads_slot() == Some(block.slot)`.
- After calling `promote_new_aggregated_payloads`, assert that
  `store.pre_merge_new_coverage()` is `Some` and reflects the new payloads.

No new integration test files; we lean on the existing harness.

### Spec tests

`forkchoice_spectests` and `signature_spectests` should remain unchanged.
The 8 pre-existing `AttestationTooFarInFuture` flakes documented in PR #386
are unrelated.

## Verification

1. `make fmt` — clean.
2. `make lint` — clippy with `-D warnings`.
3. `cargo test -p ethlambda-blockchain --release --lib --bins` — must pass including new unit tests.
4. `cargo test --workspace --release --exclude ethlambda-blockchain` — must pass.
5. `cargo test -p ethlambda-blockchain --release --test signature_spectests` — must pass.
6. `cargo test -p ethlambda-blockchain --release --test forkchoice_spectests` — must show the same 8 pre-existing flakes only, no new failures.
7. Manual devnet smoke (`make run-devnet` for ~3 slots):
   - `curl :5054/metrics | grep lean_attestation_aggregate_coverage` — should show non-zero values for `combined`/`block`/`agg_start_new` at minimum.
   - Spot-check the `diff_validators` direction values — typically both should be near zero on a healthy devnet.

## Out of scope (deliberately, despite the "full port" intent)

- **Chain-status info log line.** zeam emits a human-readable `info!` line on every per-slot report. The metric emission alone satisfies the review comment; the log line is a follow-up if operators ask for it.
- **`tests/` integration coverage of the agg-start path.** The aggregation start runs inside a `tokio::spawn_blocking` worker; covering it would require a more elaborate harness. We rely on devnet smoke testing.

## Risks / open questions

- **Concurrency on `block_payloads`.** Same locking pattern as the existing buffers (one `Mutex` per buffer). No new contention surfaces — all writes are inside `on_block` (already serialized through the BlockChain actor), reads are at slot boundaries.
- **Snapshot allocation.** `Coverage` allocates `validator_count + committee_count` bools per call. On 64-validator devnets that's ~70 bytes per snapshot — negligible. At 4096 validators it's ~4KB per emit, ×5 emits/slot. Still under noise.
- **`committee_count` propagation.** This is a public API change to `BlockChain::spawn`. Only `bin/ethlambda/src/main.rs` calls it; updated in the same PR.
- **`block_payloads_slot` semantics.** zeam resets the buffer when an inserted entry's `data.slot` differs. We reset on `block.slot` (header slot) instead — simpler and matches our insertion granularity (whole block, not per-entry). Equivalent for honest proposers.
- **What if no block was imported this slot?** Then `block_aggregated_payloads_slot() != Some(slot)`, so `block` and `combined` show only `timely + late`. `block_only` reports 0; `timely_only` may go up. This is correct: it means the proposer was offline.

## Files touched

- `crates/blockchain/src/metrics.rs` — add 3 setter functions
- `crates/blockchain/src/coverage.rs` — **new** module (~150 lines)
- `crates/blockchain/src/lib.rs` — `BlockChainServer` field, `BlockChain::spawn` signature, two emission sites in `on_tick` / `start_aggregation_session`
- `crates/blockchain/src/store.rs` — pre-merge snapshot in `accept_new_attestations`, dual-write in `on_block_core`, proposal emission in `build_block`, plus signature update on `accept_new_attestations`
- `crates/storage/src/store.rs` — block payloads buffer + slot tracker + saved-snapshot fields; new public methods
- `bin/ethlambda/src/main.rs` — pass `attestation_committee_count` into `BlockChain::spawn`
- No new files outside `coverage.rs`. No dependency changes. No RPC changes.

Estimated diff: **+400 to +550 lines** added, **~5 lines** modified at existing call sites.
