# PR #386 — Coverage Snapshot Keying: Design Fix Proposal

## Context

PR #386 emits attestation aggregate coverage metrics. A recall-focused review
surfaced a cluster of five findings (#2, #3, #5, #6, #7) that all trace to **one
root cause**: the slot identity of a coverage snapshot is established
inconsistently and ambiguously, and snapshots are overwritten at multiple
lifecycle points without slot-keying or canonicality.

This document proposes a unified fix. It deliberately separates the parts that
are correct regardless of product intent from the one **semantic decision** that
must be settled first (against zeam #876, the upstream source of truth).

## The five findings, restated

| # | Symptom | Mechanism |
|---|---------|-----------|
| #3 | `timely` non-deterministic / cross-slot | `snapshot_pre_merge_new_coverage` (store.rs:53) sets `slot = data.slot` of the **last** HashMap entry; `new_payloads` can span slots, and HashMap order is RandomState-seeded. Bits from all slots are merged regardless. |
| #2 | `diff_validators` compares different voting rounds | `block` section is keyed by `block.slot == reporting_slot`, but a block at slot S carries votes with `data.slot = S-1` (validators attest at interval 1, blocks propose at interval 0). `timely`/`late` are keyed by `data.slot == reporting_slot`. Same report, different cohorts. |
| #5 | `timely` systematically wrong on proposer slots | On proposer slots, `store::on_tick` calls `accept_new_attestations` at interval 0 of slot S, re-running `snapshot_pre_merge_new_coverage` and overwriting the end-of-slot-(S-1) snapshot **before** `emit_post_block_coverage(S-1)` reads it (lib.rs:191 runs before lib.rs:202). |
| #6 | `block` can reflect a non-canonical fork block | `save_last_block_coverage` (store.rs:556) is called for **every** block that survives `on_block_core`, before `update_head`. The last-imported block wins, canonical or not. |
| #7 | `block_only=0, timely_only=N` on missed slot reads as "proposer dropped everything" | When no block matches `reporting_slot`, `block_v` is silently all-false and the diff degenerates. (Note: the instrumentation doc states this is **intended** to signal "proposer offline" — see Open Question 2.) |

## Root cause

A coverage snapshot answers "which validators' attestations for slot X were seen
via channel C." That requires a stable, explicit notion of **X** (the voting
round = `data.slot`). The current code instead:

- derives X from incidental data (last HashMap entry → #3),
- uses an inconsistent X for the `block` channel (header slot, not vote slot → #2),
- stores X in a single `Option` that is clobbered out of lifecycle order (#5, #6),
- and treats "X not found" as "zero coverage" rather than "no data" (#7).

## Unifying principle

**Every section (`timely`, `late`, `block`, `combined`) describes the same
cohort: validators whose attestations with `data.slot == reporting_slot` were
observed via that channel. Key all coverage by `data.slot`, never by block header
slot or by HashMap-derived slot.**

## Decision: coverage state stays in `ethlambda-storage`

A relayering was considered — moving `CoverageSnapshot` and the coverage fields
out of `crates/storage/src/store.rs` into the blockchain crate (since coverage is
actor-owned observability state). **Decided against it.** `CoverageSnapshot` and
its `Store` fields stay where they are; we do not churn storage to relocate them.

The redesign below may still *reshape* `CoverageSnapshot` and remove
`last_block_coverage` from storage where the fix requires it (Changes 2 and 3) —
that is in scope. What is out of scope is the move itself.

## Open Question 1 — RESOLVED against zeam #876

Verified by reading zeam #876 (`pkgs/node/src/forkchoice.zig`,
`pkgs/node/src/chain.zig`). The intended design is **same-round cohort at a
1-slot lag**, achieved by *when* the report fires, not by a 2-slot offset:

- **All sections keyed by `data.slot` (the voting round).** zeam's block buffer
  `latest_block_aggregated_payloads_slot` is keyed by `attestation_data.slot`
  and reset when it changes (the `!= attestation_data.slot` guard in
  `forkchoice.zig`). `formatAggregationCoverageReport(slot)` fills `timely`,
  `late`, and `block` all via `collectCoverageFromPayloads(&map, slot, …)`
  filtered to the **same** `slot`. Every section is the same cohort:
  `data.slot == reporting_slot`.
- **Report fires at interval 1, not interval 0.** `chain.zig::onInterval` calls
  `printSlot(slot)` — which contains the report for `slot - 1` — at
  `interval == 1`, with the comment: *"interval to attest so we should put out
  the chain status… latest head which most likely should be the new block
  received and processed."* By interval 1 of slot S, the slot-S block (carrying
  `data.slot = S-1` votes) has typically been imported, so the `block` buffer is
  keyed to S-1 = `reporting_slot`. That is how zeam gets a same-round `block`
  section at only a 1-slot lag.
- **Canonical head.** `printSlot` calls `updateHead()` before reporting.
- **No misleading zeros.** `formatAggregationCoverageReport` returns `null`
  (emits nothing) when no section has data (`if (!has_any) return null;`) — it
  does not push `block_only=0` for empty slots.

**Implication for ethlambda:** the root divergence is *two* things, both of which
must change to match zeam: (a) the `block` buffer is keyed by `block.slot`
(header) instead of `attestation_data.slot`; and (b) the report fires at
**interval 0** instead of **interval 1**, before the current slot's block is
reliably imported. The earlier "2-slot lag" idea is dropped — the target is
zeam's interval-1, same-round, `data.slot`-keyed design.

## Proposed changes

All four changes converge on zeam's design: same-round (`data.slot`) cohort,
interval-1 trigger, `null` report when there is no data.

1. **#2 + #5/#7 timing — move the per-slot report from interval 0 to interval 1.**
   In `BlockChainServer::on_tick`, fire `emit_post_block_coverage(slot - 1)` at
   `interval == 1` (after the current slot's block has been received and
   processed), mirroring zeam's `printSlot`. This is what makes the `block`
   section observe the block that carries `data.slot = slot - 1` votes, so all
   sections line up on the same round at a 1-slot lag. (At interval 0 the
   slot-S block is not yet imported — the source of the timing skew.)

2. **#3 — deterministic, explicit `data.slot` keying on the pre-merge snapshot.**
   Stop deriving the snapshot slot from HashMap order. Store participant bits
   tagged by their own `data.slot`:
   - Change `CoverageSnapshot` from `{ slot, participant_bits }` to
     `{ entries: Vec<(u64 /*data_slot*/, AggregationBits)> }` (or
     `HashMap<u64, Vec<AggregationBits>>` grouped by `data_slot`).
   - The reader filters to `data_slot == reporting_slot`. No ambiguous single
     `slot` field; bits from other slots can never leak into the wrong report.
   - (zeam has the same latent "slot from first entry" fragility; this is a
     strict improvement over the reference.)

3. **#2/#6 — key the `block` section by `data.slot` and make it canonical.**
   Mirror zeam's `latest_block_aggregated_payloads` + slot tracker: a block
   buffer keyed by the included attestations' `data.slot`, reset when that slot
   changes. Two sub-options for canonicality:
   - **(3a)** Compute the `block` section at report time from the **canonical
     chain**: read the canonical block at `reporting_slot + 1`, union its
     attestation bits filtered to `data.slot == reporting_slot`. Removes
     `last_block_coverage` / `save_last_block_coverage` entirely; inherently
     canonical because it reads committed chain state. (zeam's `printSlot` calls
     `updateHead()` first for the same reason.)
   - **(3b)** Keep an in-memory block buffer (as the original instrumentation doc
     specified) keyed by `data.slot`, written **after** `update_head` confirms
     the head. Closer to zeam's code shape, but still needs a head check to avoid
     the fork-block overwrite (#6).
   Either way, the buffer must be keyed by `data.slot`, never `block.slot`.

4. **#7 — emit nothing when there is no data (adopt zeam's `has_any` gate).**
   `emit_post_block_coverage` should skip all `set()` calls (including
   `diff_validators`) when no section has any coverage for `reporting_slot`,
   matching zeam's `if (!has_any) return null;`. This stops the misleading
   `block_only=0, timely_only=N` "proposer dropped everything" reading on missed
   slots. Trade-off: the gauges then hold their previous value (staleness) rather
   than emitting a false zero — zeam accepts this, and it is the lesser evil for a
   gauge with no slot label. (The broader staleness findings #10/#11 are out of
   scope for this cluster.)

## Per-finding resolution map

| Finding | Fixed by |
|---------|----------|
| #2 cohort mismatch | Change 1 (interval-1 trigger) + Change 3 (block keyed by `data.slot`) |
| #3 non-deterministic slot | Change 2 (per-entry `data.slot` keying) |
| #5 proposer-slot overwrite | Change 1 (interval-1 trigger) + Change 2 (deterministic keying) |
| #6 fork-block overwrite | Change 3 (canonical block coverage) |
| #7 false `block_only=0` | Change 4 (`has_any` gate) |

## Validation

1. `make fmt`, `make lint` clean.
2. New unit tests:
   - Pre-merge snapshot with mixed-`data.slot` entries → report for slot X only
     counts X's bits (regression test for #3; must be deterministic across runs).
   - Proposer-slot ordering: simulate interval-0 accept + emit, assert the
     slot-(X-1) `timely` count is the interval-4 snapshot, not the post-promote
     one (#5).
   - Fork block at same slot: import canonical B1 then fork B2, assert `block`
     coverage reflects the canonical head (#6).
3. `cargo test -p ethlambda-blockchain --release` — including the existing 20.
4. `forkchoice_spectests` — same 8 pre-existing `AttestationTooFarInFuture`
   flakes only, no new failures.
5. Devnet smoke: run ≥4 slots, confirm `diff_validators` directions are both near
   zero on a healthy multi-node devnet (the whole point — under the current bugs
   they are not).

## Sequencing / rollout

One PR (no relayering). The four changes land together on top of #386 (or folded
in if #386 hasn't merged) — #386's coverage values are wrong until this lands.

1. Change 1 (interval-1 trigger) + Change 4 (`has_any` gate) — localized to `lib.rs`.
2. Change 2 (per-entry `data.slot` pre-merge snapshot) — reshape `CoverageSnapshot`
   in `crates/storage/src/store.rs` + the capture in `accept_new_attestations`.
3. Change 3 (block section keyed by `data.slot`, canonical) — pick 3a (report-time
   canonical read) vs 3b (slot-keyed buffer) per OQ2. 3a deletes the
   `last_block_coverage` field and the `on_block_core` capture entirely.

`CoverageSnapshot` and the coverage fields remain in `ethlambda-storage`
throughout; only their *shape* changes where the keying fix requires it.

## Files likely touched

- `crates/blockchain/src/lib.rs` — emit at `interval == 1`, report `slot - 1`;
  `has_any` gate; `block`/`late`/`timely` filter by `data.slot`; block from
  canonical chain (3a) or keyed buffer (3b).
- `crates/blockchain/src/store.rs` — `data.slot` keying in `snapshot_pre_merge_new_coverage`; remove
  `on_block_core` block capture (3a).
- `crates/storage/src/store.rs` — reshape `CoverageSnapshot` for per-entry
  `data.slot` (Change 2); remove `last_block_coverage` field + methods (3a).
- `crates/blockchain/src/metrics.rs` — no change expected (`proposal_*` already
  trimmed in the prior commit).

## Open questions (remaining)

1. **(OQ2)** Change 3a (report-time canonical chain read) vs 3b (in-memory
   slot-keyed buffer written post-`update_head`) — performance vs code-locality.
   3a is simpler and provably canonical; 3b is closer to zeam's code shape.
2. Staleness on no-data slots: zeam's `has_any` gate leaves gauges at their last
   value. If operators need to distinguish "stale" from "fresh zero", that needs
   a slot label or a separate freshness signal — out of scope for this cluster
   (overlaps findings #10/#11) but worth noting to the reviewer.
