# Early Aggregation Start

**Date:** 2026-07-01
**Status:** Approved

## Motivation

Committee-signature aggregation (leanVM XMSS proofs) is the dominant cost in the
attestation pipeline. Today the aggregation session starts exactly at the
interval-2 tick, even when all expected signatures arrived earlier. Starting the
session up to 400 ms early, when enough signatures are already present, gives the
expensive proofs more wall-clock runway before block building consumes them at
interval 4.

## Current behavior

- The blockchain actor ticks at 800 ms interval boundaries. At interval 2 (if
  `is_aggregator`), `start_aggregation_session` snapshots the current slot's
  gossip signatures (`snapshot_current_slot_aggregation_inputs`) and spawns an
  off-thread worker. A deadline timer cancels the session's token after
  `AGGREGATION_DEADLINE` (750 ms).
- Gossip signatures accumulate in the store per attestation-data group as
  `NewAttestation` messages arrive (plus self-delivery of own validators'
  attestations at interval 1). Only aggregators store them.
- Each produced aggregate is applied to the store and published to gossip
  immediately in the `AggregateProduced` handler.
- Subnet assignment is `vid % attestation_committee_count`. The set of subnets a
  node subscribes to (own-validator subnets, plus `--aggregate-subnet-ids` for
  aggregators, with a fallback to subnet 0 for validator-less aggregators) is
  computed inside `build_swarm` in the p2p crate; the blockchain actor does not
  know it.

## New behavior

### Early trigger

Aggregator-only, fires at most once per slot.

- **Window:** wall clock in `[T2 - 400 ms, T2)`, where
  `T2 = genesis_ms + slot * MILLISECONDS_PER_SLOT + 2 * MILLISECONDS_PER_INTERVAL`
  is the current slot's interval-2 boundary.
- **Condition:** some current-slot attestation-data group has gossip signatures
  from at least 2/3 of the expected validators:
  `group_count * 3 >= expected * 2`, with `expected > 0`. `group_count` is the
  number of stored gossip signatures in that group (one per validator).
  `expected` = number of head-state validators whose
  `vid % attestation_committee_count` is in this node's aggregation subnet set.
  Note that at most one group per slot can reach 2/3 (each validator signs once
  per slot), so the per-group condition can hold for at most one group.
- **Check sites:**
  1. After each gossip-signature insert in the `NewAttestation` handler, while
     the wall clock is inside the window.
  2. A one-shot `EarlyAggregationCheck { slot }` self-message scheduled at the
     interval-1 tick via `send_after(400 ms)` (interval-1 tick + 400 ms =
     T2 - 400 ms), covering the case where the threshold was already met before
     the window opened. If the interval-1 tick is skipped (overrun), the
     per-insert checks still apply.
- **Once-per-slot guard:** a session with `session_id == slot` already exists in
  `current_aggregation` (the field persists after the worker finishes; it is
  only replaced at the next session start).

### Action on trigger

Call the existing `start_aggregation_session(slot, ctx)` — the full current-slot
snapshot, not just the group that hit the threshold. This is the slot's one and
only session; it merely starts early. The existing prior-session cancel+join in
`start_aggregation_session` handles a still-running previous-slot worker
identically in both paths.

### Interval-2 tick

If `current_aggregation` already holds this slot's session (running or
finished), skip starting a new one. Otherwise start normally — the unchanged
fallback for slots where the threshold is never met.

`emit_agg_start_new_coverage` moves from the interval-2 tick into
`start_aggregation_session`, so the coverage report reflects the store state the
session actually snapshotted in both paths.

### Publish alignment

Aggregates must not reach gossip before interval 2 (mirrors the block prebuild
pattern: build early, publish aligned to the boundary).

- `AggregateProduced` handler: apply the output to the store immediately
  (nothing local consumes `new_aggregated_payloads` before interval 4, so early
  application is unobservable locally). If the wall clock is `>= T2` for the
  session's slot, publish immediately (unchanged). If `< T2`, push the
  `SignedAggregatedAttestation` into a pending-publish buffer on the actor.
- When starting an *early* session, schedule a `FlushAggregatePublishes` 
  self-message via `send_after(T2 - now)`. Its handler publishes and drains the
  buffer. This is the primary flush mechanism (not the interval-2 tick, which
  can be skipped on overrun); the handler is idempotent (draining an empty
  buffer is a no-op).
- The buffer is bounded in practice by the number of data groups in one slot.
  Entries are never carried across slots: the flush timer fires at T2 of the
  same slot that buffered them.

### Deadline change

`AGGREGATION_DEADLINE`: 750 ms → 800 ms, still measured from session start.

- Early session started at `T2 - x` (x ≤ 400): deadline at `T2 - x + 800`,
  i.e. at most `T2 + 400`.
- Normal session started at `T2`: deadline lands exactly on the interval-3
  boundary. This removes the previous 50 ms publish/propagation margin —
  accepted trade-off (the deadline only stops *new* jobs from starting; a job
  mid-proof finishes and publishes slightly after).

### Subnet-set plumbing

The subscription-subnet computation is hoisted out of `build_swarm` into a
shared pure helper (in the p2p crate, e.g.
`compute_subscription_subnets(validator_ids, committee_count, is_aggregator, explicit_ids) -> HashSet<u64>`).
`main.rs` calls it once and passes the resulting set to both:

- the p2p config (which subscribes to exactly this set, behavior unchanged), and
- the `BlockChainServer` (new field, used for the `expected` count).

The set is frozen at startup, matching the existing hot-standby aggregator
model (runtime toggles do not resubscribe subnets).

## Failure modes and edge cases

- **Snapshot returns `None` after trigger** (should not happen — the trigger
  requires signatures to be present): no session is created,
  `current_aggregation` keeps the prior slot's id, and interval 2 retries
  normally. No signatures are lost.
- **Threshold never met:** interval 2 starts the session exactly as today.
- **Signatures arriving after the early snapshot:** never aggregated that slot.
  Accepted trade-off (explicitly chosen over a top-up session).
- **Wall-clock vs monotonic drift:** checks use `unix_now_ms()` like the rest of
  the tick logic; the idempotency-guard pattern already tolerates drift. The
  worst case of drift is a slightly mistimed early start or flush, never a
  correctness issue.
- **Non-aggregators:** never store gossip signatures, and all check sites are
  additionally guarded by `AggregatorController::is_enabled()` read at check
  time.

## Observability

- Counter `lean_aggregation_early_starts_total`: early sessions started.
- Histogram for early-start lead time (`T2 - start`, seconds, buckets covering
  0–400 ms).
- Existing session logs gain an `early: bool` field so devnet log analysis can
  attribute publish-time shifts.

## Testing

- Unit tests for the pure trigger decision (window bounds, threshold math,
  `expected` derivation from subnet set + validator count, once-per-slot guard).
- Unit tests for `compute_subscription_subnets` (validator subnets, explicit
  ids, fallback-to-0, non-aggregator).
- Unit test for the publish-delay decision (before/after T2).
- Existing aggregation tests must pass unchanged (normal interval-2 path is the
  fallback and keeps its semantics; only the deadline constant changes).
- Devnet validation via `test-branch.sh`: compare aggregate publish offsets
  (per-slot duty timing method) and `lean_aggregation_early_starts_total`.

## Non-goals

- No gossip resubscription or topic changes.
- No change to the fork-choice attestation pipeline (`new_attestations` /
  `known_attestations`).
- No top-up/second session per slot.
- No persistence of the pending-publish buffer (in-memory actor state, same as
  the rest of the aggregation pipeline).
