# Early Aggregation Start Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Start the committee-signature aggregation session up to 200 ms before the interval-2 boundary when a single attestation-data group already holds 2/3 of the signatures expected from this node's aggregation subnets, while holding back any early-produced aggregates from gossip until the boundary.

**Architecture:** The blockchain actor (`BlockChainServer`, GenServer pattern) gains an early-trigger check invoked from two sites: after every stored gossip signature (`NewAttestation` handler) and once via a timer fired at the window opening (`T2 − 200 ms`). The trigger calls the existing `start_aggregation_session`, which becomes the single session-start path for both early and normal (interval-2 tick) starts; the tick skips if the slot's session already exists. Aggregates produced before T2 are buffered on the actor and flushed by a `send_after` timer at T2.

**Tech Stack:** Rust (edition 2024), spawned-concurrency actors (`send_after` self-messages), prometheus metrics via `ethlambda_metrics`.

**Verification policy (per user):** No new unit tests. Each task verifies by compiling (plus existing test suites where they already exist); final validation is a local 4-node devnet run (Task 9).

**Spec:** `docs/superpowers/specs/2026-07-01-early-aggregation-start-design.md`

**Key existing code:**
- `crates/blockchain/src/lib.rs` — actor, tick loop (`on_tick`), `start_aggregation_session` (~line 366), handlers (`NewAttestation` ~line 1034, `AggregateProduced` ~line 1050, `AggregationDone` ~line 1079, `AggregationDeadline` ~line 1099)
- `crates/blockchain/src/aggregation.rs` — session types, snapshot builders, worker, `AGGREGATION_DEADLINE`
- `crates/blockchain/src/metrics.rs` — prometheus registration patterns
- `crates/storage/src/store.rs` — `GossipSignatureBuffer` (~line 348), `Store` methods (~line 1451)
- `crates/net/p2p/src/lib.rs` — `build_swarm` subnet subscription (~lines 304–337)
- `bin/ethlambda/src/main.rs` — `BlockChain::spawn` (~line 213), `build_swarm(SwarmConfig {...})` (~line 230)

**Timing model (4 s slots, 5 × 800 ms intervals):**

```
slot start   T1=+800ms    T2=+1600ms   T3=+2400ms   T4=+3200ms
  |------------|------------|------------|------------|
               ^ attest     ^ aggregate  ^ safe tgt   ^ accept/build
                     [T2-200, T2) = early window
                     ^ timer check       (scheduled at T1 + 600ms)
                     ^..^..^ per-insert checks as gossip sigs arrive
```

---

### Task 1: Store query — max gossip group count for a slot

The early threshold needs "largest signature count among current-slot data groups" without cloning signatures (the existing `iter_gossip_signatures` snapshot clones every signature; signatures are ~3 KB each).

**Files:**
- Modify: `crates/storage/src/store.rs` (buffer method after `snapshot()` ~line 465; `Store` method next to `gossip_signatures_count()` ~line 1451)

- [ ] **Step 1: Implement the buffer method and Store wrapper**

In `impl GossipSignatureBuffer`, after `snapshot()` (~line 465):

```rust
/// Largest signature count among data groups whose attestation slot is `slot`.
fn max_group_count_for_slot(&self, slot: u64) -> usize {
    self.data
        .values()
        .filter(|entry| entry.data.slot == slot)
        .map(|entry| entry.signatures.len())
        .max()
        .unwrap_or(0)
}
```

In `impl Store`, next to `gossip_signatures_count()` (~line 1451):

```rust
/// Largest per-group signature count among gossip groups voting for `slot`.
///
/// One lock, no signature clones — cheap enough to call per gossip insert.
/// Drives the early-aggregation threshold check.
pub fn max_gossip_group_count_for_slot(&self, slot: u64) -> usize {
    let gossip = self.gossip_signatures.lock().unwrap();
    gossip.max_group_count_for_slot(slot)
}
```

- [ ] **Step 2: Build**

Run: `cargo build -p ethlambda-storage`
Expected: clean build, no warnings (the `pub` Store method keeps the private buffer method alive).

- [ ] **Step 3: Commit**

```bash
git add crates/storage/src/store.rs
git commit -m "feat(storage): add max gossip group count query for early aggregation"
```

---

### Task 2: p2p — extract `compute_subscription_subnets` helper

Single source of truth for the subnet set, callable from `main.rs` (Task 4) without touching `SwarmConfig`.

**Files:**
- Modify: `crates/net/p2p/src/lib.rs` (subnet logic in `build_swarm` ~lines 304–337)

- [ ] **Step 1: Implement the helper and use it in `build_swarm`**

Add near `build_swarm` (above it, ~line 185):

```rust
/// Compute the set of attestation subnets this node subscribes to (and, when
/// aggregating, aggregates over), per leanSpec (`src/lean_spec/__main__.py`):
/// every validator subscribes to its own subnet (`vid % committee_count`) for
/// mesh health; aggregators additionally subscribe to explicit
/// `aggregate_subnet_ids` and fall back to subnet 0 when the set would
/// otherwise be empty.
///
/// Evaluated once at startup — runtime aggregator toggles do not resubscribe
/// (hot-standby model); see the invariant note on [`SwarmConfig`].
pub fn compute_subscription_subnets(
    validator_ids: &[u64],
    attestation_committee_count: u64,
    is_aggregator: bool,
    aggregate_subnet_ids: Option<&[u64]>,
) -> HashSet<u64> {
    let mut subnets: HashSet<u64> = validator_ids
        .iter()
        .map(|vid| vid % attestation_committee_count)
        .collect();
    if is_aggregator {
        if let Some(explicit_ids) = aggregate_subnet_ids {
            subnets.extend(explicit_ids);
        }
        if subnets.is_empty() {
            subnets.insert(0);
        }
    }
    subnets
}
```

Then replace the inline logic in `build_swarm` (~lines 304–329). The metric must keep reflecting validator-only subnets, so that part stays:

```rust
    // Subscribe to attestation subnets — see `compute_subscription_subnets`.
    // The committee metric should reflect validator membership only, not
    // aggregator-only subscriptions.
    let metric_subnet = config
        .validator_ids
        .iter()
        .map(|vid| vid % config.attestation_committee_count)
        .min()
        .unwrap_or(0);
    metrics::set_attestation_committee_subnet(metric_subnet);

    let subscription_subnets = compute_subscription_subnets(
        &config.validator_ids,
        config.attestation_committee_count,
        config.is_aggregator,
        config.aggregate_subnet_ids.as_deref(),
    );
```

(The `let mut attestation_topics ...` loop over `&subscription_subnets` at ~line 331 stays unchanged.)

- [ ] **Step 2: Build and run existing p2p tests**

Run: `cargo build -p ethlambda-p2p && cargo test -p ethlambda-p2p --lib`
Expected: clean build, existing tests pass (behavior of `build_swarm` is unchanged — same set, same subscriptions).

- [ ] **Step 3: Commit**

```bash
git add crates/net/p2p/src/lib.rs
git commit -m "refactor(p2p): extract subscription subnet computation into pure helper"
```

---

### Task 3: Blockchain — pure early-aggregation helpers

Window math and threshold predicate.

**Files:**
- Modify: `crates/blockchain/src/aggregation.rs` (new consts + functions after `PRIOR_WORKER_JOIN_TIMEOUT` ~line 37)

- [ ] **Step 1: Implement consts and functions**

In `crates/blockchain/src/aggregation.rs`, after `PRIOR_WORKER_JOIN_TIMEOUT` (~line 37). Also add `use crate::{MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT};` to the file's imports (both constants are `pub` in `lib.rs`).

```rust
/// Width of the early-aggregation window: a session may start at most this
/// long before the interval-2 boundary, provided the signature threshold is
/// met (see `early_threshold_met`).
pub(crate) const EARLY_AGGREGATION_WINDOW_MS: u64 = 200;

/// Wall-clock millisecond timestamp of `slot`'s interval-2 boundary (the
/// normal aggregation start).
pub(crate) fn interval2_boundary_ms(genesis_time_ms: u64, slot: u64) -> u64 {
    genesis_time_ms + slot * MILLISECONDS_PER_SLOT + 2 * MILLISECONDS_PER_INTERVAL
}

/// If `now_ms` falls inside some slot's early-aggregation window
/// (`[T2 - EARLY_AGGREGATION_WINDOW_MS, T2)` with `T2` that slot's interval-2
/// boundary), return that slot.
pub(crate) fn early_aggregation_slot(now_ms: u64, genesis_time_ms: u64) -> Option<u64> {
    let since_genesis = now_ms.checked_sub(genesis_time_ms)?;
    let ms_into_slot = since_genesis % MILLISECONDS_PER_SLOT;
    let t2_offset = 2 * MILLISECONDS_PER_INTERVAL;
    let in_window =
        ms_into_slot >= t2_offset - EARLY_AGGREGATION_WINDOW_MS && ms_into_slot < t2_offset;
    in_window.then_some(since_genesis / MILLISECONDS_PER_SLOT)
}

/// Early-start threshold: a single attestation-data group holds at least 2/3
/// of the signatures expected from this node's aggregation subnets. At most
/// one group per slot can satisfy this (each validator signs once per slot).
pub(crate) fn early_threshold_met(max_group_count: usize, expected: usize) -> bool {
    expected > 0 && max_group_count * 3 >= expected * 2
}
```

- [ ] **Step 2: Build**

Run: `cargo build -p ethlambda-blockchain`
Expected: clean build (dead-code warnings possible until Tasks 6–7 wire the callers).

- [ ] **Step 3: Commit**

```bash
git add crates/blockchain/src/aggregation.rs
git commit -m "feat(blockchain): add early-aggregation window and threshold helpers"
```

---

### Task 4: Plumbing — subnet set into the actor, expected-count field

Compile-level wiring, no behavior change yet.

**Files:**
- Modify: `crates/blockchain/src/lib.rs` (`BlockChain::spawn` ~line 80, `BlockChainServer` struct ~line 138)
- Modify: `bin/ethlambda/src/main.rs` (~lines 206–223)

- [ ] **Step 1: Add spawn parameter and fields**

In `crates/blockchain/src/lib.rs`, change `BlockChain::spawn` signature (~line 80) — new `aggregation_subnets` parameter after `attestation_committee_count`:

```rust
    pub fn spawn(
        store: Store,
        validator_keys: HashMap<u64, ValidatorKeyPair>,
        aggregator: AggregatorController,
        attestation_committee_count: u64,
        aggregation_subnets: HashSet<u64>,
        gate_duties: bool,
        proposer_config: ProposerConfig,
    ) -> BlockChain {
```

Inside `spawn`, before the `let handle = BlockChainServer {` block (~line 101), compute the expected count (guard the modulo against a zero committee count):

```rust
        // Denominator of the early-aggregation 2/3 threshold: how many
        // validators attest on subnets this node aggregates. Computed once —
        // the validator registry is static and `head_state()` clones the full
        // state, so this must not run per gossip insert.
        let validator_count = store.head_state().validators.len() as u64;
        let early_aggregation_expected_sigs = if attestation_committee_count == 0 {
            0
        } else {
            (0..validator_count)
                .filter(|vid| {
                    aggregation_subnets.contains(&(vid % attestation_committee_count))
                })
                .count()
        };
```

Add to the `BlockChainServer` struct literal in `spawn` (`genesis_time` is already computed at ~line 90):

```rust
            genesis_time_ms: genesis_time * 1000,
            early_aggregation_expected_sigs,
            pending_aggregate_publishes: Vec::new(),
```

Add the fields to the `BlockChainServer` struct definition (after `attestation_committee_count`, ~line 170):

```rust
    /// Genesis time in milliseconds, cached at spawn. `store.config()` is an
    /// uncached backend read, too heavy for the per-gossip-insert early
    /// checks that need this.
    genesis_time_ms: u64,

    /// Number of validators whose subnet is one this node aggregates — the
    /// denominator of the early-aggregation 2/3 threshold. Computed once at
    /// spawn (the validator registry is static).
    early_aggregation_expected_sigs: usize,

    /// Aggregates produced before the interval-2 boundary, held back so they
    /// are not gossiped early. Flushed by `FlushAggregatePublishes` at the
    /// boundary; only ever holds the current slot's aggregates.
    pending_aggregate_publishes: Vec<SignedAggregatedAttestation>,
```

(`HashSet` and `SignedAggregatedAttestation` are already imported in `lib.rs`. Existing `config().genesis_time * 1000` call sites in `on_tick`/`handle_tick` stay as they are — only the new code paths use the cached field.)

- [ ] **Step 2: Update `main.rs`**

In `bin/ethlambda/src/main.rs`, add `compute_subscription_subnets` to the `ethlambda_p2p` import (line 40):

```rust
use ethlambda_p2p::{
    Bootnode, P2P, PeerId, SwarmConfig, build_swarm, compute_subscription_subnets, parse_enrs,
};
```

Before `BlockChain::spawn` (~line 213), compute the set with the same startup inputs `build_swarm` uses, and pass it (borrow `aggregate_subnet_ids` — it is moved into `SwarmConfig` further down):

```rust
    // Same startup inputs build_swarm uses — single source of truth is the
    // shared helper. Frozen at startup like the gossip subscriptions
    // themselves (hot-standby model).
    let aggregation_subnets = compute_subscription_subnets(
        &validator_ids,
        attestation_committee_count,
        options.is_aggregator,
        options.aggregate_subnet_ids.as_deref(),
    );

    let blockchain = BlockChain::spawn(
        store.clone(),
        validator_keys,
        aggregator.clone(),
        attestation_committee_count,
        aggregation_subnets,
        !options.disable_duty_sync_gate,
        ProposerConfig {
            enable_proposer_aggregation: options.enable_proposer_aggregation,
            max_attestations_per_block: options.max_attestations_per_block,
        },
    );
```

- [ ] **Step 3: Build the workspace**

Run: `cargo build --workspace`
Expected: clean build. Dead-code warnings on the two new fields are acceptable here (plain `cargo build` does not deny warnings); they become live in Tasks 6–7, before `make lint` runs in Task 8. Do not annotate with `#[allow(dead_code)]`.

- [ ] **Step 4: Commit**

```bash
git add crates/blockchain/src/lib.rs bin/ethlambda/src/main.rs
git commit -m "feat(blockchain): plumb aggregation subnet set and expected-signature count into actor"
```

---

### Task 5: Deadline change 750 → 800 ms

**Files:**
- Modify: `crates/blockchain/src/aggregation.rs:28-33`
- Modify: `crates/blockchain/src/lib.rs` (stale `+750 ms` doc-comment reference on `start_aggregation_session`, ~line 365)

- [ ] **Step 1: Change the constant and its comment**

Replace:

```rust
/// Soft deadline for committee-signature aggregation measured from the
/// interval-2 tick. After this much wall time elapses, the actor signals the
/// worker to stop via its cancellation token. The 50 ms budget before the next
/// interval (interval 3 at +800 ms) is reserved for publishing any late-arriving
/// aggregates and for gossip propagation margin.
pub(crate) const AGGREGATION_DEADLINE: Duration = Duration::from_millis(750);
```

with:

```rust
/// Soft deadline for committee-signature aggregation measured from session
/// start. After this much wall time elapses, the actor signals the worker to
/// stop via its cancellation token. A session started exactly at interval 2
/// gets the full interval (interval 3 is one interval later); a session
/// started early (see `early_aggregation_slot`) ends correspondingly earlier.
/// The deadline only stops new jobs from starting — a job mid-proof finishes
/// and publishes right after.
pub(crate) const AGGREGATION_DEADLINE: Duration = Duration::from_millis(800);
```

- [ ] **Step 2: Build and check references**

Run: `cargo build -p ethlambda-blockchain && grep -rn "750" crates/blockchain/src/lib.rs`
Expected: clean build; the grep finds no stale `+750 ms` comment references (the doc comment on `start_aggregation_session` ~line 365 says "Schedule the `AggregationDeadline` self-message at +750 ms" — update it to "+`AGGREGATION_DEADLINE`").

- [ ] **Step 3: Commit**

```bash
git add crates/blockchain/src/aggregation.rs crates/blockchain/src/lib.rs
git commit -m "feat(blockchain): extend aggregation deadline to a full interval"
```

---

### Task 6: Publish alignment — hold early aggregates until the interval-2 boundary

**Files:**
- Modify: `crates/blockchain/src/aggregation.rs` (`AggregationSession` struct ~line 75, new message)
- Modify: `crates/blockchain/src/lib.rs` (imports ~line 16, `start_aggregation_session` ~line 366, `AggregateProduced` handler ~line 1050, `AggregationDone` handler ~line 1079, interval-2 tick arm ~line 312, new handler + helper)
- Modify: `crates/blockchain/src/metrics.rs` (new counter + histogram)

- [ ] **Step 1: Add the `early` flag and the flush message in `aggregation.rs`**

Add field to `AggregationSession` (~line 75):

```rust
pub(crate) struct AggregationSession {
    /// Slot at which this session was started; used as a fencing id so we can
    /// drop late-arriving messages from a prior session.
    pub(crate) session_id: u64,
    /// Whether the session started before the slot's interval-2 boundary via
    /// the early-aggregation trigger.
    pub(crate) early: bool,
    /// Child of the actor cancellation token; fires either at the deadline or
    /// when the actor itself is stopping.
    pub(crate) cancel: CancellationToken,
    /// Handle to the `spawn_blocking` worker. Held so `stopped()` / new-session
    /// start can await completion.
    pub(crate) worker: tokio::task::JoinHandle<()>,
}
```

Add next to `AggregationDeadline` (~line 112):

```rust
/// Self-message scheduled when a session starts early; fires at the
/// interval-2 boundary and publishes any aggregates held back by the
/// publish-alignment rule (aggregates must not reach gossip before
/// interval 2).
pub(crate) struct FlushAggregatePublishes;
impl Message for FlushAggregatePublishes {
    type Result = ();
}
```

- [ ] **Step 2: Rework `start_aggregation_session` in `lib.rs`**

Extend the `use crate::aggregation::{...}` import (~line 16) with `FlushAggregatePublishes`.

In `start_aggregation_session` (~line 366): move the coverage emission here from the tick arm, and compute `early` + schedule the flush. After the prior-session join block and before the snapshot:

```rust
        coverage::emit_agg_start_new_coverage(&self.store, self.attestation_committee_count);
```

Replace the tail of the function (from `let session_id = slot;` through the final `self.current_aggregation = Some(...)`) with:

```rust
        let session_id = slot;
        // Any leftovers from a prior slot mean its flush never fired (a
        // backwards wall-clock step, or a flush timer delayed past the next
        // session). Drop them — late aggregates are dropped, same policy as
        // signatures that miss the snapshot.
        let stale = std::mem::take(&mut self.pending_aggregate_publishes);
        if !stale.is_empty() {
            warn!(
                count = stale.len(),
                "Dropping stale pending aggregate publishes"
            );
        }
        let t2_ms = aggregation::interval2_boundary_ms(self.genesis_time_ms, slot);
        let now_ms = unix_now_ms();
        let early = now_ms < t2_ms;
        if early {
            // Publish alignment: aggregates must not reach gossip before the
            // interval-2 boundary. Aggregates produced before T2 are buffered
            // in `pending_aggregate_publishes`; this timer flushes them at T2.
            let lead = Duration::from_millis(t2_ms - now_ms);
            metrics::inc_aggregation_early_starts();
            metrics::observe_aggregation_early_start_lead(lead);
            info!(
                %slot,
                lead_ms = lead.as_millis() as u64,
                "Starting aggregation session early"
            );
            send_after(lead, ctx.clone(), FlushAggregatePublishes);
        }

        // Independent token per session. Shutdown propagates via our
        // #[stopped] hook which cancels any current session; the deadline
        // timer cancels this specific session at +AGGREGATION_DEADLINE.
        let cancel = CancellationToken::new();
        let actor_ref = ctx.actor_ref();

        let worker_cancel = cancel.clone();
        let worker_actor = actor_ref.clone();
        let worker = tokio::task::spawn_blocking(move || {
            run_aggregation_worker(snapshot, worker_actor, worker_cancel, session_id);
        });

        let _deadline_timer = send_after(
            AGGREGATION_DEADLINE,
            ctx.clone(),
            AggregationDeadline { session_id },
        );

        self.current_aggregation = Some(AggregationSession {
            session_id,
            early,
            cancel,
            worker,
        });
```

(`metrics::inc_aggregation_early_starts` / `observe_aggregation_early_start_lead` are added in Step 4 of this task.)

Remove the emission from the interval-2 tick arm (~line 312), which becomes:

```rust
            // ==== interval 2 ====
            2 => {
                if is_aggregator {
                    self.start_aggregation_session(slot, ctx).await;
                } else {
                    metrics::inc_aggregator_skipped_not_aggregator();
                }
            }
```

(The `coverage::emit_agg_start_new_coverage` call and its old surrounding braces go away; the early-session skip guard lands in Task 7.)

- [ ] **Step 3: Split publish out of `AggregateProduced` and add the flush handler**

Add a helper method on `BlockChainServer` (near `on_gossip_attestation`, ~line 929):

```rust
    /// Publish an aggregated attestation to the aggregation gossip topic.
    fn publish_aggregate(&self, aggregate: SignedAggregatedAttestation) {
        if let Some(ref p2p) = self.p2p {
            let _ = p2p
                .publish_aggregated_attestation(aggregate)
                .inspect_err(|err| error!(%err, "Failed to publish aggregated attestation"));
        }
    }
```

Rewrite the body of `impl Handler<AggregateProduced>` (~line 1050) — the session-id fencing stays, then:

```rust
        aggregation::apply_aggregated_group(&mut self.store, &msg.output);

        let aggregate = SignedAggregatedAttestation {
            data: msg.output.hashed.data().clone(),
            proof: msg.output.proof,
        };

        // Publish alignment: hold back aggregates produced before this slot's
        // interval-2 boundary; `FlushAggregatePublishes` publishes them at T2.
        // (`session_id` is the session's slot.)
        let t2_ms = aggregation::interval2_boundary_ms(self.genesis_time_ms, msg.session_id);
        if unix_now_ms() < t2_ms {
            self.pending_aggregate_publishes.push(aggregate);
            return;
        }
        self.publish_aggregate(aggregate);
```

Add the flush handler next to the other aggregation handlers (~line 1099):

```rust
impl Handler<FlushAggregatePublishes> for BlockChainServer {
    async fn handle(&mut self, _msg: FlushAggregatePublishes, _ctx: &Context<Self>) {
        let pending = std::mem::take(&mut self.pending_aggregate_publishes);
        if pending.is_empty() {
            return;
        }
        info!(
            count = pending.len(),
            "Publishing aggregates held back until the interval-2 boundary"
        );
        for aggregate in pending {
            self.publish_aggregate(aggregate);
        }
    }
}
```

Add the `early` field to the `AggregationDone` completion log (~line 1085): before the `info!`, compute

```rust
        let early = self
            .current_aggregation
            .as_ref()
            .is_some_and(|s| s.session_id == msg.session_id && s.early);
```

and add `early,` to the `info!(...)` field list (after `cancelled = msg.cancelled,`).

- [ ] **Step 4: Add the two metrics**

In `crates/blockchain/src/metrics.rs` — counter in the `// --- Counters ---` section, histogram in `// --- Histograms ---`, public fns near their statics following file style:

```rust
static LEAN_AGGREGATION_EARLY_STARTS_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_aggregation_early_starts_total",
            "Aggregation sessions started before the interval-2 boundary"
        )
        .unwrap()
    });

pub fn inc_aggregation_early_starts() {
    LEAN_AGGREGATION_EARLY_STARTS_TOTAL.inc();
}
```

```rust
static LEAN_AGGREGATION_EARLY_START_LEAD_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_aggregation_early_start_lead_seconds",
            "How far before the interval-2 boundary an early aggregation session started",
            vec![0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4]
        )
        .unwrap()
    });

pub fn observe_aggregation_early_start_lead(lead: Duration) {
    LEAN_AGGREGATION_EARLY_START_LEAD_SECONDS.observe(lead.as_secs_f64());
}
```

- [ ] **Step 5: Build and run existing tests**

Run: `cargo build -p ethlambda-blockchain && cargo test -p ethlambda-blockchain --lib`
Expected: clean build, existing unit tests pass. Behavior so far is identical for normal sessions (`early` is always false when started at interval 2, so no buffering, no flush timer, no metric increments).

- [ ] **Step 6: Commit**

```bash
git add crates/blockchain/src/aggregation.rs crates/blockchain/src/lib.rs crates/blockchain/src/metrics.rs
git commit -m "feat(blockchain): hold early-produced aggregates until the interval-2 boundary"
```

---

### Task 7: Early trigger — threshold checks, timer, and interval-2 skip

**Files:**
- Modify: `crates/blockchain/src/aggregation.rs` (new message next to `FlushAggregatePublishes`)
- Modify: `crates/blockchain/src/lib.rs` (imports ~line 16, interval-1 arm ~line 290, interval-2 arm ~line 312, `NewAttestation` handler ~line 1034, new method + handler)

- [ ] **Step 1: Add the check message in `aggregation.rs`**

```rust
/// One-shot self-message scheduled at the interval-1 tick; fires when the
/// early-aggregation window opens (T2 - EARLY_AGGREGATION_WINDOW_MS) to run
/// the threshold check for signatures that all arrived before the window.
/// Arrivals inside the window are checked per insert instead.
pub(crate) struct EarlyAggregationCheck;
impl Message for EarlyAggregationCheck {
    type Result = ();
}
```

- [ ] **Step 2: Add the trigger method on `BlockChainServer`**

Extend the `use crate::aggregation::{...}` import with `EarlyAggregationCheck` and `EARLY_AGGREGATION_WINDOW_MS`. Add the method after `start_aggregation_session` (~line 418):

```rust
    /// Early-aggregation trigger: start the slot's session ahead of the
    /// interval-2 tick when, inside the window `[T2 - EARLY_AGGREGATION_WINDOW_MS, T2)`,
    /// a single attestation-data group already holds 2/3 of the signatures
    /// expected from this node's aggregation subnets. Called after every
    /// stored gossip signature and once at the window opening via
    /// [`EarlyAggregationCheck`]. Fires at most once per slot: the started
    /// session stays in `current_aggregation` (running or finished) until the
    /// next session replaces it.
    async fn maybe_start_early_aggregation(&mut self, ctx: &Context<Self>) {
        if !self.aggregator.is_enabled() {
            return;
        }
        let Some(slot) = aggregation::early_aggregation_slot(unix_now_ms(), self.genesis_time_ms)
        else {
            return;
        };
        if self
            .current_aggregation
            .as_ref()
            .is_some_and(|session| session.session_id == slot)
        {
            return;
        }
        let max_group = self.store.max_gossip_group_count_for_slot(slot);
        if !aggregation::early_threshold_met(max_group, self.early_aggregation_expected_sigs) {
            return;
        }
        info!(
            %slot,
            max_group,
            expected = self.early_aggregation_expected_sigs,
            "Early-aggregation threshold met"
        );
        self.start_aggregation_session(slot, ctx).await;
    }
```

- [ ] **Step 3: Wire the three trigger sites**

**(a) Interval-1 arm** (~line 290) — at the end of the `1 => { ... }` block, after the attestation-production `if/else`:

```rust
                // Schedule the early-aggregation window check. This tick is
                // one interval before T2, so the timer fires right as the
                // window opens at T2 - EARLY_AGGREGATION_WINDOW_MS.
                if is_aggregator {
                    send_after(
                        Duration::from_millis(
                            MILLISECONDS_PER_INTERVAL - EARLY_AGGREGATION_WINDOW_MS,
                        ),
                        ctx.clone(),
                        EarlyAggregationCheck,
                    );
                }
```

**(b) Timer handler** — next to the other aggregation handlers:

```rust
impl Handler<EarlyAggregationCheck> for BlockChainServer {
    async fn handle(&mut self, _msg: EarlyAggregationCheck, ctx: &Context<Self>) {
        self.maybe_start_early_aggregation(ctx).await;
    }
}
```

**(c) Per-insert check** — `impl Handler<NewAttestation>` (~line 1034) becomes:

```rust
impl Handler<NewAttestation> for BlockChainServer {
    async fn handle(&mut self, msg: NewAttestation, ctx: &Context<Self>) {
        self.on_gossip_attestation(&msg.attestation);
        self.maybe_start_early_aggregation(ctx).await;
    }
}
```

(The method's internal guards make this a few comparisons outside the window; `max_gossip_group_count_for_slot` is one lock with no clones inside it.)

- [ ] **Step 4: Skip the interval-2 start when the early session exists**

The `2 => { ... }` arm becomes:

```rust
            // ==== interval 2 ====
            2 => {
                if is_aggregator {
                    // The early trigger may have already started this slot's
                    // session (running or finished) — it IS the slot's session,
                    // so don't start a second one.
                    let already_started = self
                        .current_aggregation
                        .as_ref()
                        .is_some_and(|session| session.session_id == slot);
                    if !already_started {
                        self.start_aggregation_session(slot, ctx).await;
                    }
                } else {
                    metrics::inc_aggregator_skipped_not_aggregator();
                }
            }
```

- [ ] **Step 5: Build and run existing blockchain tests**

Run: `cargo build --workspace && cargo test -p ethlambda-blockchain --lib`
Expected: clean build, existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/blockchain/src/aggregation.rs crates/blockchain/src/lib.rs
git commit -m "feat(blockchain): start aggregation early when 2/3 of subnet signatures arrived"
```

---

### Task 8: Lint and existing test suites

**Files:** none (verification only)

- [ ] **Step 1: Format and lint**

Run: `make fmt && make lint`
Expected: no diffs from fmt; clippy clean with `-D warnings` (this is where any dead-code stragglers from Tasks 1–4 would surface — by now every added item has a caller).

- [ ] **Step 2: Run the existing test suites**

Run: `make test`
Expected: all workspace tests + forkchoice spec tests pass (no new tests were added; this guards against regressions in the touched paths). If fixtures are missing: `rm -rf leanSpec && make leanSpec/fixtures`.

- [ ] **Step 3: Commit any fmt fallout**

```bash
git add -u && git commit -m "chore: fmt" || true
```

(Skip the commit if the tree is clean.)

---

### Task 9: Local 4-node devnet validation

Run a local 4-node devnet on this branch and verify the early-start behavior end to end. Use the `devnet-runner` skill (`.claude/skills/devnet-runner/`) for the exact workflow; constraints that matter here:

- **Release build only** — debug binaries stack-overflow in leanVM `rec_aggregation`.
- **Exactly one node with `--is-aggregator`** — multiple co-located aggregators stall finality via leanVM CPU contention.
- If using Docker Desktop, the VM needs 16+ GiB (leanVM peaks ~4–5 GiB per node); binary mode avoids this.

- [ ] **Step 1: Start the devnet**

4 nodes, fresh genesis, one aggregator. Let it run at least ~50 slots (~4 minutes).

- [ ] **Step 2: Verify early-start behavior on the aggregator node**

Check the aggregator node's logs and metrics:

1. `"Early-aggregation threshold met"` and `"Starting aggregation session early"` appear for most slots (local gossip is fast; signatures land well inside the window). `lead_ms` values must be in `(0, 200]`.
2. `"Publishing aggregates held back until the interval-2 boundary"` appears with `count >= 1`.
3. `lean_aggregation_early_starts_total` grows (metrics port, default `:5054`, path `/metrics`).
4. `lean_aggregation_early_start_lead_seconds` observations sit in `(0, 0.4]`.
5. `"Committee signatures aggregated"` logs show `early=true` sessions. `"Prior aggregation worker still running"` warnings must be rare (the early start shrinks the worst-case gap to the previous slot's worker from 3250 ms to 2800 ms, so occasional joins under slow proofs are expected — every slot would be a bug).
6. No aggregate publish happens before its slot's interval-2 boundary: spot-check a few `"Starting aggregation session early"` slots and confirm the corresponding aggregated-attestation publish log lands at or after T2 (per-slot offset = `(log_epoch - GENESIS_TIME) mod 4 >= 1.6`).

- [ ] **Step 3: Verify chain health**

1. `lean_latest_finalized_slot` advances steadily on all 4 nodes (fresh local devnet should finalize nearly every justifiable slot).
2. Blocks carry attestations (`attestation_count > 0` in block logs).
3. No stalls, no panic/error-level logs attributable to aggregation.

- [ ] **Step 4: Stop the devnet and report**

Stop the nodes; summarize observed early-start rate (early sessions / slots), lead-time distribution, and finalization progress.
