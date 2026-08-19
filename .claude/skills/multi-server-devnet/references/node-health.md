# Is this node working? — the "all is good" checklist

A tool for answering, any time you want to know, whether a running node is doing
its job: a spot check on one node, a sanity pass after a config change or
conversion, or one input into a stall investigation. Items 1–7 verify the node
itself.

It also separates a **node** problem from a **devnet** problem, because the two
are not the same: a node can be perfectly healthy while the chain fails to
finalize (not enough of its peers are voting), and a node can be quietly broken
while the chain still finalizes without it. Judge the chain with the devnet-level
section at the end, never from a single node.

Everything below is grounded in real metric names (`crates/**/metrics.rs`) and
log strings (`crates/blockchain/src`). Cross-checks:

- **Duty *timing*** (where in the slot each duty actually lands, spill into the
  next slot): use the `devnet-profiling` skill — this doc only flags whether
  timing is in-budget, not the per-offset breakdown.
- **Log triage** (error classes, fork analysis): `devnet-log-review` skill.
- **Bootstrap-vs-stall** for the finality section: `references/operations.md`.

## Conventions for the queries below

- Metrics come from the central Prometheus, read either through the central
  Grafana or directly via its API (`$CENTRAL_PROM_URL/api/v1/query`, the same base
  `sweep.sh` takes). The Grafana URL, datasource uid, and whether anonymous read is
  enabled are deployment-specific — get them from the operator's notes, don't assume.
  Every series carries `network="<devnet>"`, `client_type`, `job`, `instance`,
  `type`. Queries here use `{network="$NET"}` for a whole devnet.
- **Scope to one node with `job`, not `instance`.** `job` is the per-node id
  `<client>_n` (e.g. `job="ethlambda_0"`, `job="zeam_8"`), matching the
  container/display name. `instance` is the **host** — every node on a host shares
  it — so it cannot isolate a node. Single-node filter: `{network="$NET", job="ethlambda_0"}`.
- The queries below were run against a live datasource; the sanity values quoted
  are from a healthy 32-node devnet (scale the per-devnet counts to your `NODES`).
- Slot = 4 s, `INTERVALS_PER_SLOT` = 5, so one interval ≈ 800 ms. A validator
  attests **once per slot** on subnet `n % SUBNETS`. Healthy per-validator
  attestation rate ≈ 0.25/s.
- Log greps are written as match strings. Apply them to
  `sudo docker logs <container>` or, via Loki in Grafana Explore, as
  `{network="$NET", node="<client>_n"} |= "<string>"`.
- **No Prometheus?** `scripts/host-check.sh` on the host covers items 1, 4 and 6
  at a glance (head/justified/finalized, sync state, aggregator flag, peer count,
  container status + restart count) straight off each node's `127.0.0.1` metrics
  port. Use it when the central stack is unreachable, or as the first pass before
  reaching for the queries below.

---

## Checklist

A healthy running node should, continuously:

1. **Follow the chain** — import blocks as they arrive; head keeps climbing and
   stays within a slot or two of wall-clock (not stuck in `syncing`).
2. **Emit a valid, *useful* attestation every slot** — not just a well-formed
   vote, but one that can actually move justification (see item 2 for the
   source/target rule).
3. **Build and publish a non-empty block in its proposer slots** — a block that
   actually packs attestations, not an empty one.
4. **If it is an aggregator** — aggregate its subnet's gossip signatures into a
   proof and publish the aggregate.
5. **Complete its duties on time** — build/attest/aggregate finish inside their
   interval budget and don't spill into the next slot.
6. **Keep peers and gossip mesh healthy** — connected to the rest of the devnet
   and subscribed with a populated mesh on the topics it uses.

Plus one network-visible check that a single node only *partly* controls:

7. **Its votes land in blocks** — blocks on the chain carry `attestation_count`
   > 0, i.e. the votes it emits are being aggregated and packed by proposers.

And one **devnet-wide** check that is **not** a node fault on its own:

- **Finality actually advances** — `finalized`/`justified` climb across the
  devnet, and `head − finalized` stays bounded.

---

## 1. Follows the chain (imports blocks)

**Means:** the node applies each new block, its head advances, and it is not
gated in `syncing`. Head advancing is the baseline "alive" signal.

**Prometheus:**
```promql
# head is climbing (slots/sec; ~0.25 healthy)
deriv(lean_head_slot{network="$NET"}[5m]) > 0
# head lag behind wall-clock; must stay small. The sync gate trips and
# suppresses duties once lag > SYNC_LAG_THRESHOLD (currently 4).
lean_current_slot{network="$NET"} - lean_head_slot{network="$NET"}
# sync state: 2=synced (healthy), 1=syncing, 0=idle
lean_node_sync_status{network="$NET", status="synced"} == 1
# blocks are actually being processed (state transition runs)
rate(lean_state_transition_block_processing_time_seconds_count{network="$NET"}[5m]) > 0
```

**Log:** `"Block imported successfully"` (one per imported block).

**Red flags:** head flat while `lean_current_slot` climbs → `head_lag` grows past
4 → `lean_node_sync_status{status="syncing"}==1`, which **suppresses attest +
propose** (log `"Skipping attestations while syncing"`). Repeated
`"Block parent missing, storing as pending"` / `"Requested missing block from
network"` → it is missing ancestors and back-filling.

---

## 2. Emits a valid, *useful* attestation every slot

**Means — two levels:**

- **Valid** (passes `validate_attestation_data` in `crates/blockchain/src/store.rs`): source → target
  → head lie on one parent chain, `source.slot ≤ target.slot ≤ head.slot`, each
  checkpoint's slot matches its block, and the vote isn't from the future.
- **Useful:** an attestation only *helps* if its **source matches the head
  state's latest-justified checkpoint**, and its **target is a justifiable slot
  strictly between the source and the head — not the head itself and not the
  source.** ethlambda's `produce_attestation_data` (same file) enforces both:
  - Source is read from the **head state's** `latest_justified`, which always
    lies on the head's own chain — deliberately *not* the store's global
    `latest_justified` (which is a highest-slot-wins max that can latch onto an
    off-head sibling). Sourcing off-head makes every head-chain target fail
    `is_valid_vote`, so the head can never re-justify and block production stalls
    (leanSpec #1166 / #595).
  - Target is `get_attestation_target`: walk back from the head
    toward the safe target, then back to the nearest slot satisfying
    `slot_is_justifiable_after(finalized)`, clamped to `≥ source`. That yields a
    justifiable, on-chain slot newer than the source and at/behind the head.

**Prometheus:**
```promql
# it is producing ~1 attestation/slot (count of production-timing observations)
rate(lean_attestations_production_time_seconds_count{network="$NET"}[5m])   # ≈0.25/validator
rate(lean_pq_sig_attestation_signing_time_seconds_count{network="$NET"}[5m]) # it signs its own vote
# nobody on the devnet is dropping votes as invalid (receiver side; should stay flat)
rate(lean_attestations_invalid_total{network="$NET"}[10m]) == 0
```

**Log:** `"Published attestation"` (`%slot %validator_id`, once per slot per local
validator).

**Red flags:** the clamp warning
`"Attestation target walked behind justified source, clamping to justified"` —
the vote stays valid but couldn't target a *new* justifiable slot that slot.
Receiver-side `UnknownSourceBlock` / `SourceNotAncestorOfTarget` /
`HeadOlderThanTarget` in *other* nodes' logs mean someone is emitting off-chain
(useless) votes. No `"Published attestation"` for a live validator → it is gated
(see item 1) or not assigned.

---

## 3. Builds and publishes a non-empty block in its proposer slots

**Means:** when it is the proposer, it builds a block that actually packs
aggregated attestation payloads (not empty) and publishes it aligned to the slot.

**Prometheus:**
```promql
# builds are succeeding, none failing
rate(lean_block_building_success_total{network="$NET"}[15m]) > 0
rate(lean_block_building_failures_total{network="$NET"}[15m]) == 0
# blocks are non-empty: avg aggregated payloads per built block > 0
  rate(lean_block_aggregated_payloads_sum{network="$NET"}[15m])
/ rate(lean_block_aggregated_payloads_count{network="$NET"}[15m])
# distinct AttestationData packed per proposal (histogram; >0)
rate(lean_block_proposal_attestation_data_selected_sum{network="$NET"}[15m]) > 0
```

**Log:** `"We are the proposer for this slot"` → `"Finished building block"` →
`"Published block"` (all `%slot %validator_id`).

**Red flags:** `"We are the proposer"` with no following `"Published block"` (build
overran its budget — see item 5), or non-empty ratio near 0 while the devnet is
gossiping attestations → **no aggregator is storing signatures** (classic
`--is-aggregator`-missing symptom: attestations verify but `attestation_count`
stays 0). Empty blocks that aren't genesis/anchor are a real problem.

---

## 4. If an aggregator: aggregate signatures and publish the aggregate

**Only applies when `lean_is_aggregator == 1`.** Skip otherwise.

**Means:** at interval 2 it aggregates the gossip signatures it collected on its
subnet into a proof and publishes the aggregate back onto gossip.

**Prometheus:**
```promql
lean_is_aggregator{network="$NET"} == 1
# aggregates are being produced, and are valid
rate(lean_pq_sig_aggregated_signatures_total{network="$NET"}[10m]) > 0
rate(lean_pq_sig_aggregated_signatures_invalid_total{network="$NET"}[10m]) == 0
# raw gossip signatures it collected to aggregate over — SCOPE to the aggregator
# job; non-aggregators read 0 BY DESIGN (they never store gossip sigs)
lean_gossip_signatures{network="$NET", job="ethlambda_0"}
# aggregation jobs are not being skipped/dropped (counter has a `reason` label)
rate(lean_aggregator_skipped_total{network="$NET"}[10m])   # ~0
# validators the aggregate covers. High-cardinality (section × subnet), so ALWAYS
# pick a selector; section=combined,subnet=combined is the headline number
# (=NODES at full coverage, e.g. 32/32). It counts validators covered — it can't
# be mapped back to one validator's own vote.
lean_attestation_aggregate_coverage_validators{network="$NET", section="combined", subnet="combined"}
```

**Log:** `"Committee signature aggregated"` (`session_id, slot, raw_sigs,
participants, elapsed`). `"Failed to publish reaggregated attestation"` on the
publish path is a warn to watch.

**Red flags:** `is_aggregator=1` but `lean_pq_sig_aggregated_signatures_total`
flat, or rising `lean_aggregator_skipped_total`, or the aggregator's
`lean_gossip_signatures` ≈ 0 (it hears no subnet signatures — often the
missing-60s-backoff mesh problem from golden rule #2). Coverage
(`section=combined`) stuck below `ceil(2/3·NODES)` starves finality.

---

## 5. Completes its duties on time

**Means:** each per-slot duty finishes inside its interval so it doesn't get
skipped or spill into the next slot. The tick scheduler drops an interval whose
work overran, so a slow build/aggregate simply doesn't publish.

**Prometheus (histograms → use quantiles / `_count`):**
```promql
# time BETWEEN ticks; healthy p90 ≈ one interval (~0.8s) BY DESIGN (not a duty
# duration). Alarm only when it climbs WELL above ~0.8s → actor starved, ticks
# (hence duties) delayed. Live-healthy: ~0.80s.
histogram_quantile(0.9, sum by (le) (rate(lean_tick_interval_duration_seconds_bucket{network="$NET"}[10m])))
# block build must finish in time to publish at interval 0 (keep p90 well under a
# slot). Live-healthy: ~0.98s.
histogram_quantile(0.9, sum by (le) (rate(lean_block_building_time_seconds_bucket{network="$NET"}[10m])))
# aggregation must beat AGGREGATION_DEADLINE (800ms); early start opens at
# interval − EARLY_AGGREGATION_WINDOW (600ms)
histogram_quantile(0.9, sum by (le) (rate(lean_committee_signatures_aggregation_time_seconds_bucket{network="$NET"}[10m])))
histogram_quantile(0.9, sum by (le) (rate(lean_pq_sig_aggregated_signatures_building_time_seconds_bucket{network="$NET"}[10m])))
```

**Receiver side** — the same question asked of what *arrives* rather than what
this node produces. `lean_gossip_*_arrival_total` classifies each gossip message
by whether it landed inside the interval it was due in, so an on-time fraction
well under 1 says votes are arriving late rather than not at all:
```promql
# share of arrivals inside their due interval, per node (block|attestation|aggregation)
sum by (job) (rate(lean_gossip_attestation_arrival_total{network="$NET", position="inside"}[10m]))
/ sum by (job) (rate(lean_gossip_attestation_arrival_total{network="$NET"}[10m]))
# how late, in seconds (absolute distance from the due interval's start)
histogram_quantile(0.9, sum by (le, job) (rate(lean_gossip_attestation_arrival_delay_seconds_bucket{network="$NET"}[10m])))
```
One node low while the fleet is fine is that node's own clock or CPU; everyone
dropping together is chain-wide production or propagation. Graphed in the client
dashboard's **Gossip Arrival Timing** row. Aggregates are anchored to the latest
aggregation-interval boundary, not their own data slot, so their tail reads as
aggregation cost (cross-check the two aggregation-time histograms above), and
`position="before"` never appears for them.

**Log:** presence/absence timing — e.g. `"Finished building block"` arriving
after the next slot boundary. For exact slot-relative offsets and spill
detection, use the **`devnet-profiling`** skill (this item only says in/out of
budget).

**Red flags:** tick-interval p90 *well above* ~0.8 s (actor starved, ticks
delayed — ~0.8 s itself is normal); build p90 climbing toward a slot (leanVM
proving under CPU contention); aggregation p90 near/over AGGREGATION_DEADLINE
(800 ms) → aggregates published late or dropped. Usually a **host CPU/contention**
symptom, not a logic bug.

---

## 6. Peers and gossip mesh healthy

**Means:** connected to the rest of its (single-host) devnet and subscribed with
a populated mesh on the topics it uses (block, aggregation, its attestation
subnet).

**Prometheus:**
```promql
# connected peers (on an isolated single-host devnet ≈ NODES-1)
sum(lean_connected_peers{network="$NET"})
# mesh peers per topic — should be non-zero on subscribed topics
lean_gossip_mesh_peers{network="$NET"}
# connection churn should be low/flat
rate(lean_peer_disconnection_events_total{network="$NET"}[10m])
```

**Log:** peer connect/disconnect events (`%peer_id %direction peer_count ...`).

**Red flags:** `connected_peers` well below `NODES-1`, an empty mesh on the
node's attestation subnet (its votes reach no aggregator — the golden-rule-#2
backoff trap), or high disconnect churn.

---

## 7. Its votes land in blocks (network-visible)

**Means:** the votes this node emits are actually aggregated and packed by
proposers, so blocks on the chain carry `attestation_count` > 0. A node only
*partly* controls this — it emits the vote (item 2) and reaches the mesh (item
6), but landing also needs a working aggregator (item 4) and an honest proposer.

**Prometheus:**
```promql
# payloads packed per block. Buckets are coarse, so the median reads as a
# fractional bucket estimate (e.g. 0.5) — prefer the avg from item 3, or the
# attestation_count log below, as the clean "non-empty" check.
histogram_quantile(0.5, sum by (le) (rate(lean_block_aggregated_payloads_bucket{network="$NET"}[15m])))
rate(lean_block_proposal_aggregates_selected_sum{network="$NET"}[15m]) > 0
# validators covered by the aggregates (section=combined,subnet=combined =
# headline count, =NODES at full coverage). Counts validators, not a single vote.
lean_attestation_aggregate_coverage_validators{network="$NET", section="combined", subnet="combined"}
```

**Log:** `"Block multi-message aggregate proof verified"` carries
`attestation_count` — grep it and confirm the field is > 0 on imported blocks:
```bash
sudo docker logs <container> 2>&1 | grep "Block multi-message aggregate proof verified"
# each line shows attestation_count=<n>; n should be > 0
```

**Red flags:** `attestation_count=0` on non-genesis blocks devnet-wide → no
aggregator is storing signatures, or the mesh is broken. Coverage stuck below
`ceil(2/3·NODES)` → votes land but not enough of them to justify.

---

## Devnet-level: finality actually advances — NOT a per-node fault

This is a property of the **chain**, not of one node. Judge it separately, and
never conclude "node X is broken" from non-finality alone: X can be doing items
1–7 perfectly while the devnet stalls because *other* nodes aren't voting.

**Prometheus (aggregate across the devnet with `max`):**
```promql
# justified and finalized both climbing
deriv(max(lean_latest_justified_slot{network="$NET"})[10m:]) > 0
deriv(max(lean_latest_finalized_slot{network="$NET"})[10m:]) > 0
rate(lean_finalizations_total{network="$NET"}[15m]) > 0
# head−finalized gap stays bounded (the finality Slack alert fires > 512)
max(lean_head_slot{network="$NET"}) - max(lean_latest_finalized_slot{network="$NET"})
```

**Reading it:**
- A **young devnet** can sit at `finalized=0` while `justified` jumps only on
  square/pronic-distance slots — that's the bootstrap regime, **not** a stall
  (see `references/operations.md`).
- `finalized` frozen with `head` climbing and the gap widening = a real stall.
  Diagnose the **devnet** ("A devnet stopped finalizing" workflow in `SKILL.md`):
  vote count vs `ceil(2/3·NODES)` → which validator cohort is missing on the
  aggregator → are missing nodes silent or voting stale targets → host CPU/mem.
- Per-node items 1–7 tell you whether *this* node is one of the healthy voters
  or one of the culprits.
