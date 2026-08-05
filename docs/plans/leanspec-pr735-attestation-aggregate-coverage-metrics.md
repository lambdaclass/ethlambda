# Attestation Aggregate Coverage Metrics (leanSpec PR #735 port)

## Goal

Port [leanSpec PR #735](https://github.com/leanEthereum/leanSpec/pull/735) to
ethlambda: register three new Prometheus metrics that describe attestation
aggregate coverage, with default zero-valued series so dashboards can render
them from a fresh node startup. **Registration only** — no instrumentation
in this PR.

## Upstream context

- **leanSpec PR #735** (Python reference, "metrics: add attestation aggregate
  coverage gauges with subnet labels"): adds three metric definitions and
  default series. Explicitly states "leanSpec does not yet instrument
  fork-choice coverage reporting (that lives in zeam #876)".
- **zeam PR #898**: the upstream that PR #735 mirrors — added the same
  metrics in zeam under `zeam_*` names.
- **zeam PR #876** ("log attestation subnet coverage in chain status",
  MERGED): the *instrumentation* PR. Tracks aggregated attestation payload
  coverage from the latest block slot separately from fork-choice's
  known/new payload pools, emits a chain-status info log per slot, and
  de-duplicates validators across payloads before calculating percentages.
  We will port this in a **follow-up PR**, not here.

Because PR #735 contains only the metric definitions, our scope for this
change is identical: declare metrics, register them, seed the defaults.
Wiring producers to these gauges lands when we port the equivalent of
zeam #876 to ethlambda.

## Metric contract

Three new gauges. All have the `lean_` prefix (project convention,
`CLAUDE.md` Metrics section).

| Metric name | Labels | Meaning |
| --- | --- | --- |
| `lean_attestation_aggregate_coverage_validators` | `section`, `subnet` | Validator coverage in a given coverage section. `subnet="combined"` is the section total across all subnets; `subnet="subnet_N"` is per-subnet coverage. |
| `lean_attestation_aggregate_coverage_subnets`    | `section`           | Number of covered subnets in a given section. |
| `lean_attestation_aggregate_coverage_diff_validators` | `direction`     | Count of validators in the symmetric difference between **block-included** aggregates and **locally-aggregated pre-merge** (`timely`) aggregates for the same slot. `direction="block_only"`: in block but not in local pool (proposer had something we didn't). `direction="timely_only"`: in local pool but not in block (we had something the proposer dropped). |

**Slot is the X-axis (time series), not a label dimension** — this is an
explicit decision carried from the upstream PR's review feedback.

### Section labels

Mirroring `ATTESTATION_AGGREGATE_COVERAGE_SECTIONS` in the upstream
registry, in order:

1. `timely`
2. `late`
3. `block`
4. `combined`
5. `agg_start_new`
6. `proposal_payloads`
7. `proposal_gossip`
8. `proposal_combined`

These match the names printed in slot/report logs in zeam.

### Direction labels

`ATTESTATION_AGGREGATE_COVERAGE_DIFF_DIRECTIONS`:

1. `block_only`
2. `timely_only`

#### What the diff metric means (operator view)

The aggregation pipeline produces two distinct pools of aggregated payloads
for the same slot:

- **`timely`** (a.k.a. `prev_new` in zeam #876): the aggregated payloads
  this node had built locally **before** the latest block was merged —
  "what we collected from gossip in time."
- **`block`**: the aggregated payloads the **block proposer** chose to
  include in the block this node just imported.

Same slot, same validator set in principle, but two independent views:
ours (gossip-fed) vs. the proposer's (whatever they could see and pack).

For each validator, ask "covered by block? covered by timely?" and count
the symmetric difference:

```
block_only  = | { v : v in block-pool  AND v not in timely-pool } |
timely_only = | { v : v in timely-pool AND v not in block-pool  } |
```

Reference implementation in zeam #876:

```zig
for (block_seen, prev_new_seen) |b, pn| {
    if (b and !pn) block_not_prev_new += 1;   // → block_only
    if (pn and !b) prev_new_not_block += 1;   // → timely_only
}
```

This is an **aggregation-divergence health signal**:

- `block_only` persistently high → this node was slow to receive/aggregate
  attestations via gossip; the proposer had a better view (local gossip
  lag or aggregation issues).
- `timely_only` persistently high → the proposer omitted attestations
  the network had time to gossip (misbehaving/minimal proposer, or a
  peering split).
- Both near zero → local aggregation tracks proposers well; the network
  is converging.

It is *not* a coverage percentage — it is a per-direction count of
validators in the disagreement set. Plotting both directions over time
shows where the asymmetry leans.

### Default series

At node start (before any instrumentation fires), the registry must expose:

- `lean_attestation_aggregate_coverage_validators{section=<each section>, subnet="combined"} = 0`
- `lean_attestation_aggregate_coverage_subnets{section=<each section>} = 0`
- `lean_attestation_aggregate_coverage_diff_validators{direction=<each direction>} = 0`

We deliberately do **not** seed `subnet="subnet_N"` series for each subnet
at startup — the upstream PR also seeds only the `combined` series. Per-
subnet series will appear lazily when instrumentation begins writing them.

## Design decisions

### `IntGaugeVec`, not `GaugeVec`

The upstream Python uses `prometheus_client.Gauge` (float). All coverage
values are integer counts (validator counts, subnet counts, deltas), and
every other labeled metric currently registered in
`crates/blockchain/src/metrics.rs` uses `IntGaugeVec`
(`LEAN_NODE_INFO`, `LEAN_TABLE_BYTES`, `LEAN_NODE_SYNC_STATUS`). We follow
the project convention.

### Location: `crates/blockchain/src/metrics.rs`

The coverage data conceptually belongs to fork-choice / aggregation logic,
which already lives in the `blockchain` crate. Placing the metric
definitions there keeps them with their eventual producers and matches
where `lean_attestation_committee_count` and the other attestation-related
metrics live.

### No setter functions in this PR

The existing metrics in `metrics.rs` each pair a `static LazyLock` with a
public setter (e.g. `update_table_bytes`). Adding setters now would create
dead code, because nothing yet computes coverage values. We will add
setters in the same PR that ports the instrumentation (zeam #876
equivalent), so the setter shape can be informed by the actual call sites.

For the LazyLocks to be reachable during `init()` without setters, we keep
the existing pattern: each metric is forced inside `init()`, which is
already the only producer-side call site for many of the registry-only
metrics today.

### Constants are public

`ATTESTATION_AGGREGATE_COVERAGE_SECTIONS` and
`ATTESTATION_AGGREGATE_COVERAGE_DIFF_DIRECTIONS` are exported `pub
const`s, mirroring upstream so future instrumentation code (and tests)
can iterate them without redefining the source of truth.

## Implementation steps

All changes are inside `crates/blockchain/src/metrics.rs`.

### 1. Add the label-set constants

Near the top of the file (alongside other module-level constants),
introduce:

```rust
/// Section labels for attestation aggregate coverage gauges. Order matches
/// the names printed in slot/report logs.
/// Slot is the X-axis (time series), not a label dimension.
pub const ATTESTATION_AGGREGATE_COVERAGE_SECTIONS: &[&str] = &[
    "timely",
    "late",
    "block",
    "combined",
    "agg_start_new",
    "proposal_payloads",
    "proposal_gossip",
    "proposal_combined",
];

/// Validator coverage delta directions between block and timely pre-merge
/// payloads.
pub const ATTESTATION_AGGREGATE_COVERAGE_DIFF_DIRECTIONS: &[&str] =
    &["block_only", "timely_only"];
```

### 2. Register the three statics

Adjacent to the other labeled gauges (after `LEAN_TABLE_BYTES` is a
natural neighbour):

```rust
static LEAN_ATTESTATION_AGGREGATE_COVERAGE_VALIDATORS:
    std::sync::LazyLock<IntGaugeVec> = std::sync::LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_attestation_aggregate_coverage_validators",
        "Validator coverage in attestation aggregate reports, labeled by \
         section and subnet. subnet=combined is the section total; \
         subnet=subnet_N is per-subnet coverage. Updated each slot \
         (slot is the X-axis).",
        &["section", "subnet"]
    )
    .unwrap()
});

static LEAN_ATTESTATION_AGGREGATE_COVERAGE_SUBNETS:
    std::sync::LazyLock<IntGaugeVec> = std::sync::LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_attestation_aggregate_coverage_subnets",
        "Number of covered subnets in attestation aggregate reports, \
         labeled by section. Updated each slot (slot is the X-axis).",
        &["section"]
    )
    .unwrap()
});

static LEAN_ATTESTATION_AGGREGATE_COVERAGE_DIFF_VALIDATORS:
    std::sync::LazyLock<IntGaugeVec> = std::sync::LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_attestation_aggregate_coverage_diff_validators",
        "Count of validators in the symmetric difference between \
         block-included aggregates and locally-aggregated pre-merge \
         (timely) aggregates for the same slot. \
         direction=block_only: in block but not in local pool. \
         direction=timely_only: in local pool but not in block. \
         Updated each slot (slot is the X-axis).",
        &["direction"]
    )
    .unwrap()
});
```

Description strings are kept faithful to the upstream wording for the
first two metrics so operator dashboards can be authored against a stable
contract regardless of which client is scraped.

The `diff_validators` description **intentionally diverges** from the
terse upstream phrasing ("Validator coverage delta between block payloads
and timely pre-merge payloads"), which is unparseable without
aggregation-pipeline context. We spell out the symmetric-difference
semantics explicitly. The metric *name*, *labels*, and *values* remain
identical to upstream — only the `help` text differs, which is purely
descriptive and does not affect dashboards or scrapers.

### 3. Force and seed in `init()`

Extend `init()`:

```rust
// Attestation aggregate coverage (leanMetrics: Fork-Choice Metrics).
std::sync::LazyLock::force(&LEAN_ATTESTATION_AGGREGATE_COVERAGE_VALIDATORS);
std::sync::LazyLock::force(&LEAN_ATTESTATION_AGGREGATE_COVERAGE_SUBNETS);
std::sync::LazyLock::force(&LEAN_ATTESTATION_AGGREGATE_COVERAGE_DIFF_VALIDATORS);

for section in ATTESTATION_AGGREGATE_COVERAGE_SECTIONS {
    LEAN_ATTESTATION_AGGREGATE_COVERAGE_VALIDATORS
        .with_label_values(&[section, "combined"])
        .set(0);
    LEAN_ATTESTATION_AGGREGATE_COVERAGE_SUBNETS
        .with_label_values(&[section])
        .set(0);
}
for direction in ATTESTATION_AGGREGATE_COVERAGE_DIFF_DIRECTIONS {
    LEAN_ATTESTATION_AGGREGATE_COVERAGE_DIFF_VALIDATORS
        .with_label_values(&[direction])
        .set(0);
}
```

The seeding loop sits in `init()` (not in a separate function) because the
defaults are part of registration, not runtime state.

### 4. No changes elsewhere

- No edits to `crates/common/metrics/src/lib.rs` — the existing
  `register_int_gauge_vec` re-export covers us.
- No new public API on the `ethlambda-metrics` crate.
- No edits to `gather.rs` — the default registry picks up the new
  collectors automatically.
- No changes to `RELEASE.md`, dashboards, or external configuration.

## Testing

### Existing tests

`cargo test --workspace --release` should pass unchanged. The new
statics are forced inside `init()` and do not affect any production code
path.

### New focused check

The blockchain crate does not currently host metric-registry tests, and
introducing the first one here is out of proportion to the change (the
upstream Python test passes because it asserts default zero values, which
is a tautology for code that calls `.set(0)`). We rely on the manual
verification step below to confirm the `/metrics` endpoint exposes the
expected series.

### Manual verification

1. `cargo run -p ethlambda -- ...` (or `make run-devnet`) on any node.
2. `curl http://127.0.0.1:5054/metrics | grep lean_attestation_aggregate_coverage`
3. Confirm all 18 expected series appear with value `0`:
   - 8 × `lean_attestation_aggregate_coverage_validators{section="...",subnet="combined"}`
   - 8 × `lean_attestation_aggregate_coverage_subnets{section="..."}`
   - 2 × `lean_attestation_aggregate_coverage_diff_validators{direction="..."}`

## Verification

1. `make fmt` — must be clean.
2. `make lint` — clippy with `-D warnings`. New statics are referenced
   from `init()`, so no dead-code warning is expected.
3. `make test` — full workspace test suite.
4. Manual `/metrics` smoke check (above).

## Out of scope

- **Per-slot coverage computation and gauge updates.** That logic is the
  ethlambda equivalent of zeam #876 and will be a separate PR. It will:
  - Compute coverage from the chain's aggregated payloads at each slot
    boundary.
  - De-duplicate validators across payloads before computing percentages.
  - Emit a chain-status `info!` log alongside writing the gauges.
  - Add the setter helpers (`update_attestation_aggregate_coverage_*`) and
    their unit coverage.
- **Per-subnet (`subnet="subnet_N"`) series at startup.** Upstream seeds
  only `combined`; per-subnet series appear when instrumentation writes
  them.
- **Renaming or relocating existing attestation metrics.**
- **Dashboards.** External; tracked by operators against the new metric
  names once they ship.

## Risks / open questions

- **Cardinality.** Once instrumentation lands, the validators metric
  carries `sections × subnets` series. With 8 sections and the current
  4-subnet devnets that is 32 active series; even at 64 subnets that is
  still 512 — well within Prometheus comfort. No cardinality concerns
  at the registration step in this PR.
- **Float vs int.** Upstream uses float `Gauge`; we use `IntGaugeVec`.
  All known producers (zeam #876, leanSpec follow-up) emit integer counts.
  If a future producer emits ratios or percentages, we will either keep
  the ratio computation in a separate metric or migrate to `GaugeVec`.
- **Description drift.** Description strings are duplicated between
  ethlambda and leanSpec. If upstream rewords, we may need to follow.
  Acceptable for now; we will keep an eye on PR #735 prior to merge in
  case the wording changes.

## Files touched

- `crates/blockchain/src/metrics.rs`

No new files. No public-crate API changes. No dependency changes.
