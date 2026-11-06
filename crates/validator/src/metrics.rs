//! Prometheus series for the validator client.
//!
//! Named `ethlambda_validator_*` rather than with this repo's usual `lean_`
//! prefix: this process follows the beacon chain, not the lean chain, and a
//! `lean_` series here would be misleading in a shared dashboard.

use std::sync::LazyLock;

use ethlambda_metrics::{
    Histogram, IntCounter, IntGauge, TimingGuard, register_histogram, register_int_counter,
    register_int_gauge,
};

static VALIDATORS_LOADED: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "ethlambda_validator_validators_loaded",
        "Validator keys loaded by this client"
    )
    .unwrap()
});

static VALIDATORS_RESOLVED: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "ethlambda_validator_validators_resolved",
        "Loaded validator keys with an index on chain, out of validators_loaded"
    )
    .unwrap()
});

static DUTIES_HELD: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "ethlambda_validator_duties_held",
        "Attester duties currently scheduled"
    )
    .unwrap()
});

static ATTESTATIONS_PUBLISHED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_attestations_published_total",
        "Attestations accepted by a beacon node"
    )
    .unwrap()
});

static ATTESTATION_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_attestation_failures_total",
        "Slots where publishing attestations failed"
    )
    .unwrap()
});

static SIGNING_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_signing_failures_total",
        "Attestations that could not be signed"
    )
    .unwrap()
});

/// Slots whose attestation work was abandoned for running past the end of the
/// slot.
///
/// Distinct from `attestation_failures_total`, which counts a duty that failed
/// and returned. This counts one that never returned in time, which points at a
/// slow or hung beacon node rather than at a rejected attestation, and is the
/// series to watch when publication delay starts climbing.
static ATTESTATION_DEADLINE_MISSED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_attestation_deadline_missed_total",
        "Slots whose attestation work was abandoned for overrunning the slot"
    )
    .unwrap()
});

/// Attestations this process declined to sign because it had already signed a
/// conflicting one for that validator in this run.
///
/// Separate from `signing_failures_total`, which counts signatures that were
/// attempted and failed. This counts signatures deliberately not attempted, and
/// it should normally read zero: a non-zero value means the duty loop tried to
/// sign something the guard judged a double vote, which is worth investigating
/// even though the attestation was correctly suppressed. See
/// `crate::attestation_guard`.
static ATTESTATIONS_REFUSED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_attestations_refused_total",
        "Attestations refused because this process already signed a conflicting one"
    )
    .unwrap()
});

static BLOCKS_PROPOSED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_blocks_proposed_total",
        "Blocks signed and accepted by a beacon node"
    )
    .unwrap()
});

/// Blocks a beacon node broadcast but could not import into its own database,
/// which is what `publishBlockV2` answers 202 for.
///
/// A subset of `blocks_proposed_total` rather than a failure counter: the block
/// did reach the network. A non-zero rate here points at the beacon node, not
/// at this client, and usually means its execution layer is unsynced.
static BLOCKS_BROADCAST_NOT_IMPORTED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_blocks_broadcast_not_imported_total",
        "Blocks broadcast by a beacon node that could not import them"
    )
    .unwrap()
});

/// Blocks this process declined to sign because it had already proposed that
/// slot for that validator in this run.
///
/// The proposal-shaped counterpart to `attestations_refused_total`, and it
/// should read zero for the same reason: a non-zero value means the duty loop
/// tried to propose a slot the guard judged already proposed, which is worth
/// investigating even though the block was correctly suppressed. See
/// `crate::proposal_guard`.
static BLOCKS_REFUSED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_blocks_refused_total",
        "Blocks refused because this process already proposed that slot"
    )
    .unwrap()
});

/// Slots where a proposal duty was held and failed to produce a published
/// block, for any reason.
static BLOCK_PROPOSAL_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_block_proposal_failures_total",
        "Proposal duties that did not result in a published block"
    )
    .unwrap()
});

/// Envelopes of self-built gloas payloads the node accepted.
static ENVELOPES_PUBLISHED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_envelopes_published_total",
        "Execution payload envelopes published for blocks this client proposed"
    )
    .unwrap()
});

/// Gloas proposals whose block went out but whose envelope did not: the slot's
/// payload is then withheld, which costs the proposer its execution rewards and
/// the chain a payload.
static ENVELOPE_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_envelope_failures_total",
        "Proposed blocks whose self-built envelope was not published"
    )
    .unwrap()
});

static PAYLOAD_ATTESTATIONS_PUBLISHED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_payload_attestations_published_total",
        "Payload timeliness committee votes the beacon node accepted"
    )
    .unwrap()
});

static PAYLOAD_ATTESTATION_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_payload_attestation_failures_total",
        "Slots whose payload timeliness committee duty did not result in published votes"
    )
    .unwrap()
});

/// End to end, from the slot's start to the node accepting the block.
///
/// The buckets are tighter at the low end than the attestation histogram's,
/// because the interesting question is different. An attestation is due a third
/// of the way into the slot; a block is due at the start, and the deadlines it
/// actually faces are the proposer re-org cutoff and the point attesters stop
/// waiting for it.
static BLOCK_PUBLICATION_DELAY_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "ethlambda_validator_block_publication_delay_seconds",
        "Time from slot start to this slot's block being accepted by a beacon node",
        vec![0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0, 8.0]
    )
    .unwrap()
});

/// Blocks whose execution-layer fee recipient was not the address this client
/// asked the beacon node to use.
///
/// Should read zero forever. A non-zero value means every block this validator
/// proposes is paying its execution rewards somewhere else, which is a beacon
/// node misconfiguration and not something this client can fix by refusing:
/// see `crate::proposal::ProposalService::check_fee_recipient` for why it signs
/// anyway.
static FEE_RECIPIENT_MISMATCHES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_fee_recipient_mismatches_total",
        "Blocks paying execution rewards to an address this client did not request"
    )
    .unwrap()
});

/// Aggregates this client signed and a beacon node accepted.
///
/// Expected to be small and bursty rather than steady: a validator is selected
/// to aggregate a few times a day, so a flat zero over hours is normal for a
/// small deployment and only meaningful against `aggregator_duties_total`.
static AGGREGATES_PUBLISHED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_aggregates_published_total",
        "Aggregates accepted by a beacon node"
    )
    .unwrap()
});

/// Slots where an aggregation duty was held and no aggregate was published.
static AGGREGATION_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_aggregation_failures_total",
        "Aggregation duties that did not result in a published aggregate"
    )
    .unwrap()
});

static BEACON_NODE_AVAILABLE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "ethlambda_validator_beacon_node_available",
        "1 when a beacon node answered the last duty refresh or attestation"
    )
    .unwrap()
});

static SIGNING_DURATION_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "ethlambda_validator_signing_duration_seconds",
        "Time spent signing one slot's batch of attestations, read lock included",
        vec![
            0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5
        ]
    )
    .unwrap()
});

static PUBLICATION_DELAY_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "ethlambda_validator_publication_delay_seconds",
        "Time from slot start to this slot's attestations being accepted by a beacon node",
        vec![0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 6.0, 8.0, 12.0]
    )
    .unwrap()
});

static SYNC_COMMITTEE_MESSAGES_PUBLISHED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_sync_committee_messages_published_total",
        "Sync committee messages the beacon node accepted"
    )
    .unwrap()
});

static SYNC_COMMITTEE_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_sync_committee_failures_total",
        "Slots whose sync committee message duty did not result in published messages"
    )
    .unwrap()
});

static SYNC_CONTRIBUTIONS_PUBLISHED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_sync_contributions_published_total",
        "Sync committee contributions published to the beacon node"
    )
    .unwrap()
});

static SYNC_CONTRIBUTION_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "ethlambda_validator_sync_contribution_failures_total",
        "Sync committee aggregation duties that ended in an error or ran past their slot"
    )
    .unwrap()
});

static SYNC_DUTIES_HELD: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "ethlambda_validator_sync_duties_held",
        "Sync committee duties held for the current period"
    )
    .unwrap()
});

/// Register every series with the Prometheus registry so `/metrics` lists them
/// at zero from startup, rather than only after whatever first touches them.
///
/// Without this, a function-scoped `LazyLock` only registers on first call, so
/// (for example) `ethlambda_validator_attestations_published_total` is absent
/// rather than zero until the first successful publish. An alert on
/// "attestations stopped" cannot fire on a series that does not exist, and
/// absent-versus-zero is exactly the distinction an operator needs.
pub fn init() {
    LazyLock::force(&VALIDATORS_LOADED);
    LazyLock::force(&VALIDATORS_RESOLVED);
    LazyLock::force(&DUTIES_HELD);
    LazyLock::force(&ATTESTATIONS_PUBLISHED_TOTAL);
    LazyLock::force(&ATTESTATION_FAILURES_TOTAL);
    LazyLock::force(&SIGNING_FAILURES_TOTAL);
    LazyLock::force(&ATTESTATIONS_REFUSED_TOTAL);
    LazyLock::force(&ATTESTATION_DEADLINE_MISSED_TOTAL);
    LazyLock::force(&BLOCKS_PROPOSED_TOTAL);
    LazyLock::force(&BLOCKS_BROADCAST_NOT_IMPORTED_TOTAL);
    LazyLock::force(&BLOCKS_REFUSED_TOTAL);
    LazyLock::force(&BLOCK_PROPOSAL_FAILURES_TOTAL);
    LazyLock::force(&ENVELOPES_PUBLISHED_TOTAL);
    LazyLock::force(&ENVELOPE_FAILURES_TOTAL);
    LazyLock::force(&PAYLOAD_ATTESTATIONS_PUBLISHED_TOTAL);
    LazyLock::force(&PAYLOAD_ATTESTATION_FAILURES_TOTAL);
    LazyLock::force(&SYNC_COMMITTEE_MESSAGES_PUBLISHED_TOTAL);
    LazyLock::force(&SYNC_COMMITTEE_FAILURES_TOTAL);
    LazyLock::force(&SYNC_CONTRIBUTIONS_PUBLISHED_TOTAL);
    LazyLock::force(&SYNC_CONTRIBUTION_FAILURES_TOTAL);
    LazyLock::force(&SYNC_DUTIES_HELD);
    LazyLock::force(&BLOCK_PUBLICATION_DELAY_SECONDS);
    LazyLock::force(&AGGREGATES_PUBLISHED_TOTAL);
    LazyLock::force(&AGGREGATION_FAILURES_TOTAL);
    LazyLock::force(&FEE_RECIPIENT_MISMATCHES_TOTAL);
    LazyLock::force(&BEACON_NODE_AVAILABLE);
    LazyLock::force(&SIGNING_DURATION_SECONDS);
    LazyLock::force(&PUBLICATION_DELAY_SECONDS);
}

pub fn set_validators_loaded(count: u64) {
    VALIDATORS_LOADED.set(count as i64);
}

pub fn set_validators_resolved(count: u64) {
    VALIDATORS_RESOLVED.set(count as i64);
}

pub fn set_duties_held(count: u64) {
    DUTIES_HELD.set(count as i64);
}

pub fn inc_attestations_published(count: u64) {
    ATTESTATIONS_PUBLISHED_TOTAL.inc_by(count);
}

pub fn inc_attestation_failures() {
    ATTESTATION_FAILURES_TOTAL.inc();
}

pub fn inc_signing_failures() {
    SIGNING_FAILURES_TOTAL.inc();
}

pub fn inc_attestations_refused() {
    ATTESTATIONS_REFUSED_TOTAL.inc();
}

pub fn inc_attestation_deadline_missed() {
    ATTESTATION_DEADLINE_MISSED_TOTAL.inc();
}

pub fn inc_blocks_proposed() {
    BLOCKS_PROPOSED_TOTAL.inc();
}

pub fn inc_blocks_broadcast_not_imported() {
    BLOCKS_BROADCAST_NOT_IMPORTED_TOTAL.inc();
}

pub fn inc_blocks_refused() {
    BLOCKS_REFUSED_TOTAL.inc();
}

pub fn inc_block_proposal_failures() {
    BLOCK_PROPOSAL_FAILURES_TOTAL.inc();
}

pub fn inc_envelopes_published() {
    ENVELOPES_PUBLISHED_TOTAL.inc();
}

pub fn inc_envelope_failures() {
    ENVELOPE_FAILURES_TOTAL.inc();
}

pub fn inc_payload_attestations_published(count: u64) {
    PAYLOAD_ATTESTATIONS_PUBLISHED_TOTAL.inc_by(count);
}

pub fn inc_payload_attestation_failures() {
    PAYLOAD_ATTESTATION_FAILURES_TOTAL.inc();
}

pub fn inc_sync_committee_messages_published(count: u64) {
    SYNC_COMMITTEE_MESSAGES_PUBLISHED_TOTAL.inc_by(count);
}

pub fn inc_sync_committee_failures() {
    SYNC_COMMITTEE_FAILURES_TOTAL.inc();
}

pub fn inc_sync_contributions_published(count: u64) {
    SYNC_CONTRIBUTIONS_PUBLISHED_TOTAL.inc_by(count);
}

pub fn inc_sync_contribution_failures() {
    SYNC_CONTRIBUTION_FAILURES_TOTAL.inc();
}

pub fn set_sync_duties_held(count: u64) {
    SYNC_DUTIES_HELD.set(count as i64);
}

/// Record how long after a slot's start its block was accepted.
pub fn observe_block_publication_delay(seconds: f64) {
    BLOCK_PUBLICATION_DELAY_SECONDS.observe(seconds);
}

pub fn inc_aggregates_published(count: u64) {
    AGGREGATES_PUBLISHED_TOTAL.inc_by(count);
}

pub fn inc_aggregation_failures() {
    AGGREGATION_FAILURES_TOTAL.inc();
}

pub fn inc_fee_recipient_mismatches() {
    FEE_RECIPIENT_MISMATCHES_TOTAL.inc();
}

pub fn set_beacon_node_available(available: bool) {
    BEACON_NODE_AVAILABLE.set(i64::from(available));
}

/// Time one slot's signing loop. The returned guard records to
/// `ethlambda_validator_signing_duration_seconds` when dropped; hold it only
/// across the synchronous signing loop, never across an await, or the sample
/// stops meaning "how long the signing took" and starts meaning "how long
/// the signing took plus whatever else shared the guard's scope".
pub fn time_signing() -> TimingGuard {
    TimingGuard::new(&SIGNING_DURATION_SECONDS)
}

/// Record how long after a slot's start its attestations were accepted.
pub fn observe_publication_delay(seconds: f64) {
    PUBLICATION_DELAY_SECONDS.observe(seconds);
}

/// A Prometheus endpoint for this process.
///
/// Deliberately not `ethlambda-rpc`'s router: reaching that would put the
/// blockchain and storage crates, and RocksDB with them, on a process that
/// only signs attestations.
pub fn router() -> axum::Router {
    use axum::response::IntoResponse;
    use axum::routing::get;

    async fn serve() -> impl IntoResponse {
        match ethlambda_metrics::gather_default_metrics() {
            Ok(body) => (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; version=0.0.4",
                )],
                body,
            )
                .into_response(),
            Err(err) => {
                tracing::warn!(%err, "Failed to gather metrics");
                axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }

    async fn health() -> impl IntoResponse {
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            r#"{"status":"healthy","service":"ethlambda-validator"}"#,
        )
    }

    axum::Router::new()
        .route("/metrics", get(serve))
        .route("/health", get(health))
}
