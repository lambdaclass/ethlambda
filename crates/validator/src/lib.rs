//! A beacon-chain validator client.
//!
//! It holds BLS keys, learns its duties from a beacon node over the standard
//! REST Beacon API, and signs and submits what those duties call for:
//! attestations, the blocks its validators are scheduled to propose, and the
//! aggregates they are selected to publish. It is beacon-node-agnostic:
//! everything it knows about the chain arrives through the `BeaconNodeApi`
//! trait, so it runs against any conformant node.
//!
//! # Deviations from the specifications
//!
//! This client implements **no slashing protection**. It keeps no durable
//! record of what it has signed, so a restart, or a second instance sharing the
//! same keystores, can double-vote or propose twice for one slot. On a live
//! network either is a slashable offence. This is a deliberate, recorded scope decision, not an oversight;
//! see [`docs/spec_deviations.md`] for the full entry, including what is and is
//! not covered.
//!
//! [`crate::attestation_guard`] and [`crate::proposal_guard`] close the part of
//! this that is reachable within a single run: a backward wall-clock step, or a
//! duty schedule replaced mid-epoch. Both are in-memory only and neither is a
//! substitute for the real thing.
//!
//! [`docs/spec_deviations.md`]: https://github.com/lambdaclass/ethlambda/blob/main/docs/spec_deviations.md
//!
//! The keymanager API is affected by the same decision. Its specification makes
//! `slashing_protection` a required field of the `DELETE /eth/v1/keystores`
//! response, so this implementation returns a well-formed but empty EIP-3076
//! interchange, and accepts and ignores the optional `slashing_protection`
//! field on import.

pub mod aggregation;
pub mod aggregation_selection;
pub mod attestation;
pub mod attestation_guard;
pub mod beacon_node;
pub mod duties;
pub mod error;
pub mod http_api;
pub mod keys;
pub mod metrics;
pub mod payload_attestation;
pub mod proposal;
pub mod proposal_guard;
pub mod proposer_settings;
pub(crate) mod secure_fs;
pub mod signing;
pub mod slot_clock;
pub mod subscriptions;
pub mod sync_committee;

pub use error::{Error, Result};

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, ExecutionAddress, ValidatorIndex};
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

use crate::aggregation::AggregationService;
use crate::attestation::AttestationService;
use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::ProposerPreparationDto;
use crate::beacon_node::fallback::FallbackBeaconNode;
use crate::beacon_node::http::HttpBeaconNode;
use crate::duties::DutiesService;
use crate::keys::ValidatorStore;
use crate::payload_attestation::PayloadAttestationService;
use crate::proposal::ProposalService;
use crate::proposer_settings::ProposerSettings;
use crate::signing::SigningContext;
use crate::slot_clock::SlotClock;
use crate::sync_committee::SyncCommitteeService;

/// Everything the client is configured with at startup.
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub beacon_nodes: Vec<String>,
    pub validators_dir: PathBuf,
    pub secrets_dir: PathBuf,
    pub metrics: std::net::SocketAddr,
    /// The graffiti every validator proposes with unless the keymanager API
    /// gives it its own. Consensus never reads it. An ethlambda beacon node
    /// appends both clients' versions to it; other nodes follow their own
    /// policy.
    pub graffiti: Bytes32,
    /// Where execution-layer block rewards should be paid, for every validator
    /// the keymanager API gives no address of its own.
    ///
    /// `None` when the operator named no address, in which case the beacon node
    /// picks one for those validators, and it will not be the operator's.
    pub suggested_fee_recipient: Option<ExecutionAddress>,
    /// Bind address for the keymanager API. `None` when `--enable-keymanager`
    /// was not passed, in which case it is never spawned.
    pub keymanager: Option<std::net::SocketAddr>,
}

/// Run the validator client until the process is stopped.
pub async fn run(config: ValidatorConfig) -> Result<()> {
    metrics::init();

    // Said once, at startup, before anything is loaded or signed.
    //
    // Until now this client's most consequential property was recorded only in
    // a rustdoc comment on this module, which nobody running a binary reads.
    // An operator can build this, point it at mainnet keys, and never meet the
    // warning. `warn!` rather than `info!` because the consequence is losing
    // stake, and it is unconditional rather than behind a flag because a
    // warning an operator can silence is one they will.
    warn!(
        "This validator client keeps NO slashing-protection record. It cannot detect that a \
         previous run, or another client holding these keys, already signed. Running the same \
         keys here and anywhere else, or restarting into a state where the chain has moved, can \
         produce a slashable double vote or a double block proposal. Do not use these keys in \
         any other client while this one runs. See docs/spec_deviations.md."
    );

    // Said at startup for the same reason the warning above is: an operator
    // who never sets this proposes blocks that pay their execution-layer
    // rewards to whatever address their beacon node was configured with, which
    // on a default configuration is nobody useful. It is silent money, and
    // nothing later in a normal run mentions it again.
    if config.suggested_fee_recipient.is_none() {
        warn!(
            "No --suggested-fee-recipient was set. Any block this client proposes will pay its \
             execution-layer rewards to an address chosen by the beacon node, which is very \
             unlikely to be yours, unless that validator is given its own address through the \
             keymanager API."
        );
    }
    let settings = Arc::new(ProposerSettings::new(
        config.graffiti,
        config.suggested_fee_recipient,
    ));

    let store = ValidatorStore::load(&config.validators_dir)?;
    if store.is_empty() {
        warn!("No validators loaded; the client will idle");
    }
    metrics::set_validators_loaded(store.len() as u64);
    // The keymanager mutates this at runtime while the duty loop reads it, so
    // it is shared rather than owned outright from here on.
    let store = Arc::new(RwLock::new(store));

    // Bound before any beacon-node network call, deliberately: a validator
    // that cannot reach its beacon node still exits (via the `?`s below) if
    // it never gets one, but until then it must expose `/health` and
    // `/metrics`, so an operator can tell "still starting, node unreachable"
    // apart from "crashed with no HTTP surface at all".
    let listener = tokio::net::TcpListener::bind(config.metrics)
        .await
        .map_err(|source| Error::Io {
            path: config.metrics.to_string(),
            source,
        })?;
    info!(address = %config.metrics, "Metrics listening");
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, metrics::router()).await {
            error!(%err, "Metrics server stopped");
        }
    });

    let nodes = config
        .beacon_nodes
        .iter()
        .map(HttpBeaconNode::new)
        .collect::<Result<Vec<_>>>()?;
    let beacon_node = Arc::new(FallbackBeaconNode::new(nodes));

    let genesis = beacon_node.genesis().await?;
    let spec = beacon_node.spec().await?;
    info!(
        genesis_time = genesis.genesis_time,
        slot_duration_ms = spec.slot_duration_ms,
        attestation_due_bps = spec.attestation_due_bps,
        aggregate_due_bps = spec.aggregate_due_bps,
        validators = store.read().await.len(),
        "Validator client starting"
    );

    let clock = SlotClock::from_config(genesis.genesis_time, &spec);
    let context = Arc::new(SigningContext {
        config: spec,
        genesis_validators_root: genesis.genesis_validators_root,
    });

    let mut duties = DutiesService::new(beacon_node.clone(), Vec::new());
    let attestation = AttestationService::new(beacon_node.clone(), context.clone());
    let aggregation = AggregationService::new(beacon_node.clone(), context.clone());
    let payload_attestation = PayloadAttestationService::new(beacon_node.clone(), context.clone());
    let sync_committee = SyncCommitteeService::new(beacon_node.clone(), context.clone());
    let proposal = ProposalService::new(beacon_node.clone(), context.clone(), settings.clone());

    if let Some(address) = config.keymanager {
        let token = http_api::load_or_create_token(&config.validators_dir)?;
        let context = http_api::KeymanagerContext {
            store: store.clone(),
            settings: settings.clone(),
            validators_dir: config.validators_dir.clone(),
            secrets_dir: config.secrets_dir.clone(),
            definitions_lock: Arc::new(Mutex::new(())),
        };
        let router = http_api::router(context, token);
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|source| Error::Io {
                path: address.to_string(),
                source,
            })?;
        info!(%address, "Keymanager API listening");
        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, router).await {
                error!(%err, "Keymanager API stopped");
            }
        });
    }

    let mut last_epoch: Option<u64> = None;
    // The slot whose duties were last attempted, so an overrunning slot does
    // not cost the next one as well. See `SlotClock::next_slot_to_serve`.
    let mut served: Option<u64> = None;

    loop {
        // One wake per slot, at the slot boundary, rather than one at the
        // attester offset.
        //
        // A slot has more than one thing due in it and they are due at
        // different points: a proposer publishes at the boundary, every
        // attester votes one third in. A loop woken only at the attester
        // offset can never propose, because by the time it runs the slot it
        // would be proposing for is already a third gone.
        //
        // Waking at the boundary and sleeping further in reaches both, and
        // gives the epoch refresh below a third of a slot of headroom it did
        // not have when it ran at the attester offset itself, where every
        // second it took came straight out of the attestation's lateness.
        let (slot, delay) = clock.next_slot_to_serve(served, SystemTime::now());
        tokio::time::sleep(delay).await;
        served = Some(slot);

        let epoch = clock.epoch_of(slot);

        if last_epoch != Some(epoch) {
            // Snapshot the pubkeys and let the guard drop right here, before
            // `refresh_epoch`'s awaits (a sync check, two duties fetches, a
            // validator lookup, a subscription POST). Passing the guard
            // itself in used to extend it across that whole call, because
            // `&*store.read().await` as a match scrutinee has its temporary
            // lifetime extended to the entire match. Holding a read lock
            // that long lets the keymanager's write lock
            // (`http_api::keystores::import`, held across slow EIP-2335
            // derivation) queue ahead of it, and since `tokio::sync::RwLock`
            // is write-preferring, every read after that point, including
            // this one next epoch, would starve until the import finished.
            let pubkeys = store.read().await.pubkeys();
            let refreshed = refresh_epoch(
                &beacon_node,
                &mut duties,
                &pubkeys,
                epoch,
                &settings,
                &store,
                &context,
            );
            match refreshed.await {
                Ok(()) => last_epoch = Some(epoch),
                // A beacon node that is down, syncing or answering badly will
                // likely answer next epoch, so keep the schedule already held
                // and try again. Anything else will not fix itself, and looping
                // on it would hide the cause behind a warning every slot.
                Err(err) if err.is_retryable() => {
                    warn!(%epoch, %err, "Failed to refresh duties; keeping the previous schedule");
                    metrics::set_beacon_node_available(false);
                }
                // Unreachable today: every error `refresh_epoch` can produce
                // comes from a `BeaconNodeApi` call, and every variant those
                // raise is classified retryable (see `Error::is_retryable`).
                // Kept rather than deleted, since it is the only thing that
                // would stop the process if a future non-retryable failure
                // (a local config or key problem, say) ever reached this
                // point; do not remove it as unreachable dead code.
                Err(err) => {
                    error!(%epoch, %err, "Cannot refresh duties; stopping");
                    return Err(err);
                }
            }
        }

        // A block is due now, at the boundary this iteration woke on.
        //
        // Cloned out of `duties` so the borrow ends before the await: the duty
        // is three small fields, and holding a borrow of the schedule across
        // the proposal would stop the next epoch's refresh from replacing it.
        if let Some(duty) = duties.proposer_at_slot(slot, epoch).cloned() {
            propose(&proposal, &clock, slot, &duty, &store).await;
        }

        // The rest of the way to the first of the slot's remaining duties:
        // the attester offset, or the sync committee offset when the network
        // puts it earlier. Zero if the refresh or the proposal above already
        // ran past it, in which case the duty is late rather than skipped.
        // Each branch of `serve_slot_duties` waits for its own offset.
        tokio::time::sleep(clock.until_first_slot_duty(slot, SystemTime::now())).await;

        let slot_duties = duties.at_slot(slot, epoch);
        let committee = duties.ptc_at_slot(slot, epoch);
        let sync_duties = duties.sync_at_slot(slot);
        serve_slot_duties(
            &attestation,
            &aggregation,
            &payload_attestation,
            &sync_committee,
            &clock,
            slot,
            &slot_duties,
            &committee,
            &sync_duties,
            &store,
        )
        .await;
    }
}

/// Everything a slot owes after its proposal: attest and aggregate, then the
/// payload timeliness committee vote.
///
/// The two halves are independent on purpose. Committee membership is drawn
/// separately from attester duties, so a client can sit on a slot's committee
/// with no attester duty in it at all, and an early return for "no attester
/// duties" would skip exactly those votes. The committee half is also gated on
/// the slot being a gloas one: before the fork there is no committee and no
/// payload to vote on.
///
/// Three quarters into the slot the committee sleeps until its own deadline,
/// then runs bounded by the end of the slot like the other duties.
#[allow(clippy::too_many_arguments)]
async fn serve_slot_duties<B: BeaconNodeApi>(
    attestation: &AttestationService<B>,
    aggregation: &AggregationService<B>,
    payload_attestation: &PayloadAttestationService<B>,
    sync_committee: &SyncCommitteeService<B>,
    clock: &SlotClock,
    slot: u64,
    slot_duties: &[crate::beacon_node::dto::AttesterDutyDto],
    committee: &[crate::beacon_node::dto::PtcDutyDto],
    sync_duties: &[crate::beacon_node::dto::SyncDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    // The sync committee work runs beside the attester and PTC work rather
    // than after it: its deadline is not ordered against theirs (gloas moves
    // it before the attestation) and each is bounded by the slot on its own.
    let attest_then_ptc = async {
        if !slot_duties.is_empty() {
            tokio::time::sleep(clock.until_attestation(slot, SystemTime::now())).await;
            attest_and_aggregate(attestation, aggregation, clock, slot, slot_duties, store).await;
        }

        if clock.is_gloas(slot) && !committee.is_empty() {
            tokio::time::sleep(clock.until_payload_attestation(slot, SystemTime::now())).await;
            payload_attest(payload_attestation, clock, slot, committee, store).await;
        }
    };
    tokio::join!(
        attest_then_ptc,
        sync_committee_duty(sync_committee, clock, slot, sync_duties, store)
    );
}

/// Run one slot's sync committee duty: sign the head at the message deadline,
/// then aggregate at the contribution deadline if a root was signed.
///
/// Each half is bounded by the end of the slot, like the other duties, and
/// failures are logged and counted rather than propagated. Nothing here is
/// slashable, so abandoning a half costs only that half.
async fn sync_committee_duty<B: BeaconNodeApi>(
    service: &SyncCommitteeService<B>,
    clock: &SlotClock,
    slot: u64,
    duties: &[crate::beacon_node::dto::SyncDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    if duties.is_empty() {
        return;
    }
    tokio::time::sleep(clock.until_sync_message(slot, SystemTime::now())).await;
    let budget = clock.remaining_in(slot, SystemTime::now());
    let root =
        match tokio::time::timeout(budget, service.publish_messages(slot, duties, store)).await {
            Ok(Ok(root)) => root,
            Ok(Err(err)) => {
                error!(%slot, %err, "Failed to publish sync committee messages for this slot");
                metrics::inc_sync_committee_failures();
                metrics::set_beacon_node_available(false);
                return;
            }
            Err(_) => {
                warn!(
                    %slot,
                    budget_ms = budget.as_millis() as u64,
                    "Sync committee messages ran past the end of their slot and were abandoned"
                );
                metrics::inc_sync_committee_failures();
                return;
            }
        };
    let Some(root) = root else {
        return;
    };

    tokio::time::sleep(clock.until_contribution(slot, SystemTime::now())).await;
    let budget = clock.remaining_in(slot, SystemTime::now());
    match tokio::time::timeout(budget, service.aggregate(slot, root, duties, store)).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            error!(%slot, %err, "Failed to publish this slot's sync contributions");
            metrics::inc_sync_contribution_failures();
        }
        Err(_) => {
            warn!(
                %slot,
                budget_ms = budget.as_millis() as u64,
                "Sync aggregation ran past the end of its slot and was abandoned"
            );
            metrics::inc_sync_contribution_failures();
        }
    }
}

/// Run one slot's attestation duty and, when it produced data, the aggregation
/// duty that follows it.
///
/// Split out of the loop so the loop can go on to the payload committee duty
/// whether or not this client has an attester duty in the slot.
async fn attest_and_aggregate<B: BeaconNodeApi>(
    attestation: &AttestationService<B>,
    aggregation: &AggregationService<B>,
    clock: &SlotClock,
    slot: u64,
    slot_duties: &[crate::beacon_node::dto::AttesterDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    // Bound the slot's work by what is left of the slot.
    //
    // Nothing else does. The per-request timeout in `HttpBeaconNode` is 8
    // seconds, failover tries each node in turn, and `attest` makes two
    // calls, so one hung node can carry a 12-second slot's duty well past
    // the slot itself and into the next one, whose duty is then late in
    // turn. An attestation that misses its slot is worth little; one that
    // also delays the next slot's is worth less than nothing.
    //
    // Dropping the future mid-flight is safe here specifically because of
    // `AttestationGuard`: it records at signing time, so a duty abandoned
    // between signing and submission cannot be re-signed next slot under
    // the same target. That is the intended outcome and matches `attest`'s
    // own "do not retry within a slot" rule; the attestation is simply
    // lost.
    let budget = clock.remaining_in(slot, SystemTime::now());
    let attempt = tokio::time::timeout(budget, attestation.attest(slot, slot_duties, store));
    match attempt.await.unwrap_or_else(|_| {
        warn!(
            %slot,
            budget_ms = budget.as_millis() as u64,
            "Attestation duty ran past the end of its slot and was abandoned"
        );
        metrics::inc_attestation_deadline_missed();
        Err(Error::AttestationDeadline { slot })
    }) {
        // `attest` scopes its own read guard away from every await (see
        // its doc comment), so passing the shared `store` straight
        // through here holds nothing across this call.
        Ok(attested) => {
            if attested.published > 0 {
                let elapsed = SystemTime::now()
                    .duration_since(clock.start_of(slot))
                    .unwrap_or_default();
                metrics::observe_publication_delay(elapsed.as_secs_f64());
            }

            // Aggregation, for whichever of this slot's duties this client
            // was selected for.
            //
            // Reached only when the attestation duty produced data, since
            // that data is what names the aggregate to ask for. It is not
            // gated on anything having been *published*, though: an
            // aggregator collects the whole committee's votes, so the duty
            // is still owed when this client's own signatures were refused.
            if let Some(data) = attested.data {
                let delay = clock.until_aggregation(slot, SystemTime::now());
                tokio::time::sleep(delay).await;
                aggregate(aggregation, clock, slot, &data, slot_duties, store).await;
            }
        }
        Err(err) => {
            error!(%slot, %err, "Failed to publish attestations for this slot");
            metrics::inc_attestation_failures();
            // Every error `attest` can return originates from the beacon
            // node (a failed fetch, a bad or mismatched response, a
            // failed submission), so a failure here is exactly the signal
            // this gauge exists for: `refresh_epoch` only runs once an
            // epoch and would otherwise leave it reporting stale
            // availability for up to that long.
            metrics::set_beacon_node_available(false);
        }
    }
}

/// Run one slot's payload timeliness committee duty, bounded by what is left of
/// the slot.
///
/// The budget is the end of the slot, like the aggregation's and for the same
/// reason: this is the last duty in its slot, so the only thing past its
/// deadline is the next slot's work. A vote that arrives after its slot is
/// worthless, since the committee's attestations are only counted for the slot
/// they are about.
///
/// Abandoning it is safe: the service records per validator at signing time, so
/// a duty dropped mid-flight is lost rather than re-signed. Failures are logged
/// and counted rather than propagated, like every other duty's.
async fn payload_attest<B: BeaconNodeApi>(
    service: &PayloadAttestationService<B>,
    clock: &SlotClock,
    slot: u64,
    committee: &[crate::beacon_node::dto::PtcDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    let budget = clock.remaining_in(slot, SystemTime::now());
    let attempt = tokio::time::timeout(budget, service.attest(slot, committee, store));
    match attempt.await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            error!(%slot, %err, "Failed to publish payload attestations for this slot");
            metrics::inc_payload_attestation_failures();
            metrics::set_beacon_node_available(false);
        }
        Err(_) => {
            warn!(
                %slot,
                budget_ms = budget.as_millis() as u64,
                "Payload attestation duty ran past the end of its slot and was abandoned"
            );
            metrics::inc_payload_attestation_failures();
        }
    }
}

/// Run one slot's aggregation, bounded by what is left of the slot.
///
/// # The budget is the end of the slot, not the attester offset
///
/// Looser than the proposal's, because the thing it competes with is different.
/// A proposal that overruns eats into this client's own attestations, which are
/// due for every validator it holds. An aggregation is already the last duty in
/// its slot, so the only thing past its deadline is the next slot's work, and
/// the same budget the attestation gets is the right one.
///
/// Abandoning it is cheap and safe. Nothing here is slashable (see
/// [`crate::aggregation`]), so a dropped future costs one aggregate and
/// nothing else, and other aggregators were selected for the same committee.
///
/// Failures are logged and counted rather than propagated, like the proposal's:
/// one slot's aggregate must not stop the client attesting for the rest of the
/// epoch.
async fn aggregate<B: BeaconNodeApi>(
    aggregation: &AggregationService<B>,
    clock: &SlotClock,
    slot: u64,
    data: &ethlambda_types::beacon::containers::shared::AttestationData,
    duties: &[crate::beacon_node::dto::AttesterDutyDto],
    store: &RwLock<ValidatorStore>,
) {
    let budget = clock.remaining_in(slot, SystemTime::now());
    let attempt = tokio::time::timeout(budget, aggregation.aggregate(slot, data, duties, store));
    match attempt.await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            error!(%slot, %err, "Failed to publish this slot's aggregates");
            metrics::inc_aggregation_failures();
        }
        Err(_) => {
            warn!(
                %slot,
                budget_ms = budget.as_millis() as u64,
                "Aggregation ran past the end of its slot and was abandoned"
            );
            metrics::inc_aggregation_failures();
        }
    }
}

/// Run one slot's proposal, bounded by what is left before the attestation is
/// due.
///
/// Split out of the loop so the deadline's reasoning has somewhere to live, and
/// so the loop body stays readable with two duties in it.
///
/// # The budget is the attester offset, not the end of the slot
///
/// Deliberately tighter than the attestation's own budget. A block published
/// after the attester offset has already lost most of its value, because that
/// is the point at which attesters stop waiting for it and vote for the
/// previous head; the specification defines no block-production deadline of its
/// own, and this is the nearest thing to one that it does define. Meanwhile
/// every second spent here past that point comes straight out of this client's
/// own attestations, which are due for every validator it holds rather than for
/// the one proposing.
///
/// So: a proposal that overruns is abandoned, and the slot's attesters still
/// vote. Dropping the future mid-flight is safe for the same reason it is on
/// the attestation path, and only for that reason: `ProposalService` records
/// the slot in its guard at signing time, so a block abandoned between signing
/// and publication cannot be signed a second time.
///
/// Failures are logged and counted rather than propagated. A proposal is one
/// slot's work; losing it must not stop the client attesting for the rest of
/// the epoch.
async fn propose<B: BeaconNodeApi>(
    proposal: &ProposalService<B>,
    clock: &SlotClock,
    slot: u64,
    duty: &crate::beacon_node::dto::ProposerDutyDto,
    store: &RwLock<ValidatorStore>,
) {
    let budget = clock.until_attestation(slot, SystemTime::now());
    let attempt = tokio::time::timeout(budget, proposal.propose(slot, duty, store));
    match attempt.await {
        Ok(Ok(_)) => {
            let elapsed = SystemTime::now()
                .duration_since(clock.start_of(slot))
                .unwrap_or_default();
            metrics::observe_block_publication_delay(elapsed.as_secs_f64());
        }
        Ok(Err(err)) => {
            error!(%slot, validator = duty.validator_index, %err, "Failed to propose this slot's block");
            metrics::inc_block_proposal_failures();
        }
        Err(_) => {
            warn!(
                %slot,
                validator = duty.validator_index,
                budget_ms = budget.as_millis() as u64,
                "Block proposal ran past the point attesters stop waiting and was abandoned"
            );
            metrics::inc_block_proposal_failures();
        }
    }
}

/// Resolve any newly activated validators, refresh the duty schedule, and
/// re-send subnet subscriptions if it moved.
async fn refresh_epoch<B: BeaconNodeApi>(
    beacon_node: &Arc<B>,
    duties: &mut DutiesService<B>,
    pubkeys: &[BlsPubkey],
    epoch: u64,
    settings: &ProposerSettings,
    store: &RwLock<ValidatorStore>,
    context: &SigningContext,
) -> Result<()> {
    // Nothing to resolve, nothing to schedule, nothing to register. Returning
    // here also keeps an empty pubkey list away from `validator_indices`, whose
    // endpoint reads one as "every validator on the chain".
    if pubkeys.is_empty() {
        return Ok(());
    }

    if beacon_node.is_optimistic_or_syncing().await? {
        return Err(Error::BeaconNodeSyncing);
    }

    // Re-resolved every epoch, not once at startup: a validator can be
    // deposited but not yet activated, in which case it has no index to ask
    // duties for until it is.
    let entries = beacon_node.validator_indices(pubkeys).await?;
    let indices: Vec<ValidatorIndex> = entries.iter().map(|entry| entry.index).collect();
    if indices.len() != pubkeys.len() {
        info!(
            resolved = indices.len(),
            loaded = pubkeys.len(),
            "Some validators have no index yet; they are not active on chain"
        );
    }
    // Kept as a continuously updated gauge, not just the one-shot warning in
    // `DutiesService::refresh` (which only fires once per empty-to-nonempty
    // transition): an operator needs to see "no validator indices resolved"
    // stay visible in monitoring for as long as it is true, not read it off
    // a single log line from whenever it first happened.
    metrics::set_validators_resolved(indices.len() as u64);
    duties.set_indices(indices);

    // Re-sent every epoch, not once at startup, because the node forgets.
    //
    // A preparation is kept for the epoch it arrived in and two more, and is
    // lost entirely when the node restarts. A client that sent this once would
    // stop being registered a few minutes later with nothing reporting it, and
    // would find out only by proposing a block that paid someone else.
    //
    // A failure is logged rather than propagated. The consequence is a payload
    // built for the wrong address, which the check before signing catches; the
    // consequence of returning here would be losing this epoch's attester
    // duties, which is worse and unrelated.
    //
    // Each validator is registered with its own address, and one with none,
    // neither its own nor the default, is left out: there is nothing to tell
    // the node, which then picks one itself, as the startup warning says.
    let preparations: Vec<ProposerPreparationDto> = entries
        .iter()
        .filter_map(|entry| {
            let fee_recipient = settings.fee_recipient(&entry.pubkey)?;
            Some(ProposerPreparationDto {
                validator_index: entry.index,
                fee_recipient: crate::beacon_node::dto::encode_hex(&fee_recipient.0),
            })
        })
        .collect();
    if !preparations.is_empty()
        && let Err(err) = beacon_node.prepare_beacon_proposer(&preparations).await
    {
        warn!(
            %epoch,
            %err,
            "Failed to register this client's fee recipients; blocks proposed this epoch may \
             pay somewhere else"
        );
    }

    let changed = duties.refresh_around(epoch).await?;
    refresh_ptc(duties, epoch, context).await;
    refresh_sync(beacon_node, duties, epoch, context).await;
    metrics::set_duties_held(duties.all().len() as u64);
    if changed {
        subscriptions::subscribe(beacon_node, &duties.all(), store, context).await?;
    }
    metrics::set_beacon_node_available(true);
    Ok(())
}

/// Fetch the payload timeliness committee schedule for this epoch and the next,
/// each only if it is a gloas epoch.
///
/// Gated per epoch rather than once, because the fork can activate between the
/// two: the lookahead is the epoch the first gloas slots belong to when the
/// current one is the last before the fork. A failed fetch is logged and
/// shrugged off, like the proposer and lookahead ones: it must not cost this
/// epoch's attester schedule, which is already in hand.
async fn refresh_ptc<B: BeaconNodeApi>(
    duties: &mut DutiesService<B>,
    epoch: u64,
    context: &SigningContext,
) {
    for target in [epoch, epoch + 1] {
        if context.config.fork_at_epoch(target) < ethlambda_types::beacon::fork::ForkName::Gloas {
            continue;
        }
        if let Err(err) = duties.refresh_ptc(target).await {
            warn!(
                epoch = target,
                %err,
                "Payload committee duties fetch failed; this client may miss its votes"
            );
        }
    }
    duties.prune_ptc_before(epoch);
}

/// How many epochs before a period boundary the next period's subnets are
/// joined: lighthouse's lookahead, at the specification's upper bound
/// `SYNC_COMMITTEE_SUBNET_COUNT` for the random early-join window.
const SYNC_SUBSCRIPTION_LOOKAHEAD_EPOCHS: u64 =
    ethlambda_types::beacon::constants::SYNC_COMMITTEE_SUBNET_COUNT as u64;

/// Fetch the sync committee schedule for this period and the next, and ask the
/// node to join the subnets involved.
///
/// Only from altair. Failures are logged and swallowed, like the payload
/// committee's: they must not cost this epoch's attester schedule.
///
/// Subscriptions are sent every epoch because the node forgets them on
/// restart. The current period's run to its end; the next period's are added
/// once the boundary is within [`SYNC_SUBSCRIPTION_LOOKAHEAD_EPOCHS`], so the
/// subnets are already joined when the new committee starts signing.
async fn refresh_sync<B: BeaconNodeApi>(
    beacon_node: &Arc<B>,
    duties: &mut DutiesService<B>,
    epoch: u64,
    context: &SigningContext,
) {
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD as PERIOD_EPOCHS;

    if context.config.fork_at_epoch(epoch) < ForkName::Altair {
        return;
    }
    let period = crate::duties::sync_committee_period(epoch);
    for target in [period, period + 1] {
        if let Err(err) = duties.refresh_sync(target).await {
            warn!(
                period = target,
                %err,
                "Sync committee duties fetch failed; this client may miss its messages"
            );
        }
    }
    duties.prune_sync_before(period);
    metrics::set_sync_duties_held(duties.sync_for_period(period).len() as u64);

    let current = duties.sync_for_period(period);
    if let Err(err) =
        subscriptions::subscribe_sync(beacon_node, &current, (period + 1) * PERIOD_EPOCHS).await
    {
        warn!(%err, "Failed to subscribe to sync committee subnets");
    }
    if epoch + SYNC_SUBSCRIPTION_LOOKAHEAD_EPOCHS >= (period + 1) * PERIOD_EPOCHS {
        let next = duties.sync_for_period(period + 1);
        if let Err(err) =
            subscriptions::subscribe_sync(beacon_node, &next, (period + 2) * PERIOD_EPOCHS).await
        {
            warn!(%err, "Failed to subscribe to the next period's sync committee subnets");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::ValidatorEntry;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::primitives::{H160, Root};

    fn pubkey(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    /// A node that resolves two validators and has duties for epoch 3, so
    /// `refresh_epoch` gets all the way through to the preparation.
    fn node() -> MockBeaconNode {
        let mut node = MockBeaconNode::new().with_duties(3, Root::repeat_byte(1), Vec::new());
        node = node.with_duties(4, Root::repeat_byte(2), Vec::new());
        node = node.with_proposers(3, Root::repeat_byte(1), Vec::new());
        node.validators = vec![
            ValidatorEntry {
                index: 11,
                pubkey: pubkey(1),
                status: "active_ongoing".to_string(),
            },
            ValidatorEntry {
                index: 22,
                pubkey: pubkey(2),
                status: "active_ongoing".to_string(),
            },
        ];
        node
    }

    fn context() -> SigningContext {
        SigningContext {
            config: ethlambda_types::beacon::config::Config::mainnet(),
            genesis_validators_root: Root::ZERO,
        }
    }

    fn empty_store() -> RwLock<ValidatorStore> {
        RwLock::new(ValidatorStore::new())
    }

    fn settings(fee_recipient: Option<ExecutionAddress>) -> ProposerSettings {
        ProposerSettings::new(Bytes32::ZERO, fee_recipient)
    }

    async fn refresh(node: Arc<MockBeaconNode>, fee_recipient: Option<ExecutionAddress>) {
        refresh_with(node, &settings(fee_recipient)).await;
    }

    async fn refresh_with(node: Arc<MockBeaconNode>, settings: &ProposerSettings) {
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(
            &node,
            &mut duties,
            &keys,
            3,
            settings,
            &empty_store(),
            &context(),
        )
        .await
        .expect("refreshes");
    }

    /// One preparation per resolved validator, every epoch. The node keeps a
    /// preparation for three epochs and forgets all of them on restart, so a
    /// client that sent this once at startup would quietly stop being
    /// registered.
    #[tokio::test]
    async fn every_resolved_validator_is_registered_for_its_fee_recipient() {
        let node = Arc::new(node());
        refresh(node.clone(), Some(H160([0xab; 20]))).await;

        let sent = node.preparations();
        assert_eq!(sent.len(), 2);
        let indices: Vec<u64> = sent.iter().map(|entry| entry.validator_index).collect();
        assert_eq!(indices, vec![11, 22]);
        assert!(
            sent.iter()
                .all(|entry| entry.fee_recipient == format!("0x{}", "ab".repeat(20))),
            "got {sent:?}"
        );
    }

    /// Re-sent, not sent once. Two refreshes must produce two registrations.
    #[tokio::test]
    async fn the_registration_is_repeated_on_every_refresh() {
        let node = Arc::new(node());
        refresh(node.clone(), Some(H160([0xab; 20]))).await;
        refresh(node.clone(), Some(H160([0xab; 20]))).await;
        assert_eq!(node.preparations().len(), 4);
    }

    #[tokio::test]
    async fn no_configured_address_sends_no_registration() {
        let node = Arc::new(node());
        refresh(node.clone(), None).await;
        assert!(node.preparations().is_empty());
    }

    /// A validator's own address is the one registered for it, and the
    /// default still covers the rest.
    #[tokio::test]
    async fn a_validators_own_address_is_registered_for_it() {
        let node = Arc::new(node());
        let settings = settings(Some(H160([0xab; 20])));
        settings.set_fee_recipient(&pubkey(2), H160([0xcd; 20]));
        refresh_with(node.clone(), &settings).await;

        let sent: Vec<(u64, String)> = node
            .preparations()
            .into_iter()
            .map(|entry| (entry.validator_index, entry.fee_recipient))
            .collect();
        assert_eq!(
            sent,
            vec![
                (11, format!("0x{}", "ab".repeat(20))),
                (22, format!("0x{}", "cd".repeat(20))),
            ]
        );
    }

    /// With no default, only the validators given an address of their own are
    /// registered. The others have nothing to tell the node.
    #[tokio::test]
    async fn without_a_default_only_validators_with_their_own_address_are_registered() {
        let node = Arc::new(node());
        let settings = settings(None);
        settings.set_fee_recipient(&pubkey(1), H160([0xcd; 20]));
        refresh_with(node.clone(), &settings).await;

        let sent = node.preparations();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].validator_index, 11);
        assert_eq!(sent[0].fee_recipient, format!("0x{}", "cd".repeat(20)));
    }

    /// A failed registration must not cost this epoch's duties. The
    /// consequence of the failure is a payload built for the wrong address,
    /// which the check before signing catches; the consequence of propagating
    /// it would be attesting on last epoch's schedule, which is worse and
    /// unrelated.
    #[tokio::test]
    async fn a_failed_registration_does_not_fail_the_refresh() {
        let node = Arc::new(node().failing_call("prepare_beacon_proposer", "node is unhappy"));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];

        refresh_epoch(
            &node,
            &mut duties,
            &keys,
            3,
            &settings(Some(H160([0xab; 20]))),
            &empty_store(),
            &context(),
        )
        .await
        .expect("the refresh must survive a failed registration");
        assert_eq!(duties.indices(), &[11, 22]);
    }

    /// A client with no keys must not ask the beacon node anything.
    ///
    /// The validators endpoint reads an empty id list as "return every
    /// validator", which on mainnet is millions of entries, fetched every
    /// epoch, and then fed straight into the attester-duties request. A keyless
    /// client is a supported state, so this is reachable by simply starting one
    /// with an empty validators directory.
    #[tokio::test]
    async fn a_client_with_no_keys_asks_the_node_for_nothing() {
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), Vec::new());

        refresh_epoch(
            &node,
            &mut duties,
            &[],
            3,
            &settings(Some(H160([0xab; 20]))),
            &empty_store(),
            &context(),
        )
        .await
        .expect("a keyless client idles rather than failing");

        assert_eq!(
            node.validator_indices_call_count(),
            0,
            "an empty id list means every validator on the chain; it must never be sent"
        );
        assert_eq!(node.duties_call_count(), 0);
        assert!(node.preparations().is_empty());
    }

    /// And the implementations answer an empty request themselves, so a caller
    /// that reaches them directly cannot make the same mistake.
    #[tokio::test]
    async fn an_empty_pubkey_list_resolves_to_no_validators() {
        let node = node();
        let resolved = node
            .validator_indices(&[])
            .await
            .expect("an empty request is not an error");
        assert!(
            resolved.is_empty(),
            "the answer to 'resolve nothing' is nothing, not everything"
        );
    }

    /// With nothing resolved there is nobody to register, and an empty array
    /// must not be posted: it is a request that can only fail or do nothing.
    #[tokio::test]
    async fn nothing_is_registered_when_no_validator_resolved() {
        let mut bare = MockBeaconNode::new().with_duties(3, Root::repeat_byte(1), Vec::new());
        bare = bare.with_duties(4, Root::repeat_byte(2), Vec::new());
        bare = bare.with_proposers(3, Root::repeat_byte(1), Vec::new());
        let node = Arc::new(bare);

        refresh(node.clone(), Some(H160([0xab; 20]))).await;
        assert!(node.preparations().is_empty());
    }

    // ---- gloas ----------------------------------------------------------

    fn gloas_context(epoch: u64) -> SigningContext {
        SigningContext {
            config: ethlambda_types::beacon::config::Config::mainnet()
                .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Gloas, epoch),
            genesis_validators_root: Root::ZERO,
        }
    }

    fn ptc_duty(index: u64, slot: u64) -> crate::beacon_node::dto::PtcDutyDto {
        crate::beacon_node::dto::PtcDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&[0u8; 48]),
            validator_index: index,
            slot,
        }
    }

    /// The committee schedule is fetched for gloas epochs only, so a chain that
    /// has not forked is never asked, and the lookahead is gated on its own
    /// epoch: the last pre-gloas epoch looks ahead into the first gloas one.
    #[tokio::test]
    async fn the_committee_schedule_is_fetched_for_gloas_epochs_only() {
        let node = Arc::new(
            node()
                .with_ptc_duties(4, Root::repeat_byte(1), vec![ptc_duty(11, 130)])
                .with_ptc_duties(5, Root::repeat_byte(1), Vec::new()),
        );
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];

        // Epoch 3 is the last before gloas at epoch 4: only the lookahead asks.
        node.set_duties(3, Root::repeat_byte(1), Vec::new());
        refresh_epoch(
            &node,
            &mut duties,
            &keys,
            3,
            &settings(None),
            &empty_store(),
            &gloas_context(4),
        )
        .await
        .expect("refreshes");
        assert_eq!(
            node.ptc_call_count(),
            1,
            "only epoch 4, the first gloas one"
        );
        assert_eq!(duties.ptc_at_slot(130, 4).len(), 1);

        // A chain with no gloas scheduled is never asked at all.
        let node = Arc::new(node_without_ptc());
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        refresh_epoch(
            &node,
            &mut duties,
            &keys,
            3,
            &settings(None),
            &empty_store(),
            &context(),
        )
        .await
        .expect("refreshes");
        assert_eq!(node.ptc_call_count(), 0);
    }

    fn node_without_ptc() -> MockBeaconNode {
        node()
    }

    /// A failed committee fetch must not cost the epoch's attester schedule.
    #[tokio::test]
    async fn a_failed_committee_fetch_does_not_fail_the_refresh() {
        let node = Arc::new(node().failing_call("ptc_duties", "node is unhappy"));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(
            &node,
            &mut duties,
            &keys,
            3,
            &settings(None),
            &empty_store(),
            &gloas_context(0),
        )
        .await
        .expect("the refresh survives it");
        assert_eq!(duties.indices(), &[11, 22]);
    }

    /// The restructured loop: a client on a slot's committee with no attester
    /// duty at all must still vote. This is the case the old early `continue`
    /// on "no attester duties" would have skipped.
    #[tokio::test]
    async fn a_committee_member_with_no_attester_duty_still_votes() {
        use crate::beacon_node::mock::MockBeaconNode;
        use ethlambda_types::beacon::containers::gloas::PayloadAttestationData;

        let mut config = ethlambda_types::beacon::config::Config::mainnet()
            .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Gloas, 0);
        config.slot_duration_ms = 1_000;
        let context = Arc::new(SigningContext {
            config: config.clone(),
            genesis_validators_root: Root::ZERO,
        });
        let now_secs = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        let clock = SlotClock::from_config(now_secs - 100, &config);
        let slot = clock.now().expect("after genesis") + 1;

        let mut store = ValidatorStore::new();
        let secret: [u8; 32] =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .expect("hex")
                .try_into()
                .expect("32 bytes");
        let key = store.insert_secret("test", &secret).expect("inserts");
        let store = RwLock::new(store);

        let node = Arc::new(MockBeaconNode::new().with_payload_attestation_data(
            PayloadAttestationData {
                beacon_block_root: Root::repeat_byte(5),
                slot,
                payload_present: true,
                blob_data_available: true,
            },
        ));
        let committee = [crate::beacon_node::dto::PtcDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&key.0),
            validator_index: 3,
            slot,
        }];

        serve_slot_duties(
            &AttestationService::new(node.clone(), context.clone()),
            &AggregationService::new(node.clone(), context.clone()),
            &PayloadAttestationService::new(node.clone(), context.clone()),
            &SyncCommitteeService::new(node.clone(), context.clone()),
            &clock,
            slot,
            &[],
            &committee,
            &[],
            &store,
        )
        .await;

        assert_eq!(node.attestation_data_call_count(), 0, "no attester duty");
        assert_eq!(node.submitted_payload_attestations().len(), 1);
    }

    fn altair_context() -> SigningContext {
        SigningContext {
            config: ethlambda_types::beacon::config::Config::mainnet()
                .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Altair, 0),
            genesis_validators_root: Root::ZERO,
        }
    }

    fn sync_duty(index: u64, seats: Vec<u64>) -> crate::beacon_node::dto::SyncDutyDto {
        crate::beacon_node::dto::SyncDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&[0u8; 48]),
            validator_index: index,
            validator_sync_committee_indices: seats,
        }
    }

    /// Both periods' duties are fetched, and the current period's subnets are
    /// subscribed every refresh, to the period's end.
    #[tokio::test]
    async fn sync_duties_for_both_periods_are_fetched_and_subscribed() {
        use ethlambda_types::beacon::preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD as PERIOD;

        let node = Arc::new(
            node()
                .with_sync_duties(0, vec![sync_duty(11, vec![3, 130])])
                .with_sync_duties(PERIOD, vec![sync_duty(11, vec![200])]),
        );
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        for _ in 0..2 {
            refresh_epoch(
                &node,
                &mut duties,
                &keys,
                3,
                &settings(None),
                &empty_store(),
                &altair_context(),
            )
            .await
            .expect("refreshes");
        }

        let requested: Vec<u64> = node
            .sync_duty_requests()
            .iter()
            .map(|(epoch, _)| *epoch)
            .collect();
        assert_eq!(requested, vec![0, PERIOD, 0, PERIOD]);
        assert_eq!(duties.sync_for_period(1).len(), 1);

        let sent = node.sync_subscriptions();
        assert_eq!(sent.len(), 2, "re-sent every epoch, current period only");
        assert_eq!(sent[0].sync_committee_indices, vec![3, 130]);
        assert_eq!(sent[0].until_epoch, PERIOD);
    }

    /// Not asked before altair.
    #[tokio::test]
    async fn no_sync_duties_are_fetched_before_altair() {
        let node = Arc::new(node());
        refresh(node.clone(), None).await;
        assert!(node.sync_duty_requests().is_empty());
    }

    /// A failed sync fetch must not cost the epoch's attester schedule.
    #[tokio::test]
    async fn a_failed_sync_fetch_does_not_fail_the_refresh() {
        let node = Arc::new(node().failing_call("sync_duties", "node is unhappy"));
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(
            &node,
            &mut duties,
            &keys,
            3,
            &settings(None),
            &empty_store(),
            &altair_context(),
        )
        .await
        .expect("the refresh survives it");
        assert_eq!(duties.indices(), &[11, 22]);
    }

    /// A sync committee member with no other duty in the slot still signs.
    #[tokio::test]
    async fn a_sync_committee_member_with_no_other_duty_still_signs() {
        use crate::beacon_node::mock::MockBeaconNode;

        let mut config = ethlambda_types::beacon::config::Config::mainnet()
            .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Altair, 0);
        config.slot_duration_ms = 1_000;
        let context = Arc::new(SigningContext {
            config: config.clone(),
            genesis_validators_root: Root::ZERO,
        });
        let now_secs = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        let clock = SlotClock::from_config(now_secs - 100, &config);
        let slot = clock.now().expect("after genesis") + 1;

        let mut store = ValidatorStore::new();
        let secret: [u8; 32] =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .expect("hex")
                .try_into()
                .expect("32 bytes");
        let key = store.insert_secret("test", &secret).expect("inserts");
        let store = RwLock::new(store);

        let node = Arc::new(MockBeaconNode::new().with_head_root(Root::repeat_byte(5)));
        let duties = [crate::beacon_node::dto::SyncDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&key.0),
            validator_index: 3,
            validator_sync_committee_indices: vec![0],
        }];

        serve_slot_duties(
            &AttestationService::new(node.clone(), context.clone()),
            &AggregationService::new(node.clone(), context.clone()),
            &PayloadAttestationService::new(node.clone(), context.clone()),
            &SyncCommitteeService::new(node.clone(), context.clone()),
            &clock,
            slot,
            &[],
            &[],
            &duties,
            &store,
        )
        .await;

        assert_eq!(node.attestation_data_call_count(), 0, "no attester duty");
        let sent = node.submitted_sync_messages();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].slot, slot);
        assert_eq!(sent[0].beacon_block_root, Root::repeat_byte(5));
    }

    /// Before gloas there is no committee: even a stale schedule entry is not
    /// acted on.
    #[tokio::test]
    async fn no_committee_vote_is_cast_before_gloas() {
        use crate::beacon_node::mock::MockBeaconNode;

        let config = ethlambda_types::beacon::config::Config::mainnet();
        let context = Arc::new(SigningContext {
            config: config.clone(),
            genesis_validators_root: Root::ZERO,
        });
        let clock = SlotClock::from_config(0, &config);
        let node = Arc::new(MockBeaconNode::new());
        let store = empty_store();

        serve_slot_duties(
            &AttestationService::new(node.clone(), context.clone()),
            &AggregationService::new(node.clone(), context.clone()),
            &PayloadAttestationService::new(node.clone(), context.clone()),
            &SyncCommitteeService::new(node.clone(), context.clone()),
            &clock,
            5,
            &[],
            &[ptc_duty(3, 5)],
            &[],
            &store,
        )
        .await;
        assert_eq!(node.payload_attestation_data_call_count(), 0);
    }
}
