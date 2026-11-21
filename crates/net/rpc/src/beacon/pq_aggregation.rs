//! PQ aggregation for this node's validator client.
//!
//! A PQ aggregator proves its committee's signatures instead of aggregating
//! them (PQ `validator.md`, "Aggregate stark"), and proving takes the
//! sidecar seconds, too long to run inside the `aggregate_attestation`
//! request. So, as Lighthouse's PQ branch does, the node proves ahead: the
//! validator client names the committees it aggregates for through
//! `beacon_committee_subscriptions`, the node collects their validated votes'
//! signatures ([`ethlambda_storage::pools::PqSignaturePool`]), and once a slot
//! the task here seals that slot's signatures halfway between the
//! attestation and aggregate deadlines and proves each committee's before the
//! aggregate deadline, largest first. The endpoint then answers with what was
//! proved, and the aggregate also goes into the pool block production packs
//! from, since gossip never hands a node its own messages.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ethlambda_state_transition::beacon::{
    fork_choice::{get_attestation_due_ms, get_slot_component_duration_ms},
    helpers::{accessors::CommitteeCacheExt as _, pq::get_attestation_statements},
};
use ethlambda_storage::{
    Store,
    pools::{CommitteeSignatures, PooledPqAggregate},
};
use ethlambda_types::beacon::{
    config::Config,
    containers::{BeaconState, pq},
    fork::ForkName,
    primitives::Slot,
    signing::compute_epoch_at_slot,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::beacon::validator::head;

/// Start proving PQ aggregates once a slot, if the network schedules PQ.
/// Stops with `shutdown`.
pub(crate) fn spawn(store: Store, shutdown: CancellationToken) {
    let config = store.config();
    if config.fork_epoch(ForkName::Pq) == u64::MAX {
        return;
    }
    tokio::spawn(async move {
        // Never a slot already sealed, even if the wall clock reads a hair
        // short of the cutoff it just slept until.
        let mut next = 0;
        loop {
            let slot = next_slot_to_seal(&config, now_ms()).max(next);
            next = slot + 1;
            let cutoff = collection_cutoff_ms(&config, slot);
            let wait = Duration::from_millis(cutoff.saturating_sub(now_ms()));
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
            if config.fork_at_epoch(compute_epoch_at_slot(slot)) != ForkName::Pq {
                continue;
            }
            prove_slot(&store, &config, slot).await;
        }
    });
}

/// Seal `slot`'s collected signatures and prove what the time to its
/// aggregate deadline allows.
async fn prove_slot(store: &Store, config: &Config, slot: Slot) {
    let groups = store.pq_signature_pool().seal(slot);
    if groups.is_empty() {
        return;
    }
    let deadline_ms = slot_start_ms(config, slot) + aggregate_due_ms(config, slot);
    let Some(budget) = deadline_ms.checked_sub(now_ms()).filter(|&left| left > 0) else {
        warn!(%slot, "No time left to prove this slot's PQ aggregates");
        return;
    };
    let deadline = Instant::now() + Duration::from_millis(budget);
    let committees = groups.len();
    let signatures: usize = groups.iter().map(|group| group.signatures.len()).sum();
    let store = store.clone();
    let spawned = Instant::now();
    let job = tokio::task::spawn_blocking(move || {
        // Time spent waiting for a blocking thread, which comes out of the
        // budget like the proving does.
        let queued_ms = spawned.elapsed().as_millis() as u64;
        let started = Instant::now();
        let state = match head(&store) {
            Ok((_, state)) => state,
            Err(err) => {
                warn!(%slot, ?err, "Could not read the head state to prove this slot's PQ aggregates");
                return;
            }
        };
        let state_ms = started.elapsed().as_millis() as u64;
        let mut groups = groups;
        // The larger groups first, in case not every one fits before the
        // deadline.
        groups.sort_by_key(|group| std::cmp::Reverse(group.signatures.len()));
        let (mut proved, mut failed, mut late) = (0usize, 0usize, 0usize);
        let mut prove_ms_total = 0u64;
        for group in groups {
            if Instant::now() >= deadline {
                warn!(%slot, "The PQ aggregate deadline passed with committees left to prove");
                break;
            }
            let committee = group.committee_index;
            let collected = group.signatures.len();
            let committee_started = Instant::now();
            let result = prove_committee(&store, &state, group);
            let took_ms = committee_started.elapsed().as_millis() as u64;
            match result {
                Ok((aggregate, prove_ms)) if Instant::now() < deadline => {
                    proved += 1;
                    prove_ms_total += prove_ms;
                    info!(
                        %slot,
                        committee,
                        attesters = aggregate.attesting_indices.len(),
                        proof_bytes = aggregate.proof.len(),
                        prove_ms,
                        took_ms,
                        "Proved a PQ aggregate"
                    );
                    store.pq_aggregate_pool().insert((*aggregate).clone());
                    store.pq_signature_pool().insert_proven(aggregate);
                }
                Ok((aggregate, prove_ms)) => {
                    late += 1;
                    prove_ms_total += prove_ms;
                    warn!(
                        %slot,
                        committee,
                        attesters = aggregate.attesting_indices.len(),
                        prove_ms,
                        took_ms,
                        "A PQ aggregate was proved after its deadline"
                    );
                    break;
                }
                Err(err) => {
                    failed += 1;
                    debug!(
                        %slot,
                        committee,
                        signatures = collected,
                        took_ms,
                        %err,
                        "Could not prove a PQ aggregate"
                    );
                }
            }
        }
        // One line for the slot's whole proving pass: what the sidecar was
        // asked for, what it cost, and what the budget left undone.
        info!(
            %slot,
            committees,
            signatures,
            proved,
            failed,
            late,
            unproved = committees - proved - failed - late,
            queued_ms,
            state_ms,
            prove_ms = prove_ms_total,
            took_ms = started.elapsed().as_millis() as u64,
            budget_ms = budget,
            "Finished proving this slot's PQ aggregates"
        );
    });
    let _ = job.await;
}

/// The network aggregate of `group`'s committee and the proof of its
/// signatures, over the committee `state` assigns: bits at the attesters'
/// positions, signatures in committee order, which is the order
/// `get_attestation_statements` lists their keys in.
///
/// Also returns how long the proof itself took, in milliseconds: the rest
/// of the call is reading the committee and assembling the statements.
fn prove_committee(
    store: &Store,
    state: &BeaconState,
    group: CommitteeSignatures,
) -> Result<(Arc<PooledPqAggregate>, u64), String> {
    let committees = store.committee_cache();
    let epoch_committees = committees.committees(state, group.data.target.epoch);
    let committee = epoch_committees
        .committee(group.data.slot, group.committee_index)
        .map_err(|err| err.to_string())?;
    let mut aggregation_bits = pq::AggregationBits::with_length(committee.len());
    let mut attesting_indices = Vec::new();
    let mut signatures = Vec::new();
    for (position, &validator) in committee.iter().enumerate() {
        if let Some(signature) = group.signatures.get(&validator) {
            aggregation_bits
                .set(position, true)
                .map_err(|_| "a position past the committee".to_string())?;
            attesting_indices.push(validator);
            signatures.push(signature.0.to_vec());
        }
    }
    if signatures.is_empty() {
        return Err("no collected signature belongs to the committee".into());
    }
    let mut committee_bits = pq::CommitteeBits::default();
    committee_bits
        .set(group.committee_index as usize, true)
        .map_err(|_| "a committee index past MAX_COMMITTEES_PER_SLOT_PQ".to_string())?;
    let attestation = pq::Attestation {
        aggregation_bits,
        data: group.data,
        committee_bits,
    };
    let statements = get_attestation_statements(state, &attestation, &committees)
        .map_err(|err| err.to_string())?;
    let proving = Instant::now();
    let proof = ethlambda_state_transition::beacon::helpers::pq::prove_aggregates(
        &statements,
        &[signatures],
    )
    .map_err(|err| err.to_string())?;
    let prove_ms = proving.elapsed().as_millis() as u64;
    attesting_indices.sort_unstable();
    let aggregate = Arc::new(PooledPqAggregate {
        attestation,
        committee_index: group.committee_index,
        attesting_indices,
        proof: proof
            .try_into()
            .map_err(|_| "the proof exceeds MAX_STARK_PROOF_SIZE".to_string())?,
    });
    Ok((aggregate, prove_ms))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

fn slot_start_ms(config: &Config, slot: Slot) -> u64 {
    config
        .genesis_time
        .saturating_mul(1000)
        .saturating_add(slot.saturating_mul(config.slot_duration_ms))
}

/// The first slot whose signatures are still being collected at `now_ms`:
/// slot 0 before genesis, then the wall clock's slot until its collection
/// cutoff and the next one after it. Taking the wall clock's slot plus one
/// skipped slot 0 on a node started before genesis, whose aggregators' votes
/// were then never proved.
fn next_slot_to_seal(config: &Config, now_ms: u64) -> Slot {
    let genesis_ms = config.genesis_time.saturating_mul(1000);
    let Some(elapsed) = now_ms.checked_sub(genesis_ms) else {
        return 0;
    };
    let slot = elapsed / config.slot_duration_ms.max(1);
    if now_ms < collection_cutoff_ms(config, slot) {
        slot
    } else {
        slot + 1
    }
}

/// How far into `slot` its aggregates are due.
fn aggregate_due_ms(config: &Config, slot: Slot) -> u64 {
    let gloas_on = config.fork_at_epoch(compute_epoch_at_slot(slot)) >= ForkName::Gloas;
    let basis_points = if gloas_on {
        config.aggregate_due_bps_gloas
    } else {
        config.aggregate_due_bps
    };
    get_slot_component_duration_ms(basis_points, config)
}

/// When `slot`'s signatures stop being collected: halfway from the
/// attestation deadline to the aggregate deadline.
fn collection_cutoff_ms(config: &Config, slot: Slot) -> u64 {
    let attestation_due = get_attestation_due_ms(compute_epoch_at_slot(slot), config);
    let aggregate_due = aggregate_due_ms(config, slot);
    let window = aggregate_due.saturating_sub(attestation_due);
    slot_start_ms(config, slot) + attestation_due + window / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_collected_until_halfway_to_the_aggregate_deadline() {
        let mut config = Config::mainnet();
        config.genesis_time = 100;
        config.gloas_fork_epoch = 0;
        // Gloas timing: attestations at 25% of 12 s, aggregates at 50%.
        assert_eq!(slot_start_ms(&config, 2), 100_000 + 24_000);
        assert_eq!(aggregate_due_ms(&config, 2), 6_000);
        assert_eq!(collection_cutoff_ms(&config, 2), 124_000 + 3_000 + 1_500);
    }

    #[test]
    fn the_next_slot_to_seal_starts_at_genesis() {
        let mut config = Config::mainnet();
        config.genesis_time = 100;
        config.gloas_fork_epoch = 0;
        // Before genesis: slot 0, whose cutoff is 4.5 s into it.
        assert_eq!(next_slot_to_seal(&config, 0), 0);
        assert_eq!(next_slot_to_seal(&config, 99_999), 0);
        assert_eq!(next_slot_to_seal(&config, 104_499), 0);
        assert_eq!(next_slot_to_seal(&config, 104_500), 1);
        // Mid-slot: that slot until its cutoff, the next one from then on.
        assert_eq!(next_slot_to_seal(&config, 124_000), 2);
        assert_eq!(next_slot_to_seal(&config, 128_499), 2);
        assert_eq!(next_slot_to_seal(&config, 128_500), 3);
        assert_eq!(next_slot_to_seal(&config, 135_999), 3);
    }
}
