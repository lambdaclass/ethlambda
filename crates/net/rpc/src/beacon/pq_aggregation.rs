//! PQ aggregation for this node's validator client.
//!
//! A PQ aggregator proves its committee's signatures instead of aggregating
//! them (PQ `validator.md`, "Aggregate stark"), and proving takes leanVM
//! seconds, too long to run inside the `aggregate_attestation` request. So,
//! as Lighthouse's PQ branch does, the node proves ahead: the validator
//! client names the committees it aggregates for through
//! `beacon_committee_subscriptions`, the node collects their validated votes'
//! signatures ([`ethlambda_storage::pools::PqSignaturePool`]), and proves
//! each committee's at its aggregator's cutoff.
//!
//! The aggregators of a committee are staggered by their seat in its
//! aggregation committee (PQ `validator.md`, "Construct aggregate"): the one
//! at `position` stops collecting at `get_aggregation_cutoff_ms(position)` and
//! broadcasts at `get_aggregate_due_ms(position)`. The task here wakes at
//! each seat's cutoff in turn, proves what was collected for the committees
//! one of this node's validators holds that seat in, and ends the slot's
//! collection after the last seat's. The endpoint then answers with what was
//! proved, and the aggregate also goes into the pool block production packs
//! from, since gossip never hands a node its own messages.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ethlambda_state_transition::beacon::{
    fork_choice::{get_aggregation_cutoff_ms, get_pq_aggregate_due_ms},
    helpers::{
        accessors::CommitteeCacheExt as _,
        pq::{get_aggregation_committee, get_attestation_statements},
    },
};
use ethlambda_storage::{
    Store,
    pools::{CommitteeSignatures, PooledPqAggregate},
};
use ethlambda_types::beacon::{
    config::Config,
    constants::AGGREGATORS_PER_COMMITTEE,
    containers::{BeaconState, pq},
    fork::ForkName,
    primitives::Slot,
    signing::compute_epoch_at_slot,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::beacon::validator::head;

/// Start proving PQ aggregates at every aggregator's cutoff, if the network
/// schedules PQ. Stops with `shutdown`.
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
            for position in 0..AGGREGATORS_PER_COMMITTEE {
                let cutoff =
                    slot_start_ms(&config, slot) + get_aggregation_cutoff_ms(position, &config);
                let wait = Duration::from_millis(cutoff.saturating_sub(now_ms()));
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(wait) => {}
                }
                if config.fork_at_epoch(compute_epoch_at_slot(slot)) == ForkName::Pq {
                    prove_seat(&store, &config, slot, position).await;
                }
            }
            // The last seat's cutoff has passed: nothing more is collected.
            store.pq_signature_pool().seal(slot);
        }
    });
}

/// The committees of `slot` in which one of this node's aggregators holds
/// seat `position` of the aggregation committee, as `state` names them.
fn committees_at_seat(store: &Store, state: &BeaconState, slot: Slot, position: u64) -> Vec<u64> {
    // Bound first, so the pool's lock is not held while committees are read.
    let aggregators = store.pq_signature_pool().aggregators(slot);
    aggregators
        .into_iter()
        .filter(|(committee, validators)| {
            get_aggregation_committee(state, slot, *committee).is_ok_and(|members| {
                members
                    .get(position as usize)
                    .is_some_and(|member| validators.contains(member))
            })
        })
        .map(|(committee, _)| committee)
        .collect()
}

/// Prove what `slot` collected for the committees whose aggregator at
/// `position` is this node's, before that aggregator's broadcast time.
async fn prove_seat(store: &Store, config: &Config, slot: Slot, position: u64) {
    if store.pq_signature_pool().aggregators(slot).is_empty() {
        return;
    }
    let deadline_ms = slot_start_ms(config, slot) + get_pq_aggregate_due_ms(position, config);
    let Some(budget) = deadline_ms.checked_sub(now_ms()).filter(|&left| left > 0) else {
        warn!(%slot, position, "No time left to prove this seat's PQ aggregates");
        return;
    };
    let deadline = Instant::now() + Duration::from_millis(budget);
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
                warn!(%slot, position, ?err, "Could not read the head state to prove this seat's PQ aggregates");
                return;
            }
        };
        let committees = committees_at_seat(&store, &state, slot, position);
        if committees.is_empty() {
            return;
        }
        let state_ms = started.elapsed().as_millis() as u64;
        let mut groups = store.pq_signature_pool().collected(slot, &committees);
        let committees = groups.len();
        let signatures: usize = groups.iter().map(|group| group.signatures.len()).sum();
        // The larger groups first, in case not every one fits before the
        // deadline.
        groups.sort_by_key(|group| std::cmp::Reverse(group.signatures.len()));
        let (mut proved, mut failed, mut late) = (0usize, 0usize, 0usize);
        let mut prove_ms_total = 0u64;
        for group in groups {
            if Instant::now() >= deadline {
                warn!(%slot, position, "The PQ aggregate deadline passed with committees left to prove");
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
                        position,
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
                        position,
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
                        position,
                        signatures = collected,
                        took_ms,
                        %err,
                        "Could not prove a PQ aggregate"
                    );
                }
            }
        }
        // One line for the seat's whole proving pass: what leanVM was asked
        // for, what it cost, and what the budget left undone.
        info!(
            %slot,
            position,
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
            "Finished proving this seat's PQ aggregates"
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
/// slot 0 before genesis, then the wall clock's slot until its last seat's
/// collection cutoff and the next one after it. Taking the wall clock's slot
/// plus one skipped slot 0 on a node started before genesis, whose
/// aggregators' votes were then never proved.
fn next_slot_to_seal(config: &Config, now_ms: u64) -> Slot {
    let genesis_ms = config.genesis_time.saturating_mul(1000);
    let Some(elapsed) = now_ms.checked_sub(genesis_ms) else {
        return 0;
    };
    let slot = elapsed / config.slot_duration_ms.max(1);
    let last_cutoff = slot_start_ms(config, slot)
        + get_aggregation_cutoff_ms(AGGREGATORS_PER_COMMITTEE - 1, config);
    if now_ms < last_cutoff { slot } else { slot + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_seat_proves_between_its_cutoff_and_its_broadcast() {
        let mut config = Config::mainnet();
        config.genesis_time = 100;
        assert_eq!(slot_start_ms(&config, 2), 100_000 + 24_000);
        for position in 0..AGGREGATORS_PER_COMMITTEE {
            let cutoff = get_aggregation_cutoff_ms(position, &config);
            let due = get_pq_aggregate_due_ms(position, &config);
            // 2.4 s to prove on a 12 s slot, whatever the seat.
            assert_eq!(due - cutoff, 2_400);
        }
    }

    #[test]
    fn the_next_slot_to_seal_starts_at_genesis() {
        let mut config = Config::mainnet();
        config.genesis_time = 100;
        // Before genesis: slot 0, whose last seat (3) stops collecting
        // 40% + 3 * 5% of 12 s in, at 6.6 s.
        assert_eq!(next_slot_to_seal(&config, 0), 0);
        assert_eq!(next_slot_to_seal(&config, 99_999), 0);
        assert_eq!(next_slot_to_seal(&config, 106_599), 0);
        assert_eq!(next_slot_to_seal(&config, 106_600), 1);
        // Mid-slot: that slot until its last cutoff, the next one from then on.
        assert_eq!(next_slot_to_seal(&config, 124_000), 2);
        assert_eq!(next_slot_to_seal(&config, 130_599), 2);
        assert_eq!(next_slot_to_seal(&config, 130_600), 3);
        assert_eq!(next_slot_to_seal(&config, 135_999), 3);
    }
}
