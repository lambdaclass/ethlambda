//! Sync committee lookups and signing roots for the gossip rules, the pool and
//! block production.
//!
//! The specification's own helpers (`p2p-interface.md`
//! `get_sync_subcommittee_pubkeys`, `validator.md`
//! `compute_subnets_for_sync_committee`) pick the committee by
//! `state.slot + 1`. These pick it by the *message's* slot instead, and take
//! signing domains from [`Config`]'s fork schedule instead of `state.fork`.
//! When the head state is in the message's period and fork the answers are the
//! specification's; when the head lags across a period or fork boundary the
//! specification would reject honest messages and these do not. See
//! `docs/spec_deviations.md`.

use std::collections::BTreeSet;

use ethlambda_types::beacon::containers::altair::{
    ContributionAndProof, SyncAggregatorSelectionData,
};

pub use super::altair::compute_sync_committee_period;
pub use ethlambda_types::beacon::containers::altair::SYNC_SUBCOMMITTEE_SIZE;

use super::accessors::get_current_epoch;
use super::math::bytes_to_uint64;
use super::misc::{compute_domain, compute_epoch_at_slot, compute_signing_root};
use crate::beacon::config::Config;
use crate::beacon::constants::{
    DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    SYNC_COMMITTEE_SUBNET_COUNT, TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
};
use crate::beacon::containers::{BeaconState, altair::SyncCommittee};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::hash::hash;
use crate::beacon::primitives::{
    BlsPubkey, BlsSignature, Domain, DomainType, HashTreeRoot as _, Root, Slot, ValidatorIndex,
};

/// The committee whose members sign at `slot` (for inclusion at `slot + 1`):
/// `state.current_sync_committee` when the period of `slot + 1`'s epoch is the
/// head's own, `next_sync_committee` when it is the one after, else an error.
/// A pre-altair state has no committee and also errors.
pub fn sync_committee_for_slot(state: &BeaconState, slot: Slot) -> Result<&SyncCommittee> {
    let (current, next) = state.sync_committees()?;
    let signing_period = compute_sync_committee_period(compute_epoch_at_slot(slot + 1));
    let state_period = compute_sync_committee_period(get_current_epoch(state));
    if signing_period == state_period {
        Ok(current)
    } else if signing_period == state_period + 1 {
        Ok(next)
    } else {
        Err(Error::SpecAssert(
            "the state's sync committees cover the slot's period",
        ))
    }
}

/// Every `(subcommittee_index, index_within_subcommittee)` seat `pubkey`
/// holds, ascending. One pass over the committee; repeats are kept, since the
/// committee is drawn with replacement.
pub fn sync_committee_seats(committee: &SyncCommittee, pubkey: &BlsPubkey) -> Vec<(u64, usize)> {
    committee
        .pubkeys
        .iter()
        .enumerate()
        .filter(|(_, candidate)| *candidate == pubkey)
        .map(|(position, _)| {
            (
                (position / SYNC_SUBCOMMITTEE_SIZE) as u64,
                position % SYNC_SUBCOMMITTEE_SIZE,
            )
        })
        .collect()
}

/// `validator.md`'s `compute_subnets_for_sync_committee`, by message slot.
pub fn compute_subnets_for_sync_committee(
    state: &BeaconState,
    slot: Slot,
    validator_index: ValidatorIndex,
) -> Result<BTreeSet<u64>> {
    let committee = sync_committee_for_slot(state, slot)?;
    let pubkey = state.validator(validator_index)?.pubkey;
    Ok(sync_committee_seats(committee, &pubkey)
        .into_iter()
        .map(|(subnet, _)| subnet)
        .collect())
}

/// `p2p-interface.md`'s `get_sync_subcommittee_pubkeys`, by message slot.
pub fn get_sync_subcommittee_pubkeys(
    state: &BeaconState,
    slot: Slot,
    subcommittee_index: u64,
) -> Result<&[BlsPubkey]> {
    verify(
        subcommittee_index < SYNC_COMMITTEE_SUBNET_COUNT as u64,
        "subcommittee_index < SYNC_COMMITTEE_SUBNET_COUNT",
    )?;
    let committee = sync_committee_for_slot(state, slot)?;
    let start = subcommittee_index as usize * SYNC_SUBCOMMITTEE_SIZE;
    Ok(&committee.pubkeys[start..start + SYNC_SUBCOMMITTEE_SIZE])
}

/// `validator.md`'s `is_sync_committee_aggregator`.
pub fn is_sync_committee_aggregator(selection_proof: &BlsSignature) -> bool {
    let modulo = (SYNC_SUBCOMMITTEE_SIZE as u64 / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE).max(1);
    let digest = hash(selection_proof.as_ref());
    bytes_to_uint64(&digest.0[0..8]).is_multiple_of(modulo)
}

/// `get_domain` for a sync committee signature at `slot`, from `config`'s
/// schedule rather than `state.fork`.
pub fn sync_committee_domain(
    config: &Config,
    genesis_validators_root: Root,
    domain_type: DomainType,
    slot: Slot,
) -> Domain {
    let fork = config.fork_at_epoch(compute_epoch_at_slot(slot));
    compute_domain(
        domain_type,
        config.fork_version(fork),
        genesis_validators_root,
    )
}

/// What a sync committee member signs: `beacon_block_root` under
/// `DOMAIN_SYNC_COMMITTEE` at `slot`.
pub fn sync_committee_message_signing_root(
    config: &Config,
    genesis_validators_root: Root,
    slot: Slot,
    beacon_block_root: Root,
) -> Root {
    let domain =
        sync_committee_domain(config, genesis_validators_root, DOMAIN_SYNC_COMMITTEE, slot);
    compute_signing_root(beacon_block_root, domain)
}

/// What an aggregator signs to prove it was selected: a
/// [`SyncAggregatorSelectionData`] under `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF`.
pub fn sync_selection_proof_signing_root(
    config: &Config,
    genesis_validators_root: Root,
    slot: Slot,
    subcommittee_index: u64,
) -> Root {
    let domain = sync_committee_domain(
        config,
        genesis_validators_root,
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        slot,
    );
    let data = SyncAggregatorSelectionData {
        slot,
        subcommittee_index,
    };
    compute_signing_root(data.hash_tree_root(), domain)
}

/// What an aggregator signs over its [`ContributionAndProof`], under
/// `DOMAIN_CONTRIBUTION_AND_PROOF` at the contribution's slot.
pub fn contribution_and_proof_signing_root(
    config: &Config,
    genesis_validators_root: Root,
    message: &ContributionAndProof,
) -> Root {
    let domain = sync_committee_domain(
        config,
        genesis_validators_root,
        DOMAIN_CONTRIBUTION_AND_PROOF,
        message.contribution.slot,
    );
    compute_signing_root(message.hash_tree_root(), domain)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::test_state::{secret_key_for, with_signing_validators_at};
    use crate::beacon::preset;

    /// A fulu state with `validators` signing validators, one epoch in. The
    /// current committee seats validator `position % validators`, the next one
    /// `(position + 1) % validators`, so the two differ at every position.
    pub(crate) fn state_with_committees(validators: usize) -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Fulu, validators);
        let pubkey = |index: usize| BlsPubkey(secret_key_for(index).sk_to_pk().to_bytes());
        let committee = |shift: usize| SyncCommittee {
            pubkeys: (0..preset::SYNC_COMMITTEE_SIZE)
                .map(|position| pubkey((position + shift) % validators))
                .collect::<Vec<_>>()
                .try_into()
                .expect("built at the committee's exact length"),
            aggregate_pubkey: Default::default(),
        };
        let (current, next) = state.sync_committees_mut().expect("fulu has committees");
        *current = committee(0);
        *next = committee(1);
        state.apply_pending_mutations();
        state
    }

    fn last_slot_of_period_zero() -> Slot {
        preset::SLOTS_PER_EPOCH * preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD - 1
    }

    #[test]
    fn the_committee_is_current_within_the_period_and_next_at_its_last_slot() {
        let state = state_with_committees(8);
        let (current, next) = state.sync_committees().unwrap();
        assert_eq!(sync_committee_for_slot(&state, 5).unwrap(), current);
        assert_eq!(
            sync_committee_for_slot(&state, last_slot_of_period_zero() - 1).unwrap(),
            current
        );
        assert_eq!(
            sync_committee_for_slot(&state, last_slot_of_period_zero()).unwrap(),
            next
        );
    }

    #[test]
    fn a_slot_two_periods_ahead_or_a_pre_altair_state_has_no_committee() {
        let state = state_with_committees(8);
        let far = 2 * preset::SLOTS_PER_EPOCH * preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        assert!(sync_committee_for_slot(&state, far).is_err());
        let phase0 = crate::beacon::helpers::test_state::with_validators(4);
        assert!(sync_committee_for_slot(&phase0, 5).is_err());
    }

    #[test]
    fn seats_keep_repeats_and_subnets_deduplicate() {
        let state = state_with_committees(2);
        let committee = sync_committee_for_slot(&state, 5).unwrap();
        let pubkey = state.validator(0).unwrap().pubkey;
        let seats = sync_committee_seats(committee, &pubkey);
        // Validator 0 holds every even position of a committee drawn from two.
        assert_eq!(seats.len(), preset::SYNC_COMMITTEE_SIZE / 2);
        assert_eq!(seats[0], (0, 0));
        assert_eq!(seats[1], (0, 2));
        assert!(seats.windows(2).all(|pair| pair[0] < pair[1]));
        let subnets = compute_subnets_for_sync_committee(&state, 5, 0).unwrap();
        assert_eq!(
            subnets,
            (0..SYNC_COMMITTEE_SUBNET_COUNT as u64).collect::<BTreeSet<_>>()
        );
        assert!(compute_subnets_for_sync_committee(&state, 5, 99).is_err());
    }

    #[test]
    fn a_subcommittee_is_its_slice_of_the_committee() {
        let state = state_with_committees(8);
        let committee = sync_committee_for_slot(&state, 5).unwrap();
        for subcommittee in 0..SYNC_COMMITTEE_SUBNET_COUNT as u64 {
            let start = subcommittee as usize * SYNC_SUBCOMMITTEE_SIZE;
            assert_eq!(
                get_sync_subcommittee_pubkeys(&state, 5, subcommittee).unwrap(),
                &committee.pubkeys[start..start + SYNC_SUBCOMMITTEE_SIZE]
            );
        }
        assert!(get_sync_subcommittee_pubkeys(&state, 5, 4).is_err());
    }

    /// A signature-shaped value whose hash is picked by `seed`.
    fn signature_with(seed: u64) -> BlsSignature {
        let mut bytes = [0u8; 96];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        BlsSignature(bytes)
    }

    #[test]
    fn the_aggregator_modulo_is_sized_from_the_subcommittee_and_read_little_endian() {
        let modulo =
            (SYNC_SUBCOMMITTEE_SIZE as u64 / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE).max(1);
        let mut selected = 0;
        let total = 4000u64;
        for seed in 0..total {
            let signature = signature_with(seed);
            let digest = hash(signature.as_ref());
            let expected = u64::from_le_bytes(digest.0[0..8].try_into().unwrap()) % modulo == 0;
            assert_eq!(is_sync_committee_aggregator(&signature), expected);
            selected += u64::from(expected);
        }
        // About one in `modulo` is selected.
        let expected = total / modulo;
        assert!(
            selected > expected / 2 && selected < expected * 2,
            "{selected}"
        );
    }

    #[test]
    fn the_domain_follows_the_schedule_while_the_state_fork_lags() {
        // Fulu from epoch 10, whatever a state's own `fork` still says.
        let config = Config::mainnet().with_fork_epoch(ForkName::Fulu, 10);
        let gvr = Root::repeat_byte(3);
        let before = sync_committee_domain(
            &config,
            gvr,
            DOMAIN_SYNC_COMMITTEE,
            9 * preset::SLOTS_PER_EPOCH,
        );
        let after = sync_committee_domain(
            &config,
            gvr,
            DOMAIN_SYNC_COMMITTEE,
            10 * preset::SLOTS_PER_EPOCH,
        );
        assert_ne!(before, after);
        assert_eq!(
            after,
            compute_domain(
                DOMAIN_SYNC_COMMITTEE,
                config.fork_version(ForkName::Fulu),
                gvr
            )
        );
        assert_eq!(
            before,
            compute_domain(
                DOMAIN_SYNC_COMMITTEE,
                config.fork_version(config.fork_at_epoch(9)),
                gvr
            )
        );
    }

    #[test]
    fn the_signing_roots_differ_by_object() {
        let config = Config::mainnet();
        let gvr = Root::ZERO;
        let message_root =
            sync_committee_message_signing_root(&config, gvr, 5, Root::repeat_byte(1));
        let selection = sync_selection_proof_signing_root(&config, gvr, 5, 1);
        assert_ne!(message_root, selection);
        assert_ne!(
            selection,
            sync_selection_proof_signing_root(&config, gvr, 5, 2)
        );
    }
}
