//! Gossip validation for `voluntary_exit`, `proposer_slashing`,
//! `attester_slashing` and `bls_to_execution_change`.
//!
//! The rules are the specification's `validate_voluntary_exit_gossip`
//! (`phase0/p2p-interface.md`, modified in `deneb/p2p-interface.md` to pin the
//! signature domain to the capella fork version), `validate_proposer_slashing_gossip`,
//! `validate_attester_slashing_gossip` (phase0; electra changes only the
//! `AttesterSlashing` type) and `validate_bls_to_execution_change_gossip`
//! (`capella/p2p-interface.md`), as of consensus-specs v1.7.0-beta.1, which is
//! what the conformance vectors are generated from.
//!
//! Each function splits where the specification first reads `state`:
//! `cheap_checks` is everything before it (the seen records, the clock, and
//! stateless message checks), `stateful_checks` everything from it on. The
//! state is the fork-choice head's post-state, read as it is and never
//! advanced: an operation has no block of its own to name one, and the
//! specification checks it against the head without a slot transition. The
//! rules do not run `process_*`, so they also do not apply a block's own
//! extra conditions (an exit's pending balance, say); block packing filters
//! those.

use std::collections::HashSet;

use ethlambda_types::beacon::containers::capella::SignedBLSToExecutionChange;
use ethlambda_types::beacon::containers::electra::AttesterSlashing;
use ethlambda_types::beacon::containers::shared::{ProposerSlashing, SignedVoluntaryExit};
use ethlambda_types::beacon::operation::BeaconOperation;

use super::{IgnoreReason, Outcome, RejectReason, is_future_epoch};
use crate::beacon::ForkName;
use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::{
    BLS_WITHDRAWAL_PREFIX, DOMAIN_BEACON_PROPOSER, DOMAIN_BLS_TO_EXECUTION_CHANGE,
    DOMAIN_VOLUNTARY_EXIT, FAR_FUTURE_EPOCH,
};
use crate::beacon::containers::BeaconState;
use crate::beacon::fork_choice::Store;
use crate::beacon::hash::hash;
use crate::beacon::helpers::accessors::{get_current_epoch, get_domain};
use crate::beacon::helpers::electra::is_valid_indexed_attestation;
use crate::beacon::helpers::misc::{compute_domain, compute_epoch_at_slot, compute_signing_root};
use crate::beacon::helpers::predicates::{
    is_active_validator, is_slashable_attestation_data, is_slashable_validator,
};
use crate::beacon::primitives::{HashTreeRoot as _, ValidatorIndex};

/// What `voluntary_exit`, `proposer_slashing`, `attester_slashing` and
/// `bls_to_execution_change` have already accepted: the specification's
/// "first valid" records. Recorded only on `Accept`. Never pruned: an entry
/// needs a validator to really exit, be slashed or change credentials, so the
/// sets stay small and are bounded by the registry, and they must outlive the
/// pool so an included operation re-gossiped later is ignored, not rejected.
#[derive(Debug, Default)]
pub struct SeenOperations {
    voluntary_exits: HashSet<ValidatorIndex>,
    proposer_slashings: HashSet<ValidatorIndex>,
    attester_slashed: HashSet<ValidatorIndex>,
    bls_to_execution_changes: HashSet<ValidatorIndex>,
}

/// The indices both of an attester slashing's attestations name: the
/// validators it slashes.
fn slashed_indices(slashing: &AttesterSlashing) -> Vec<ValidatorIndex> {
    let first: HashSet<ValidatorIndex> = slashing
        .attestation_1
        .attesting_indices
        .iter()
        .copied()
        .collect();
    slashing
        .attestation_2
        .attesting_indices
        .iter()
        .copied()
        .filter(|index| first.contains(index))
        .collect()
}

impl SeenOperations {
    /// `false` when the specification's IGNORE condition holds.
    pub fn is_new(&self, operation: &BeaconOperation) -> bool {
        match operation {
            BeaconOperation::VoluntaryExit(exit) => {
                !self.voluntary_exits.contains(&exit.message.validator_index)
            }
            BeaconOperation::ProposerSlashing(slashing) => !self
                .proposer_slashings
                .contains(&slashing.signed_header_1.message.proposer_index),
            BeaconOperation::AttesterSlashing(slashing) => slashed_indices(slashing)
                .iter()
                .any(|index| !self.attester_slashed.contains(index)),
            BeaconOperation::BlsToExecutionChange(change) => !self
                .bls_to_execution_changes
                .contains(&change.message.validator_index),
        }
    }

    /// Record an accepted operation. `false` if another verdict recorded the
    /// same key first (two copies validating at once): the caller then
    /// downgrades its `Accept` to `Ignore(AlreadySeen)`.
    pub fn record(&mut self, operation: &BeaconOperation) -> bool {
        match operation {
            BeaconOperation::VoluntaryExit(exit) => {
                self.voluntary_exits.insert(exit.message.validator_index)
            }
            BeaconOperation::ProposerSlashing(slashing) => self
                .proposer_slashings
                .insert(slashing.signed_header_1.message.proposer_index),
            BeaconOperation::AttesterSlashing(slashing) => {
                // Every index is recorded, so one new index is enough to
                // count as new.
                // An explicit loop rather than `any`, which would short-circuit.
                let mut any_new = false;
                for index in slashed_indices(slashing) {
                    any_new |= self.attester_slashed.insert(index);
                }
                any_new
            }
            BeaconOperation::BlsToExecutionChange(change) => self
                .bls_to_execution_changes
                .insert(change.message.validator_index),
        }
    }
}

/// Everything the specification checks before it reads the head state: the
/// seen records, the clock and the message's own shape. Inline in the p2p
/// actor.
///
/// `Err` carries the verdict; `Ok` sends the operation on to
/// [`stateful_checks`].
pub fn cheap_checks(
    seen: &SeenOperations,
    store: &Store,
    operation: &BeaconOperation,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    match operation {
        BeaconOperation::VoluntaryExit(exit) => {
            // [IGNORE] The first valid exit for the validator.
            if !seen.is_new(operation) {
                return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
            }
            // [IGNORE] The exit's epoch is not in the future.
            if is_future_epoch(&config, exit.message.epoch, now_ms) {
                return Err(Outcome::Ignore(IgnoreReason::FutureEpoch));
            }
        }
        BeaconOperation::ProposerSlashing(slashing) => {
            let header_1 = &slashing.signed_header_1.message;
            let header_2 = &slashing.signed_header_2.message;
            // [IGNORE] The first valid slashing for the proposer.
            if !seen.is_new(operation) {
                return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
            }
            // [REJECT] The header slots, and proposer indices, match, and the
            // headers differ.
            if header_1.slot != header_2.slot
                || header_1.proposer_index != header_2.proposer_index
                || header_1 == header_2
            {
                return Err(Outcome::Reject(RejectReason::InvalidOperation));
            }
        }
        BeaconOperation::AttesterSlashing(slashing) => {
            // [IGNORE] At least one overlapping index is unseen.
            if !seen.is_new(operation) {
                return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
            }
            // [REJECT] The data is a double or surround vote.
            if !is_slashable_attestation_data(
                &slashing.attestation_1.data,
                &slashing.attestation_2.data,
            ) {
                return Err(Outcome::Reject(RejectReason::InvalidOperation));
            }
        }
        BeaconOperation::BlsToExecutionChange(_) => {
            // [IGNORE] The first valid change for the validator.
            if !seen.is_new(operation) {
                return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
            }
            // [IGNORE] The clock has reached the capella fork.
            if is_future_epoch(&config, config.capella_fork_epoch, now_ms) {
                return Err(Outcome::Ignore(IgnoreReason::BeforeFork));
            }
        }
    }
    Ok(())
}

/// The remaining conditions, checked against the head state as it stands
/// (never advanced). Runs on a blocking thread.
///
/// `Ignore(StateUnavailable)` when there is no head state, or when it is not
/// electra or fulu. That is a deliberate deviation: this build only serves
/// electra-shaped operations, where the specification would validate older
/// forks' shapes too.
pub fn stateful_checks(store: &Store, operation: &BeaconOperation) -> Outcome {
    let Some((_slot, head_root)) = store.beacon_head() else {
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
    };
    let Ok(Some(state)) = store.get_state(&head_root) else {
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
    };
    if !matches!(state.fork_name(), ForkName::Electra | ForkName::Fulu) {
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
    }
    let config = store.config();
    let verdict = match operation {
        BeaconOperation::VoluntaryExit(op) => voluntary_exit(&state, op, &config),
        BeaconOperation::ProposerSlashing(op) => proposer_slashing(&state, op),
        BeaconOperation::AttesterSlashing(op) => attester_slashing(&state, op),
        BeaconOperation::BlsToExecutionChange(op) => bls_to_execution_change(&state, op, &config),
    };
    verdict.map_or_else(|outcome| outcome, |()| Outcome::Accept)
}

type Verdict = Result<(), Outcome>;

fn voluntary_exit(state: &BeaconState, signed: &SignedVoluntaryExit, config: &Config) -> Verdict {
    let exit = &signed.message;
    // [REJECT] The validator index is valid.
    let validator = state
        .validator(exit.validator_index)
        .map_err(|_| Outcome::Reject(RejectReason::UnknownValidator))?;
    let current_epoch = get_current_epoch(state);
    // [IGNORE] The validator has not already initiated its exit.
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Err(Outcome::Ignore(IgnoreReason::AlreadyExiting));
    }
    // [REJECT] The validator is active, and has been for long enough.
    if !is_active_validator(validator, current_epoch)
        || current_epoch
            < validator
                .activation_epoch
                .saturating_add(config.shard_committee_period)
    {
        return Err(Outcome::Reject(RejectReason::InvalidOperation));
    }
    // [Modified in Deneb:EIP7044] [REJECT] The signature, under the capella
    // fork version so exits stay valid across forks.
    let domain = compute_domain(
        DOMAIN_VOLUNTARY_EXIT,
        config.capella_fork_version,
        state.genesis_validators_root(),
    );
    let signing_root = compute_signing_root(exit.hash_tree_root(), domain);
    if !bls::verify(&validator.pubkey, signing_root, &signed.signature) {
        return Err(Outcome::Reject(RejectReason::BadSignature));
    }
    Ok(())
}

fn proposer_slashing(state: &BeaconState, slashing: &ProposerSlashing) -> Verdict {
    let proposer_index = slashing.signed_header_1.message.proposer_index;
    // [REJECT] The proposer index is valid.
    let proposer = state
        .validator(proposer_index)
        .map_err(|_| Outcome::Reject(RejectReason::UnknownValidator))?;
    // [REJECT] The proposer is slashable.
    if !is_slashable_validator(proposer, get_current_epoch(state)) {
        return Err(Outcome::Reject(RejectReason::InvalidOperation));
    }
    // [REJECT] Both signatures are valid.
    for signed_header in [&slashing.signed_header_1, &slashing.signed_header_2] {
        let header = &signed_header.message;
        let domain = get_domain(
            state,
            DOMAIN_BEACON_PROPOSER,
            Some(compute_epoch_at_slot(header.slot)),
        );
        let signing_root = compute_signing_root(header.hash_tree_root(), domain);
        if !bls::verify(&proposer.pubkey, signing_root, &signed_header.signature) {
            return Err(Outcome::Reject(RejectReason::BadSignature));
        }
    }
    Ok(())
}

fn attester_slashing(state: &BeaconState, slashing: &AttesterSlashing) -> Verdict {
    // The order differs from the specification's, which interleaves each
    // attestation's checks with its signature check: every condition here is a
    // REJECT, so running the cheap ones first cannot change a verdict, and a
    // forged slashing is rejected before any pairing work.
    let attestations = [&slashing.attestation_1, &slashing.attestation_2];
    let validator_count = state.validator_count() as u64;
    // [REJECT] Every index is a validator.
    if attestations.iter().any(|attestation| {
        attestation
            .attesting_indices
            .iter()
            .any(|index| *index >= validator_count)
    }) {
        return Err(Outcome::Reject(RejectReason::UnknownValidator));
    }
    // [REJECT] Each indexed attestation is non-empty, sorted and unique.
    if attestations.iter().any(|attestation| {
        let indices = &attestation.attesting_indices;
        indices.is_empty() || !indices.windows(2).all(|pair| pair[0] < pair[1])
    }) {
        return Err(Outcome::Reject(RejectReason::InvalidOperation));
    }
    // [REJECT] At least one overlapping validator is slashable.
    let current_epoch = get_current_epoch(state);
    let any_slashable = slashed_indices(slashing).into_iter().any(|index| {
        state
            .validator(index)
            .is_ok_and(|validator| is_slashable_validator(validator, current_epoch))
    });
    if !any_slashable {
        return Err(Outcome::Reject(RejectReason::InvalidOperation));
    }
    // [REJECT] Both aggregate signatures verify.
    if !attestations
        .iter()
        .all(|attestation| is_valid_indexed_attestation(state, attestation))
    {
        return Err(Outcome::Reject(RejectReason::InvalidOperation));
    }
    Ok(())
}

fn bls_to_execution_change(
    state: &BeaconState,
    signed: &SignedBLSToExecutionChange,
    config: &Config,
) -> Verdict {
    let change = &signed.message;
    // [REJECT] The validator index is valid.
    let validator = state
        .validator(change.validator_index)
        .map_err(|_| Outcome::Reject(RejectReason::UnknownValidator))?;
    let credentials = &validator.withdrawal_credentials.0;
    // [REJECT] The validator still has BLS withdrawal credentials, for the
    // change's pubkey.
    if credentials[0] != BLS_WITHDRAWAL_PREFIX
        || credentials[1..] != hash(&change.from_bls_pubkey.0).0[1..]
    {
        return Err(Outcome::Reject(RejectReason::InvalidOperation));
    }
    // [REJECT] The signature, under the genesis fork version.
    let domain = compute_domain(
        DOMAIN_BLS_TO_EXECUTION_CHANGE,
        config.genesis_fork_version,
        state.genesis_validators_root(),
    );
    let signing_root = compute_signing_root(change.hash_tree_root(), domain);
    if !bls::verify(&change.from_bls_pubkey, signing_root, &signed.signature) {
        return Err(Outcome::Reject(RejectReason::BadSignature));
    }
    Ok(())
}

/// Both halves in one call: what the fixture runner and the Beacon API's pool
/// POSTs run, the latter with a fresh seen set.
pub fn validate(
    seen: &SeenOperations,
    store: &Store,
    operation: &BeaconOperation,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(seen, store, operation, now_ms) {
        return outcome;
    }
    stateful_checks(store, operation)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_storage::CacheKey;
    use ethlambda_types::beacon::containers::{capella, electra, shared};

    use super::*;
    use crate::beacon::containers::SignedBeaconBlock;
    use crate::beacon::gossip::test_support::{fulu_parent, slot_start_ms, store};
    use crate::beacon::helpers::test_state::sign_for;
    use crate::beacon::primitives::{BlsSignature, Root};

    fn exit_for(validator_index: ValidatorIndex) -> BeaconOperation {
        BeaconOperation::VoluntaryExit(shared::SignedVoluntaryExit {
            message: shared::VoluntaryExit {
                epoch: 0,
                validator_index,
            },
            signature: BlsSignature::default(),
        })
    }

    fn slashing_over(first: &[u64], second: &[u64]) -> BeaconOperation {
        let indexed = |indices: &[u64]| electra::IndexedAttestation {
            attesting_indices: indices.to_vec().try_into().unwrap(),
            data: Default::default(),
            signature: BlsSignature::default(),
        };
        BeaconOperation::AttesterSlashing(electra::AttesterSlashing {
            attestation_1: indexed(first),
            attestation_2: indexed(second),
        })
    }

    /// A store whose head is a block with `state` as its post-state.
    fn store_with_head(state: crate::beacon::containers::BeaconState) -> Store {
        let mut store = store(0);
        store
            .insert_pending_block(
                Root::ZERO,
                SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
                    message: electra::BeaconBlock {
                        slot: 0,
                        proposer_index: 0,
                        parent_root: Root::ZERO,
                        state_root: Root::ZERO,
                        body: electra::BeaconBlockBody::empty(),
                    },
                    signature: Default::default(),
                }),
            )
            .expect("insert pending block");
        store.cache_state(CacheKey::BlockState(Root::ZERO), Arc::new(state));
        store
    }

    #[test]
    fn a_recorded_exit_is_ignored_on_resubmission() {
        let mut seen = SeenOperations::default();
        let store = store(0);
        let exit = exit_for(3);
        let now = slot_start_ms(&store, 0);
        assert_eq!(cheap_checks(&seen, &store, &exit, now), Ok(()));
        assert!(seen.record(&exit));
        assert_eq!(
            cheap_checks(&seen, &store, &exit, now),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );
        assert!(!seen.record(&exit));
        assert_eq!(cheap_checks(&seen, &store, &exit_for(4), now), Ok(()));
    }

    #[test]
    fn an_attester_slashing_is_ignored_only_when_every_overlap_index_was_seen() {
        let mut seen = SeenOperations::default();
        assert!(seen.record(&slashing_over(&[1, 2, 3], &[2, 3, 4])));
        // Overlap {2, 3}: both seen.
        assert!(!seen.is_new(&slashing_over(&[2, 3, 9], &[2, 3, 10])));
        // Overlap {3, 4}: 4 is new.
        assert!(seen.is_new(&slashing_over(&[3, 4], &[3, 4, 5])));
        // Indices only one side names are not slashed.
        assert!(!seen.is_new(&slashing_over(&[2, 3, 7], &[2, 3])));
    }

    #[test]
    fn a_bls_change_before_capella_is_ignored() {
        let seen = SeenOperations::default();
        let config = crate::beacon::config::Config::mainnet();
        let store = Store::init_beacon(
            Arc::new(ethlambda_storage::backend::InMemoryBackend::new()),
            crate::beacon::gossip::test_support::GENESIS_TIME,
            config.clone(),
            Root::ZERO,
            ethlambda_types::checkpoint::Checkpoint {
                root: Root::ZERO,
                slot: 0,
            },
            0,
        );
        let change = BeaconOperation::BlsToExecutionChange(capella::SignedBLSToExecutionChange {
            message: capella::BLSToExecutionChange {
                validator_index: 1,
                from_bls_pubkey: Default::default(),
                to_execution_address: Default::default(),
            },
            signature: BlsSignature::default(),
        });
        let before = slot_start_ms(&store, 0);
        assert_eq!(
            cheap_checks(&seen, &store, &change, before),
            Err(Outcome::Ignore(IgnoreReason::BeforeFork))
        );
        let at_capella = slot_start_ms(
            &store,
            config.capella_fork_epoch * crate::beacon::preset::SLOTS_PER_EPOCH,
        );
        assert_eq!(cheap_checks(&seen, &store, &change, at_capella), Ok(()));
    }

    #[test]
    fn no_head_state_is_ignored() {
        let store = store(0);
        assert_eq!(
            stateful_checks(&store, &exit_for(0)),
            Outcome::Ignore(IgnoreReason::StateUnavailable)
        );
    }

    #[test]
    fn an_exit_for_an_unknown_validator_is_rejected() {
        let store = store_with_head(fulu_parent(0));
        assert_eq!(
            stateful_checks(&store, &exit_for(1_000)),
            Outcome::Reject(RejectReason::UnknownValidator)
        );
    }

    #[test]
    fn a_validly_signed_exit_is_accepted() {
        let mut state = fulu_parent(0);
        // Past `SHARD_COMMITTEE_PERIOD` epochs since activation.
        let config = crate::beacon::config::Config::mainnet();
        *state.slot_mut() =
            (config.shard_committee_period + 1) * crate::beacon::preset::SLOTS_PER_EPOCH;
        let message = shared::VoluntaryExit {
            epoch: 0,
            validator_index: 2,
        };
        let domain = crate::beacon::helpers::misc::compute_domain(
            crate::beacon::constants::DOMAIN_VOLUNTARY_EXIT,
            config.capella_fork_version,
            state.genesis_validators_root(),
        );
        let signing_root =
            crate::beacon::helpers::misc::compute_signing_root(message.hash_tree_root(), domain);
        state.apply_pending_mutations();
        let store = store_with_head(state);
        let exit = BeaconOperation::VoluntaryExit(shared::SignedVoluntaryExit {
            message,
            signature: sign_for(2, signing_root),
        });
        assert_eq!(stateful_checks(&store, &exit), Outcome::Accept);
    }
}
