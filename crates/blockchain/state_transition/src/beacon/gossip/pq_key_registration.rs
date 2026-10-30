//! Gossip validation for `pq_key_registration` (EIP-8450).
//!
//! The rules are the specification's `validate_pq_key_registration_gossip`, in its order.
//! Several conditions depend on the node's head, which can lag or lead the network.
//! Those are IGNORE rather than REJECT, so an honest peer is never penalized for them.
//!
//! The first-seen record keys on the pair of index and named change epoch.
//! The pair is looked up when the message arrives and judged at the specification's position.
//! So a later REJECT condition still wins over a duplicate.

use super::{IgnoreReason, Outcome, RejectReason, is_future_epoch};
use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::FAR_FUTURE_EPOCH;
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::gloas::BuilderIndex;
use crate::beacon::containers::heze::SignedPQKeyRegistration;
use crate::beacon::helpers::accessors::get_current_epoch;
use crate::beacon::helpers::gloas::{
    convert_validator_index_to_builder_index, is_active_builder, is_builder_index,
};
use crate::beacon::helpers::heze::{
    get_pq_key_registration_signing_root, is_valid_pq_possession_proof,
};
use crate::beacon::preset;

type Verdict = Result<(), Outcome>;

/// The one condition read before the head state: the clock has reached the fork.
///
/// The clock check allows for the gossip clock disparity, as every epoch check here does.
pub fn cheap_checks(config: &Config, now_ms: u64) -> Verdict {
    // [IGNORE] The current epoch is at or after the fork epoch.
    if is_future_epoch(config, config.heze_fork_epoch, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::BeforeFork));
    }
    Ok(())
}

/// The remaining conditions, against the head state as it stands.
///
/// `first_seen` tells whether no valid registration for the pair was accepted before.
pub fn stateful_checks(
    state: &BeaconState,
    signed_registration: &SignedPQKeyRegistration,
    first_seen: bool,
    config: &Config,
    now_ms: u64,
) -> Verdict {
    let registration = &signed_registration.message;
    let key_material = registration.key_material;

    // [IGNORE] The head state is at or after the fork, so it has the registry.
    if get_current_epoch(state) < config.heze_fork_epoch {
        return Err(Outcome::Ignore(IgnoreReason::BeforeFork));
    }
    let Some(registry) = state.pq_registry() else {
        return Err(Outcome::Ignore(IgnoreReason::BeforeFork));
    };

    let (pubkey, entry) = if is_builder_index(registration.index) {
        let builder_index = convert_validator_index_to_builder_index(registration.index);
        let builders = state
            .builders()
            .map_err(|_| Outcome::Ignore(IgnoreReason::BeforeFork))?;
        // [IGNORE] The builder exists in the head state: a recent deposit may not be in every head.
        let Some(builder) = builders.get(builder_index as usize) else {
            return Err(Outcome::Ignore(IgnoreReason::UnknownRegistrant));
        };
        // [REJECT] The builder has not initiated an exit.
        if builder.withdrawable_epoch != FAR_FUTURE_EPOCH {
            return Err(Outcome::Reject(RejectReason::RegistrantExiting));
        }
        // [IGNORE] The builder is active, which depends on the node's view of finality.
        if !is_active_builder(state, builder_index as BuilderIndex).unwrap_or(false) {
            return Err(Outcome::Ignore(IgnoreReason::BuilderNotActive));
        }
        // [REJECT] The builder registers a zero VRF root.
        if !key_material.vrf_root.is_zero() {
            return Err(Outcome::Reject(RejectReason::BuilderVrfRoot));
        }
        let entry = registry
            .builder(builder_index)
            .ok_or(Outcome::Ignore(IgnoreReason::UnknownRegistrant))?;
        (builder.pubkey, entry)
    } else {
        // [IGNORE] The validator exists in the head state: a recent deposit may not be in every head.
        let Ok(validator) = state.validator(registration.index) else {
            return Err(Outcome::Ignore(IgnoreReason::UnknownRegistrant));
        };
        // [REJECT] The validator has not initiated an exit.
        if validator.exit_epoch != FAR_FUTURE_EPOCH {
            return Err(Outcome::Reject(RejectReason::RegistrantExiting));
        }
        let entry = registry
            .validator(registration.index)
            .ok_or(Outcome::Ignore(IgnoreReason::UnknownRegistrant))?;
        (validator.pubkey, entry)
    };

    // [IGNORE] The first valid registration for the pair of index and change epoch.
    if !first_seen {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] The registration names the head's stored change: another head may hold another.
    if registration.previous_change_epoch != entry.change_epoch {
        return Err(Outcome::Ignore(IgnoreReason::ChangeEpochMismatch));
    }
    // [IGNORE] A change of registered keys waits for the delay, by the clock.
    if entry.is_registered() {
        let earliest = registration
            .previous_change_epoch
            .saturating_add(preset::MIN_PQ_KEY_CHANGE_DELAY);
        if is_future_epoch(config, earliest, now_ms) {
            return Err(Outcome::Ignore(IgnoreReason::PqKeyChangeTooSoon));
        }
    }
    // [REJECT] The leanXMSS key is not all-zero.
    let key = key_material.xmss_public_key;
    if key.is_zero() {
        return Err(Outcome::Reject(RejectReason::ZeroPqKey));
    }
    // [IGNORE] No index holds the key in the head state: the holder can differ between heads.
    if registry.is_key_in_use(&key) {
        return Err(Outcome::Ignore(IgnoreReason::PqKeyInUse));
    }
    // [REJECT] The registrant's BLS key signed the registration.
    let genesis_validators_root = state.genesis_validators_root();
    let signing_root =
        get_pq_key_registration_signing_root(genesis_validators_root, registration, config);
    if !bls::verify(&pubkey, signing_root, &signed_registration.signature) {
        return Err(Outcome::Reject(RejectReason::BadSignature));
    }
    // [REJECT] The proof of possession is valid.
    if !is_valid_pq_possession_proof(
        genesis_validators_root,
        &pubkey,
        &key,
        &signed_registration.possession,
        config,
    ) {
        return Err(Outcome::Reject(RejectReason::PossessionProof));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::fork::ForkName;
    use crate::beacon::gossip::slot_start_ms;
    use crate::beacon::helpers::test_state::with_signing_validators_at;
    use crate::beacon::primitives::{Epoch, XmssPublicKey};
    use crate::beacon::stf::heze::process_pq_key_registration;
    use crate::beacon::stf::heze_fixture::{
        BUILDER, EPOCH, config, possession, registration, resign, state,
    };

    /// The clock at the first slot of an epoch.
    fn at_epoch(epoch: Epoch) -> u64 {
        slot_start_ms(&config(), epoch * preset::SLOTS_PER_EPOCH)
    }

    fn check(state: &BeaconState, signed: &SignedPQKeyRegistration, first_seen: bool) -> Verdict {
        stateful_checks(state, signed, first_seen, &config(), at_epoch(EPOCH))
    }

    #[test]
    fn a_valid_first_registration_is_accepted() {
        let state = state();
        let signed = registration(&state, 1, 0, FAR_FUTURE_EPOCH);

        assert_eq!(check(&state, &signed, true), Ok(()));
    }

    #[test]
    fn a_seen_pair_is_ignored_unless_an_earlier_rule_rejects() {
        // Fixture state: a valid registration for the pair (1, far future) was accepted before.
        let state = state();
        let signed = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        assert_eq!(
            check(&state, &signed, false),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );

        // Mutation: validator 1 initiated an exit since.
        // The exit check comes first in the specification, so the duplicate is rejected.
        let mut exiting = state;
        exiting.validator_mut(1).unwrap().exit_epoch = 30;
        assert_eq!(
            check(&exiting, &signed, false),
            Err(Outcome::Reject(RejectReason::RegistrantExiting))
        );
    }

    #[test]
    fn a_pre_fork_head_is_ignored() {
        // Mutation: the head state is gloas, which has no registry.
        let heze = state();
        let signed = registration(&heze, 1, 0, FAR_FUTURE_EPOCH);
        let gloas = with_signing_validators_at(ForkName::Gloas, 4);

        assert_eq!(
            check(&gloas, &signed, true),
            Err(Outcome::Ignore(IgnoreReason::BeforeFork))
        );
    }

    #[test]
    fn an_index_absent_from_the_head_is_ignored() {
        // Mutation: validator index 4, one past the head's registry.
        let state = state();
        let mut signed = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        signed.message.index = 4;

        assert_eq!(
            check(&state, &signed, true),
            Err(Outcome::Ignore(IgnoreReason::UnknownRegistrant))
        );
    }

    #[test]
    fn a_builder_awaiting_finality_is_ignored() {
        // Mutation: the head's finalized epoch is 0, the builder's deposit epoch.
        let mut state = state();
        state.finalized_checkpoint_mut().epoch = 0;
        let signed = registration(&state, BUILDER, 0, 0);

        assert_eq!(
            check(&state, &signed, true),
            Err(Outcome::Ignore(IgnoreReason::BuilderNotActive))
        );
    }

    #[test]
    fn a_change_is_timed_by_the_clock_against_the_named_epoch() {
        // Fixture state: validator 1 registered key 0 at epoch 20.
        let mut state = state();
        let first = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        process_pq_key_registration(&mut state, &first, &config()).unwrap();
        let change = registration(&state, 1, 1, EPOCH);
        let due = EPOCH + preset::MIN_PQ_KEY_CHANGE_DELAY;

        // One epoch before the delay is due, the change is ignored.
        assert_eq!(
            stateful_checks(&state, &change, true, &config(), at_epoch(due - 1)),
            Err(Outcome::Ignore(IgnoreReason::PqKeyChangeTooSoon))
        );
        // At the due epoch it passes, judged on the same head.
        assert_eq!(
            stateful_checks(&state, &change, true, &config(), at_epoch(due)),
            Ok(())
        );
    }

    #[test]
    fn a_stale_change_epoch_is_ignored() {
        // Mutation: the registration names epoch 7, but validator 1 never registered.
        let state = state();
        let signed = resign(&state, registration(&state, 1, 0, 7), 1);

        assert_eq!(
            check(&state, &signed, true),
            Err(Outcome::Ignore(IgnoreReason::ChangeEpochMismatch))
        );
    }

    #[test]
    fn a_held_key_is_ignored_and_a_zero_key_rejected() {
        // Fixture state: validator 1 holds key 0.
        let mut state = state();
        let first = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        process_pq_key_registration(&mut state, &first, &config()).unwrap();

        // Validator 2 registering key 0: another head may not hold it, so ignored.
        let copy = registration(&state, 2, 0, FAR_FUTURE_EPOCH);
        assert_eq!(
            check(&state, &copy, true),
            Err(Outcome::Ignore(IgnoreReason::PqKeyInUse))
        );

        // Mutation: validator 2 registers the all-zero key, invalid on every head.
        let mut zero = registration(&state, 2, 1, FAR_FUTURE_EPOCH);
        zero.message.key_material.xmss_public_key = XmssPublicKey::default();
        let zero = resign(&state, zero, 2);
        assert_eq!(
            check(&state, &zero, true),
            Err(Outcome::Reject(RejectReason::ZeroPqKey))
        );
    }

    #[test]
    fn a_bad_signature_or_proof_is_rejected() {
        let state = state();

        // Mutation: validator 2 signs validator 1's registration.
        let forged = resign(&state, registration(&state, 1, 0, FAR_FUTURE_EPOCH), 2);
        assert_eq!(
            check(&state, &forged, true),
            Err(Outcome::Reject(RejectReason::BadSignature))
        );

        // Mutation: the proof is signed at leaf 1 rather than the reserved leaf 0.
        let mut misplaced = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        misplaced.possession = possession(&state, 1, 0, 1);
        assert_eq!(
            check(&state, &misplaced, true),
            Err(Outcome::Reject(RejectReason::PossessionProof))
        );
    }

    #[test]
    fn the_clock_must_reach_the_fork() {
        // Fixture state: heze scheduled at epoch 5, the clock at epoch 4.
        let mut config = config();
        config.heze_fork_epoch = 5;
        let now = slot_start_ms(&config, 4 * preset::SLOTS_PER_EPOCH);

        assert_eq!(
            cheap_checks(&config, now),
            Err(Outcome::Ignore(IgnoreReason::BeforeFork))
        );
        assert_eq!(
            cheap_checks(&config, slot_start_ms(&config, 5 * preset::SLOTS_PER_EPOCH)),
            Ok(())
        );
    }
}
