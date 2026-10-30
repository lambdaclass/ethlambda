//! Heze's post-quantum key registrations (EIP-8450).
//!
//! A registration names a validator or a builder by index, and carries new keys.
//! The registrant's BLS signing key authorizes it, and a leanXMSS proof shows the key is held.
//! Changes of registered keys are rate-limited, and each names the change it replaces.

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::FAR_FUTURE_EPOCH;
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::gloas::BuilderIndex;
use crate::beacon::containers::heze::SignedPQKeyRegistration;
use crate::beacon::containers::pq_registry::PqEntry;
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::get_current_epoch;
use crate::beacon::helpers::gloas::{
    convert_validator_index_to_builder_index, is_active_builder, is_builder_index,
};
use crate::beacon::helpers::heze::{
    get_pq_key_registration_signing_root, is_valid_pq_possession_proof,
};
use crate::beacon::preset;
use crate::beacon::primitives::{BlsPubkey, ValidatorIndex, VrfRoot};

/// The name every failure of this module reports.
const FUNCTION: &str = "process_pq_key_registration";

/// Who a registration is for: the flag bit of its index tells a builder from a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Registrant {
    Validator(ValidatorIndex),
    Builder(BuilderIndex),
}

impl Registrant {
    /// Decodes a registration's index, as builder withdrawals do (EIP-7732).
    fn from_index(index: ValidatorIndex) -> Self {
        if is_builder_index(index) {
            Self::Builder(convert_validator_index_to_builder_index(index))
        } else {
            Self::Validator(index)
        }
    }
}

/// Registers keys for a validator or builder without any, or replaces registered ones.
///
/// It refuses, in order:
///
/// - an index past its registry, an exiting validator, or a builder not yet active;
/// - a builder registering a nonzero VRF root, since builders make no selection proofs;
/// - a registration naming another change than the stored one, which blocks replays;
/// - a change sooner than the delay after the last one;
/// - a BLS signature that is not the registrant's;
/// - the all-zero key, a key any index holds, or an invalid proof of possession.
///
/// See `process_pq_key_registration` in EIP-8450.
pub fn process_pq_key_registration(
    state: &mut BeaconState,
    signed_registration: &SignedPQKeyRegistration,
    config: &Config,
) -> Result<()> {
    let registration = &signed_registration.message;
    let key_material = registration.key_material;
    let registrant = Registrant::from_index(registration.index);
    let (pubkey, entry) = registrant_entry(state, registrant, key_material.vrf_root)?;

    // Replay protection: a registration applies only to the entry it names.
    verify(
        registration.previous_change_epoch == entry.change_epoch,
        "process_pq_key_registration: registration.previous_change_epoch == last_change_epoch",
    )?;
    // Changes of registered keys are rate-limited.
    let current_epoch = get_current_epoch(state);
    if entry.is_registered() {
        let earliest = entry
            .change_epoch
            .checked_add(preset::MIN_PQ_KEY_CHANGE_DELAY)
            .ok_or(Error::ArithmeticOverflow(
                "process_pq_key_registration: last_change_epoch + MIN_PQ_KEY_CHANGE_DELAY",
            ))?;
        verify(
            current_epoch >= earliest,
            "process_pq_key_registration: get_current_epoch(state) >= last_change_epoch + MIN_PQ_KEY_CHANGE_DELAY",
        )?;
    }

    // Authorization by the registrant's BLS signing key.
    let genesis_validators_root = state.genesis_validators_root();
    let signing_root =
        get_pq_key_registration_signing_root(genesis_validators_root, registration, config);
    verify(
        bls::verify(&pubkey, signing_root, &signed_registration.signature),
        "process_pq_key_registration: bls.Verify(pubkey, signing_root, signed_registration.signature)",
    )?;

    // A new leanXMSS key, whose possession is proven.
    let key = key_material.xmss_public_key;
    verify(
        !key.is_zero(),
        "process_pq_key_registration: key_material.xmss_public_key != XMSSPublicKey()",
    )?;
    let registry = state
        .pq_registry()
        .ok_or_else(|| unsupported(state, FUNCTION))?;
    verify(
        !registry.is_key_in_use(&key),
        "process_pq_key_registration: not is_pq_public_key_in_use(state, key_material.xmss_public_key)",
    )?;
    verify(
        is_valid_pq_possession_proof(
            genesis_validators_root,
            &pubkey,
            &key,
            &signed_registration.possession,
            config,
        ),
        "process_pq_key_registration: is_valid_pq_possession_proof(state, pubkey, key_material.xmss_public_key, signed_registration.possession)",
    )?;

    // The change is stamped with the current epoch, never a registrant's marker.
    let fork = state.fork_name();
    let mut registry = state.pq_registry_mut().ok_or(Error::UnsupportedForFork {
        function: FUNCTION,
        fork,
    })?;
    match registrant {
        Registrant::Validator(index) => registry.set_validator(index, key_material, current_epoch),
        Registrant::Builder(index) => registry.set_builder(index, key_material, current_epoch),
    }
}

/// The registrant's BLS public key and registry entry, once it may register.
///
/// A validator must exist and not have initiated an exit.
/// A builder must exist and be active, so its deposit epoch is finalized, and register no VRF root.
fn registrant_entry(
    state: &BeaconState,
    registrant: Registrant,
    vrf_root: VrfRoot,
) -> Result<(BlsPubkey, PqEntry)> {
    let registry = state
        .pq_registry()
        .ok_or_else(|| unsupported(state, FUNCTION))?;
    match registrant {
        Registrant::Builder(index) => {
            let builders = state.builders()?;
            verify(
                index < builders.len() as BuilderIndex,
                "process_pq_key_registration: builder_index < len(state.builders)",
            )?;
            verify(
                is_active_builder(state, index)?,
                "process_pq_key_registration: is_active_builder(state, builder_index)",
            )?;
            verify(
                vrf_root.is_zero(),
                "process_pq_key_registration: key_material.vrf_root == VRFRoot()",
            )?;
            let pubkey = builders[index as usize].pubkey;
            // Invariant: the builder lists stay as long as the builder registry.
            let entry = registry.builder(index).ok_or(Error::IndexOutOfBounds {
                index: index as usize,
                len: builders.len(),
            })?;
            Ok((pubkey, entry))
        }
        Registrant::Validator(index) => {
            verify(
                index < state.validator_count() as u64,
                "process_pq_key_registration: validator_index < len(state.validators)",
            )?;
            let validator = state.validator(index)?;
            verify(
                validator.exit_epoch == FAR_FUTURE_EPOCH,
                "process_pq_key_registration: state.validators[validator_index].exit_epoch == FAR_FUTURE_EPOCH",
            )?;
            // Invariant: the validator lists stay as long as the validator registry.
            let entry = registry.validator(index).ok_or(Error::IndexOutOfBounds {
                index: index as usize,
                len: state.validator_count(),
            })?;
            Ok((validator.pubkey, entry))
        }
    }
}

/// The error for a state without a key registry: a fork before heze.
fn unsupported(state: &BeaconState, function: &'static str) -> Error {
    Error::UnsupportedForFork {
        function,
        fork: state.fork_name(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::constants::PQ_POSSESSION_XMSS_INDEX;
    use crate::beacon::containers::gloas::Builder;
    use crate::beacon::containers::heze::PQKeyMaterial;
    use crate::beacon::containers::pq_registry::PqEntry;
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::gloas::add_builder_to_registry;
    use crate::beacon::helpers::test_state::with_signing_validators_at;
    use crate::beacon::primitives::{ExecutionAddress, XmssPublicKey};
    use crate::beacon::stf::heze_fixture::{
        BUILDER, BUILDER_SIGNER, EPOCH, config, key_material, possession, registration, resign,
        state,
    };

    fn register(state: &mut BeaconState, signed: &SignedPQKeyRegistration) -> Result<()> {
        process_pq_key_registration(state, signed, &config())
    }

    /// Asserts the registration failed the named specification assertion.
    fn assert_refused(result: Result<()>, expected: &str) {
        assert!(
            matches!(&result, Err(Error::SpecAssert(message)) if *message == expected),
            "expected {expected:?}, got {result:?}"
        );
    }

    fn entry(state: &BeaconState, index: ValidatorIndex) -> PqEntry {
        state.pq_registry().unwrap().registrant(index).unwrap()
    }

    #[test]
    fn a_first_registration_stores_the_keys_and_the_current_epoch() {
        // Fixture state: validator 1 has the unset entry, epoch 20.
        let mut state = state();
        let signed = registration(&state, 1, 0, FAR_FUTURE_EPOCH);

        register(&mut state, &signed).unwrap();

        assert_eq!(
            entry(&state, 1),
            PqEntry {
                key_material: key_material(1, 0),
                change_epoch: EPOCH,
            }
        );
    }

    #[test]
    fn an_active_builder_registers_a_key_with_a_zero_vrf_root() {
        // Fixture state: builder 0, deposited at epoch 0, finalized past it.
        // Its never-registered marker is that deposit epoch.
        let mut state = state();
        let signed = registration(&state, BUILDER, 0, 0);

        register(&mut state, &signed).unwrap();

        assert_eq!(
            entry(&state, BUILDER),
            PqEntry {
                key_material: key_material(BUILDER, 0),
                change_epoch: EPOCH,
            }
        );
    }

    #[test]
    fn a_builder_registering_a_vrf_root_is_refused() {
        // Mutation: the builder's registration carries a nonzero VRF root.
        let mut state = state();
        let mut signed = registration(&state, BUILDER, 0, 0);
        signed.message.key_material.vrf_root = VrfRoot::repeat_byte(1);
        let signed = resign(&state, signed, BUILDER_SIGNER);

        assert_refused(
            register(&mut state, &signed),
            "process_pq_key_registration: key_material.vrf_root == VRFRoot()",
        );
    }

    #[test]
    fn a_builder_whose_deposit_is_not_finalized_is_refused() {
        // Mutation: the finalized epoch drops to 0, the builder's deposit epoch.
        let mut state = state();
        state.finalized_checkpoint_mut().epoch = 0;
        let signed = registration(&state, BUILDER, 0, 0);

        assert_refused(
            register(&mut state, &signed),
            "process_pq_key_registration: is_active_builder(state, builder_index)",
        );
    }

    #[test]
    fn an_applied_registration_cannot_be_replayed() {
        // Fixture state: validator 1 registered key 0, naming the never-registered marker.
        let mut state = state();
        let signed = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        register(&mut state, &signed).unwrap();

        // The same bytes again name the marker, but the stored change is now epoch 20.
        assert_refused(
            register(&mut state, &signed),
            "process_pq_key_registration: registration.previous_change_epoch == last_change_epoch",
        );
    }

    #[test]
    fn a_change_waits_exactly_the_delay() {
        // Fixture state: validator 1 registered key 0 at epoch 20.
        let mut state = state();
        let first = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        register(&mut state, &first).unwrap();
        let change = registration(&state, 1, 1, EPOCH);

        // One epoch short of the delay, the change is refused.
        let mut early = state.clone();
        *early.slot_mut() = (EPOCH + preset::MIN_PQ_KEY_CHANGE_DELAY - 1) * preset::SLOTS_PER_EPOCH;
        assert_refused(
            register(&mut early, &change),
            "process_pq_key_registration: get_current_epoch(state) >= last_change_epoch + MIN_PQ_KEY_CHANGE_DELAY",
        );

        // At exactly the delay, it applies and restamps the entry.
        let at = EPOCH + preset::MIN_PQ_KEY_CHANGE_DELAY;
        *state.slot_mut() = at * preset::SLOTS_PER_EPOCH;
        register(&mut state, &change).unwrap();
        assert_eq!(
            entry(&state, 1),
            PqEntry {
                key_material: key_material(1, 1),
                change_epoch: at,
            }
        );
    }

    #[test]
    fn another_validators_signature_is_refused() {
        // Mutation: validator 2's BLS key signs validator 1's registration.
        let mut state = state();
        let signed = resign(&state, registration(&state, 1, 0, FAR_FUTURE_EPOCH), 2);

        assert_refused(
            register(&mut state, &signed),
            "process_pq_key_registration: bls.Verify(pubkey, signing_root, signed_registration.signature)",
        );
    }

    #[test]
    fn the_all_zero_key_is_refused() {
        // Mutation: the registration carries the all-zero key, the marker of an unset entry.
        let mut state = state();
        let mut signed = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        signed.message.key_material.xmss_public_key = XmssPublicKey::default();
        let signed = resign(&state, signed, 1);

        assert_refused(
            register(&mut state, &signed),
            "process_pq_key_registration: key_material.xmss_public_key != XMSSPublicKey()",
        );
    }

    #[test]
    fn a_key_any_index_holds_is_refused_even_its_own_holder() {
        // Fixture state: validator 1 holds key 0, registered at epoch 20.
        let mut state = state();
        let first = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        register(&mut state, &first).unwrap();
        *state.slot_mut() = (EPOCH + preset::MIN_PQ_KEY_CHANGE_DELAY) * preset::SLOTS_PER_EPOCH;
        let in_use = "process_pq_key_registration: not is_pq_public_key_in_use(state, key_material.xmss_public_key)";

        // Validator 2 registering key 0, with its own valid proof, is refused.
        let other = registration(&state, 2, 0, FAR_FUTURE_EPOCH);
        assert_refused(register(&mut state.clone(), &other), in_use);

        // Validator 1 keeping key 0 while changing its VRF root is refused too.
        let mut keep = registration(&state, 1, 0, EPOCH);
        keep.message.key_material.vrf_root = VrfRoot::repeat_byte(0x6b);
        let keep = resign(&state, keep, 1);
        assert_refused(register(&mut state, &keep), in_use);
    }

    #[test]
    fn a_proof_at_another_leaf_or_for_another_registrant_is_refused() {
        let invalid = "process_pq_key_registration: is_valid_pq_possession_proof(state, pubkey, key_material.xmss_public_key, signed_registration.possession)";
        let state = state();

        // Mutation: a valid signature of the possession message, but at leaf 1.
        let mut at_leaf_one = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        at_leaf_one.possession = possession(&state, 1, 0, 1);
        assert_refused(register(&mut state.clone(), &at_leaf_one), invalid);

        // Mutation: validator 2's proof of key 0, which names validator 2's BLS key.
        let mut copied = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        copied.possession = possession(&state, 2, 0, PQ_POSSESSION_XMSS_INDEX);
        assert_refused(register(&mut state.clone(), &copied), invalid);
    }

    #[test]
    fn an_exiting_or_unknown_validator_is_refused() {
        // Mutation: validator 1 initiated an exit at epoch 30.
        let mut exiting = state();
        exiting.validator_mut(1).unwrap().exit_epoch = 30;
        let signed = registration(&exiting, 1, 0, FAR_FUTURE_EPOCH);
        assert_refused(
            register(&mut exiting, &signed),
            "process_pq_key_registration: state.validators[validator_index].exit_epoch == FAR_FUTURE_EPOCH",
        );

        // Mutation: index 4 is one past the four validators.
        let mut state = state();
        let mut unknown = registration(&state, 1, 0, FAR_FUTURE_EPOCH);
        unknown.message.index = 4;
        assert_refused(
            register(&mut state, &unknown),
            "process_pq_key_registration: validator_index < len(state.validators)",
        );
    }

    #[test]
    fn a_reused_builder_index_drops_the_previous_builders_key() {
        // Fixture state: builder 0 registered key 0 at epoch 20.
        let mut state = state();
        let signed = registration(&state, BUILDER, 0, 0);
        register(&mut state, &signed).unwrap();

        // Mutation: builder 0 exits and is swept, so a new deposit reuses its index.
        let builder = &mut state.builders_mut().unwrap()[0];
        builder.withdrawable_epoch = EPOCH;
        builder.balance = 0;
        let index = add_builder_to_registry(
            &mut state,
            Builder::default().pubkey,
            0,
            ExecutionAddress::ZERO,
            0,
            EPOCH * preset::SLOTS_PER_EPOCH,
        )
        .unwrap();

        // The new builder at index 0 starts unset, marked by its own deposit epoch, 20.
        assert_eq!(index, 0);
        assert_eq!(
            entry(&state, BUILDER),
            PqEntry {
                key_material: PQKeyMaterial::default(),
                change_epoch: EPOCH,
            }
        );
    }

    #[test]
    fn a_gloas_state_has_no_registry_to_register_in() {
        // Mutation: the same registration against a gloas state.
        let heze = state();
        let signed = registration(&heze, 1, 0, FAR_FUTURE_EPOCH);
        let mut gloas = with_signing_validators_at(ForkName::Gloas, 4);

        assert!(matches!(
            register(&mut gloas, &signed),
            Err(Error::UnsupportedForFork {
                function: "process_pq_key_registration",
                fork: ForkName::Gloas,
            })
        ));
    }
}
