//! A heze state with real BLS and leanXMSS keys, shared by the registry's tests.

use std::sync::LazyLock;

use ethlambda_crypto::lean_xmss::SecretKey as XmssSecretKey;

use crate::beacon::config::Config;
use crate::beacon::constants::{BUILDER_INDEX_FLAG, FAR_FUTURE_EPOCH, PQ_POSSESSION_XMSS_INDEX};
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::gloas::Builder;
use crate::beacon::containers::heze::{PQKeyMaterial, PQKeyRegistration, SignedPQKeyRegistration};
use crate::beacon::fork::ForkName;
use crate::beacon::helpers::heze::{
    get_pq_key_registration_signing_root, get_pq_possession_signing_root,
};
use crate::beacon::helpers::test_state::{pubkey_for, sign_for, with_signing_validators_at};
use crate::beacon::preset;
use crate::beacon::primitives::{
    Epoch, Root, ValidatorIndex, VrfRoot, XmssPublicKey, XmssSignature,
};

/// Validators in the fixture registry, with BLS keys 0 to 3.
pub(crate) const VALIDATORS: u64 = 4;

/// The BLS key the fixture's one builder signs with.
pub(crate) const BUILDER_SIGNER: usize = 4;

/// The registration index naming the fixture's builder, builder index 0.
pub(crate) const BUILDER: ValidatorIndex = BUILDER_INDEX_FLAG;

/// The epoch the fixture state is at.
pub(crate) const EPOCH: Epoch = 20;

/// Three leanXMSS keys, built once per test process.
///
/// Each key generation builds a top tree of 2^16 leaves.
static XMSS_KEYS: LazyLock<[XmssSecretKey; 3]> = LazyLock::new(|| {
    [
        XmssSecretKey::from_seed([1; 32]),
        XmssSecretKey::from_seed([2; 32]),
        XmssSecretKey::from_seed([3; 32]),
    ]
});

/// The chain configuration of the fixture, with heze active from genesis.
pub(crate) fn config() -> Config {
    Config::active().with_fork_epoch(ForkName::Heze, 0)
}

/// A heze state at epoch 20 with four active validators and one active builder.
///
/// No validator or builder holds keys yet.
/// The finalized epoch is 1, after the builder's deposit epoch 0, so the builder is active.
pub(crate) fn state() -> BeaconState {
    let mut state = with_signing_validators_at(ForkName::Heze, VALIDATORS as usize);
    *state.genesis_validators_root_mut() = Root::repeat_byte(0x77);
    *state.slot_mut() = EPOCH * preset::SLOTS_PER_EPOCH;
    state.finalized_checkpoint_mut().epoch = 1;
    let builder = Builder {
        pubkey: pubkey_for(BUILDER_SIGNER),
        deposit_epoch: 0,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
        ..Default::default()
    };
    state.builders_mut().unwrap().push(builder);
    state
        .pq_registry_mut()
        .unwrap()
        .reset_builder(0, 0)
        .unwrap();
    state.apply_pending_mutations();
    state
}

/// The public half of a fixture leanXMSS key.
pub(crate) fn public_key(key: usize) -> XmssPublicKey {
    XmssPublicKey(XMSS_KEYS[key].public_key().to_bytes())
}

/// Key material of a fixture key: a builder's has a zero VRF root, a validator's does not.
pub(crate) fn key_material(index: ValidatorIndex, key: usize) -> PQKeyMaterial {
    let vrf_root = if index == BUILDER {
        VrfRoot::ZERO
    } else {
        VrfRoot::repeat_byte(0x5a)
    };
    PQKeyMaterial {
        xmss_public_key: public_key(key),
        vrf_root,
    }
}

/// A fixture key's proof of possession for a BLS key, signed at a leaf.
pub(crate) fn possession(
    state: &BeaconState,
    signer: usize,
    key: usize,
    leaf_index: u32,
) -> XmssSignature {
    let root = get_pq_possession_signing_root(
        state.genesis_validators_root(),
        &pubkey_for(signer),
        &public_key(key),
        &config(),
    );
    let signature = XMSS_KEYS[key].sign(&root.0, leaf_index).unwrap();
    XmssSignature(signature.to_bytes())
}

/// A registration of a fixture key, correctly signed by the registrant's own keys.
///
/// The registrant is validator `index`, or the builder when `index` names it.
pub(crate) fn registration(
    state: &BeaconState,
    index: ValidatorIndex,
    key: usize,
    previous_change_epoch: Epoch,
) -> SignedPQKeyRegistration {
    let signer = if index == BUILDER {
        BUILDER_SIGNER
    } else {
        index as usize
    };
    let message = PQKeyRegistration {
        index,
        key_material: key_material(index, key),
        previous_change_epoch,
    };
    let root =
        get_pq_key_registration_signing_root(state.genesis_validators_root(), &message, &config());
    SignedPQKeyRegistration {
        message,
        possession: possession(state, signer, key, PQ_POSSESSION_XMSS_INDEX),
        signature: sign_for(signer, root),
    }
}

/// Re-signs a registration whose message a test changed, with the registrant's BLS key.
pub(crate) fn resign(
    state: &BeaconState,
    mut signed: SignedPQKeyRegistration,
    signer: usize,
) -> SignedPQKeyRegistration {
    let root = get_pq_key_registration_signing_root(
        state.genesis_validators_root(),
        &signed.message,
        &config(),
    );
    signed.signature = sign_for(signer, root);
    signed
}
