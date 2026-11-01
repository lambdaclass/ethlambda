//! Helpers of EIP-8450's post-quantum key registry.
//!
//! Each keeps the EIP's name, so a call site reads against its pseudocode line by line.

use ethlambda_crypto::lean_xmss;

use crate::beacon::config::Config;
use crate::beacon::constants::{
    DOMAIN_PQ_KEY_POSSESSION, DOMAIN_PQ_KEY_REGISTRATION, PQ_POSSESSION_XMSS_INDEX,
};
use crate::beacon::containers::heze::{PQKeyPossession, PQKeyRegistration};
use crate::beacon::primitives::{BlsPubkey, HashTreeRoot as _, Root, XmssPublicKey, XmssSignature};

use super::misc::{compute_domain, compute_signing_root};

/// The message a proof of possession signs: the key, for its registrant's BLS public key.
///
/// The domain uses the genesis fork version, so a proof stays valid across forks.
/// A proof names no change epoch, so each key's proof is signed once.
pub fn get_pq_possession_signing_root(
    genesis_validators_root: Root,
    pubkey: &BlsPubkey,
    xmss_public_key: &XmssPublicKey,
    config: &Config,
) -> Root {
    let possession = PQKeyPossession {
        pubkey: *pubkey,
        xmss_public_key: *xmss_public_key,
    };
    let domain = compute_domain(
        DOMAIN_PQ_KEY_POSSESSION,
        config.genesis_fork_version,
        genesis_validators_root,
    );
    compute_signing_root(possession.hash_tree_root(), domain)
}

/// The message the registrant's BLS key signs to authorize a registration.
///
/// The domain uses the genesis fork version, as a BLS-to-execution change does.
pub fn get_pq_key_registration_signing_root(
    genesis_validators_root: Root,
    registration: &PQKeyRegistration,
    config: &Config,
) -> Root {
    let domain = compute_domain(
        DOMAIN_PQ_KEY_REGISTRATION,
        config.genesis_fork_version,
        genesis_validators_root,
    );
    compute_signing_root(registration.hash_tree_root(), domain)
}

/// Whether the holder of a leanXMSS key signed it for a BLS public key, at the reserved leaf.
///
/// The leaf index is read from the proof's first four bytes before any hashing.
/// A key or proof that does not decode fails, without an error.
/// See `is_valid_pq_possession_proof` in EIP-8450.
pub fn is_valid_pq_possession_proof(
    genesis_validators_root: Root,
    pubkey: &BlsPubkey,
    xmss_public_key: &XmssPublicKey,
    proof: &XmssSignature,
    config: &Config,
) -> bool {
    // Leaf 0 is reserved: a duty never signs there, so the proof reuses no one-time key.
    if proof.leaf_index() != PQ_POSSESSION_XMSS_INDEX {
        return false;
    }
    let signing_root =
        get_pq_possession_signing_root(genesis_validators_root, pubkey, xmss_public_key, config);
    lean_xmss::verify(&xmss_public_key.0, &signing_root.0, &proof.0).is_ok()
}
