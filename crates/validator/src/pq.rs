//! The validator client on the PQ fork (`specs/_features/pq/validator.md`).
//!
//! At PQ a validator signs with leanXMSS and reveals RANDAO with a VRF proof,
//! both derived from its BLS signing key the way the PQ devnet's genesis
//! tooling registered them (`ethlambda_crypto::pq_keys`), so a keystore is
//! still all a validator needs. This module holds that material per key,
//! translates between a validator's BLS key and the form the PQ registry names
//! it by, and signs at the leaf each message is assigned.
//!
//! **The registry's form.** A PQ state names each validator by its 32-byte
//! XMSS key in the 48-byte form an execution-layer request names one: 16 zero
//! bytes, then the key. Duty responses carry that form, and no BLS key starts
//! with 16 zero bytes (its first byte carries the compression flag), so
//! [`bls_for_request_key`] maps one back to the local key that owns it, and
//! the client keeps working with BLS keys everywhere else.
//!
//! **Leaves.** XMSS is stateful: signing two messages at one leaf exposes it.
//! Every message has a leaf of its own (an attestation one per target epoch,
//! everything else one per slot and kind), so the slashing protection record
//! already covers blocks (one per slot) and attestations (one per target).
//! The other per-slot messages (payload attestations, aggregates,
//! envelopes) are guarded here, in memory: one signing root per leaf. The
//! specification asks for that record to persist across restarts; this one
//! does not, so a client restarted within a slot could sign a second
//! different message at one of those leaves.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use ethlambda_crypto::{lean_xmss, pq_keys};
use ethlambda_types::beacon::constants::{
    XMSS_ATTESTATION_LEAVES, XMSS_BUILDER_BID_LEAVES, XMSS_LEAVES_PER_SLOT, XMSS_RESERVED_LEAVES,
};
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, XmssSignature};

pub use ethlambda_types::beacon::constants::{
    LEAF_OFFSET_AGGREGATE_AND_PROOF, LEAF_OFFSET_BEACON_PROPOSER,
    LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE, LEAF_OFFSET_PTC_ATTESTER,
};

/// A validator's PQ key material.
pub struct PqKey {
    xmss: lean_xmss::SecretKey,
    vrf: pq_keys::VrfTree,
    /// The 48-byte form the PQ registry names the validator by.
    pub request_key: [u8; 48],
}

#[derive(Default)]
struct Registry {
    by_bls: HashMap<BlsPubkey, Arc<PqKey>>,
    by_request: HashMap<[u8; 48], BlsPubkey>,
}

fn registry() -> &'static RwLock<Registry> {
    static REGISTRY: OnceLock<RwLock<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

fn signed_leaves() -> &'static Mutex<HashMap<(BlsPubkey, u64), Root>> {
    static SIGNED: OnceLock<Mutex<HashMap<(BlsPubkey, u64), Root>>> = OnceLock::new();
    SIGNED.get_or_init(Default::default)
}

/// Derives and registers the PQ key of the validator whose BLS key is
/// `pubkey` and secret key `secret` (32 bytes, big-endian, as a keystore
/// holds it). Slow: a leanXMSS key generation (about a second and a half
/// across cores) and a VRF tree (two million hashes), plus building the
/// bottom trees its next attestation and per-slot signatures fall in. Run it
/// off the async runtime.
pub fn derive_and_register(pubkey: BlsPubkey, secret: &[u8; 32], current_slot: Slot) {
    let xmss = pq_keys::xmss_key(secret);
    let vrf = pq_keys::VrfTree::from_bls(secret);
    let mut request_key = [0u8; 48];
    request_key[16..].copy_from_slice(&xmss.public_key().to_bytes());
    // Warm the two bottom trees duties sign in, so the first signature of each
    // kind does not pay for one at its deadline.
    let epoch = current_slot / ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
    let _ = xmss.prepare(attestation_leaf(epoch) as u32);
    let _ = xmss.prepare(slot_leaf(current_slot, 0) as u32);
    let key = Arc::new(PqKey {
        xmss,
        vrf,
        request_key,
    });
    let mut registry = registry().write().expect("PQ key registry poisoned");
    registry.by_request.insert(request_key, pubkey);
    registry.by_bls.insert(pubkey, key);
}

/// Whether any key is registered: the network schedules PQ and this client
/// derived its keys.
pub fn enabled() -> bool {
    !registry()
        .read()
        .expect("PQ key registry poisoned")
        .by_bls
        .is_empty()
}

/// The local BLS key whose PQ key `request_key` names, if any.
pub fn bls_for_request_key(request_key: &[u8; 48]) -> Option<BlsPubkey> {
    if request_key[..16] != [0; 16] {
        return None;
    }
    registry()
        .read()
        .expect("PQ key registry poisoned")
        .by_request
        .get(request_key)
        .copied()
}

/// The request-key form of `pubkey`'s PQ key, if it has one.
pub fn request_key(pubkey: &BlsPubkey) -> Option<[u8; 48]> {
    key(pubkey).map(|key| key.request_key)
}

fn key(pubkey: &BlsPubkey) -> Option<Arc<PqKey>> {
    registry()
        .read()
        .expect("PQ key registry poisoned")
        .by_bls
        .get(pubkey)
        .cloned()
}

/// `compute_xmss_attestation_leaf_index`.
pub fn attestation_leaf(target_epoch: Epoch) -> u64 {
    XMSS_RESERVED_LEAVES + target_epoch
}

/// `compute_xmss_leaf_index`.
pub fn slot_leaf(slot: Slot, offset: u64) -> u64 {
    XMSS_RESERVED_LEAVES
        + XMSS_ATTESTATION_LEAVES
        + XMSS_BUILDER_BID_LEAVES
        + slot * XMSS_LEAVES_PER_SLOT
        + offset
}

#[derive(Debug, thiserror::Error)]
pub enum PqSignError {
    #[error("no PQ key for this validator")]
    UnknownValidator,
    #[error("leaf {0} already signed a different message")]
    LeafUsed(u64),
    #[error("leanXMSS: {0:?}")]
    Sign(lean_xmss::SignError),
}

/// Signs `root` at `leaf` with `pubkey`'s leanXMSS key. Refuses a leaf this
/// process already signed a different root at; the same root again is
/// re-signed, which yields the same bytes (signing is deterministic).
/// Blocking: building a bottom tree takes about a second and a half.
pub fn sign(pubkey: &BlsPubkey, leaf: u64, root: Root) -> Result<XmssSignature, PqSignError> {
    let key = key(pubkey).ok_or(PqSignError::UnknownValidator)?;
    {
        let mut signed = signed_leaves().lock().expect("PQ leaf record poisoned");
        match signed.get(&(*pubkey, leaf)) {
            Some(previous) if *previous != root => return Err(PqSignError::LeafUsed(leaf)),
            Some(_) => {}
            None => {
                signed.insert((*pubkey, leaf), root);
            }
        }
    }
    let leaf_index = u32::try_from(leaf).map_err(|_| PqSignError::LeafUsed(leaf))?;
    let signature = key
        .xmss
        .sign(&root.0, leaf_index)
        .map_err(PqSignError::Sign)?;
    let bytes: [u8; ethlambda_types::beacon::constants::XMSS_SIGNATURE_SIZE] = signature
        .to_bytes()
        .try_into()
        .expect("a leanXMSS signature is XMSS_SIGNATURE_SIZE bytes");
    Ok(XmssSignature(bytes))
}

/// `pubkey`'s VRF proof for `slot`, its RANDAO reveal at PQ.
pub fn vrf_proof(pubkey: &BlsPubkey, slot: Slot) -> Result<Vec<Root>, PqSignError> {
    let key = key(pubkey).ok_or(PqSignError::UnknownValidator)?;
    Ok(key.vrf.proof(slot).into_iter().map(Root::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_follow_the_specification() {
        assert_eq!(attestation_leaf(3), (1 << 15) + 3);
        assert_eq!(
            slot_leaf(10, LEAF_OFFSET_PTC_ATTESTER),
            (1 << 15) + (1 << 29) + (1 << 30) + 80 + 2
        );
        // The slot leaves start halfway into a bottom tree, so the first 4096
        // slots share one (and every later 8192 another), attestations another.
        assert_eq!(slot_leaf(0, 0) >> 16, slot_leaf(4095, 7) >> 16);
        assert_ne!(slot_leaf(0, 0) >> 16, slot_leaf(4096, 0) >> 16);
        assert_ne!(attestation_leaf(0) >> 16, slot_leaf(0, 0) >> 16);
    }

    #[test]
    fn a_request_key_maps_back_and_a_leaf_signs_once() {
        let secret = [7u8; 32];
        let pubkey = BlsPubkey([9; 48]);
        derive_and_register(pubkey, &secret, 0);
        let request = request_key(&pubkey).unwrap();
        assert_eq!(request[..16], [0; 16]);
        assert_eq!(bls_for_request_key(&request), Some(pubkey));
        assert_eq!(bls_for_request_key(&pubkey.0), None);

        let leaf = slot_leaf(5, LEAF_OFFSET_PTC_ATTESTER);
        let first = sign(&pubkey, leaf, Root::from([1; 32])).unwrap();
        assert_eq!(sign(&pubkey, leaf, Root::from([1; 32])).unwrap(), first);
        assert!(matches!(
            sign(&pubkey, leaf, Root::from([2; 32])),
            Err(PqSignError::LeafUsed(_))
        ));
        let public = request[16..].try_into().unwrap();
        assert!(lean_xmss::verify(&public, leaf, &[1; 32], &first.0));
        assert_eq!(vrf_proof(&pubkey, 5).unwrap().len(), 32);
    }
}
