//! Validating a whole registry's public keys at once, when a state is loaded.

use super::{IndexedPubkey, key_validate};

/// Validates and caches every key in `pubkeys`, returning how many passed
/// `KeyValidate`.
pub fn warm_pubkeys(pubkeys: &[IndexedPubkey]) -> usize {
    pubkeys
        .iter()
        .filter(|pubkey| key_validate(*pubkey))
        .count()
}
