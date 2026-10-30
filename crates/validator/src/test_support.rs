//! Helpers the service tests share.

use std::sync::Arc;

use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, H160};

use crate::keys::ValidatorStore;
use crate::proposer_settings::ProposerSettings;

/// `count` distinct keys. The secrets are small integers, which are valid BLS
/// scalars, so no keystore is needed.
pub(crate) fn store_with_keys(count: usize) -> (ValidatorStore, Vec<BlsPubkey>) {
    let mut store = ValidatorStore::new();
    let pubkeys = (0..count)
        .map(|index| {
            let mut secret = [0u8; 32];
            secret[24..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            store.insert_secret("test", &secret).expect("inserts")
        })
        .collect();
    (store, pubkeys)
}

/// Settings with `fee_recipient` as the default one and the default graffiti.
pub(crate) fn settings(fee_recipient: Option<H160>) -> Arc<ProposerSettings> {
    Arc::new(ProposerSettings::new(Bytes32::ZERO, fee_recipient))
}
