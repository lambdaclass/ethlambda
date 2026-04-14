use std::collections::HashMap;

use ethlambda_types::{
    attestation::{AttestationData, XmssSignature},
    primitives::{H256, HashTreeRoot as _},
    signature::{ValidatorSecretKey, ValidatorSignature},
};
use tracing::info;

use crate::metrics;

/// Error types for KeyManager operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyManagerError {
    #[error("Validator key not found for validator_id: {0}")]
    ValidatorKeyNotFound(u64),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Signature conversion error: {0}")]
    SignatureConversionError(String),
}

/// A validator's dual XMSS key pair for attestation and block proposal signing.
///
/// Each key is independent and advances its OTS preparation separately,
/// allowing the validator to sign both an attestation and a block proposal
/// within the same slot.
pub struct ValidatorKeyPair {
    pub attestation_key: ValidatorSecretKey,
    pub proposal_key: ValidatorSecretKey,
}

/// Manages validator secret keys for signing attestations and block proposals.
///
/// Each validator has two independent XMSS keys: one for attestation signing
/// and one for block proposal signing.
pub struct KeyManager {
    keys: HashMap<u64, ValidatorKeyPair>,
}

impl KeyManager {
    pub fn new(keys: HashMap<u64, ValidatorKeyPair>) -> Self {
        Self { keys }
    }

    /// Returns a list of all registered validator IDs.
    pub fn validator_ids(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }

    /// Signs an attestation using the validator's attestation key.
    pub fn sign_attestation(
        &mut self,
        validator_id: u64,
        attestation_data: &AttestationData,
    ) -> Result<XmssSignature, KeyManagerError> {
        let message_hash = attestation_data.hash_tree_root();
        let slot = attestation_data.slot as u32;
        self.sign_with_attestation_key(validator_id, slot, &message_hash)
    }

    /// Signs a block root using the validator's proposal key.
    pub fn sign_block_root(
        &mut self,
        validator_id: u64,
        slot: u32,
        block_root: &H256,
    ) -> Result<XmssSignature, KeyManagerError> {
        self.sign_with_proposal_key(validator_id, slot, block_root)
    }

    fn sign_with_attestation_key(
        &mut self,
        validator_id: u64,
        slot: u32,
        message: &H256,
    ) -> Result<XmssSignature, KeyManagerError> {
        let key_pair = self
            .keys
            .get_mut(&validator_id)
            .ok_or(KeyManagerError::ValidatorKeyNotFound(validator_id))?;

        // Advance XMSS key preparation window if the slot is outside the current window.
        // Each bottom tree covers 65,536 slots; the window holds 2 at a time.
        // Multiple advances may be needed if the node was offline for an extended period.
        if !key_pair.attestation_key.is_prepared_for(slot) {
            info!(validator_id, slot, "Advancing XMSS key preparation window");
            while !key_pair.attestation_key.is_prepared_for(slot) {
                let before = key_pair.attestation_key.get_prepared_interval();
                key_pair.attestation_key.advance_preparation();
                if key_pair.attestation_key.get_prepared_interval() == before {
                    return Err(KeyManagerError::SigningError(format!(
                        "XMSS key exhausted for validator {validator_id}: \
                         slot {slot} is beyond the key's activation interval"
                    )));
                }
            }
        }

        let signature: ValidatorSignature = {
            let _timing = metrics::time_pq_sig_attestation_signing();
            key_pair
                .attestation_key
                .sign(slot, message)
                .map_err(|e| KeyManagerError::SigningError(e.to_string()))
        }?;
        metrics::inc_pq_sig_attestation_signatures();

        let sig_bytes = signature.to_bytes();
        XmssSignature::try_from(sig_bytes)
            .map_err(|e| KeyManagerError::SignatureConversionError(e.to_string()))
    }

    fn sign_with_proposal_key(
        &mut self,
        validator_id: u64,
        slot: u32,
        message: &H256,
    ) -> Result<XmssSignature, KeyManagerError> {
        let key_pair = self
            .keys
            .get_mut(&validator_id)
            .ok_or(KeyManagerError::ValidatorKeyNotFound(validator_id))?;

        // Advance XMSS key preparation window if the slot is outside the current window.
        // Each bottom tree covers 65,536 slots; the window holds 2 at a time.
        // Multiple advances may be needed if the node was offline for an extended period.
        if !key_pair.proposal_key.is_prepared_for(slot) {
            info!(
                validator_id,
                slot, "Advancing XMSS proposal key preparation window"
            );
            while !key_pair.proposal_key.is_prepared_for(slot) {
                let before = key_pair.proposal_key.get_prepared_interval();
                key_pair.proposal_key.advance_preparation();
                if key_pair.proposal_key.get_prepared_interval() == before {
                    return Err(KeyManagerError::SigningError(format!(
                        "XMSS proposal key exhausted for validator {validator_id}: \
                         slot {slot} is beyond the key's activation interval"
                    )));
                }
            }
        }

        let signature: ValidatorSignature = key_pair
            .proposal_key
            .sign(slot, message)
            .map_err(|e| KeyManagerError::SigningError(e.to_string()))?;

        let sig_bytes = signature.to_bytes();
        XmssSignature::try_from(sig_bytes)
            .map_err(|e| KeyManagerError::SignatureConversionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_ids() {
        let keys = HashMap::new();
        let key_manager = KeyManager::new(keys);
        assert_eq!(key_manager.validator_ids().len(), 0);
    }

    #[test]
    fn test_sign_attestation_validator_not_found() {
        let keys = HashMap::new();
        let mut key_manager = KeyManager::new(keys);
        let message = H256::default();

        let result = key_manager.sign_with_attestation_key(123, 0, &message);
        assert!(matches!(
            result,
            Err(KeyManagerError::ValidatorKeyNotFound(123))
        ));
    }

    #[test]
    fn test_sign_block_root_validator_not_found() {
        let keys = HashMap::new();
        let mut key_manager = KeyManager::new(keys);
        let message = H256::default();

        let result = key_manager.sign_block_root(123, 0, &message);
        assert!(matches!(
            result,
            Err(KeyManagerError::ValidatorKeyNotFound(123))
        ));
    }
}
