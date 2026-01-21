use std::collections::HashMap;

use ethlambda_types::{
    attestation::{AttestationData, XmssSignature},
    primitives::{H256, TreeHash},
    signature::{ValidatorSecretKey, ValidatorSignature},
};

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

/// Manages validator secret keys for signing attestations.
///
/// The KeyManager stores a mapping of validator IDs to their secret keys
/// and provides methods to sign attestations on behalf of validators.
pub struct KeyManager {
    keys: HashMap<u64, ValidatorSecretKey>,
}

impl KeyManager {
    /// Creates a new KeyManager with the given mapping of validator IDs to secret keys.
    ///
    /// # Arguments
    ///
    /// * `keys` - A HashMap mapping validator IDs (u64) to their secret keys
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut keys = HashMap::new();
    /// keys.insert(0, ValidatorSecretKey::from_bytes(&key_bytes)?);
    /// let key_manager = KeyManager::new(keys);
    /// ```
    pub fn new(keys: HashMap<u64, ValidatorSecretKey>) -> Self {
        Self { keys }
    }

    /// Returns a list of all registered validator IDs.
    ///
    /// The returned vector contains all validator IDs that have keys registered
    /// in this KeyManager instance.
    pub fn validator_ids(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }

    /// Signs an attestation for the specified validator.
    ///
    /// This method computes the message hash from the attestation data and signs it
    /// using the validator's secret key.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The ID of the validator whose key should be used for signing
    /// * `attestation_data` - The attestation data to sign
    ///
    /// # Returns
    ///
    /// Returns an `XmssSignature` (3112 bytes) on success, or a `KeyManagerError` if:
    /// - The validator ID is not found in the KeyManager
    /// - The signing operation fails
    pub fn sign_attestation(
        &mut self,
        validator_id: u64,
        attestation_data: &AttestationData,
    ) -> Result<XmssSignature, KeyManagerError> {
        let message_hash = attestation_data.tree_hash_root();
        let epoch = attestation_data.slot as u32;
        self.sign_message(validator_id, epoch, &message_hash)
    }

    /// Signs a message hash for the specified validator.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The ID of the validator whose key should be used for signing
    /// * `epoch` - The epoch number used in the XMSS signature scheme
    /// * `message` - The message hash to sign
    ///
    /// # Returns
    ///
    /// Returns an `XmssSignature` (3112 bytes) on success, or a `KeyManagerError` if:
    /// - The validator ID is not found in the KeyManager
    /// - The signing operation fails
    fn sign_message(
        &mut self,
        validator_id: u64,
        epoch: u32,
        message: &H256,
    ) -> Result<XmssSignature, KeyManagerError> {
        let secret_key = self
            .keys
            .get_mut(&validator_id)
            .ok_or(KeyManagerError::ValidatorKeyNotFound(validator_id))?;

        let signature: ValidatorSignature = secret_key
            .sign(epoch, message)
            .map_err(|e| KeyManagerError::SigningError(e.to_string()))?;

        // Convert ValidatorSignature to XmssSignature (FixedVector<u8, SignatureSize>)
        let sig_bytes = signature.to_bytes();
        let xmss_sig = XmssSignature::try_from(sig_bytes)
            .map_err(|e| KeyManagerError::SignatureConversionError(e.to_string()))?;

        Ok(xmss_sig)
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

        let result = key_manager.sign_message(123, 0, &message);
        assert!(matches!(
            result,
            Err(KeyManagerError::ValidatorKeyNotFound(123))
        ));
    }
}
