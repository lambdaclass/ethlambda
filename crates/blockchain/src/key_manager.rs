use std::collections::HashMap;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

use ethlambda_crypto::signature::{ValidatorSecretKey, ValidatorSignature};
use ethlambda_types::{
    attestation::{AttestationData, XmssSignature},
    primitives::{H256, HashTreeRoot as _},
};
use tracing::{trace, warn};

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
/// Each key holds its own one-time leaves, so the validator can sign both an
/// attestation and a block proposal within the same slot.
pub struct ValidatorKeyPair {
    pub attestation_key: ValidatorSecretKey,
    pub proposal_key: ValidatorSecretKey,
}

/// Manages validator secret keys for signing attestations and block proposals.
///
/// Each validator has two independent XMSS keys: one for attestation signing
/// and one for block proposal signing.
pub struct KeyManager {
    /// Shared so a background warm can hold the keys while the actor signs.
    keys: HashMap<u64, Arc<ValidatorKeyPair>>,
    /// The in-flight [`Self::prepare_keys_in_background`] thread, if any.
    warm_worker: Option<JoinHandle<()>>,
}

/// Which of a validator's two keys a warm-up entry names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyRole {
    Attestation,
    Proposal,
}

/// A key to warm: the validator, which of its keys, and its shared key pair.
type WarmEntry = (u64, KeyRole, Arc<ValidatorKeyPair>);

/// Keys each helper thread of [`KeyManager::prepare_keys_for`] warms.
///
/// leanVM rebuilds a subtree sequentially, so the only parallelism is across
/// keys. Batching them keeps the thread count a fraction of the key count,
/// while each thread still has a few rebuilds to spread its spawn cost over.
const KEYS_PER_WARM_THREAD: usize = 4;

impl KeyManager {
    pub fn new(keys: HashMap<u64, ValidatorKeyPair>) -> Self {
        let keys = keys
            .into_iter()
            .map(|(id, pair)| (id, Arc::new(pair)))
            .collect();
        Self {
            keys,
            warm_worker: None,
        }
    }

    /// Returns a list of all registered validator IDs.
    pub fn validator_ids(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }

    /// Warms the signing caches the duties at `slot` sign with: every
    /// attestation key, plus `proposer`'s proposal key when one of our
    /// validators proposes at `slot`.
    ///
    /// Pure latency shifting: the key rebuilds the same bottom Merkle subtree
    /// inside `sign` on a miss, so this only moves that cost off the duty's
    /// critical path. A key caches a single subtree, though, so warming it
    /// evicts the subtree an earlier slot signs with whenever the two slots
    /// straddle a subtree boundary. Call this only once nothing is left to sign
    /// before `slot`, or that signature rebuilds the evicted subtree on its own
    /// critical path.
    ///
    /// The other proposal keys are left cold: nothing signs with them before
    /// their own turn to propose, and warming all of them rebuilds one subtree
    /// per validator at every boundary.
    ///
    /// Blocks until every key is warm, with the rebuilds spread over scoped
    /// threads of [`KEYS_PER_WARM_THREAD`] keys each. Each key knows which
    /// subtree it holds and rebuilds only on a miss, so a repeat call for a
    /// slot already warmed costs a lock per key and the thread spawns.
    pub fn prepare_keys_for(&self, slot: u32, proposer: Option<u64>) {
        warm_keys(slot, &self.keys_to_warm(proposer));
    }

    /// Same warm as [`Self::prepare_keys_for`], on a background thread, so the
    /// caller does not wait out the subtree rebuilds at a boundary.
    ///
    /// Safe to overlap with signing: a key's cache sits behind a lock that
    /// `sign` also takes, so a signature racing the warm of the same key waits
    /// for that rebuild and reuses it instead of rebuilding again. The
    /// eviction rule of [`Self::prepare_keys_for`] still applies to when this
    /// is called.
    ///
    /// Skips the warm while the previous one is still running, and warns
    /// instead of failing when the thread cannot be spawned: either way the
    /// only cost is latency, since `sign` rebuilds a missing subtree itself.
    pub fn prepare_keys_in_background(&mut self, slot: u32, proposer: Option<u64>) {
        if let Some(worker) = self.warm_worker.take() {
            if !worker.is_finished() {
                warn!(slot, "Previous XMSS warm still running, skipping this one");
                self.warm_worker = Some(worker);
                return;
            }
            let _ = worker
                .join()
                .inspect_err(|_| warn!("XMSS warm thread panicked"));
        }

        let keys = self.keys_to_warm(proposer);
        self.warm_worker = std::thread::Builder::new()
            .name("xmss-warm".to_string())
            .spawn(move || warm_keys(slot, &keys))
            .inspect_err(|err| warn!(slot, %err, "Failed to spawn XMSS warm thread"))
            .ok();
    }

    /// The keys [`Self::prepare_keys_for`] warms: every attestation key, then
    /// `proposer`'s proposal key if that validator is ours.
    fn keys_to_warm(&self, proposer: Option<u64>) -> Vec<WarmEntry> {
        let attestation_keys = self
            .keys
            .iter()
            .map(|(&id, pair)| (id, KeyRole::Attestation, Arc::clone(pair)));
        let proposal_key = proposer.and_then(|id| {
            let pair = self.keys.get(&id)?;
            Some((id, KeyRole::Proposal, Arc::clone(pair)))
        });
        attestation_keys.chain(proposal_key).collect()
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

        // A slot outside the key's range can never be signed, however long the
        // node waits, so name that rather than letting it surface as a generic
        // signing error.
        signable_at(validator_id, &key_pair.attestation_key, slot)?;

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

        signable_at(validator_id, &key_pair.proposal_key, slot)?;

        let signature: ValidatorSignature = key_pair
            .proposal_key
            .sign(slot, message)
            .map_err(|e| KeyManagerError::SigningError(e.to_string()))?;

        let sig_bytes = signature.to_bytes();
        XmssSignature::try_from(sig_bytes)
            .map_err(|e| KeyManagerError::SignatureConversionError(e.to_string()))
    }
}

/// Reject a slot the key cannot sign at.
///
/// The signable range is fixed at key generation, so this is exhaustion, not a
/// window that will catch up.
fn signable_at(
    validator_id: u64,
    key: &ValidatorSecretKey,
    slot: u32,
) -> Result<(), KeyManagerError> {
    if key.can_sign_at(slot) {
        return Ok(());
    }
    let range = key.signable_slots();
    Err(KeyManagerError::SigningError(format!(
        "XMSS key exhausted for validator {validator_id}: slot {slot} is outside \
         the key's signable range [{}, {}]",
        range.start(),
        range.end()
    )))
}

/// Warm `keys` for `slot`, spreading the rebuilds over scoped threads of
/// [`KEYS_PER_WARM_THREAD`] keys each, and return once all are done.
fn warm_keys(slot: u32, keys: &[WarmEntry]) {
    let start = Instant::now();
    std::thread::scope(|scope| {
        for batch in keys.chunks(KEYS_PER_WARM_THREAD) {
            scope.spawn(move || {
                for (validator_id, role, pair) in batch {
                    let key = match role {
                        KeyRole::Attestation => &pair.attestation_key,
                        KeyRole::Proposal => &pair.proposal_key,
                    };
                    let _ = prepare_key(key, slot).inspect_err(|err| {
                        warn!(validator_id, slot, ?role, %err, "Failed to warm XMSS signing cache")
                    });
                }
            });
        }
    });
    trace!(slot, keys = keys.len(), elapsed = ?start.elapsed(), "Warmed XMSS signing caches");
}

/// Warm one key's signing cache, timing the miss that rebuilds a subtree.
fn prepare_key(key: &ValidatorSecretKey, slot: u32) -> Result<(), KeyManagerError> {
    let start = Instant::now();
    key.prepare(slot)
        .map_err(|err| KeyManagerError::SigningError(err.to_string()))?;
    trace!(slot, elapsed = ?start.elapsed(), "Warmed XMSS signing cache");
    Ok(())
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

    /// A key manager for validators `0..count`, each key covering slots 0 and
    /// 1 only, which keeps generation cheap.
    fn tiny_key_manager(count: u64) -> KeyManager {
        let key = |seed: u8| ValidatorSecretKey::generate_from_seed([seed; 32], 0..=1).unwrap();
        let keys = (0..count)
            .map(|id| {
                let pair = ValidatorKeyPair {
                    attestation_key: key(2 * id as u8),
                    proposal_key: key(2 * id as u8 + 1),
                };
                (id, pair)
            })
            .collect();
        KeyManager::new(keys)
    }

    fn warmed(key_manager: &KeyManager, proposer: Option<u64>) -> Vec<(u64, KeyRole)> {
        let mut entries: Vec<_> = key_manager
            .keys_to_warm(proposer)
            .into_iter()
            .map(|(id, role, _)| (id, role))
            .collect();
        entries.sort_by_key(|&(id, role)| (role == KeyRole::Proposal, id));
        entries
    }

    #[test]
    fn keys_to_warm_takes_every_attestation_key_and_only_the_proposers_proposal_key() {
        let key_manager = tiny_key_manager(3);
        let attestation_keys: Vec<_> = (0..3).map(|id| (id, KeyRole::Attestation)).collect();

        assert_eq!(warmed(&key_manager, None), attestation_keys);

        let mut with_proposer = attestation_keys.clone();
        with_proposer.push((1, KeyRole::Proposal));
        assert_eq!(warmed(&key_manager, Some(1)), with_proposer);

        // A proposer that is not one of ours adds nothing.
        assert_eq!(warmed(&key_manager, Some(99)), attestation_keys);
    }

    #[test]
    fn prepare_keys_for_warms_every_batch() {
        // More keys than one batch holds, so the warm spans several threads.
        let count = 2 * KEYS_PER_WARM_THREAD as u64 + 1;
        let mut key_manager = tiny_key_manager(count);

        key_manager.prepare_keys_for(1, Some(0));
        // A repeat call finds every key warm.
        key_manager.prepare_keys_for(1, Some(0));
        // A slot outside every key's range only warns.
        key_manager.prepare_keys_for(7, None);

        // The warmed keys still sign.
        let message = H256::default();
        key_manager
            .sign_with_attestation_key(count - 1, 1, &message)
            .unwrap();
        key_manager.sign_block_root(0, 1, &message).unwrap();
    }

    #[test]
    fn prepare_keys_in_background_warms_without_blocking_signing() {
        let count = 2 * KEYS_PER_WARM_THREAD as u64 + 1;
        let mut key_manager = tiny_key_manager(count);

        key_manager.prepare_keys_in_background(1, Some(0));
        // Signing while the warm may still be running waits on the key's cache
        // lock rather than failing.
        let message = H256::default();
        key_manager
            .sign_with_attestation_key(count - 1, 1, &message)
            .unwrap();

        key_manager
            .warm_worker
            .take()
            .expect("warm thread spawned")
            .join()
            .expect("warm thread finished cleanly");

        // A later call spawns a fresh warm once the previous one is done.
        key_manager.prepare_keys_in_background(1, Some(0));
        assert!(key_manager.warm_worker.is_some());
        key_manager.sign_block_root(0, 1, &message).unwrap();
    }
}
