//! Seeded XMSS validator keys for real-crypto benchmark runs.
//!
//! Every validator gets an attestation key and a proposal key derived from the
//! run seed, so two runs with the same seed use identical keys and, since XMSS
//! signing is deterministic, identical signatures and proofs. Keys are
//! generated only for the slots the run will sign (leansig's keygen cost scales
//! with the active window), and `--key-cache` stores them so reruns skip keygen.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use ethlambda_blockchain::key_manager::{KeyManager, ValidatorKeyPair};
use ethlambda_crypto::signature::{LeanSignatureScheme, ValidatorPublicKey, ValidatorSecretKey};
use ethlambda_types::state::ValidatorPubkeyBytes;
use eyre::WrapErr as _;
use leansig::{serialization::Serializable as _, signature::SignatureScheme as _};
use rand::{SeedableRng as _, rngs::StdRng};

const PUBKEY_LEN: usize = std::mem::size_of::<ValidatorPubkeyBytes>();

#[derive(Debug, Clone, Copy)]
enum Role {
    Attestation,
    Proposal,
}

impl Role {
    fn tag(self) -> &'static str {
        match self {
            Role::Attestation => "attestation",
            Role::Proposal => "proposal",
        }
    }
}

/// One validator's generated key material: pubkeys as stored in the genesis
/// state, secrets as leansig serialized bytes.
struct ValidatorKeys {
    attestation_pubkey: ValidatorPubkeyBytes,
    proposal_pubkey: ValidatorPubkeyBytes,
    attestation_secret: Vec<u8>,
    proposal_secret: Vec<u8>,
}

pub(crate) struct KeySet {
    validators: Vec<ValidatorKeys>,
}

impl KeySet {
    /// Generate, or load from `cache`, keys for `num_validators` validators, each
    /// active for epochs (slots) `0..num_slots`.
    ///
    /// Cache entries are keyed by the leansig revision, seed, validator index,
    /// role and window, so a leansig bump or a different run shape never reuses
    /// a stale key.
    pub(crate) fn generate(
        seed: u64,
        num_validators: u64,
        num_slots: u64,
        cache: Option<&Path>,
    ) -> eyre::Result<Self> {
        if let Some(dir) = cache {
            std::fs::create_dir_all(dir)
                .wrap_err_with(|| format!("failed to create key cache {}", dir.display()))?;
        }
        let num_active_epochs = usize::try_from(num_slots)
            .ok()
            .filter(|epochs| *epochs >= 1)
            .ok_or_else(|| eyre::eyre!("key window must cover at least one slot"))?;

        let start = Instant::now();
        let mut generated = 0usize;
        let mut validators = Vec::with_capacity(num_validators as usize);
        for index in 0..num_validators {
            let mut key = |role: Role| -> eyre::Result<(ValidatorPubkeyBytes, Vec<u8>)> {
                let file = cache.map(|dir| {
                    dir.join(format!(
                        "xmss-{}-seed{seed}-v{index}-{}-w{num_slots}.bin",
                        env!("ETHLAMBDA_LEANSIG_REV"),
                        role.tag()
                    ))
                });
                if let Some(file) = &file
                    && file.is_file()
                {
                    return load_cached(file);
                }
                let (pubkey, secret) = generate_key(seed, index, role, num_active_epochs)?;
                generated += 1;
                if let Some(file) = &file {
                    let mut bytes = pubkey.to_vec();
                    bytes.extend_from_slice(&secret);
                    std::fs::write(file, bytes).wrap_err_with(|| {
                        format!("failed to write cached key {}", file.display())
                    })?;
                }
                Ok((pubkey, secret))
            };
            let (attestation_pubkey, attestation_secret) = key(Role::Attestation)?;
            let (proposal_pubkey, proposal_secret) = key(Role::Proposal)?;
            validators.push(ValidatorKeys {
                attestation_pubkey,
                proposal_pubkey,
                attestation_secret,
                proposal_secret,
            });
        }
        eprintln!(
            "validator keys ready in {:.1}s ({generated} generated, {} loaded from cache)",
            start.elapsed().as_secs_f64(),
            validators.len() * 2 - generated,
        );
        Ok(Self { validators })
    }

    /// `(attestation_pubkey, proposal_pubkey)` per validator, for the genesis state.
    pub(crate) fn genesis_pubkeys(&self) -> Vec<(ValidatorPubkeyBytes, ValidatorPubkeyBytes)> {
        self.validators
            .iter()
            .map(|keys| (keys.attestation_pubkey, keys.proposal_pubkey))
            .collect()
    }

    /// Decoded attestation pubkeys, indexed by validator, for type-1 aggregation.
    pub(crate) fn attestation_pubkeys(&self) -> eyre::Result<Vec<ValidatorPublicKey>> {
        self.validators
            .iter()
            .enumerate()
            .map(|(index, keys)| {
                ValidatorPublicKey::from_bytes(&keys.attestation_pubkey)
                    .map_err(|err| eyre::eyre!("validator {index} attestation pubkey: {}", err.0))
            })
            .collect()
    }

    /// Build the production `KeyManager` over these keys, so the benchmark signs
    /// through exactly the code path the node uses.
    pub(crate) fn into_key_manager(self) -> eyre::Result<KeyManager> {
        let mut keys = HashMap::with_capacity(self.validators.len());
        for (index, validator) in self.validators.into_iter().enumerate() {
            let decode = |bytes: &[u8], role: Role| {
                ValidatorSecretKey::from_bytes(bytes).map_err(|err| {
                    eyre::eyre!(
                        "validator {index} {} secret key does not decode ({}); \
                         if --key-cache was used, delete the cache directory and rerun",
                        role.tag(),
                        err.0
                    )
                })
            };
            keys.insert(
                index as u64,
                ValidatorKeyPair {
                    attestation_key: decode(&validator.attestation_secret, Role::Attestation)?,
                    proposal_key: decode(&validator.proposal_secret, Role::Proposal)?,
                },
            );
        }
        Ok(KeyManager::new(keys))
    }
}

/// Deterministic keygen: the RNG is seeded from `(seed, index, role)` so every
/// key is distinct and reproducible.
fn generate_key(
    seed: u64,
    index: u64,
    role: Role,
    num_active_epochs: usize,
) -> eyre::Result<(ValidatorPubkeyBytes, Vec<u8>)> {
    let role_bit = match role {
        Role::Attestation => 0,
        Role::Proposal => 1,
    };
    let mut rng = StdRng::seed_from_u64(seed ^ (index << 1 | role_bit).rotate_left(32));
    let (pubkey, secret) = LeanSignatureScheme::key_gen(&mut rng, 0, num_active_epochs);
    let pubkey: ValidatorPubkeyBytes = pubkey.to_bytes().try_into().map_err(|bytes: Vec<u8>| {
        eyre::eyre!(
            "leansig pubkey is {} bytes, expected {PUBKEY_LEN}",
            bytes.len()
        )
    })?;
    Ok((pubkey, secret.to_bytes()))
}

/// A cache entry is the pubkey bytes followed by the serialized secret key.
fn load_cached(file: &Path) -> eyre::Result<(ValidatorPubkeyBytes, Vec<u8>)> {
    let bytes = std::fs::read(file)
        .wrap_err_with(|| format!("failed to read cached key {}", file.display()))?;
    eyre::ensure!(
        bytes.len() > PUBKEY_LEN,
        "cached key {} is truncated; delete it and rerun",
        file.display()
    );
    let (pubkey, secret) = bytes.split_at(PUBKEY_LEN);
    let pubkey: ValidatorPubkeyBytes = pubkey.try_into().expect("split at PUBKEY_LEN");
    Ok((pubkey, secret.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_deterministic_per_seed_and_distinct_per_role() {
        let (a_pub, a_sec) = generate_key(7, 3, Role::Attestation, 2).unwrap();
        let (b_pub, b_sec) = generate_key(7, 3, Role::Attestation, 2).unwrap();
        assert_eq!(a_pub, b_pub);
        assert_eq!(a_sec, b_sec);
        let (p_pub, _) = generate_key(7, 3, Role::Proposal, 2).unwrap();
        assert_ne!(a_pub, p_pub);
        let (s_pub, _) = generate_key(8, 3, Role::Attestation, 2).unwrap();
        assert_ne!(a_pub, s_pub);
    }

    #[test]
    fn cache_round_trips_and_decodes() {
        let dir = std::env::temp_dir().join(format!(
            "ethlambda-bench-keys-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = KeySet::generate(11, 1, 2, Some(&dir)).unwrap();
        let second = KeySet::generate(11, 1, 2, Some(&dir)).unwrap();
        assert_eq!(first.genesis_pubkeys(), second.genesis_pubkeys());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        let mut key_manager = second.into_key_manager().unwrap();
        assert_eq!(key_manager.validator_ids(), vec![0]);
        key_manager
            .sign_block_root(0, 1, &ethlambda_types::primitives::H256::ZERO)
            .expect("cached key signs within its window");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
