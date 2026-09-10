//! Seeded XMSS validator keys for real-crypto benchmark runs.
//!
//! Every validator gets an attestation key and a proposal key derived from the
//! run seed, so two runs with the same seed use identical keys and, since XMSS
//! signing is deterministic, identical signatures and proofs. Keys are
//! generated only for the slots the run will sign (XMSS keygen cost scales
//! with the active window), in parallel, and `--key-cache` stores them so
//! reruns skip keygen.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use ethlambda_blockchain::key_manager::{KeyManager, ValidatorKeyPair};
use ethlambda_crypto::signature::ValidatorSecretKey;
use ethlambda_types::state::ValidatorPubkeyBytes;
use eyre::WrapErr as _;
use rayon::prelude::*;

const PUBKEY_LEN: usize = size_of::<ValidatorPubkeyBytes>();

#[derive(Debug, Clone, Copy)]
#[repr(u64)]
enum Role {
    Attestation = 0,
    Proposal = 1,
}

impl Role {
    fn tag(self) -> &'static str {
        match self {
            Role::Attestation => "attestation",
            Role::Proposal => "proposal",
        }
    }
}

struct Key {
    pubkey: ValidatorPubkeyBytes,
    secret: ValidatorSecretKey,
    cached: bool,
}

pub(crate) struct KeySet {
    /// `(attestation_pubkey, proposal_pubkey)` per validator, for the genesis state.
    pub genesis_pubkeys: Vec<(ValidatorPubkeyBytes, ValidatorPubkeyBytes)>,
    /// The production signer over every validator's keys, so the benchmark
    /// signs through exactly the code path the node uses.
    pub key_manager: KeyManager,
}

impl KeySet {
    /// Generate, or load from `cache`, keys for `num_validators` validators, each
    /// active for epochs (slots) `0..num_slots`.
    ///
    /// Cache entries are keyed by the leanVM revision, seed, validator index,
    /// role and window, so a leanVM bump or a different run shape never reuses
    /// a stale key. leanVM owns the whole XMSS scheme, so a rev bump can change
    /// the key format without changing its size.
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

        // Every key is independent and deterministic in (seed, index, role), so
        // they are produced in parallel; `collect` keeps the job order.
        let start = Instant::now();
        let jobs: Vec<(u64, Role)> = (0..num_validators)
            .flat_map(|index| [(index, Role::Attestation), (index, Role::Proposal)])
            .collect();
        let keys: Vec<Key> = jobs
            .into_par_iter()
            .map(|(index, role)| load_or_generate(seed, index, role, num_active_epochs, cache))
            .collect::<eyre::Result<_>>()?;
        let cached = keys.iter().filter(|key| key.cached).count();
        eprintln!(
            "validator keys ready in {:.1}s ({} generated, {cached} loaded from cache)",
            start.elapsed().as_secs_f64(),
            keys.len() - cached,
        );

        let mut genesis_pubkeys = Vec::with_capacity(num_validators as usize);
        let mut pairs = HashMap::with_capacity(num_validators as usize);
        let mut keys = keys.into_iter();
        for index in 0..num_validators {
            let (attestation, proposal) = (keys.next(), keys.next());
            let (Some(attestation), Some(proposal)) = (attestation, proposal) else {
                eyre::bail!("key generation produced fewer keys than validators");
            };
            genesis_pubkeys.push((attestation.pubkey, proposal.pubkey));
            pairs.insert(
                index,
                ValidatorKeyPair {
                    attestation_key: attestation.secret,
                    proposal_key: proposal.secret,
                },
            );
        }
        Ok(Self {
            genesis_pubkeys,
            key_manager: KeyManager::new(pairs),
        })
    }
}

/// Load the cached key for `(seed, index, role)` if present, else derive it
/// (and cache it when a cache directory is given).
fn load_or_generate(
    seed: u64,
    index: u64,
    role: Role,
    num_active_epochs: usize,
    cache: Option<&Path>,
) -> eyre::Result<Key> {
    let file = cache.map(|dir| {
        dir.join(format!(
            "xmss-{}-seed{seed}-v{index}-{}-w{num_active_epochs}.bin",
            env!("ETHLAMBDA_LEANVM_REV"),
            role.tag()
        ))
    });
    if let Some(file) = &file
        && file.is_file()
    {
        return load_cached(file);
    }

    let key_seed = seed ^ (index << 1 | role as u64).rotate_left(32);
    // leanVM seeds a key with 32 bytes; the run's `u64` fills the low end and
    // the rest stays zero, which keeps the derivation reproducible without
    // pretending to more entropy than the seed carries.
    let mut key_seed_bytes = [0u8; 32];
    key_seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
    let last_epoch =
        u32::try_from(num_active_epochs - 1).wrap_err("key window exceeds the XMSS epoch range")?;
    let secret = ValidatorSecretKey::generate_from_seed(key_seed_bytes, 0..=last_epoch)
        .map_err(|err| eyre::eyre!("XMSS key generation failed: {err:?}"))?;
    let pubkey: ValidatorPubkeyBytes =
        secret
            .public_key()
            .to_bytes()
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                eyre::eyre!(
                    "XMSS pubkey is {} bytes, expected {PUBKEY_LEN}",
                    bytes.len()
                )
            })?;
    if let Some(file) = &file {
        let mut bytes = pubkey.to_vec();
        bytes.extend_from_slice(&secret.to_bytes().wrap_err("failed to encode secret key")?);
        std::fs::write(file, bytes)
            .wrap_err_with(|| format!("failed to write cached key {}", file.display()))?;
    }
    Ok(Key {
        pubkey,
        secret,
        cached: false,
    })
}

/// A cache entry is the pubkey bytes followed by the serialized secret key.
fn load_cached(file: &Path) -> eyre::Result<Key> {
    let bytes = std::fs::read(file)
        .wrap_err_with(|| format!("failed to read cached key {}", file.display()))?;
    eyre::ensure!(
        bytes.len() > PUBKEY_LEN,
        "cached key {} is truncated; delete it and rerun",
        file.display()
    );
    let (pubkey, secret) = bytes.split_at(PUBKEY_LEN);
    let secret = ValidatorSecretKey::from_bytes(secret).map_err(|err| {
        eyre::eyre!(
            "cached key {} does not decode ({err}); delete it and rerun",
            file.display()
        )
    })?;
    Ok(Key {
        pubkey: pubkey.try_into().expect("split at PUBKEY_LEN"),
        secret,
        cached: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_deterministic_per_seed_and_distinct_per_role() {
        let a = load_or_generate(7, 3, Role::Attestation, 2, None).unwrap();
        let b = load_or_generate(7, 3, Role::Attestation, 2, None).unwrap();
        assert_eq!(a.pubkey, b.pubkey);
        assert_eq!(a.secret.to_bytes().unwrap(), b.secret.to_bytes().unwrap());
        let proposal = load_or_generate(7, 3, Role::Proposal, 2, None).unwrap();
        assert_ne!(a.pubkey, proposal.pubkey);
        let other_seed = load_or_generate(8, 3, Role::Attestation, 2, None).unwrap();
        assert_ne!(a.pubkey, other_seed.pubkey);
    }

    #[test]
    fn cache_round_trips_and_decodes() {
        let dir = tempfile::tempdir().unwrap();
        let first = KeySet::generate(11, 1, 2, Some(dir.path())).unwrap();
        let mut second = KeySet::generate(11, 1, 2, Some(dir.path())).unwrap();
        assert_eq!(first.genesis_pubkeys, second.genesis_pubkeys);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        assert_eq!(second.key_manager.validator_ids(), vec![0]);
        second
            .key_manager
            .sign_block_root(0, 1, &ethlambda_types::primitives::H256::ZERO)
            .expect("cached key signs within its window");
    }
}
