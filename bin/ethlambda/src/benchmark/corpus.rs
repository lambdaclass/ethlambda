//! Synthetic benchmark corpus: deterministic validators, a genesis store,
//! per-slot attestation-pool seeding, and the crypto-mode-specific steps of one
//! slot (seal, import, which phases to expect).

use std::sync::Arc;
use std::time::Instant;

use ethlambda_blockchain::block_builder::seal_block;
use ethlambda_blockchain::key_manager::KeyManager;
use ethlambda_blockchain::metrics::{
    BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASES, BLOCK_PROPOSAL_SEAL_PHASES,
};
use ethlambda_blockchain::store::{
    StoreError, on_block, on_block_without_verification, produce_attestation_data,
};
use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_types::{
    attestation::{AggregationBits, HashedAttestationData, validator_indices},
    block::{Block, MultiMessageAggregate, SignedBlock, SingleMessageAggregate},
    constants::DEFAULT_MILLISECONDS_PER_SLOT,
    primitives::HashTreeRoot as _,
    state::{PUBLIC_KEY_SIZE, State, Validator, ValidatorPubkeyBytes},
};
use eyre::WrapErr as _;

/// Fixed genesis time for synthetic runs. The harness derives every tick
/// timestamp from slot numbers relative to this value and never reads the wall
/// clock, so runs are reproducible at any time of day.
const GENESIS_TIME: u64 = 1_700_000_000;

/// Everything that differs between a mock and a real-crypto run.
pub(crate) enum CryptoMode {
    /// Empty placeholder proofs and placeholder pubkey bytes, no seal, and
    /// unverified import. No code path decodes the placeholders.
    Mock,
    /// Real XMSS signatures aggregated into real leanVM type-1 proofs, the
    /// proposer's real seal, and verified import.
    Real {
        /// `(attestation_pubkey, proposal_pubkey)` per validator, for genesis.
        genesis_pubkeys: Vec<(ValidatorPubkeyBytes, ValidatorPubkeyBytes)>,
        /// Signs attestations for the corpus and block roots for the seal.
        key_manager: KeyManager,
    },
}

/// What one slot's seeding produced.
pub(crate) struct SeedOutcome {
    /// Pool entries (new + known) the next build will see.
    pub pool_entries: usize,
    /// Seconds spent signing and aggregating this slot's entries; 0 in mock mode.
    pub aggregate_seconds: f64,
}

pub(crate) struct SyntheticCorpus {
    num_validators: u64,
    proofs_per_data: u64,
    crypto: CryptoMode,
}

impl SyntheticCorpus {
    pub(crate) fn new(num_validators: u64, proofs_per_data: u64, crypto: CryptoMode) -> Self {
        Self {
            num_validators,
            proofs_per_data,
            crypto,
        }
    }

    /// Build a genesis store over an in-memory backend with `num_validators`
    /// validators: the key set's pubkeys in real mode, seed-derived placeholder
    /// bytes in mock mode.
    pub(crate) fn genesis_store(&self, seed: u64) -> Store {
        let mut rng_state = seed;
        let validators = (0..self.num_validators)
            .map(|index| {
                let (attestation_pubkey, proposal_pubkey) = match &self.crypto {
                    CryptoMode::Mock => (
                        synthetic_pubkey(&mut rng_state),
                        synthetic_pubkey(&mut rng_state),
                    ),
                    CryptoMode::Real {
                        genesis_pubkeys, ..
                    } => genesis_pubkeys[index as usize],
                };
                Validator {
                    attestation_pubkey,
                    proposal_pubkey,
                    index,
                }
            })
            .collect();
        let genesis_state = State::from_genesis(GENESIS_TIME, validators);
        Store::from_anchor_state(
            Arc::new(InMemoryBackend::new()),
            genesis_state,
            DEFAULT_MILLISECONDS_PER_SLOT,
        )
    }

    /// Seed the pending ("new") pool with the full validator set's attestations
    /// for `attestation_slot`, split into `proofs_per_data` disjoint aggregates.
    ///
    /// Mirrors what committee aggregators gossip during a slot: several
    /// aggregates for the same `AttestationData`, each covering a validator
    /// subset. In real mode each subset's validators sign the data and the
    /// signatures are aggregated into a type-1 proof; in mock mode the proofs
    /// are empty. The proposal tick then promotes the entries to the known
    /// pool, exactly as on a live node. Entries are inserted in a fixed order
    /// because pool insertion order pins within-entry proof choice during
    /// selection.
    pub(crate) fn seed_pool(
        &mut self,
        store: &mut Store,
        attestation_slot: u64,
    ) -> eyre::Result<SeedOutcome> {
        let data = produce_attestation_data(store, attestation_slot);
        let hashed = HashedAttestationData::new(data.clone());
        let groups = participant_groups(self.num_validators, self.proofs_per_data);

        let (entries, aggregate_seconds) = match &mut self.crypto {
            CryptoMode::Mock => {
                let entries = groups
                    .into_iter()
                    .map(|participants| {
                        (hashed.clone(), SingleMessageAggregate::empty(participants))
                    })
                    .collect();
                (entries, 0.0)
            }
            CryptoMode::Real { key_manager, .. } => {
                let start = Instant::now();
                let validators = store.head_state().validators;
                let message = data.hash_tree_root();
                let slot: u32 = attestation_slot.try_into().expect("slot exceeds u32");
                let mut entries = Vec::with_capacity(groups.len());
                for participants in groups {
                    let mut pubkeys = Vec::new();
                    let mut signatures = Vec::new();
                    for validator in validator_indices(&participants) {
                        let pubkey_bytes = &validators
                            .get(validator as usize)
                            .ok_or_else(|| eyre::eyre!("validator {validator} not in state"))?
                            .attestation_pubkey;
                        pubkeys.push(ValidatorPublicKey::from_bytes(pubkey_bytes)?);
                        let signature = key_manager
                            .sign_attestation(validator, &data)
                            .wrap_err_with(|| {
                                format!("validator {validator} failed to sign slot {slot}")
                            })?;
                        signatures.push(ValidatorSignature::from_bytes(&signature)?);
                    }
                    let count = signatures.len();
                    let proof =
                        ethlambda_crypto::aggregate_signatures(pubkeys, signatures, &message, slot)
                            .wrap_err_with(|| {
                                format!(
                                    "type-1 aggregation of {count} signatures failed at slot {slot}"
                                )
                            })?;
                    entries.push((
                        hashed.clone(),
                        SingleMessageAggregate::new(participants, proof),
                    ));
                }
                (entries, start.elapsed().as_secs_f64())
            }
        };
        store.insert_new_aggregated_payloads_batch(entries);

        // The pending pool evicts whole data-root entries FIFO once its proof
        // cap is exceeded, so an over-cap batch seeds nothing and every
        // measured block would come out empty.
        let pending = store.new_aggregated_payloads_count();
        eyre::ensure!(
            pending > 0,
            "attestations seeded for slot {attestation_slot} were evicted from the pending pool; \
             the measured workload would not match the requested parameters"
        );
        Ok(SeedOutcome {
            pool_entries: pending + store.known_aggregated_payloads_count(),
            aggregate_seconds,
        })
    }

    /// Turn the built block into a `SignedBlock` the way the proposer does. Mock
    /// mode has nothing to sign with, so it ships an empty proof, the way the
    /// fork-choice spec tests do.
    pub(crate) fn seal(
        &mut self,
        store: &Store,
        block: Block,
        aggregates: Vec<SingleMessageAggregate>,
    ) -> eyre::Result<SignedBlock> {
        match &mut self.crypto {
            CryptoMode::Mock => Ok(SignedBlock {
                message: block,
                proof: MultiMessageAggregate::default(),
            }),
            CryptoMode::Real { key_manager, .. } => {
                let head_state = store.head_state();
                Ok(seal_block(&head_state, key_manager, block, aggregates)?)
            }
        }
    }

    /// Import the sealed block. Real mode verifies the merged proof, so a bad
    /// seal fails the run instead of producing a report about invalid blocks.
    pub(crate) fn import(&self, store: &mut Store, block: SignedBlock) -> Result<(), StoreError> {
        match self.crypto {
            CryptoMode::Mock => on_block_without_verification(store, block),
            CryptoMode::Real { .. } => on_block(store, block),
        }
    }

    /// The phases one slot observes exactly once: the build phases always, plus
    /// the seal phases when the seal runs.
    pub(crate) fn phases(&self) -> impl Iterator<Item = &'static str> {
        let seal = match self.crypto {
            CryptoMode::Mock => &[][..],
            CryptoMode::Real { .. } => BLOCK_PROPOSAL_SEAL_PHASES,
        };
        BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASES
            .iter()
            .chain(seal)
            .copied()
    }
}

/// Partition validators 0..num_validators into `groups` disjoint bitfields,
/// assigning validator `i` to group `i % groups`. Every group is non-empty
/// (groups is capped at the validator count) and the union covers every
/// validator exactly once.
fn participant_groups(num_validators: u64, groups: u64) -> Vec<AggregationBits> {
    let groups = groups.clamp(1, num_validators);
    (0..groups)
        .map(|group| {
            let mut bits = AggregationBits::with_length(num_validators as usize)
                .expect("validator count is within the bitlist limit");
            for index in (group..num_validators).step_by(groups as usize) {
                bits.set(index as usize, true)
                    .expect("index is within the bitlist length");
            }
            bits
        })
        .collect()
}

/// splitmix64: tiny deterministic generator for placeholder pubkey bytes,
/// avoiding a rand dependency.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn synthetic_pubkey(rng_state: &mut u64) -> ValidatorPubkeyBytes {
    let mut bytes = [0u8; PUBLIC_KEY_SIZE];
    for chunk in bytes.chunks_mut(8) {
        let word = splitmix64(rng_state).to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_groups_partition_all_validators() {
        for (validators, groups) in [(8u64, 2u64), (8, 3), (5, 8), (1, 1), (4096, 4)] {
            let partition = participant_groups(validators, groups);
            assert_eq!(partition.len() as u64, groups.min(validators));
            let mut seen = vec![0u32; validators as usize];
            for bits in &partition {
                let indices: Vec<u64> = validator_indices(bits).collect();
                assert!(!indices.is_empty(), "every group must be non-empty");
                for index in indices {
                    seen[index as usize] += 1;
                }
            }
            assert!(
                seen.iter().all(|&count| count == 1),
                "every validator must appear in exactly one group: {seen:?}"
            );
        }
    }

    #[test]
    fn synthetic_pubkeys_are_deterministic() {
        let mut a = 42u64;
        let mut b = 42u64;
        assert_eq!(synthetic_pubkey(&mut a), synthetic_pubkey(&mut b));
        let mut c = 43u64;
        assert_ne!(synthetic_pubkey(&mut a), synthetic_pubkey(&mut c));
    }

    /// Real seeding produces a proof the verifier accepts for exactly the
    /// participants it claims. Runs the leanVM prover, so it is opt-in like the
    /// crypto crate's own aggregation tests.
    #[test]
    #[ignore = "too slow"]
    fn real_seeding_produces_verifiable_proofs() {
        use crate::benchmark::keys::KeySet;
        let keys = KeySet::generate(1, 2, 2, None).unwrap();
        let mut corpus = SyntheticCorpus::new(
            2,
            1,
            CryptoMode::Real {
                genesis_pubkeys: keys.genesis_pubkeys,
                key_manager: keys.key_manager,
            },
        );
        let mut store = corpus.genesis_store(1);
        let outcome = corpus.seed_pool(&mut store, 0).unwrap();
        assert_eq!(outcome.pool_entries, 1);
        assert!(outcome.aggregate_seconds > 0.0);

        let data = produce_attestation_data(&store, 0);
        store.promote_new_aggregated_payloads();
        let (_, proofs) = store
            .known_aggregated_payloads()
            .into_values()
            .next()
            .expect("one seeded entry");
        let proof = &proofs[0];
        let validators = store.head_state().validators;
        let pubkeys = proof
            .participant_indices()
            .map(|index| {
                ValidatorPublicKey::from_bytes(&validators[index as usize].attestation_pubkey)
                    .unwrap()
            })
            .collect();
        ethlambda_crypto::verify_aggregated_signature(
            &proof.proof,
            pubkeys,
            &data.hash_tree_root(),
            0,
        )
        .expect("seeded proof verifies");
    }
}
