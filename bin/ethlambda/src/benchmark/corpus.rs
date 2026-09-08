//! Synthetic benchmark corpus: deterministic validators, a genesis store, and
//! per-slot attestation-pool seeding.

use std::sync::Arc;
use std::time::Instant;

use ethlambda_blockchain::key_manager::KeyManager;
use ethlambda_blockchain::store::produce_attestation_data;
use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_types::{
    attestation::{AggregationBits, HashedAttestationData, validator_indices},
    block::SingleMessageAggregate,
    constants::DEFAULT_MILLISECONDS_PER_SLOT,
    primitives::HashTreeRoot as _,
    state::{State, Validator, ValidatorPubkeyBytes},
};
use eyre::WrapErr as _;

/// Fixed genesis time for synthetic runs. The harness derives every tick
/// timestamp from slot numbers relative to this value and never reads the wall
/// clock, so runs are reproducible at any time of day.
const GENESIS_TIME: u64 = 1_700_000_000;

/// How the corpus produces pool entries and genesis pubkeys.
pub(crate) enum CryptoMode {
    /// Empty placeholder proofs and placeholder pubkey bytes. No code path
    /// decodes either: verification is skipped and best-proof compaction never
    /// resolves pubkeys.
    Mock,
    /// Real XMSS signatures aggregated into real leanVM type-1 proofs, over the
    /// genesis pubkeys of the seeded key set.
    Real {
        genesis_pubkeys: Vec<(ValidatorPubkeyBytes, ValidatorPubkeyBytes)>,
        attestation_pubkeys: Vec<ValidatorPublicKey>,
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
    /// subset. In real mode each subset's validators sign the data through
    /// `key_manager` and the signatures are aggregated into a type-1 proof; in
    /// mock mode the proofs are empty. The proposal tick then promotes the
    /// entries to the known pool, exactly as on a live node. Entries are
    /// inserted in a fixed order because pool insertion order pins within-entry
    /// proof choice during selection.
    pub(crate) fn seed_pool(
        &self,
        store: &mut Store,
        key_manager: &mut KeyManager,
        attestation_slot: u64,
    ) -> eyre::Result<SeedOutcome> {
        let data = produce_attestation_data(store, attestation_slot);
        let groups = participant_groups(self.num_validators, self.proofs_per_data);

        let aggregate_start = Instant::now();
        let entries = match &self.crypto {
            CryptoMode::Mock => groups
                .into_iter()
                .map(|participants| {
                    (
                        HashedAttestationData::new(data.clone()),
                        SingleMessageAggregate::empty(participants),
                    )
                })
                .collect(),
            CryptoMode::Real {
                attestation_pubkeys,
                ..
            } => {
                let message = data.hash_tree_root();
                let slot: u32 = attestation_slot.try_into().expect("slot exceeds u32");
                let mut entries = Vec::with_capacity(groups.len());
                for participants in groups {
                    let indices: Vec<u64> = validator_indices(&participants).collect();
                    let mut pubkeys = Vec::with_capacity(indices.len());
                    let mut signatures = Vec::with_capacity(indices.len());
                    for &validator in &indices {
                        let bytes = key_manager
                            .sign_attestation(validator, &data)
                            .wrap_err_with(|| {
                                format!("validator {validator} failed to sign slot {slot}")
                            })?;
                        let signature = ValidatorSignature::from_bytes(&bytes)
                            .map_err(|err| eyre::eyre!("signature bytes: {}", err.0))?;
                        pubkeys.push(attestation_pubkeys[validator as usize].clone());
                        signatures.push(signature);
                    }
                    let proof =
                        ethlambda_crypto::aggregate_signatures(pubkeys, signatures, &message, slot)
                            .wrap_err_with(|| {
                                format!(
                                    "type-1 aggregation of {} signatures failed at slot {slot}",
                                    indices.len()
                                )
                            })?;
                    entries.push((
                        HashedAttestationData::new(data.clone()),
                        SingleMessageAggregate::new(participants, proof),
                    ));
                }
                entries
            }
        };
        let aggregate_seconds = match self.crypto {
            CryptoMode::Mock => 0.0,
            CryptoMode::Real { .. } => aggregate_start.elapsed().as_secs_f64(),
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
    let mut bytes = [0u8; 52];
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
        let corpus = SyntheticCorpus::new(
            2,
            1,
            CryptoMode::Real {
                genesis_pubkeys: keys.genesis_pubkeys(),
                attestation_pubkeys: keys.attestation_pubkeys().unwrap(),
            },
        );
        let mut key_manager = keys.into_key_manager().unwrap();
        let mut store = corpus.genesis_store(1);
        let outcome = corpus.seed_pool(&mut store, &mut key_manager, 0).unwrap();
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
        let pubkeys = proof
            .participant_indices()
            .map(|index| {
                let validator = &store.head_state().validators[index as usize];
                ValidatorPublicKey::from_bytes(&validator.attestation_pubkey).unwrap()
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
