//! Synthetic benchmark corpus: deterministic validators, a genesis store, and
//! per-slot attestation-pool seeding.

use std::sync::Arc;

use ethlambda_blockchain::store::produce_attestation_data;
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_types::{
    attestation::{AggregationBits, HashedAttestationData},
    block::SingleMessageAggregate,
    state::{State, Validator, ValidatorPubkeyBytes},
};

/// Fixed genesis time for synthetic runs. The harness derives every tick
/// timestamp from slot numbers relative to this value and never reads the wall
/// clock, so runs are reproducible at any time of day.
const GENESIS_TIME: u64 = 1_700_000_000;

pub(crate) struct SyntheticCorpus {
    num_validators: u64,
    proofs_per_data: u64,
}

impl SyntheticCorpus {
    pub(crate) fn new(num_validators: u64, proofs_per_data: u64) -> Self {
        Self {
            num_validators,
            proofs_per_data,
        }
    }

    /// Build a genesis store over an in-memory backend with `num_validators`
    /// seed-derived validators.
    ///
    /// Pubkeys are deterministic placeholder bytes: in mock-crypto mode no code
    /// path decodes them (signature verification is skipped and best-proof
    /// compaction never resolves pubkeys).
    pub(crate) fn genesis_store(&self, seed: u64) -> Store {
        let mut rng_state = seed;
        let validators = (0..self.num_validators)
            .map(|index| Validator {
                attestation_pubkey: synthetic_pubkey(&mut rng_state),
                proposal_pubkey: synthetic_pubkey(&mut rng_state),
                index,
            })
            .collect();
        let genesis_state = State::from_genesis(GENESIS_TIME, validators);
        Store::from_anchor_state(Arc::new(InMemoryBackend::new()), genesis_state)
    }

    /// Seed the pending ("new") pool with the full validator set's attestations
    /// for `attestation_slot`, split into `proofs_per_data` disjoint aggregates.
    ///
    /// Mirrors what committee aggregators gossip during a slot: several
    /// aggregates for the same `AttestationData`, each covering a validator
    /// subset. The proposal tick then promotes them to the known pool, exactly
    /// as on a live node. Entries are inserted in a fixed order because pool
    /// insertion order pins within-entry proof choice during selection.
    pub(crate) fn seed_pool(&self, store: &mut Store, attestation_slot: u64) {
        let data = produce_attestation_data(store, attestation_slot);
        let entries = participant_groups(self.num_validators, self.proofs_per_data)
            .into_iter()
            .map(|participants| {
                (
                    HashedAttestationData::new(data.clone()),
                    SingleMessageAggregate::empty(participants),
                )
            })
            .collect();
        store.insert_new_aggregated_payloads_batch(entries);
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
    use ethlambda_types::attestation::validator_indices;

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
}
