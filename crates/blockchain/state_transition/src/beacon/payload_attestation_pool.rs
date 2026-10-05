//! Payload timeliness committee votes, held until a proposer packs them.
//!
//! Gloas `validator.md` ("Payload attestations"): the proposer of slot `N`
//! listens to `payload_attestation_message`, keeps the votes on its parent
//! block (slot `N - 1`), and aggregates every vote sharing one
//! `PayloadAttestationData` into a single `PayloadAttestation` for its body.
//!
//! Only messages that already passed validation go in (gossip's
//! `payload_attestation_message` verdict, or the Beacon API's pool endpoint
//! after the same checks), since that is what makes combining their
//! signatures safe: one bad share fails the whole aggregate, and with it the
//! block that carries it.
//!
//! The method signatures below are the shared contract between what fills the
//! pool and block production, which only calls [`messages_for`].
//!
//! [`messages_for`]: PayloadAttestationPool::messages_for

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use ethlambda_types::beacon::{
    containers::gloas::{PayloadAttestationData, PayloadAttestationMessage},
    primitives::{Root, Slot},
};

/// The pool, shared between whatever fills it (the Beacon API's pool
/// endpoint, the `payload_attestation_message` gossip verdict) and what reads
/// it (block production, `GET /eth/v1/beacon/pool/payload_attestations`).
/// There must be exactly one per node.
pub type SharedPayloadAttestationPool = Arc<Mutex<PayloadAttestationPool>>;

/// Votes sharing one `PayloadAttestationData`, by voting validator. The data
/// has no `Hash`/`Ord`, and a slot holds only a handful of distinct values
/// (the committee splits at most a few ways), so a linear scan over a `Vec`
/// is both simple and fast.
type VotesByData = Vec<(
    PayloadAttestationData,
    BTreeMap<u64, PayloadAttestationMessage>,
)>;

#[derive(Debug, Default)]
pub struct PayloadAttestationPool {
    /// slot -> data -> validator index -> message. Keyed by slot first so
    /// pruning and the per-slot queries never visit unrelated slots.
    messages: BTreeMap<Slot, VotesByData>,
}

impl PayloadAttestationPool {
    /// Record a validated message. Returns `false` (and keeps the first) when
    /// the pool already holds a message from the same validator for the same
    /// `data`. Drops every message for a slot more than one before the
    /// message's own.
    pub fn insert(&mut self, message: PayloadAttestationMessage) -> bool {
        self.prune_before(message.data.slot.saturating_sub(1));
        let by_data = self.messages.entry(message.data.slot).or_default();
        let votes = match by_data.iter().position(|(data, _)| *data == message.data) {
            Some(position) => &mut by_data[position].1,
            None => {
                by_data.push((message.data, BTreeMap::new()));
                &mut by_data.last_mut().expect("just pushed").1
            }
        };
        if votes.contains_key(&message.validator_index) {
            return false;
        }
        votes.insert(message.validator_index, message);
        true
    }

    /// Every held message voting on `beacon_block_root` at `slot`, in any
    /// order, one per (validator, data).
    pub fn messages_for(
        &self,
        slot: Slot,
        beacon_block_root: Root,
    ) -> Vec<PayloadAttestationMessage> {
        self.messages
            .get(&slot)
            .into_iter()
            .flatten()
            .filter(|(data, _)| data.beacon_block_root == beacon_block_root)
            .flat_map(|(_, votes)| votes.values().cloned())
            .collect()
    }

    /// Every held message, or only those for `slot` when given.
    pub fn all(&self, slot: Option<Slot>) -> Vec<PayloadAttestationMessage> {
        self.messages
            .iter()
            .filter(|(held, _)| slot.is_none_or(|slot| **held == slot))
            .flat_map(|(_, by_data)| by_data.iter())
            .flat_map(|(_, votes)| votes.values().cloned())
            .collect()
    }

    /// Drop every message for a slot before `slot`.
    pub fn prune_before(&mut self, slot: Slot) {
        self.messages = self.messages.split_off(&slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::primitives::BlsSignature;

    fn message(
        validator_index: u64,
        slot: Slot,
        root: u8,
        present: bool,
    ) -> PayloadAttestationMessage {
        PayloadAttestationMessage {
            validator_index,
            data: PayloadAttestationData {
                beacon_block_root: Root::from([root; 32]),
                slot,
                payload_present: present,
                blob_data_available: true,
            },
            signature: BlsSignature::default(),
        }
    }

    #[test]
    fn insert_dedups_per_validator_and_data() {
        let mut pool = PayloadAttestationPool::default();
        assert!(pool.insert(message(1, 10, 1, true)));
        assert!(!pool.insert(message(1, 10, 1, true)));
        // Same validator, different data: an equivocation, kept as its own entry.
        assert!(pool.insert(message(1, 10, 1, false)));
        assert!(pool.insert(message(2, 10, 1, true)));
        assert_eq!(pool.all(Some(10)).len(), 3);
    }

    #[test]
    fn messages_for_filters_by_slot_and_root() {
        let mut pool = PayloadAttestationPool::default();
        pool.insert(message(1, 10, 1, true));
        pool.insert(message(2, 10, 2, true));
        pool.insert(message(3, 11, 1, true));
        let held = pool.messages_for(10, Root::from([1; 32]));
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].validator_index, 1);
        assert!(pool.messages_for(12, Root::from([1; 32])).is_empty());
    }

    #[test]
    fn insert_prunes_to_current_and_previous_slot() {
        let mut pool = PayloadAttestationPool::default();
        pool.insert(message(1, 8, 1, true));
        pool.insert(message(1, 9, 1, true));
        pool.insert(message(1, 10, 1, true));
        let slots: Vec<Slot> = pool.all(None).iter().map(|m| m.data.slot).collect();
        assert_eq!(slots, vec![9, 10]);
    }

    #[test]
    fn prune_before_drops_older_slots() {
        let mut pool = PayloadAttestationPool::default();
        pool.insert(message(1, 5, 1, true));
        pool.insert(message(1, 6, 1, true));
        pool.prune_before(6);
        assert_eq!(pool.all(None).len(), 1);
        assert!(pool.all(Some(5)).is_empty());
    }
}
