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
//! The method signatures below are the shared contract between the tasks
//! that fill the pool and block production, which only calls
//! [`messages_for`]. The storage behind them is a placeholder.
//!
//! [`messages_for`]: PayloadAttestationPool::messages_for

use std::sync::{Arc, Mutex};

use ethlambda_types::beacon::{
    containers::gloas::PayloadAttestationMessage,
    primitives::{Root, Slot},
};

/// The pool, shared between whatever fills it (the Beacon API's pool
/// endpoint, the `payload_attestation_message` gossip verdict) and what reads
/// it (block production, `GET /eth/v1/beacon/pool/payload_attestations`).
/// There must be exactly one per node.
pub type SharedPayloadAttestationPool = Arc<Mutex<PayloadAttestationPool>>;

#[derive(Debug, Default)]
pub struct PayloadAttestationPool {
    /// Placeholder storage; the PTC task may restructure it freely.
    messages: Vec<PayloadAttestationMessage>,
}

impl PayloadAttestationPool {
    /// Record a validated message. Returns `false` (and keeps the first) when
    /// the pool already holds a message from the same validator for the same
    /// `data`. Drops every message for a slot more than one before the
    /// message's own.
    pub fn insert(&mut self, message: PayloadAttestationMessage) -> bool {
        self.prune_before(message.data.slot.saturating_sub(1));
        let held = self.messages.iter().any(|held| {
            held.validator_index == message.validator_index && held.data == message.data
        });
        if !held {
            self.messages.push(message);
        }
        !held
    }

    /// Every held message voting on `beacon_block_root` at `slot`, in any
    /// order, one per (validator, data).
    pub fn messages_for(
        &self,
        slot: Slot,
        beacon_block_root: Root,
    ) -> Vec<PayloadAttestationMessage> {
        self.messages
            .iter()
            .filter(|held| {
                held.data.slot == slot && held.data.beacon_block_root == beacon_block_root
            })
            .cloned()
            .collect()
    }

    /// Every held message, or only those for `slot` when given.
    pub fn all(&self, slot: Option<Slot>) -> Vec<PayloadAttestationMessage> {
        self.messages
            .iter()
            .filter(|held| slot.is_none_or(|slot| held.data.slot == slot))
            .cloned()
            .collect()
    }

    /// Drop every message for a slot before `slot`.
    pub fn prune_before(&mut self, slot: Slot) {
        self.messages.retain(|held| held.data.slot >= slot);
    }
}
