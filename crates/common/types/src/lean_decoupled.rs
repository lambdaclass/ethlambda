//! Lean wire containers for the decoupled consensus mode.
//!
//! A lean chain running the decoupled protocol replaces 3SF-mini's blocks and
//! votes with these. They are deliberately separate types on separate topics:
//! the 3SF-mini containers stay byte-for-byte what other lean clients speak.
//!
//! Goldilocks has a validator sign up to two messages per slot (a Goldfish
//! vote every slot, and an attestation in a slot where it has something new
//! to say), and an XMSS one-time key may sign only one message per epoch, so
//! the attestation key signs on a doubled epoch grid: see
//! [`goldfish_vote_epoch`] and [`attestation_epoch`]. Attestation data names
//! no slot, so every attestation envelope carries the slot it was signed in.
//! Blocks keep the proposal key at `epoch = slot`.
//!
//! Goldfish votes keep individual signatures: a block carries the previous
//! slot's votes one interval after they are cast, too soon for a leanVM
//! proof. Attestations are aggregated. A validator signs its attestation's
//! *data* root, so every validator with the same view in the same slot signs
//! the same message, and travels on its subnet
//! ([`attestation_subnet`]) as a [`SignedDecoupledAttestation`]. Subnet
//! aggregators fold them into an [`AggregatedDecoupledAttestation`], merge
//! those across subnets, and blocks carry only aggregates.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};

use crate::attestation::{AggregationBits, XmssSignature};
use crate::block::ByteList512KiB;
use crate::decoupled::{Attestation, AttestationData, GoldfishVote, Slot};
use crate::primitives::H256;
use crate::state::VALIDATOR_REGISTRY_LIMIT;

/// Goldfish votes a block may carry: at most two per validator.
pub const MAX_BLOCK_VOTES: usize = 2 * VALIDATOR_REGISTRY_LIMIT;

/// Aggregated attestations a block may carry. A round's attestations
/// normally share one data, so a handful of entries covers every validator;
/// the bound keeps a block of near-cap proofs inside the gossip size limit.
pub const MAX_BLOCK_AGGREGATES: usize = 16;

/// The attestation subnet of `validator`: `validator mod committee_count`.
pub fn attestation_subnet(validator: u64, committee_count: u64) -> u64 {
    validator % committee_count.max(1)
}

/// The signing subgroup of `validator` within its subnet:
/// `⌊validator / committee_count⌋ mod subgroups`.
///
/// Dividing by the subnet count first spreads every subnet over all the
/// subgroups. `validator mod subgroups` would not: with as many subnets as
/// subgroups, a whole subnet would land in one subgroup.
pub fn attestation_subgroup(validator: u64, committee_count: u64, subgroups: u64) -> u64 {
    (validator / committee_count.max(1)) % subgroups.max(1)
}

/// The XMSS epoch a Goldfish vote of `slot` is signed at: `2 · slot`.
pub fn goldfish_vote_epoch(slot: Slot) -> u64 {
    2 * slot
}

/// The XMSS epoch an attestation signed in `slot` is signed at:
/// `2 · slot + 1`. Odd, so it never meets a vote's epoch, and at most one
/// attestation per slot.
pub fn attestation_epoch(slot: Slot) -> u64 {
    2 * slot + 1
}

/// A Goldfish vote signed with the voter's attestation key at
/// [`goldfish_vote_epoch`], over the vote's `hash_tree_root`.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedGoldfishVote {
    pub vote: GoldfishVote,
    pub signature: XmssSignature,
}

/// An attestation signed with the attester's attestation key at
/// [`attestation_epoch`] of `slot`, over the `hash_tree_root` of its *data*.
///
/// The validator index is not signed, so every validator signing one data in
/// one slot signs one message, which is what lets leanVM aggregate them. A
/// signature still binds its signer: it verifies under that validator's key
/// only. `slot` is not signed either: it only picks the epoch, and an XMSS
/// signature verifies at no epoch but its own.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedDecoupledAttestation {
    pub attestation: Attestation,
    pub slot: Slot,
    pub signature: XmssSignature,
}

/// The attestations of every validator in `participants`, all over `data` and
/// signed in `slot`, as one leanVM proof.
///
/// `proof` is the `to_bytes_without_pubkeys` form: the verifier rebuilds the
/// signer set from `participants` and its own registry, and the proof binds
/// the message (`data`'s root) and epoch ([`attestation_epoch`] of `slot`).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct AggregatedDecoupledAttestation {
    pub data: AttestationData,
    pub slot: Slot,
    pub participants: AggregationBits,
    pub proof: ByteList512KiB,
}

impl AggregatedDecoupledAttestation {
    /// The validators the proof binds, ascending.
    pub fn participant_indices(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.participants.len())
            .filter(|&index| self.participants.get(index) == Some(true))
            .map(|index| index as u64)
    }

    /// One engine attestation per participant.
    pub fn attestations(&self) -> impl Iterator<Item = Attestation> + '_ {
        self.participant_indices().map(|validator| Attestation {
            validator,
            data: self.data.clone(),
        })
    }
}

/// The protocol content of a block.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DecoupledBlockBody {
    /// `B.votes`: every previous-slot vote the proposer held.
    pub votes: SszList<SignedGoldfishVote, MAX_BLOCK_VOTES>,
    /// `B.support_votes`: bit `i` set when `votes[i]` was resolved at proposal
    /// time.
    pub support: SszBitlist<MAX_BLOCK_VOTES>,
    /// `B.attestations`, as aggregates: every participant of every entry.
    pub attestations: SszList<AggregatedDecoupledAttestation, MAX_BLOCK_AGGREGATES>,
}

/// A decoupled lean block. No state root: the only consensus state is the
/// finality gadget's chain state, which names the block it belongs to and so
/// cannot be committed to by it.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DecoupledBlock {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub body: DecoupledBlockBody,
}

/// A block signed with the proposer's proposal key at `epoch = slot`, over the
/// block's `hash_tree_root`.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedDecoupledBlock {
    pub message: DecoupledBlock,
    pub signature: XmssSignature,
}

/// Request for decoupled blocks by root.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct DecoupledBlocksByRootRequest {
    pub roots: SszList<H256, 1024>,
}

impl DecoupledBlock {
    /// The anchor block of a decoupled lean chain: slot 0, no content, its
    /// parent root the genesis state's root, so two chains with different
    /// validator sets or genesis times have different genesis blocks.
    pub fn genesis(genesis_state_root: H256) -> Self {
        Self {
            slot: 0,
            proposer_index: 0,
            parent_root: genesis_state_root,
            body: DecoupledBlockBody {
                votes: Default::default(),
                support: Default::default(),
                attestations: Default::default(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn every_subnet_spreads_over_every_subgroup() {
        // Four subnets and four subgroups: `validator mod 4` would put a whole
        // subnet in one subgroup.
        let (committees, subgroups) = (4, 4);
        for subnet in 0..committees {
            let seen: HashSet<u64> = (0..64)
                .filter(|&validator| attestation_subnet(validator, committees) == subnet)
                .map(|validator| attestation_subgroup(validator, committees, subgroups))
                .collect();
            assert_eq!(seen.len(), subgroups as usize, "subnet {subnet}");
        }
    }

    #[test]
    fn subgroups_split_a_subnet_evenly() {
        let (committees, subgroups) = (3, 4);
        let mut counts = [0usize; 4];
        for validator in (0..96).filter(|&v| attestation_subnet(v, committees) == 1) {
            counts[attestation_subgroup(validator, committees, subgroups) as usize] += 1;
        }
        assert_eq!(counts, [8, 8, 8, 8]);
    }
}
