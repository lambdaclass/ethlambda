//! Lean wire containers for the decoupled consensus (EIP-8453) mode.
//!
//! A lean chain running the decoupled protocol replaces 3SF-mini's blocks and
//! votes with these. They are deliberately separate types on separate topics:
//! the 3SF-mini containers stay byte-for-byte what other lean clients speak,
//! and a decoupled lean network is ethlambda-only.
//!
//! Every object carries an individual XMSS signature. A validator signs a head
//! vote every slot and an FG attestation once per round, in its attestation
//! slot, and an XMSS one-time key may sign only one message per epoch, so the
//! attestation key signs on a doubled epoch grid: see [`head_vote_epoch`] and
//! [`attestation_epoch`]. Blocks keep the proposal key at `epoch = slot`.
//!
//! Signatures are not aggregated: leanVM aggregation costs seconds per proof,
//! and a block carries the previous slot's votes three quarters of a slot after
//! they are cast. Individual signatures are 1208 bytes, which is fine at devnet
//! scale; aggregation is the deployment-scale follow-up.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};

use crate::attestation::XmssSignature;
use crate::decoupled::{AttestationData, HeadVoteMessage, Round, Slot, ValidatorIndex};
use crate::primitives::H256;

/// Head votes a block may carry.
pub const MAX_BLOCK_HEAD_VOTES: usize = 8192;

/// FG attestations a block may carry.
pub const MAX_BLOCK_ATTESTATIONS: usize = 16384;

/// The XMSS epoch a head vote of `slot` is signed at: `2 · slot`.
pub fn head_vote_epoch(slot: Slot) -> u64 {
    2 * slot
}

/// The XMSS epoch an FG attestation cast in `slot` is signed at:
/// `2 · slot + 1`. Odd, so it never meets a head vote's epoch, and a validator
/// attests in one slot per round.
pub fn attestation_epoch(slot: Slot) -> u64 {
    2 * slot + 1
}

/// The slot in which `validator` casts its FG attestation of `round`.
///
/// EIP-8453 spreads `ATTESTATION_COMMITTEES_PER_ROUND` committees evenly over a
/// round's slots (`compute_attestation_committee_slot`). Lean has no
/// committees: validator `v` sits in committee `v mod R`, one per slot.
pub fn attestation_slot(round: Round, validator: ValidatorIndex, slots_per_round: u64) -> Slot {
    round * slots_per_round + validator % slots_per_round
}

/// A head vote signed with the voter's attestation key at [`head_vote_epoch`],
/// over the message's `hash_tree_root`.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedHeadVote {
    pub message: HeadVoteMessage,
    pub signature: XmssSignature,
}

/// One validator's FG attestation of `round`. The round is lean's stand-in for
/// the spec's unsigned `SingleAttestation.epoch`: it fixes the slot the
/// attestation was cast in, hence the XMSS epoch it is signed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SszEncode, SszDecode, HashTreeRoot)]
pub struct FinalityAttestation {
    pub validator_index: ValidatorIndex,
    pub round: Round,
    pub data: AttestationData,
}

/// An FG attestation signed with the attester's attestation key at
/// [`attestation_epoch`] of its [`attestation_slot`], over the message's
/// `hash_tree_root`.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedFinalityAttestation {
    pub message: FinalityAttestation,
    pub signature: XmssSignature,
}

/// The protocol content of a block.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DecoupledBlockBody {
    /// `body.head_votes`: the previous slot's head votes the proposer held,
    /// one voter each.
    pub head_votes: SszList<SignedHeadVote, MAX_BLOCK_HEAD_VOTES>,
    /// `body.head_vote_support`: bit `i` set when the proposer counted
    /// `head_votes[i]` as support in its proposal view.
    pub head_vote_support: SszBitlist<MAX_BLOCK_HEAD_VOTES>,
    /// `body.attestations`.
    pub attestations: SszList<SignedFinalityAttestation, MAX_BLOCK_ATTESTATIONS>,
}

/// A decoupled lean block. No state root: the only consensus state is the
/// finality gadget's chain state, which names the block it belongs to (a
/// height's target is the block that entered it) and so cannot be committed to
/// by it. Lean has no execution payloads, so every block builds on its
/// parent's EMPTY branch.
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
                head_votes: Default::default(),
                head_vote_support: Default::default(),
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
    fn the_signing_epochs_never_collide() {
        // One head vote per slot, one attestation per validator per round in
        // its own slot: no epoch is signed twice by one validator.
        for slots_per_round in [1, 3, 4, 8] {
            for validator in 0..10 {
                let mut epochs = HashSet::new();
                for slot in 0..100 {
                    assert!(epochs.insert(head_vote_epoch(slot)));
                }
                for round in 0..(100 / slots_per_round) {
                    let slot = attestation_slot(round, validator, slots_per_round);
                    assert_eq!(slot / slots_per_round, round);
                    assert!(epochs.insert(attestation_epoch(slot)));
                }
            }
        }
    }
}
