//! Lean wire containers for the decoupled consensus mode.
//!
//! A lean chain running the decoupled protocol replaces 3SF-mini's blocks and
//! votes with these. They are deliberately separate types on separate topics:
//! the 3SF-mini containers stay byte-for-byte what other lean clients speak.
//!
//! Every object carries an individual XMSS signature. Goldilocks has a
//! validator sign up to two messages per slot (a Goldfish vote every slot, and
//! an attestation in a slot where it has something new to say), and an XMSS
//! one-time key may sign only one message per epoch, so the attestation key
//! signs on a doubled epoch grid: see [`goldfish_vote_epoch`] and
//! [`attestation_epoch`]. Attestation data names no slot, so the signed
//! envelope carries the slot it was signed in. Blocks keep the proposal key at
//! `epoch = slot`.
//!
//! Signatures are not aggregated: leanVM aggregation costs seconds per proof,
//! and a block carries the previous slot's votes three intervals after they
//! are cast. Individual signatures are 1208 bytes, which is fine at devnet
//! scale; aggregation is the deployment-scale follow-up.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};

use crate::attestation::XmssSignature;
use crate::decoupled::{Attestation, GoldfishVote, Slot};
use crate::primitives::H256;

/// Goldfish votes a block may carry: at most two per validator.
pub const MAX_BLOCK_VOTES: usize = 8192;

/// Attestations a block may carry.
pub const MAX_BLOCK_ATTESTATIONS: usize = 16384;

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
/// [`attestation_epoch`] of `slot`, over the attestation's `hash_tree_root`.
///
/// `slot` is not signed: it only picks the epoch, and an XMSS signature
/// verifies at no epoch but its own.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedDecoupledAttestation {
    pub attestation: Attestation,
    pub slot: Slot,
    pub signature: XmssSignature,
}

/// The protocol content of a block.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DecoupledBlockBody {
    /// `B.votes`: every previous-slot vote the proposer held.
    pub votes: SszList<SignedGoldfishVote, MAX_BLOCK_VOTES>,
    /// `B.support_votes`: bit `i` set when `votes[i]` was resolved at proposal
    /// time.
    pub support: SszBitlist<MAX_BLOCK_VOTES>,
    /// `B.attestations`.
    pub attestations: SszList<SignedDecoupledAttestation, MAX_BLOCK_ATTESTATIONS>,
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
