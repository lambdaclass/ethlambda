//! EIP-8453's fork choice, chain-agnostic.
//!
//! This crate implements the fork choice, finality gadget rules and validator
//! signing rules of EIP-8453 ("Decoupled Consensus") as specified on
//! consensus-specs branch `decoupled-consensus` at
//! `0f4fa3ffdd26ec083ff4dba65645d81433178413`
//! (`specs/_features/eip8453/{fork-choice,beacon-chain,validator}.md`), built
//! on gloas/heze's payload-aware `ForkChoiceNode`s. Two parts:
//!
//! * **Finality gadget (FG)**: heights, each with a target block; a quorum of
//!   target votes justifies the target and moves to the next height, a quorum
//!   of target votes and timeouts moves on after `TIMEOUT_DELAY_SLOTS`, and a
//!   quorum of finality pairs finalizes a pending justification. The rules
//!   live in a chain state per block; [`chain_state`] is lean's copy of what
//!   the beacon chain keeps in its `BeaconState`.
//! * **Available chain (AC)**: every slot a head vote committee votes for a
//!   head at a quarter of the slot; a GHOST walk over seats picks the head
//!   inside the FG frame, from an anchor the live locks set; the previous
//!   slot is confirmed at half the slot, and confirmations create locks
//!   (fast: half the seats; slow: under every saved confirmation of the
//!   window) that veto conflicting confirmations until they expire or are
//!   unlocked.
//!
//! The crate is the protocol only. Each chain supplies time (in units of `Δ`,
//! see [`params`]), state transitions (the FG checkpoints of every block),
//! signatures, committees and payload verification, and carries the objects
//! on its own wire. See `docs/decoupled_consensus.md`.

pub mod chain_state;
mod confirmation;
mod duties;
pub mod fork_choice;
mod invalidation;
pub mod params;
pub mod store;
pub mod types;
pub mod validator_client;
mod views;

pub use chain_state::{ChainState, ChainStates};
pub use duties::{AcFrame, AcProposal, FinalityAttestationInput, head_vote_data};
pub use fork_choice::{FgFrame, View, get_equivocating_indices};
pub use invalidation::PayloadInvalidation;
pub use params::{Params, ParamsError};
pub use store::{BlockError, CommitteeError, HeadVoteError, PayloadError, Store, TickEvents};
pub use types::{
    AcVote, Anchor, AttestationData, BlockInput, BlockRef, Electorate, FgCheckpoints,
    ForkChoiceNode, HeadVote, HeadVoteCommittee, HeadVoteCommittees, HeadVoteData, HeadVoteMessage,
    Height, HeightCheckpoint, INFINITE_TIME, PayloadStatus, Round, Slot, Tick, ValidatorIndex,
};
pub use validator_client::{FinalitySigningRecord, is_slashable_attestation_data};
pub use views::get_ac_vote;

#[cfg(test)]
mod simulation;
#[cfg(test)]
mod tests;
