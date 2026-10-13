//! Goldilocks: Goldfish with locks, composed with a finality gadget.
//!
//! Two independent voting processes, both chain-agnostic here:
//!
//! ```text
//! finalized  ⪯  confirmed (locked)  ⪯  head
//!   (FG)          (AC)                 (AC)
//! ```
//!
//! * **Available chain** (AC): every slot, the slot's committee votes for a
//!   head at `t_s + Δ`; the proposer at `t_s` carries the previous slot's
//!   votes in its block; the confirmation update runs at `t_s + 6Δ`. Locks
//!   give the walk its anchor: a fast lock when half of a whole committee
//!   supports a block, a slow lock after `k` consecutive confirmations; a
//!   lock steps back when half a committee opposes it and expires after `k`
//!   slots. The AC has no block store of its own and never reads network
//!   attestations.
//! * **Finality gadget** (FG): attestations are pure finality votes
//!   `(validator, h, T, timeout, h_f, T_f)`, cast whenever a validator has
//!   something new to say rather than once per round. The chain state σ of
//!   every block counts them into heights, justifications and
//!   finalizations, and the FG constrains the AC's fork choice to a frame
//!   (the tree rooted at `F`, the fork-choice root, the viable heads).
//!
//! The crate is the protocol only. Each chain supplies time (in units of `Δ`,
//! see [`types::Tick`]), validates signatures, committees and proposers,
//! declares committee sizes, and carries the objects on its own wire. See
//! `docs/decoupled_consensus.md`.

pub mod chain_state;
mod duties;
pub mod fork_choice;
mod locks;
pub mod params;
pub mod store;
pub mod types;
pub mod validator_client;

pub use chain_state::ChainState;
pub use duties::Proposal;
pub use fork_choice::VoteView;
pub use locks::CommitteeSizes;
pub use params::{DEFAULT_LOCK_PERIOD, Params, ParamsError};
pub use store::{BlockError, Frame, Store, TickEvents};
pub use types::{
    Attestation, AttestationData, BlockInput, BlockRef, Electorate, FinalityVote, GoldfishVote,
    Height, HeightVote, LockStatus, Slot, Tick, ValidatorIndex,
};
pub use validator_client::{AttestationInput, Record, SourceFields};

#[cfg(test)]
mod simulation;
