//! Goldilocks: Goldfish with locks, composed with a finality gadget.
//!
//! Two independent voting processes, both chain-agnostic here:
//!
//! ```text
//! finalized   confirmed   head
//!   (FG)        (AC)      (AC)
//! ```
//!
//! * **Available chain** (AC): every slot, the slot's committee votes for a
//!   head at `t_s + Δ`; the proposer at `t_s` carries the previous slot's
//!   votes in its block; the confirmation update runs at `t_s + 6Δ`. Lock
//!   entries give every walk its anchor: an update that confirms a block
//!   locks the deepest block on its path that half of the whole committee
//!   supports (fast test) or that the previous `k − 1` confirmations agree
//!   on (slow test). An entry moves back when half a committee opposes it
//!   and expires after `k` slots. The AC has no block store of its own and
//!   never reads network attestations.
//! * **Finality gadget** (FG): attestations are finality votes
//!   `(validator, h, T, timeout, h_f, T_f)`, cast once per round of `R`
//!   slots, and only when the height pair is new. The chain state σ of every
//!   block counts them into heights, justifications and finalizations of
//!   the last `K_W` justifications, and the FG constrains the AC's fork
//!   choice to a frame (the tree rooted at `F`, the fork-choice root, the
//!   viable heads).
//!
//! The crate follows the Goldilocks specification's pseudocode. It is the
//! protocol only: each chain supplies time (in units of `Δ`, see
//! [`types::Tick`]), validates signatures, committees and proposers,
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

pub use chain_state::{ChainState, PendingFinality};
pub use duties::Proposal;
pub use fork_choice::VoteView;
pub use locks::CommitteeSizes;
pub use params::{
    DEFAULT_LOCK_PERIOD, DEFAULT_PENDING_WINDOW, DEFAULT_SLOTS_PER_ROUND, Params, ParamsError,
};
pub use store::{BlockError, Frame, Store, TickEvents};
pub use types::{
    Attestation, AttestationData, BlockInput, BlockRef, Electorate, FinalityVote, GoldfishVote,
    Height, HeightVote, LockStatus, Slot, Tick, ValidatorIndex,
};
pub use validator_client::{AttestationInput, Record, SourceFields};

#[cfg(test)]
mod simulation;
