//! The decoupled consensus protocol, chain-agnostic.
//!
//! This crate implements the complete protocol of Section 7 of the paper, as
//! formalized and machine-checked in `fradamt/verified-consensus`
//! (`docs/PROTOCOL.md` there is the reference pseudocode; section names below
//! follow it). Three layers, nested by construction at every node and time:
//!
//! ```text
//! finalized  ⪯  stable  ⪯  confirmed
//!   (FG)         (SG)       (Goldfish)
//! ```
//!
//! * **Goldfish** (available chain): every slot, the slot's committee votes for
//!   a head at `t_s + Δ`; the proposer at `t_s` carries the previous slot's
//!   votes in its block; confirmation runs at `t_s + 6Δ`.
//! * **Stabilization gadget** (SG): once per round of `R` slots every validator
//!   casts a combined attestation; its `(validator, round, safe)` projection
//!   feeds three relative-majority grades per round, which anchor the
//!   Goldfish walk and veto conflicting confirmations.
//! * **Finality gadget** (FG): the same attestation carries a height pair and a
//!   finality pair; the chain state σ of every block counts them into
//!   heights, justifications and finalizations.
//!
//! The crate is the protocol only. Each chain supplies time (in units of `Δ`,
//! see [`types::Tick`]), validates signatures, committees and proposers, and
//! carries the objects on its own wire. See `docs/decoupled_consensus.md`.

pub mod chain_state;
mod duties;
pub mod fork_choice;
pub mod grades;
pub mod params;
pub mod store;
pub mod types;
pub mod validator_client;

pub use chain_state::ChainState;
pub use duties::Proposal;
pub use fork_choice::VoteView;
pub use params::{Params, ParamsError};
pub use store::{BlockError, Store, TickEvents};
pub use types::{
    Attestation, AttestationData, BlockInput, BlockRef, Electorate, FinalityVote, GoldfishVote,
    Height, HeightVote, Round, Slot, Tick, ValidatorIndex,
};
pub use validator_client::{AttestationInput, Record, SourceFields};

#[cfg(test)]
mod simulation;
