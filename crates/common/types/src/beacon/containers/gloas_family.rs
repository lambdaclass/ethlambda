//! Borrowed views of the gloas-family states: gloas, EIP-8483 and PQ.
//!
//! The three forks' states are separate structs, since each derives its own SSZ
//! shape, but they share every field the ePBS (EIP-7732) machinery reads: the
//! builder registry, the payment queues, the latest bid, the payload timeliness
//! committee window, the progressive pending queues. [`GloasFamily`] and
//! [`GloasFamilyMut`] borrow exactly those fields, at one type whichever of the
//! three states they come from, so the gloas state transition runs on all three
//! instead of existing once per fork. `fork` says which one it was, for the
//! few places the later forks change a rule.
//!
//! What is *not* here: `validators` and `balances` (the registry accessors on
//! [`BeaconState`](super::BeaconState) already cover every fork, and the PQ
//! element differs), the sync committees (the PQ fork removes them), and each
//! later fork's own tail (EIP-8483's registrations, PQ's preregistrations and
//! aggregation committee window), which only that fork's code reads.
//!
//! The PQ state's builders are a [`super::pq::Builders`], which keeps gloas's
//! records in memory (see that type's doc); the view borrows the gloas list
//! inside it.

use super::fulu::ProposerLookahead;
use super::gloas::{
    BuilderIndex, BuilderPendingPayments, BuilderPendingWithdrawals, Builders, EpochParticipation,
    ExecutionPayloadAvailability, ExecutionPayloadBid, InactivityScores,
    PayloadTimelinessCommitteeWindow, PendingConsolidations, PendingDeposits,
    PendingPartialWithdrawals, Withdrawals,
};
use super::shared::{
    BeaconBlockHeader, BlockRoots, Checkpoint, Eth1Data, Eth1DataVotes, HistoricalRoots,
    HistoricalSummaries, JustificationBits, RandaoMixes, Slashings, StateRoots,
};
use super::{BeaconState, eip8483, gloas, pq};
use crate::beacon::fork::ForkName;
use crate::beacon::primitives::{
    Epoch, ExecutionBlockHash, Gwei, Root, Slot, ValidatorIndex, WithdrawalIndex,
};

/// Declares both views over one field list, and their constructors from each
/// of the three states, so a field cannot be in one view and not the other.
macro_rules! gloas_family {
    ($($field:ident: $ty:ty),* $(,)?) => {
        /// The gloas-family fields of a gloas, EIP-8483 or PQ state. See the
        /// module doc.
        pub struct GloasFamily<'a> {
            /// Which of the three forks the state is.
            pub fork: ForkName,
            /// The builder registry, gloas's records whichever fork.
            pub builders: &'a Builders,
            $(pub $field: &'a $ty,)*
        }

        /// [`GloasFamily`], mutably.
        pub struct GloasFamilyMut<'a> {
            /// Which of the three forks the state is.
            pub fork: ForkName,
            /// The builder registry, gloas's records whichever fork.
            pub builders: &'a mut Builders,
            $(pub $field: &'a mut $ty,)*
        }

        impl<'a> GloasFamily<'a> {
            fn of_gloas(state: &'a gloas::BeaconState) -> Self {
                Self { fork: ForkName::Gloas, builders: &state.builders, $($field: &state.$field,)* }
            }

            fn of_eip8483(state: &'a eip8483::BeaconState) -> Self {
                Self { fork: ForkName::Eip8483, builders: &state.builders, $($field: &state.$field,)* }
            }

            fn of_pq(state: &'a pq::BeaconState) -> Self {
                Self { fork: ForkName::Pq, builders: &state.builders.0, $($field: &state.$field,)* }
            }
        }

        impl<'a> GloasFamilyMut<'a> {
            fn of_gloas(state: &'a mut gloas::BeaconState) -> Self {
                Self {
                    fork: ForkName::Gloas,
                    builders: &mut state.builders,
                    $($field: &mut state.$field,)*
                }
            }

            fn of_eip8483(state: &'a mut eip8483::BeaconState) -> Self {
                Self {
                    fork: ForkName::Eip8483,
                    builders: &mut state.builders,
                    $($field: &mut state.$field,)*
                }
            }

            fn of_pq(state: &'a mut pq::BeaconState) -> Self {
                Self {
                    fork: ForkName::Pq,
                    builders: &mut state.builders.0,
                    $($field: &mut state.$field,)*
                }
            }

            /// The same view, read-only, for a helper that takes a
            /// [`GloasFamily`] while this one is held.
            pub fn as_ref(&self) -> GloasFamily<'_> {
                GloasFamily { fork: self.fork, builders: &*self.builders, $($field: &*self.$field,)* }
            }
        }
    };
}

gloas_family!(
    genesis_time: u64,
    genesis_validators_root: Root,
    slot: Slot,
    latest_block_header: BeaconBlockHeader,
    block_roots: BlockRoots,
    state_roots: StateRoots,
    historical_roots: HistoricalRoots,
    eth1_data: Eth1Data,
    eth1_data_votes: Eth1DataVotes,
    eth1_deposit_index: u64,
    randao_mixes: RandaoMixes,
    slashings: Slashings,
    previous_epoch_participation: EpochParticipation,
    current_epoch_participation: EpochParticipation,
    justification_bits: JustificationBits,
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    inactivity_scores: InactivityScores,
    latest_block_hash: ExecutionBlockHash,
    next_withdrawal_index: WithdrawalIndex,
    next_withdrawal_validator_index: ValidatorIndex,
    historical_summaries: HistoricalSummaries,
    deposit_requests_start_index: u64,
    deposit_balance_to_consume: Gwei,
    exit_balance_to_consume: Gwei,
    earliest_exit_epoch: Epoch,
    consolidation_balance_to_consume: Gwei,
    earliest_consolidation_epoch: Epoch,
    pending_deposits: PendingDeposits,
    pending_partial_withdrawals: PendingPartialWithdrawals,
    pending_consolidations: PendingConsolidations,
    proposer_lookahead: ProposerLookahead,
    next_withdrawal_builder_index: BuilderIndex,
    execution_payload_availability: ExecutionPayloadAvailability,
    builder_pending_payments: BuilderPendingPayments,
    builder_pending_withdrawals: BuilderPendingWithdrawals,
    latest_execution_payload_bid: ExecutionPayloadBid,
    payload_expected_withdrawals: Withdrawals,
    ptc_window: PayloadTimelinessCommitteeWindow,
);

macro_rules! from_state {
    ($state:ty, $ctor:ident) => {
        impl<'a> From<&'a $state> for GloasFamily<'a> {
            fn from(state: &'a $state) -> Self {
                GloasFamily::$ctor(state)
            }
        }

        impl<'a> From<&'a mut $state> for GloasFamilyMut<'a> {
            fn from(state: &'a mut $state) -> Self {
                GloasFamilyMut::$ctor(state)
            }
        }
    };
}

from_state!(gloas::BeaconState, of_gloas);
from_state!(eip8483::BeaconState, of_eip8483);
from_state!(pq::BeaconState, of_pq);

impl BeaconState {
    /// The gloas-family fields, or `None` before gloas (and for lean).
    pub fn gloas_family(&self) -> Option<GloasFamily<'_>> {
        match self {
            BeaconState::Gloas(state) => Some(GloasFamily::of_gloas(state)),
            BeaconState::Eip8483(state) => Some(GloasFamily::of_eip8483(state)),
            BeaconState::Pq(state) => Some(GloasFamily::of_pq(state)),
            _ => None,
        }
    }

    /// [`Self::gloas_family`], mutably.
    pub fn gloas_family_mut(&mut self) -> Option<GloasFamilyMut<'_>> {
        match self {
            BeaconState::Gloas(state) => Some(GloasFamilyMut::of_gloas(state)),
            BeaconState::Eip8483(state) => Some(GloasFamilyMut::of_eip8483(state)),
            BeaconState::Pq(state) => Some(GloasFamilyMut::of_pq(state)),
            _ => None,
        }
    }
}
