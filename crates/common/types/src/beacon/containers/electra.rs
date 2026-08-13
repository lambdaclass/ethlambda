//! Containers whose shape is specific to electra.
//!
//! Electra bundles several EIPs, and each explains a cluster of the containers
//! below.
//!
//! Through deneb, an attestation names one committee
//! (`AttestationData.index`) and its aggregation bitfield is one bit per
//! member of that single committee. EIP-7549 moves the committee index out of
//! `AttestationData` and into a new [`Attestation::committee_bits`] field
//! naming every committee the attestation covers, so [`AggregationBits`] now
//! has to be wide enough to hold a bit for every attester across every
//! committee in a slot rather than one committee's worth. That reshaping is
//! also why [`preset::MAX_ATTESTATIONS_ELECTRA`] is far smaller than phase0's
//! `MAX_ATTESTATIONS`: one electra attestation now does the work of a whole
//! slot's committees, so a block needs far fewer of them to cover the same
//! validator set. Pre-electra, an unaggregated gossip vote reused
//! `Attestation` itself with one bit set; that no longer works once the
//! bitfield spans the whole slot, which is why [`SingleAttestation`] exists as
//! a separate, explicitly-indexed container.
//!
//! EIP-7251 lets a validator's effective balance grow past
//! `MAX_EFFECTIVE_BALANCE` (given a compounding withdrawal credential), which
//! turns deposits, exits, and consolidations from operations bounded by a
//! count of validators into operations that have to be bounded by balance
//! instead: one very large validator's deposit, exit, or consolidation could
//! otherwise move as much stake in a single slot as thousands of ordinary
//! ones. [`PendingDeposit`], [`PendingPartialWithdrawal`], and
//! [`PendingConsolidation`] are the state's queues for exactly that, each
//! drained a bounded amount per epoch or slot rather than applied the instant
//! they are known about.
//!
//! EIP-6110 and EIP-7002 let the execution layer request a deposit or
//! withdrawal directly, instead of consensus replaying the deposit contract's
//! event log or a validator signing a voluntary exit; EIP-7251 extends the
//! same mechanism to consolidations. [`ExecutionRequests`] is the per-block
//! envelope the execution payload carries all three request kinds in.
//!
//! [`BeaconState`]'s field count crosses a power of two at electra, so its
//! merkle tree gains a level relative to deneb's; see `docs/beacon_stf.md`
//! for the generalized-index table this implies.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszBitvector, SszList};

use super::altair::{SyncAggregate, SyncCommittee};
use super::capella::SignedBLSToExecutionChange;
use super::deneb::{ExecutionPayload, ExecutionPayloadHeader, KzgCommitments};
use super::shared::{
    AttestationData, Balances, BeaconBlockHeader, BlockRoots, Checkpoint, Deposit,
    EpochParticipation, Eth1Data, Eth1DataVotes, Fork, HistoricalRoots, HistoricalSummaries,
    InactivityScores, JustificationBits, ProposerSlashing, RandaoMixes, SignedVoluntaryExit,
    Slashings, StateRoots, Validators,
};
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, CommitteeIndex, Epoch, ExecutionAddress, Gwei, Root, Slot,
    ValidatorIndex, WithdrawalIndex,
};

// ---------------------------------------------------------------------------
// Collection aliases
// ---------------------------------------------------------------------------

/// The attesters covered by one aggregate attestation: one bit per member of
/// every committee named in [`CommitteeBits`], rather than one committee's
/// worth as in every fork before electra.
///
/// Bounded by `MAX_VALIDATORS_PER_SLOT`, the product of `MAX_COMMITTEES_PER_SLOT`
/// and `MAX_VALIDATORS_PER_COMMITTEE`, since one attestation can now span
/// every committee in the slot.
pub type AggregationBits = SszBitlist<{ preset::MAX_VALIDATORS_PER_SLOT }>;

/// Which of a slot's committees an [`Attestation`] covers, one bit per
/// committee index.
///
/// `get_committee_indices` reads this to recover the ordered list of
/// committees, and [`AggregationBits`] is the concatenation of each named
/// committee's member bits in that same ascending order, so `committee_bits`
/// is what tells a reader where one committee's segment ends and the next
/// begins.
pub type CommitteeBits = SszBitvector<{ preset::MAX_COMMITTEES_PER_SLOT }>;

/// The attesters covered by one aggregate, named explicitly rather than as a
/// bitfield, which is the form signature verification needs.
///
/// Bounded the same way as [`AggregationBits`], for the same reason: one
/// [`IndexedAttestation`] can now name attesters from every committee in a
/// slot.
pub type AttestingIndices = SszList<ValidatorIndex, { preset::MAX_VALIDATORS_PER_SLOT }>;

/// Attestations included in a block.
///
/// Bounded by `MAX_ATTESTATIONS_ELECTRA`, far smaller than phase0's
/// `MAX_ATTESTATIONS`: one electra attestation now covers a whole slot's
/// committees, so a block needs far fewer of them to cover the same
/// validator set.
pub type Attestations = SszList<Attestation, { preset::MAX_ATTESTATIONS_ELECTRA }>;

/// Evidence of conflicting attestations included in a block.
///
/// Bounded by `MAX_ATTESTER_SLASHINGS_ELECTRA`, tightened from phase0's
/// `MAX_ATTESTER_SLASHINGS`: one electra [`IndexedAttestation`] can now name
/// every attester in a slot, so a single slashing's evidence is
/// proportionally larger to include.
pub type AttesterSlashings = SszList<AttesterSlashing, { preset::MAX_ATTESTER_SLASHINGS_ELECTRA }>;

/// Deposits queued in the state, not yet credited to the validator registry.
pub type PendingDeposits = SszList<PendingDeposit, { preset::PENDING_DEPOSITS_LIMIT }>;

/// Partial withdrawals queued in the state, not yet paid out.
pub type PendingPartialWithdrawals =
    SszList<PendingPartialWithdrawal, { preset::PENDING_PARTIAL_WITHDRAWALS_LIMIT }>;

/// Validator consolidations queued in the state, not yet applied.
pub type PendingConsolidations =
    SszList<PendingConsolidation, { preset::PENDING_CONSOLIDATIONS_LIMIT }>;

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// An aggregate attestation, as gossiped and as included in a block.
///
/// EIP-7549 moves the committee index out of `AttestationData` and into
/// [`Attestation::committee_bits`], so one attestation can now name every
/// committee in a slot rather than just one. From electra on, `data.index` is
/// required to be zero: `committee_bits` is the only source of which
/// committees an attestation covers, and `data` is otherwise shared unchanged
/// with every earlier fork.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct Attestation {
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
    /// The aggregate signature of every attester set across every committee
    /// named in `committee_bits`, over `data`.
    pub signature: BlsSignature,
    /// Which committees `aggregation_bits` covers. [`AggregationBits`] is the
    /// concatenation of each named committee's member bits, in ascending
    /// committee-index order.
    pub committee_bits: CommitteeBits,
}

/// An attestation with its attesters named rather than bit-encoded.
///
/// Signature verification needs the public keys, which needs the indices, so
/// the state transition converts an [`Attestation`] into this form before
/// checking it. `attesting_indices` now spans every committee an
/// [`Attestation`] covers, following the same widening as [`AggregationBits`].
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct IndexedAttestation {
    /// The attesters, which the specification requires to be sorted and
    /// unique.
    pub attesting_indices: AttestingIndices,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

/// Evidence that a set of validators made two conflicting attestations.
///
/// The container's own shape is unchanged from phase0; what changed is
/// [`IndexedAttestation`] itself, which now names attesters from every
/// committee in a slot instead of one. That is also why this is bounded by
/// `MAX_ATTESTER_SLASHINGS_ELECTRA` rather than phase0's larger
/// `MAX_ATTESTER_SLASHINGS`: evidence spanning a whole slot is proportionally
/// more expensive to include.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

/// One attester's unaggregated vote, gossiped on a per-committee attestation
/// subnet before an aggregator folds it into an [`Attestation`].
///
/// Pre-electra, an unaggregated vote reused [`Attestation`] itself with
/// exactly one bit set in `aggregation_bits`, since that bitfield was already
/// scoped to a single committee. From electra on, `aggregation_bits` spans
/// every committee in the slot, so a lone attester's bit position no longer
/// says which committee it belongs to on its own. `SingleAttestation` carries
/// `committee_index` and `attester_index` explicitly instead, and an
/// aggregator combines every `SingleAttestation` sharing the same `data` into
/// one widened [`Attestation`].
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SingleAttestation {
    pub committee_index: CommitteeIndex,
    pub attester_index: ValidatorIndex,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// Execution layer triggered requests
// ---------------------------------------------------------------------------
//
// EIP-6110, EIP-7002, and EIP-7251 let the execution layer request a deposit,
// withdrawal, or consolidation directly, without consensus waiting to replay
// the deposit contract's event log or a validator signing a voluntary exit.
// `ExecutionRequests` is the per-block envelope the execution payload carries
// these three request kinds in.

/// An execution-layer-triggered deposit (EIP-6110).
///
/// Carries the same fields a `Deposit`'s underlying data does, plus `index`:
/// unlike a contract-log deposit, a request arrives already ordered by the
/// execution layer, so there is no merkle proof to check, only a position to
/// record.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct DepositRequest {
    pub pubkey: BlsPubkey,
    pub withdrawal_credentials: Bytes32,
    pub amount: Gwei,
    pub signature: BlsSignature,
    pub index: u64,
}

/// An execution-layer-triggered exit or partial withdrawal (EIP-7002).
///
/// `source_address` is the execution-layer account that requested it, which
/// `process_withdrawal_request` checks against the validator's withdrawal
/// credentials before honoring the request. An `amount` of
/// `FULL_EXIT_REQUEST_AMOUNT` signals a full exit rather than a partial
/// withdrawal of that amount.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct WithdrawalRequest {
    pub source_address: ExecutionAddress,
    pub validator_pubkey: BlsPubkey,
    pub amount: Gwei,
}

/// An execution-layer-triggered validator consolidation (EIP-7251): a request
/// to merge `source_pubkey`'s balance into `target_pubkey`'s and exit the
/// source, which is how a validator raises its effective balance past
/// `MAX_EFFECTIVE_BALANCE` without a fresh deposit.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct ConsolidationRequest {
    pub source_address: ExecutionAddress,
    pub source_pubkey: BlsPubkey,
    pub target_pubkey: BlsPubkey,
}

/// The execution payload's envelope for every execution-layer-triggered
/// request in this block, grouped by kind.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct ExecutionRequests {
    pub deposits: SszList<DepositRequest, { preset::MAX_DEPOSIT_REQUESTS_PER_PAYLOAD }>,
    pub withdrawals: SszList<WithdrawalRequest, { preset::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD }>,
    pub consolidations:
        SszList<ConsolidationRequest, { preset::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD }>,
}

// ---------------------------------------------------------------------------
// Pending balance queues
// ---------------------------------------------------------------------------
//
// EIP-7251 lets a validator's effective balance grow past
// `MAX_EFFECTIVE_BALANCE`, so the churn that used to be bounded by a count of
// validators now has to be bounded by balance instead. These three
// containers are the state's queues for deposits, partial withdrawals, and
// consolidations that are known about but not yet applied, each drained a
// bounded amount per epoch or slot so no single operation outruns the churn
// limit.

/// A deposit recorded in the state, not yet credited to the validator
/// registry.
///
/// Carries the same fields a `Deposit`'s data does, plus `slot`: unlike a
/// `Deposit`, a pending deposit did not arrive with a merkle proof against the
/// deposit contract, so the state has to remember when it was queued instead.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct PendingDeposit {
    pub pubkey: BlsPubkey,
    pub withdrawal_credentials: Bytes32,
    pub amount: Gwei,
    pub signature: BlsSignature,
    pub slot: Slot,
}

/// A partial withdrawal recorded in the state, not yet paid out.
///
/// Queued rather than applied immediately so
/// `MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP` can bound how many of these
/// `get_expected_withdrawals` drains in one slot.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct PendingPartialWithdrawal {
    pub validator_index: ValidatorIndex,
    pub amount: Gwei,
    pub withdrawable_epoch: Epoch,
}

/// A validator consolidation recorded in the state, not yet applied.
///
/// `source_index` exits once `target_index` absorbs its balance, which is why
/// only the two indices need to be kept: everything else about the merge
/// follows from the validators' own records at the epoch it is processed.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct PendingConsolidation {
    pub source_index: ValidatorIndex,
    pub target_index: ValidatorIndex,
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// The contents of a block: deneb's operations, plus the execution-layer-
/// triggered requests this block's payload carries.
///
/// Unchanged from deneb except for three things: `attester_slashings` and
/// `attestations` are now bounded (and, for attestations, shaped)
/// differently, and `execution_requests` is appended at the end.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlockBody {
    /// The proposer's contribution to the chain's randomness, which is a
    /// signature over the current epoch and so cannot be chosen freely.
    pub randao_reveal: BlsSignature,
    /// The proposer's vote on the execution chain's deposit state.
    pub eth1_data: Eth1Data,
    /// Arbitrary proposer-chosen bytes, which consensus never reads.
    pub graffiti: Bytes32,
    pub proposer_slashings: SszList<ProposerSlashing, { preset::MAX_PROPOSER_SLASHINGS }>,
    pub attester_slashings: AttesterSlashings,
    pub attestations: Attestations,
    pub deposits: SszList<Deposit, { preset::MAX_DEPOSITS }>,
    pub voluntary_exits: SszList<SignedVoluntaryExit, { preset::MAX_VOLUNTARY_EXITS }>,
    /// The aggregated sync committee signature over the previous slot's block
    /// root, plus which members contributed.
    pub sync_aggregate: SyncAggregate,
    pub execution_payload: ExecutionPayload,
    pub bls_to_execution_changes:
        SszList<SignedBLSToExecutionChange, { preset::MAX_BLS_TO_EXECUTION_CHANGES }>,
    pub blob_kzg_commitments: KzgCommitments,
    /// The execution-layer-triggered deposit, withdrawal, and consolidation
    /// requests carried by this block's payload. The one field electra adds
    /// to the body.
    pub execution_requests: ExecutionRequests,
}

/// A block.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconBlock {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    /// The root of the state after this block is applied, which the state
    /// transition recomputes and compares.
    pub state_root: Root,
    pub body: BeaconBlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    pub signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The electra beacon state: 37 fields, in the specification's order.
///
/// Field order is load-bearing. SSZ encoding and merkleization both follow
/// declaration order, so reordering or omitting a field silently produces a
/// wrong `hash_tree_root`.
///
/// Fields through `historical_summaries` are identical to deneb's, field for
/// field (28 of them). Electra appends nine more, serving two EIPs:
/// `deposit_requests_start_index` (EIP-6110) is where the state switches from
/// crediting deposits off `Eth1Data` votes to crediting them off
/// execution-layer `DepositRequest`s, and the remaining eight (EIP-7251) are
/// the balance-churn accounting and the three pending queues that let a
/// validator's effective balance grow past `MAX_EFFECTIVE_BALANCE` without
/// letting a single large validator's deposit, exit, or consolidation move
/// more stake in one slot than the churn limit allows.
///
/// Crossing 37 fields also crosses a power of two, so this state's merkle
/// tree gains a level relative to deneb's; see `docs/beacon_stf.md` for the
/// generalized-index table this implies.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct BeaconState {
    // -- Versioning --
    pub genesis_time: u64,
    /// The root of the genesis validator registry, which separates this chain
    /// from any other running the same fork schedule.
    pub genesis_validators_root: Root,
    pub slot: Slot,
    pub fork: Fork,

    // -- History --
    /// The most recent block's header, with `state_root` left zero until the
    /// slot advances, since a block cannot commit to the root of the state
    /// containing it.
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: BlockRoots,
    pub state_roots: StateRoots,
    pub historical_roots: HistoricalRoots,

    // -- Eth1 --
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: Eth1DataVotes,
    /// How many deposits from the contract have been processed, which is
    /// where the next one will be read from. Superseded for new deposits once
    /// `deposit_requests_start_index` is set, but kept for deposits still in
    /// flight from before that point.
    pub eth1_deposit_index: u64,

    // -- Registry --
    pub validators: Validators,
    pub balances: Balances,

    // -- Randomness --
    pub randao_mixes: RandaoMixes,

    // -- Slashings --
    pub slashings: Slashings,

    // -- Participation --
    pub previous_epoch_participation: EpochParticipation,
    pub current_epoch_participation: EpochParticipation,

    // -- Finality --
    pub justification_bits: JustificationBits,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // -- Inactivity --
    pub inactivity_scores: InactivityScores,

    // -- Sync committees --
    /// The committee currently signing sync aggregates.
    pub current_sync_committee: SyncCommittee,
    /// The committee that takes over from `current_sync_committee` at the
    /// next sync committee period boundary.
    pub next_sync_committee: SyncCommittee,

    // -- Execution --
    pub latest_execution_payload_header: ExecutionPayloadHeader,

    // -- Withdrawals --
    pub next_withdrawal_index: WithdrawalIndex,
    /// The next validator index `get_expected_withdrawals`'s registry sweep
    /// resumes from, so the sweep makes bounded progress across the whole
    /// registry over many slots instead of restarting from zero each time.
    pub next_withdrawal_validator_index: ValidatorIndex,

    // -- Deep history --
    pub historical_summaries: HistoricalSummaries,

    // -- Deposit requests (EIP-6110) --
    /// The execution-layer deposit request index at which the state switched
    /// from crediting deposits off `Eth1Data` votes to crediting them off
    /// `DepositRequest`s directly. Holds `UNSET_DEPOSIT_REQUESTS_START_INDEX`
    /// until the first `DepositRequest` is seen.
    pub deposit_requests_start_index: u64,

    // -- Balance churn (EIP-7251) --
    /// How much of this epoch's deposit balance churn limit remains unused,
    /// so a deposit that would exceed it is queued in `pending_deposits`
    /// instead of activating immediately.
    pub deposit_balance_to_consume: Gwei,
    /// How much of this epoch's exit balance churn limit remains unused, the
    /// exit-side counterpart of `deposit_balance_to_consume`.
    pub exit_balance_to_consume: Gwei,
    /// The earliest epoch an exit initiated now could take effect, advanced
    /// by `compute_exit_epoch_and_update_churn` as exits consume the churn
    /// limit faster than it refills.
    pub earliest_exit_epoch: Epoch,
    /// How much of this epoch's consolidation churn limit remains unused.
    pub consolidation_balance_to_consume: Gwei,
    /// The earliest epoch a consolidation initiated now could take effect,
    /// the consolidation-side counterpart of `earliest_exit_epoch`.
    pub earliest_consolidation_epoch: Epoch,

    // -- Pending queues (EIP-7251) --
    /// Deposits known but not yet credited to the validator registry,
    /// drained a bounded amount per epoch by `process_pending_deposits`.
    pub pending_deposits: PendingDeposits,
    /// Partial withdrawals known but not yet paid out, drained a bounded
    /// amount per slot by `get_expected_withdrawals`.
    pub pending_partial_withdrawals: PendingPartialWithdrawals,
    /// Consolidations known but not yet applied, drained a bounded amount per
    /// epoch by `process_pending_consolidations`.
    pub pending_consolidations: PendingConsolidations,
}

// ---------------------------------------------------------------------------
// Validator-side containers
// ---------------------------------------------------------------------------

/// An aggregate together with proof that its aggregator was selected to
/// produce it.
///
/// Unchanged in shape from phase0: `aggregate` simply carries electra's wider
/// [`Attestation`] now.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct AggregateAndProof {
    pub aggregator_index: ValidatorIndex,
    pub aggregate: Attestation,
    /// The aggregator's signature over the slot, which is what makes
    /// selection verifiable rather than self-declared.
    pub selection_proof: BlsSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedAggregateAndProof {
    pub message: AggregateAndProof,
    pub signature: BlsSignature,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn attestation_aggregation_bits_span_every_named_committee() {
        // Two committees named in committee_bits (indices 0 and 2), each
        // contributing a slice of aggregation_bits: this is the electra-only
        // shape no earlier fork has, since every earlier fork's
        // aggregation_bits covers exactly one committee.
        let mut committee_bits = CommitteeBits::default();
        committee_bits.set(0, true).unwrap();
        committee_bits.set(2, true).unwrap();

        let mut aggregation_bits = AggregationBits::with_length(6).unwrap();
        aggregation_bits.set(0, true).unwrap();
        aggregation_bits.set(4, true).unwrap();

        let attestation = Attestation {
            aggregation_bits,
            data: AttestationData::default(),
            signature: BlsSignature::default(),
            committee_bits,
        };

        let bytes = attestation.to_ssz();
        assert_eq!(Attestation::from_ssz_bytes(&bytes).unwrap(), attestation);
    }

    #[test]
    fn pending_deposit_round_trips_through_ssz() {
        let deposit = PendingDeposit {
            pubkey: BlsPubkey([9; 48]),
            withdrawal_credentials: Bytes32::repeat_byte(1),
            amount: 32_000_000_000,
            signature: BlsSignature::default(),
            slot: 100,
        };

        let bytes = deposit.to_ssz();
        assert_eq!(PendingDeposit::from_ssz_bytes(&bytes).unwrap(), deposit);
    }

    #[test]
    fn new_fixed_size_containers_have_no_offsets() {
        // Every field of each is itself fixed-length, so none of these carry
        // SSZ offsets, unlike Attestation, IndexedAttestation, and
        // ExecutionRequests, which each hold at least one list or bitlist.
        assert!(<SingleAttestation as libssz::SszEncode>::is_fixed_size());
        assert!(<DepositRequest as libssz::SszEncode>::is_fixed_size());
        assert!(<WithdrawalRequest as libssz::SszEncode>::is_fixed_size());
        assert!(<ConsolidationRequest as libssz::SszEncode>::is_fixed_size());
        assert!(<PendingDeposit as libssz::SszEncode>::is_fixed_size());
        assert!(<PendingPartialWithdrawal as libssz::SszEncode>::is_fixed_size());
        assert!(<PendingConsolidation as libssz::SszEncode>::is_fixed_size());
    }

    #[test]
    fn variable_length_containers_carry_offsets() {
        assert!(!<Attestation as libssz::SszEncode>::is_fixed_size());
        assert!(!<IndexedAttestation as libssz::SszEncode>::is_fixed_size());
        assert!(!<AttesterSlashing as libssz::SszEncode>::is_fixed_size());
        assert!(!<ExecutionRequests as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlockBody as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconBlock as libssz::SszEncode>::is_fixed_size());
        assert!(!<BeaconState as libssz::SszEncode>::is_fixed_size());
        assert!(!<AggregateAndProof as libssz::SszEncode>::is_fixed_size());
        assert!(!<SignedAggregateAndProof as libssz::SszEncode>::is_fixed_size());
    }
}
