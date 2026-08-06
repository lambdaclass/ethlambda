//! Preset constants: the compile-time-selectable half of the specification's
//! tunables.
//!
//! The specification splits its numeric parameters into two kinds. *Configuration*
//! values (genesis time, fork-activation epochs, network-specific limits) can
//! differ between two networks running the same client binary, so they belong in
//! [`crate::config`] as runtime data. *Preset* values instead fix the shape of the
//! SSZ containers the state transition operates on: how many slots a historical
//! roots vector holds, how many attestations fit in a block, how many field
//! elements make up a blob. Two networks that disagree on a preset value are
//! running different, mutually unintelligible protocols, because every hash tree
//! root over a preset-bounded list or vector depends on that bound. That is also
//! why the values below are Rust constants rather than fields on a struct: a
//! container's SSZ shape is a type-level property (`SszList<T, { preset::X }>`),
//! decided once when the crate is compiled, not something a running node could
//! switch at runtime without also swapping out its state's memory layout.
//!
//! The specification defines exactly two presets, `mainnet` and `minimal`
//! (`minimal` exists to keep spec test fixtures and local devnets fast). This
//! crate mirrors that: [`mainnet`] and [`minimal`] each define every preset
//! constant the specification uses from phase0 through fulu, and the top-level
//! re-export picks one at compile time, gated on the `preset-minimal` feature.
//! Downstream code should import from here (`preset::SLOTS_PER_EPOCH`, not
//! `preset::mainnet::SLOTS_PER_EPOCH`), so that it automatically follows whichever
//! preset the crate was built against.
//!
//! # Why some constants are `usize` and others are `u64`
//!
//! A constant that bounds an SSZ collection (`List`, `Vector`, `Bitlist`,
//! `Bitvector`) in some container, in any fork from phase0 through fulu, is typed
//! `usize` here, because it gets threaded through this crate as a const-generic
//! parameter on that collection's Rust representation, and const generics require
//! `usize`. Every other preset constant (reward/penalty divisors, Gwei amounts,
//! epoch/slot durations that never size a container by themselves) is typed `u64`,
//! matching the `uint64` the specification gives it. A few constants are factors
//! of a container bound without being one themselves (`SLOTS_PER_EPOCH` is the
//! textbook case: it never bounds anything alone, only in products like
//! `SLOTS_PER_EPOCH * EPOCHS_PER_ETH1_VOTING_PERIOD`), so they stay `u64` and the
//! product gets its own `usize` constant instead.
//!
//! # Derived constants
//!
//! Some values a container needs are not literal preset entries at all: the
//! specification writes them as an inline formula over other presets, directly in
//! a container's field-type annotation rather than in the preset YAML. This module
//! gives each of those formulas a name (`MAX_PENDING_ATTESTATIONS`,
//! `SLOTS_PER_ETH1_VOTING_PERIOD`, `BYTES_PER_BLOB`, `BYTES_PER_CELL`,
//! `PROPOSER_LOOKAHEAD_LENGTH`, `MAX_VALIDATORS_PER_SLOT`) and computes it from the
//! constants it depends on, so the relationship is checked by the compiler instead
//! of copied by hand into two places.
//!
//! Constants that the specification instead lists as fixed, preset-independent
//! `Constant`s (for example `JUSTIFICATION_BITS_LENGTH`, `BYTES_PER_FIELD_ELEMENT`,
//! `DEPOSIT_CONTRACT_TREE_DEPTH`) do not appear here even when they bound a
//! container or feed one of the formulas above; they belong to this crate's
//! `constants` module instead, since they cannot vary between `mainnet` and
//! `minimal` in the first place.

/// The mainnet preset: the values that secure the real Ethereum network.
///
/// Sourced from `presets/mainnet/{phase0,altair,bellatrix,capella,deneb,electra,
/// fulu}.yaml` in the specification, plus the derived constants documented at the
/// module level.
pub mod mainnet {
    // ================================================================
    // Phase0
    // ================================================================

    // --- Misc ---

    /// How many committees a single slot's active validators are split into.
    /// Also bounds `Attestation.committee_bits` from electra onward
    /// (`Bitvector<MAX_COMMITTEES_PER_SLOT>`), and is a factor of
    /// `MAX_VALIDATORS_PER_SLOT`.
    pub const MAX_COMMITTEES_PER_SLOT: usize = 64;

    /// The committee size `get_committee_count_per_slot` aims for when splitting a
    /// slot's active validators into committees. Not itself a container bound.
    pub const TARGET_COMMITTEE_SIZE: u64 = 128;

    /// Bounds `Attestation.aggregation_bits` (a `Bitlist`) and, pre-electra,
    /// `IndexedAttestation.attesting_indices` (a `List<ValidatorIndex, _>`). From
    /// electra onward it is instead a factor of `MAX_VALIDATORS_PER_SLOT`, which
    /// bounds those same fields.
    pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;

    /// Number of swap-or-not shuffle rounds `compute_shuffled_index` performs when
    /// deriving committee membership from a seed.
    pub const SHUFFLE_ROUND_COUNT: u64 = 90;

    /// Denominator of the balance band, centered on a multiple of
    /// `EFFECTIVE_BALANCE_INCREMENT`, that a validator's effective balance must
    /// leave before `process_effective_balance_updates` moves it.
    pub const HYSTERESIS_QUOTIENT: u64 = 4;

    /// Numerator narrowing the downward half of the hysteresis band relative to
    /// `HYSTERESIS_QUOTIENT`, so effective balance falls faster than it rises.
    pub const HYSTERESIS_DOWNWARD_MULTIPLIER: u64 = 1;

    /// Numerator widening the upward half of the hysteresis band relative to
    /// `HYSTERESIS_QUOTIENT`, damping effective balance increases.
    pub const HYSTERESIS_UPWARD_MULTIPLIER: u64 = 5;

    // --- Gwei values ---

    /// Smallest deposit amount `process_deposit` accepts onto the validator
    /// registry (deposits below this are recorded but never activate a
    /// validator).
    pub const MIN_DEPOSIT_AMOUNT: u64 = 1_000_000_000;

    /// Ceiling that reward, penalty, and churn-limit math clamps a validator's
    /// effective balance to, pre-electra (electra validators with a compounding
    /// withdrawal credential instead use `MAX_EFFECTIVE_BALANCE_ELECTRA`).
    pub const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;

    /// Rounding granularity effective balance is truncated to, and the unit that
    /// base-reward math scales by.
    pub const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;

    // --- Time parameters ---

    /// Minimum number of slots `process_attestation` requires between an
    /// attestation's slot and the slot it is included in.
    pub const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;

    /// Slots per epoch. Never bounds a container by itself; it is a factor of
    /// several derived bounds below (`SLOTS_PER_ETH1_VOTING_PERIOD`,
    /// `MAX_PENDING_ATTESTATIONS`, `PROPOSER_LOOKAHEAD_LENGTH`).
    pub const SLOTS_PER_EPOCH: u64 = 32;

    /// Epochs the RANDAO mix used to seed a shuffling lags behind the epoch it
    /// shuffles, so the seed is unpredictable before that epoch starts. Also a
    /// factor of `PROPOSER_LOOKAHEAD_LENGTH`.
    pub const MIN_SEED_LOOKAHEAD: u64 = 1;

    /// Epochs an exiting validator's withdrawable epoch is delayed past its exit
    /// epoch, bounding how far in advance the exit queue can be gamed.
    pub const MAX_SEED_LOOKAHEAD: u64 = 4;

    /// Epochs a single ETH1 voting period spans. A factor of
    /// `SLOTS_PER_ETH1_VOTING_PERIOD`; not itself a container bound.
    pub const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 64;

    /// `EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH`, the specification's
    /// formula for the bound on `BeaconState.eth1_data_votes`
    /// (`List<Eth1Data, SLOTS_PER_ETH1_VOTING_PERIOD>`), the votes collected
    /// during one ETH1 voting period.
    pub const SLOTS_PER_ETH1_VOTING_PERIOD: usize =
        EPOCHS_PER_ETH1_VOTING_PERIOD as usize * SLOTS_PER_EPOCH as usize;

    /// Bounds `BeaconState.block_roots` and `state_roots`, both
    /// `Vector<Root, SLOTS_PER_HISTORICAL_ROOT>`.
    pub const SLOTS_PER_HISTORICAL_ROOT: usize = 8192;

    /// Epochs since the last finality advance before
    /// `process_inactivity_updates`-adjacent penalty logic starts leaking an
    /// inactive validator's balance.
    pub const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64 = 4;

    // --- State list lengths ---

    /// Bounds `BeaconState.randao_mixes` (`Vector<Bytes32,
    /// EPOCHS_PER_HISTORICAL_VECTOR>`), the ring buffer of past RANDAO mixes
    /// shufflings are seeded from.
    pub const EPOCHS_PER_HISTORICAL_VECTOR: usize = 65536;

    /// Bounds `BeaconState.slashings` (`Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>`),
    /// the ring buffer `process_slashings` sums to scale the correlated slashing
    /// penalty.
    pub const EPOCHS_PER_SLASHINGS_VECTOR: usize = 8192;

    /// Bounds `BeaconState.historical_roots`, and from capella onward
    /// `historical_summaries` (both `List<_, HISTORICAL_ROOTS_LIMIT>`).
    pub const HISTORICAL_ROOTS_LIMIT: usize = 16_777_216;

    /// Bounds every validator-indexed list in `BeaconState`: `validators`,
    /// `balances`, and, from altair, `previous_epoch_participation`,
    /// `current_epoch_participation`, and `inactivity_scores`.
    pub const VALIDATOR_REGISTRY_LIMIT: usize = 1_099_511_627_776;

    // --- Rewards and penalties ---

    /// Numerator of the base reward per increment of effective balance, before
    /// dividing by the integer square root of total active balance.
    pub const BASE_REWARD_FACTOR: u64 = 64;

    /// Divisor of a slashed validator's effective balance that sets the combined
    /// whistleblower/proposer reward `slash_validator` pays out.
    pub const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 512;

    /// Divisor of the whistleblower reward that the block proposer's share is set
    /// to; the remainder goes to whoever reported the slashable offense.
    pub const PROPOSER_REWARD_QUOTIENT: u64 = 8;

    /// Divisor controlling how fast effective balance leaks during non-finality,
    /// pre-altair (altair replaces this with
    /// `INACTIVITY_PENALTY_QUOTIENT_ALTAIR`).
    pub const INACTIVITY_PENALTY_QUOTIENT: u64 = 67_108_864;

    /// Divisor of effective balance burned immediately on slashing, pre-altair.
    pub const MIN_SLASHING_PENALTY_QUOTIENT: u64 = 128;

    /// Multiplier scaling the slashing penalty by the proportion of validators
    /// slashed in the same slashings-vector window, pre-altair.
    pub const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 1;

    // --- Max operations per block ---

    /// Bounds `BeaconBlockBody.proposer_slashings`
    /// (`List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>`).
    pub const MAX_PROPOSER_SLASHINGS: usize = 16;

    /// Bounds `BeaconBlockBody.attester_slashings`, pre-electra
    /// (`List<AttesterSlashing, MAX_ATTESTER_SLASHINGS>`; electra replaces it with
    /// `MAX_ATTESTER_SLASHINGS_ELECTRA`).
    pub const MAX_ATTESTER_SLASHINGS: usize = 2;

    /// Bounds `BeaconBlockBody.attestations`, pre-electra
    /// (`List<Attestation, MAX_ATTESTATIONS>`; electra replaces it with
    /// `MAX_ATTESTATIONS_ELECTRA`). Also a factor of `MAX_PENDING_ATTESTATIONS`.
    pub const MAX_ATTESTATIONS: usize = 128;

    /// `MAX_ATTESTATIONS * SLOTS_PER_EPOCH`, the specification's formula for the
    /// bound on `BeaconState.previous_epoch_attestations` and
    /// `current_epoch_attestations` (`List<PendingAttestation, _>`), the phase0
    /// per-epoch attestation backlog that altair replaces with participation
    /// flags.
    pub const MAX_PENDING_ATTESTATIONS: usize = MAX_ATTESTATIONS * SLOTS_PER_EPOCH as usize;

    /// Bounds `BeaconBlockBody.deposits` (`List<Deposit, MAX_DEPOSITS>`).
    pub const MAX_DEPOSITS: usize = 16;

    /// Bounds `BeaconBlockBody.voluntary_exits`
    /// (`List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>`).
    pub const MAX_VOLUNTARY_EXITS: usize = 16;

    // ================================================================
    // Altair
    // ================================================================

    // --- Rewards and penalties ---

    /// Altair's replacement for `INACTIVITY_PENALTY_QUOTIENT`, retuned for the
    /// participation-flag accounting altair introduces.
    pub const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64 = 50_331_648;

    /// Altair's replacement for `MIN_SLASHING_PENALTY_QUOTIENT`.
    pub const MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: u64 = 64;

    /// Altair's replacement for `PROPORTIONAL_SLASHING_MULTIPLIER`.
    pub const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: u64 = 2;

    // --- Sync committee ---

    /// Bounds `SyncCommittee.pubkeys` (`Vector<BLSPubkey, SYNC_COMMITTEE_SIZE>`)
    /// and a sync aggregate's `sync_committee_bits`
    /// (`Bitvector<SYNC_COMMITTEE_SIZE>`).
    pub const SYNC_COMMITTEE_SIZE: usize = 512;

    /// Epochs a sync committee serves before the next one rotates in. A factor of
    /// `UPDATE_TIMEOUT`; not itself a container bound.
    pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

    // --- Sync protocol ---

    /// Minimum signer count a sync aggregate must have for light-client update
    /// validity checks to accept it.
    pub const MIN_SYNC_COMMITTEE_PARTICIPANTS: u64 = 1;

    /// Slots since the light client store's finalized header before
    /// `process_light_client_store_force_update` force-applies the best pending
    /// update. Equal to `SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD`.
    pub const UPDATE_TIMEOUT: u64 = 8192;

    // ================================================================
    // Bellatrix
    // ================================================================

    // --- Rewards and penalties ---

    /// Bellatrix's replacement for `INACTIVITY_PENALTY_QUOTIENT_ALTAIR`.
    pub const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64 = 16_777_216;

    /// Bellatrix's replacement for `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR`.
    pub const MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: u64 = 32;

    /// Bellatrix's replacement for `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR`.
    pub const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64 = 3;

    // --- Execution ---

    /// Bounds the `Transaction` type itself (`ByteList<MAX_BYTES_PER_TRANSACTION>`
    /// is `Transaction`'s SSZ definition).
    pub const MAX_BYTES_PER_TRANSACTION: usize = 1_073_741_824;

    /// Bounds `ExecutionPayload.transactions`
    /// (`List<Transaction, MAX_TRANSACTIONS_PER_PAYLOAD>`).
    pub const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1_048_576;

    /// Bounds `ExecutionPayload(Header).logs_bloom`
    /// (`ByteVector<BYTES_PER_LOGS_BLOOM>`).
    pub const BYTES_PER_LOGS_BLOOM: usize = 256;

    /// Bounds `ExecutionPayload(Header).extra_data`
    /// (`ByteList<MAX_EXTRA_DATA_BYTES>`).
    pub const MAX_EXTRA_DATA_BYTES: usize = 32;

    // ================================================================
    // Capella
    // ================================================================

    // --- Max operations per block ---

    /// Bounds `BeaconBlockBody.bls_to_execution_changes`
    /// (`List<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>`).
    pub const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;

    // --- Execution ---

    /// Bounds `ExecutionPayload(Header).withdrawals`
    /// (`List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>`).
    pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;

    // --- Withdrawals processing ---

    /// Cap on how many validators `get_expected_withdrawals` scans per slot while
    /// sweeping the registry for withdrawable balances. A loop bound the
    /// withdrawal-sweep algorithm uses, not a container length, so it stays
    /// `u64`.
    pub const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16384;

    // ================================================================
    // Deneb
    // ================================================================

    // --- Execution ---

    /// Bounds `BeaconBlockBody.blob_kzg_commitments`
    /// (`List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>`) and, from fulu,
    /// `DataColumnSidecar.column` / `kzg_commitments`.
    pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;

    // --- Networking ---

    /// Bounds `BlobSidecar.kzg_commitment_inclusion_proof`
    /// (`Vector<Bytes32, KZG_COMMITMENT_INCLUSION_PROOF_DEPTH>`), the merkle proof
    /// that a commitment sits at its claimed index in `blob_kzg_commitments`.
    pub const KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: usize = 17;

    // --- Blob ---

    /// Bounds a blob's polynomial representation
    /// (`Vector<BLSFieldElement, FIELD_ELEMENTS_PER_BLOB>`), and is a factor of
    /// `BYTES_PER_BLOB` and (doubled) fulu's `FIELD_ELEMENTS_PER_EXT_BLOB`.
    pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;

    /// `BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB`, the specification's
    /// formula for the bound on the `Blob` type
    /// (`ByteVector<BYTES_PER_BLOB>`), carried in `BlobSidecar.blob`.
    ///
    /// Derived rather than transcribed, so the two cannot drift apart.
    /// `BYTES_PER_FIELD_ELEMENT` is a fixed spec constant rather than a preset
    /// value, so it comes from [`crate::constants`].
    pub const BYTES_PER_BLOB: usize =
        crate::constants::BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB;

    // ================================================================
    // Electra
    // ================================================================

    // --- Gwei values ---

    /// Minimum balance a validator must reach before it can activate. Electra's
    /// deposit-flow counterpart to `MIN_DEPOSIT_AMOUNT`.
    pub const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;

    /// Electra's raised ceiling on effective balance for validators with a
    /// compounding (0x02) withdrawal credential; validators without one still use
    /// `MAX_EFFECTIVE_BALANCE`.
    pub const MAX_EFFECTIVE_BALANCE_ELECTRA: u64 = 2_048_000_000_000;

    // --- Rewards and penalties ---

    /// Electra's replacement for `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR`, tightened
    /// alongside the higher `MAX_EFFECTIVE_BALANCE_ELECTRA`.
    pub const MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA: u64 = 4096;

    /// Electra's replacement for `WHISTLEBLOWER_REWARD_QUOTIENT`.
    pub const WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: u64 = 4096;

    // --- State list lengths ---

    /// Bounds `BeaconState.pending_deposits`
    /// (`List<PendingDeposit, PENDING_DEPOSITS_LIMIT>`), electra's queue of
    /// deposits not yet processed into the registry.
    pub const PENDING_DEPOSITS_LIMIT: usize = 134_217_728;

    /// Bounds `BeaconState.pending_partial_withdrawals`
    /// (`List<PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT>`).
    pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 134_217_728;

    /// Bounds `BeaconState.pending_consolidations`
    /// (`List<PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT>`).
    pub const PENDING_CONSOLIDATIONS_LIMIT: usize = 262_144;

    // --- Max operations per block ---

    /// Electra's replacement for `MAX_ATTESTER_SLASHINGS`, bounding
    /// `BeaconBlockBody.attester_slashings` now that committee bits move
    /// attesting indices out of the slashing itself.
    pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;

    /// Electra's replacement for `MAX_ATTESTATIONS`, lowered because one electra
    /// `Attestation` now covers every committee in a slot instead of one.
    pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;

    /// `MAX_COMMITTEES_PER_SLOT * MAX_VALIDATORS_PER_COMMITTEE`, the
    /// specification's formula for the bound on `Attestation.aggregation_bits`
    /// (`Bitlist<MAX_VALIDATORS_PER_SLOT>`) and
    /// `IndexedAttestation.attesting_indices`
    /// (`List<ValidatorIndex, MAX_VALIDATORS_PER_SLOT>`) from electra onward,
    /// since one attestation's bitfield now spans every committee in the slot
    /// rather than one.
    pub const MAX_VALIDATORS_PER_SLOT: usize =
        MAX_COMMITTEES_PER_SLOT * MAX_VALIDATORS_PER_COMMITTEE;

    // --- Execution ---

    /// Bounds `ExecutionRequests.deposits`
    /// (`List<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>`).
    pub const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 8192;

    /// Bounds `ExecutionRequests.withdrawals`
    /// (`List<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>`).
    pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 16;

    /// Bounds `ExecutionRequests.consolidations`
    /// (`List<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>`).
    pub const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = 2;

    // --- Withdrawals processing ---

    /// Cap on pending partial withdrawals `get_expected_withdrawals` drains per
    /// slot. A loop bound, not a container length, so it stays `u64`.
    pub const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: u64 = 8;

    // --- Pending deposits processing ---

    /// Cap on pending deposits `process_pending_deposits` processes per epoch. A
    /// loop bound, not a container length, so it stays `u64`.
    pub const MAX_PENDING_DEPOSITS_PER_EPOCH: u64 = 16;

    // ================================================================
    // Fulu
    // ================================================================

    // --- Networking ---

    /// Bounds `DataColumnSidecar.kzg_commitments_inclusion_proof`
    /// (`Vector<Bytes32, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH>`). Shallower than
    /// deneb's `KZG_COMMITMENT_INCLUSION_PROOF_DEPTH` because it proves the root
    /// of the whole `blob_kzg_commitments` list rather than one leaf.
    pub const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: usize = 4;

    // --- Blob ---

    /// Bounds a `Cell`'s field-element view
    /// (`Vector<BLSFieldElement, FIELD_ELEMENTS_PER_CELL>`), and is a factor of
    /// `BYTES_PER_CELL`.
    pub const FIELD_ELEMENTS_PER_CELL: usize = 64;

    /// Bounds the Reed-Solomon-extended blob polynomial (`PolynomialCoeff`, a
    /// `List<BLSFieldElement, FIELD_ELEMENTS_PER_EXT_BLOB>`); twice
    /// `FIELD_ELEMENTS_PER_BLOB` since the extension doubles the evaluation
    /// domain.
    pub const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 8192;

    /// Bounds the per-blob cell and proof arrays `compute_cells_and_kzg_proofs`
    /// returns (`Vector<Cell, CELLS_PER_EXT_BLOB>` and
    /// `Vector<KZGProof, CELLS_PER_EXT_BLOB>`).
    pub const CELLS_PER_EXT_BLOB: usize = 128;

    /// Bounds `DataColumnsByRootIdentifier.columns`
    /// (`List<ColumnIndex, NUMBER_OF_COLUMNS>`). One data column corresponds to
    /// one index across the extended matrix, so this equals `CELLS_PER_EXT_BLOB`.
    pub const NUMBER_OF_COLUMNS: usize = 128;

    /// `FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT`, the specification's
    /// formula for the bound on the `Cell` type (`ByteVector<BYTES_PER_CELL>`).
    ///
    /// Derived rather than transcribed, from the same [`crate::constants`] value
    /// `BYTES_PER_BLOB` uses.
    pub const BYTES_PER_CELL: usize =
        FIELD_ELEMENTS_PER_CELL * crate::constants::BYTES_PER_FIELD_ELEMENT;

    // --- State list lengths ---

    /// `(MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH`, the specification's formula
    /// for the length of `BeaconState.proposer_lookahead`
    /// (`Vector<ValidatorIndex, PROPOSER_LOOKAHEAD_LENGTH>`), the vector of
    /// precomputed proposer indices fulu adds to the state.
    pub const PROPOSER_LOOKAHEAD_LENGTH: usize =
        (MIN_SEED_LOOKAHEAD as usize + 1) * SLOTS_PER_EPOCH as usize;
}

/// The minimal preset: the same shape as [`mainnet`], scaled down so spec test
/// fixtures and local devnets run fast.
///
/// Sourced from `presets/minimal/{phase0,altair,bellatrix,capella,deneb,electra,
/// fulu}.yaml` in the specification. Several values equal their mainnet
/// counterpart (the specification only "customizes" the ones that matter for
/// making a small network self-consistent); each is still spelled out here rather
/// than reused from [`mainnet`], so the two modules stay independent sources of
/// truth that happen to agree, rather than one silently defining the other.
pub mod minimal {
    // ================================================================
    // Phase0
    // ================================================================

    // --- Misc ---

    /// How many committees a single slot's active validators are split into.
    /// Also bounds `Attestation.committee_bits` from electra onward
    /// (`Bitvector<MAX_COMMITTEES_PER_SLOT>`), and is a factor of
    /// `MAX_VALIDATORS_PER_SLOT`.
    pub const MAX_COMMITTEES_PER_SLOT: usize = 4;

    /// The committee size `get_committee_count_per_slot` aims for when splitting a
    /// slot's active validators into committees. Not itself a container bound.
    pub const TARGET_COMMITTEE_SIZE: u64 = 4;

    /// Bounds `Attestation.aggregation_bits` (a `Bitlist`) and, pre-electra,
    /// `IndexedAttestation.attesting_indices` (a `List<ValidatorIndex, _>`). From
    /// electra onward it is instead a factor of `MAX_VALIDATORS_PER_SLOT`, which
    /// bounds those same fields.
    pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;

    /// Number of swap-or-not shuffle rounds `compute_shuffled_index` performs when
    /// deriving committee membership from a seed.
    pub const SHUFFLE_ROUND_COUNT: u64 = 10;

    /// Denominator of the balance band, centered on a multiple of
    /// `EFFECTIVE_BALANCE_INCREMENT`, that a validator's effective balance must
    /// leave before `process_effective_balance_updates` moves it.
    pub const HYSTERESIS_QUOTIENT: u64 = 4;

    /// Numerator narrowing the downward half of the hysteresis band relative to
    /// `HYSTERESIS_QUOTIENT`, so effective balance falls faster than it rises.
    pub const HYSTERESIS_DOWNWARD_MULTIPLIER: u64 = 1;

    /// Numerator widening the upward half of the hysteresis band relative to
    /// `HYSTERESIS_QUOTIENT`, damping effective balance increases.
    pub const HYSTERESIS_UPWARD_MULTIPLIER: u64 = 5;

    // --- Gwei values ---

    /// Smallest deposit amount `process_deposit` accepts onto the validator
    /// registry (deposits below this are recorded but never activate a
    /// validator).
    pub const MIN_DEPOSIT_AMOUNT: u64 = 1_000_000_000;

    /// Ceiling that reward, penalty, and churn-limit math clamps a validator's
    /// effective balance to, pre-electra (electra validators with a compounding
    /// withdrawal credential instead use `MAX_EFFECTIVE_BALANCE_ELECTRA`).
    pub const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;

    /// Rounding granularity effective balance is truncated to, and the unit that
    /// base-reward math scales by.
    pub const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;

    // --- Time parameters ---

    /// Minimum number of slots `process_attestation` requires between an
    /// attestation's slot and the slot it is included in.
    pub const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;

    /// Slots per epoch. Never bounds a container by itself; it is a factor of
    /// several derived bounds below (`SLOTS_PER_ETH1_VOTING_PERIOD`,
    /// `MAX_PENDING_ATTESTATIONS`, `PROPOSER_LOOKAHEAD_LENGTH`).
    pub const SLOTS_PER_EPOCH: u64 = 8;

    /// Epochs the RANDAO mix used to seed a shuffling lags behind the epoch it
    /// shuffles, so the seed is unpredictable before that epoch starts. Also a
    /// factor of `PROPOSER_LOOKAHEAD_LENGTH`.
    pub const MIN_SEED_LOOKAHEAD: u64 = 1;

    /// Epochs an exiting validator's withdrawable epoch is delayed past its exit
    /// epoch, bounding how far in advance the exit queue can be gamed.
    pub const MAX_SEED_LOOKAHEAD: u64 = 4;

    /// Epochs a single ETH1 voting period spans. A factor of
    /// `SLOTS_PER_ETH1_VOTING_PERIOD`; not itself a container bound.
    pub const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 4;

    /// `EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH`, the specification's
    /// formula for the bound on `BeaconState.eth1_data_votes`
    /// (`List<Eth1Data, SLOTS_PER_ETH1_VOTING_PERIOD>`), the votes collected
    /// during one ETH1 voting period.
    pub const SLOTS_PER_ETH1_VOTING_PERIOD: usize =
        EPOCHS_PER_ETH1_VOTING_PERIOD as usize * SLOTS_PER_EPOCH as usize;

    /// Bounds `BeaconState.block_roots` and `state_roots`, both
    /// `Vector<Root, SLOTS_PER_HISTORICAL_ROOT>`.
    pub const SLOTS_PER_HISTORICAL_ROOT: usize = 64;

    /// Epochs since the last finality advance before
    /// `process_inactivity_updates`-adjacent penalty logic starts leaking an
    /// inactive validator's balance.
    pub const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64 = 4;

    // --- State list lengths ---

    /// Bounds `BeaconState.randao_mixes` (`Vector<Bytes32,
    /// EPOCHS_PER_HISTORICAL_VECTOR>`), the ring buffer of past RANDAO mixes
    /// shufflings are seeded from.
    pub const EPOCHS_PER_HISTORICAL_VECTOR: usize = 64;

    /// Bounds `BeaconState.slashings` (`Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>`),
    /// the ring buffer `process_slashings` sums to scale the correlated slashing
    /// penalty.
    pub const EPOCHS_PER_SLASHINGS_VECTOR: usize = 64;

    /// Bounds `BeaconState.historical_roots`, and from capella onward
    /// `historical_summaries` (both `List<_, HISTORICAL_ROOTS_LIMIT>`).
    pub const HISTORICAL_ROOTS_LIMIT: usize = 16_777_216;

    /// Bounds every validator-indexed list in `BeaconState`: `validators`,
    /// `balances`, and, from altair, `previous_epoch_participation`,
    /// `current_epoch_participation`, and `inactivity_scores`.
    pub const VALIDATOR_REGISTRY_LIMIT: usize = 1_099_511_627_776;

    // --- Rewards and penalties ---

    /// Numerator of the base reward per increment of effective balance, before
    /// dividing by the integer square root of total active balance.
    pub const BASE_REWARD_FACTOR: u64 = 64;

    /// Divisor of a slashed validator's effective balance that sets the combined
    /// whistleblower/proposer reward `slash_validator` pays out.
    pub const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 512;

    /// Divisor of the whistleblower reward that the block proposer's share is set
    /// to; the remainder goes to whoever reported the slashable offense.
    pub const PROPOSER_REWARD_QUOTIENT: u64 = 8;

    /// Divisor controlling how fast effective balance leaks during non-finality,
    /// pre-altair (altair replaces this with
    /// `INACTIVITY_PENALTY_QUOTIENT_ALTAIR`).
    pub const INACTIVITY_PENALTY_QUOTIENT: u64 = 33_554_432;

    /// Divisor of effective balance burned immediately on slashing, pre-altair.
    pub const MIN_SLASHING_PENALTY_QUOTIENT: u64 = 64;

    /// Multiplier scaling the slashing penalty by the proportion of validators
    /// slashed in the same slashings-vector window, pre-altair. Set lower than
    /// mainnet's for a gentler test-network safety margin.
    pub const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 2;

    // --- Max operations per block ---

    /// Bounds `BeaconBlockBody.proposer_slashings`
    /// (`List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>`).
    pub const MAX_PROPOSER_SLASHINGS: usize = 16;

    /// Bounds `BeaconBlockBody.attester_slashings`, pre-electra
    /// (`List<AttesterSlashing, MAX_ATTESTER_SLASHINGS>`; electra replaces it with
    /// `MAX_ATTESTER_SLASHINGS_ELECTRA`).
    pub const MAX_ATTESTER_SLASHINGS: usize = 2;

    /// Bounds `BeaconBlockBody.attestations`, pre-electra
    /// (`List<Attestation, MAX_ATTESTATIONS>`; electra replaces it with
    /// `MAX_ATTESTATIONS_ELECTRA`). Also a factor of `MAX_PENDING_ATTESTATIONS`.
    pub const MAX_ATTESTATIONS: usize = 128;

    /// `MAX_ATTESTATIONS * SLOTS_PER_EPOCH`, the specification's formula for the
    /// bound on `BeaconState.previous_epoch_attestations` and
    /// `current_epoch_attestations` (`List<PendingAttestation, _>`), the phase0
    /// per-epoch attestation backlog that altair replaces with participation
    /// flags.
    pub const MAX_PENDING_ATTESTATIONS: usize = MAX_ATTESTATIONS * SLOTS_PER_EPOCH as usize;

    /// Bounds `BeaconBlockBody.deposits` (`List<Deposit, MAX_DEPOSITS>`).
    pub const MAX_DEPOSITS: usize = 16;

    /// Bounds `BeaconBlockBody.voluntary_exits`
    /// (`List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>`).
    pub const MAX_VOLUNTARY_EXITS: usize = 16;

    // ================================================================
    // Altair
    // ================================================================

    // --- Rewards and penalties ---

    /// Altair's replacement for `INACTIVITY_PENALTY_QUOTIENT`, retuned for the
    /// participation-flag accounting altair introduces.
    pub const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: u64 = 50_331_648;

    /// Altair's replacement for `MIN_SLASHING_PENALTY_QUOTIENT`.
    pub const MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: u64 = 64;

    /// Altair's replacement for `PROPORTIONAL_SLASHING_MULTIPLIER`.
    pub const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: u64 = 2;

    // --- Sync committee ---

    /// Bounds `SyncCommittee.pubkeys` (`Vector<BLSPubkey, SYNC_COMMITTEE_SIZE>`)
    /// and a sync aggregate's `sync_committee_bits`
    /// (`Bitvector<SYNC_COMMITTEE_SIZE>`).
    pub const SYNC_COMMITTEE_SIZE: usize = 32;

    /// Epochs a sync committee serves before the next one rotates in. A factor of
    /// `UPDATE_TIMEOUT`; not itself a container bound.
    pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 8;

    // --- Sync protocol ---

    /// Minimum signer count a sync aggregate must have for light-client update
    /// validity checks to accept it.
    pub const MIN_SYNC_COMMITTEE_PARTICIPANTS: u64 = 1;

    /// Slots since the light client store's finalized header before
    /// `process_light_client_store_force_update` force-applies the best pending
    /// update. Equal to `SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD`.
    pub const UPDATE_TIMEOUT: u64 = 64;

    // ================================================================
    // Bellatrix
    // ================================================================

    // --- Rewards and penalties ---

    /// Bellatrix's replacement for `INACTIVITY_PENALTY_QUOTIENT_ALTAIR`.
    pub const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64 = 16_777_216;

    /// Bellatrix's replacement for `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR`.
    pub const MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: u64 = 32;

    /// Bellatrix's replacement for `PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR`.
    pub const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64 = 3;

    // --- Execution ---

    /// Bounds the `Transaction` type itself (`ByteList<MAX_BYTES_PER_TRANSACTION>`
    /// is `Transaction`'s SSZ definition).
    pub const MAX_BYTES_PER_TRANSACTION: usize = 1_073_741_824;

    /// Bounds `ExecutionPayload.transactions`
    /// (`List<Transaction, MAX_TRANSACTIONS_PER_PAYLOAD>`).
    pub const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1_048_576;

    /// Bounds `ExecutionPayload(Header).logs_bloom`
    /// (`ByteVector<BYTES_PER_LOGS_BLOOM>`).
    pub const BYTES_PER_LOGS_BLOOM: usize = 256;

    /// Bounds `ExecutionPayload(Header).extra_data`
    /// (`ByteList<MAX_EXTRA_DATA_BYTES>`).
    pub const MAX_EXTRA_DATA_BYTES: usize = 32;

    // ================================================================
    // Capella
    // ================================================================

    // --- Max operations per block ---

    /// Bounds `BeaconBlockBody.bls_to_execution_changes`
    /// (`List<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>`).
    pub const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;

    // --- Execution ---

    /// Bounds `ExecutionPayload(Header).withdrawals`
    /// (`List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>`).
    pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 4;

    // --- Withdrawals processing ---

    /// Cap on how many validators `get_expected_withdrawals` scans per slot while
    /// sweeping the registry for withdrawable balances. A loop bound the
    /// withdrawal-sweep algorithm uses, not a container length, so it stays
    /// `u64`.
    pub const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16;

    // ================================================================
    // Deneb
    // ================================================================

    // --- Execution ---

    /// Bounds `BeaconBlockBody.blob_kzg_commitments`
    /// (`List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>`) and, from fulu,
    /// `DataColumnSidecar.column` / `kzg_commitments`.
    pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;

    // --- Networking ---

    /// Bounds `BlobSidecar.kzg_commitment_inclusion_proof`
    /// (`Vector<Bytes32, KZG_COMMITMENT_INCLUSION_PROOF_DEPTH>`), the merkle proof
    /// that a commitment sits at its claimed index in `blob_kzg_commitments`.
    pub const KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: usize = 17;

    // --- Blob ---

    /// Bounds a blob's polynomial representation
    /// (`Vector<BLSFieldElement, FIELD_ELEMENTS_PER_BLOB>`), and is a factor of
    /// `BYTES_PER_BLOB` and (doubled) fulu's `FIELD_ELEMENTS_PER_EXT_BLOB`. Not
    /// customized for minimal: a smaller blob would need a different trusted
    /// setup, so this preset keeps mainnet's value.
    pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;

    /// `BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB`, the specification's
    /// formula for the bound on the `Blob` type
    /// (`ByteVector<BYTES_PER_BLOB>`), carried in `BlobSidecar.blob`.
    ///
    /// Derived rather than transcribed, so the two cannot drift apart.
    /// `BYTES_PER_FIELD_ELEMENT` is a fixed spec constant rather than a preset
    /// value, so it comes from [`crate::constants`].
    pub const BYTES_PER_BLOB: usize =
        crate::constants::BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB;

    // ================================================================
    // Electra
    // ================================================================

    // --- Gwei values ---

    /// Minimum balance a validator must reach before it can activate. Electra's
    /// deposit-flow counterpart to `MIN_DEPOSIT_AMOUNT`.
    pub const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;

    /// Electra's raised ceiling on effective balance for validators with a
    /// compounding (0x02) withdrawal credential; validators without one still use
    /// `MAX_EFFECTIVE_BALANCE`.
    pub const MAX_EFFECTIVE_BALANCE_ELECTRA: u64 = 2_048_000_000_000;

    // --- Rewards and penalties ---

    /// Electra's replacement for `MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR`, tightened
    /// alongside the higher `MAX_EFFECTIVE_BALANCE_ELECTRA`.
    pub const MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA: u64 = 4096;

    /// Electra's replacement for `WHISTLEBLOWER_REWARD_QUOTIENT`.
    pub const WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: u64 = 4096;

    // --- State list lengths ---

    /// Bounds `BeaconState.pending_deposits`
    /// (`List<PendingDeposit, PENDING_DEPOSITS_LIMIT>`), electra's queue of
    /// deposits not yet processed into the registry.
    pub const PENDING_DEPOSITS_LIMIT: usize = 134_217_728;

    /// Bounds `BeaconState.pending_partial_withdrawals`
    /// (`List<PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT>`).
    pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 64;

    /// Bounds `BeaconState.pending_consolidations`
    /// (`List<PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT>`).
    pub const PENDING_CONSOLIDATIONS_LIMIT: usize = 64;

    // --- Max operations per block ---

    /// Electra's replacement for `MAX_ATTESTER_SLASHINGS`, bounding
    /// `BeaconBlockBody.attester_slashings` now that committee bits move
    /// attesting indices out of the slashing itself.
    pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;

    /// Electra's replacement for `MAX_ATTESTATIONS`, lowered because one electra
    /// `Attestation` now covers every committee in a slot instead of one.
    pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;

    /// `MAX_COMMITTEES_PER_SLOT * MAX_VALIDATORS_PER_COMMITTEE`, the
    /// specification's formula for the bound on `Attestation.aggregation_bits`
    /// (`Bitlist<MAX_VALIDATORS_PER_SLOT>`) and
    /// `IndexedAttestation.attesting_indices`
    /// (`List<ValidatorIndex, MAX_VALIDATORS_PER_SLOT>`) from electra onward,
    /// since one attestation's bitfield now spans every committee in the slot
    /// rather than one.
    pub const MAX_VALIDATORS_PER_SLOT: usize =
        MAX_COMMITTEES_PER_SLOT * MAX_VALIDATORS_PER_COMMITTEE;

    // --- Execution ---

    /// Bounds `ExecutionRequests.deposits`
    /// (`List<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>`).
    pub const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 8192;

    /// Bounds `ExecutionRequests.withdrawals`
    /// (`List<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>`).
    pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 16;

    /// Bounds `ExecutionRequests.consolidations`
    /// (`List<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>`).
    pub const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = 2;

    // --- Withdrawals processing ---

    /// Cap on pending partial withdrawals `get_expected_withdrawals` drains per
    /// slot. A loop bound, not a container length, so it stays `u64`.
    pub const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: u64 = 2;

    // --- Pending deposits processing ---

    /// Cap on pending deposits `process_pending_deposits` processes per epoch. A
    /// loop bound, not a container length, so it stays `u64`.
    pub const MAX_PENDING_DEPOSITS_PER_EPOCH: u64 = 16;

    // ================================================================
    // Fulu
    // ================================================================

    // --- Networking ---

    /// Bounds `DataColumnSidecar.kzg_commitments_inclusion_proof`
    /// (`Vector<Bytes32, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH>`). Shallower than
    /// deneb's `KZG_COMMITMENT_INCLUSION_PROOF_DEPTH` because it proves the root
    /// of the whole `blob_kzg_commitments` list rather than one leaf.
    pub const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: usize = 4;

    // --- Blob ---

    /// Bounds a `Cell`'s field-element view
    /// (`Vector<BLSFieldElement, FIELD_ELEMENTS_PER_CELL>`), and is a factor of
    /// `BYTES_PER_CELL`.
    pub const FIELD_ELEMENTS_PER_CELL: usize = 64;

    /// Bounds the Reed-Solomon-extended blob polynomial (`PolynomialCoeff`, a
    /// `List<BLSFieldElement, FIELD_ELEMENTS_PER_EXT_BLOB>`); twice
    /// `FIELD_ELEMENTS_PER_BLOB` since the extension doubles the evaluation
    /// domain.
    pub const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 8192;

    /// Bounds the per-blob cell and proof arrays `compute_cells_and_kzg_proofs`
    /// returns (`Vector<Cell, CELLS_PER_EXT_BLOB>` and
    /// `Vector<KZGProof, CELLS_PER_EXT_BLOB>`).
    pub const CELLS_PER_EXT_BLOB: usize = 128;

    /// Bounds `DataColumnsByRootIdentifier.columns`
    /// (`List<ColumnIndex, NUMBER_OF_COLUMNS>`). One data column corresponds to
    /// one index across the extended matrix, so this equals `CELLS_PER_EXT_BLOB`.
    pub const NUMBER_OF_COLUMNS: usize = 128;

    /// `FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT`, the specification's
    /// formula for the bound on the `Cell` type (`ByteVector<BYTES_PER_CELL>`).
    ///
    /// Derived rather than transcribed, from the same [`crate::constants`] value
    /// `BYTES_PER_BLOB` uses.
    pub const BYTES_PER_CELL: usize =
        FIELD_ELEMENTS_PER_CELL * crate::constants::BYTES_PER_FIELD_ELEMENT;

    // --- State list lengths ---

    /// `(MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH`, the specification's formula
    /// for the length of `BeaconState.proposer_lookahead`
    /// (`Vector<ValidatorIndex, PROPOSER_LOOKAHEAD_LENGTH>`), the vector of
    /// precomputed proposer indices fulu adds to the state.
    pub const PROPOSER_LOOKAHEAD_LENGTH: usize =
        (MIN_SEED_LOOKAHEAD as usize + 1) * SLOTS_PER_EPOCH as usize;
}

#[cfg(not(feature = "preset-minimal"))]
pub use mainnet::*;
#[cfg(feature = "preset-minimal")]
pub use minimal::*;

/// Preset values that a later fork retunes without changing any container's
/// shape.
///
/// The specification expresses these as a fresh constant per fork
/// (`MIN_SLASHING_PENALTY_QUOTIENT`, then `..._ALTAIR`, then `..._BELLATRIX`)
/// and redefines the function that reads it, so that each fork's copy of the
/// function reads its own constant. Reproducing that here would mean one copy of
/// `process_slashings` and `slash_validator` per fork, differing in a single
/// identifier. Selecting the value by fork instead keeps one copy of each
/// function, and puts the whole fork-to-value mapping in one place where it can
/// be read against the specification's own tables.
///
/// This is the one place in the crate where a preset value is chosen at runtime.
/// It is sound because none of these bound a container: they are divisors and
/// multipliers in balance arithmetic, so nothing about them has to be known at
/// compile time.
///
/// # The two presets do not agree on the direction of these changes
///
/// The minimal preset overrides only the *phase0* values and inherits every
/// later fork's from mainnet unchanged. So a value can move one way across a
/// fork boundary under mainnet and the other way under minimal:
/// `INACTIVITY_PENALTY_QUOTIENT` falls from phase0 to altair under mainnet and
/// rises under minimal, and `MIN_SLASHING_PENALTY_QUOTIENT` falls under mainnet
/// but is unchanged under minimal.
///
/// That is worth knowing before writing anything that assumes these get
/// uniformly harsher over time. They do under mainnet; the tests below therefore
/// pin the fork-to-constant mapping, which holds under both presets, rather than
/// any numeric relationship, which does not.
pub mod retuned {
    use crate::fork::ForkName;

    /// How much the summed slashings are scaled by before being capped at the
    /// total active balance.
    ///
    /// Raised at altair and again at bellatrix, so slashing together with a
    /// larger fraction of the validator set costs proportionally more than it
    /// used to.
    pub fn proportional_slashing_multiplier(fork: ForkName) -> u64 {
        match fork {
            ForkName::Phase0 => super::PROPORTIONAL_SLASHING_MULTIPLIER,
            ForkName::Altair => super::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR,
            _ => super::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
        }
    }

    /// The divisor setting the immediate penalty a slashed validator pays, before
    /// the epoch boundary's proportional penalty.
    ///
    /// Lowered through altair and bellatrix, so the immediate penalty grows, and
    /// then raised steeply at electra. That reversal is not a relaxation: electra
    /// raises the ceiling on a validator's effective balance, so leaving the
    /// divisor where bellatrix put it would have made the immediate penalty on a
    /// maximally consolidated validator far larger in absolute terms than the
    /// penalty bellatrix intended. The divisor grows roughly in step with the
    /// balance ceiling.
    pub fn min_slashing_penalty_quotient(fork: ForkName) -> u64 {
        match fork {
            ForkName::Phase0 => super::MIN_SLASHING_PENALTY_QUOTIENT,
            ForkName::Altair => super::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
            ForkName::Bellatrix | ForkName::Capella | ForkName::Deneb => {
                super::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX
            }
            ForkName::Electra | ForkName::Fulu => super::MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
        }
    }

    /// The divisor setting the reporter's cut of a slashed validator's effective
    /// balance.
    ///
    /// Electra raises the divisor, which lowers the reward, because the same
    /// fork raises the maximum effective balance: leaving the divisor alone would
    /// have made reporting a large validator far more lucrative than reporting a
    /// small one.
    pub fn whistleblower_reward_quotient(fork: ForkName) -> u64 {
        match fork {
            ForkName::Electra | ForkName::Fulu => super::WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
            _ => super::WHISTLEBLOWER_REWARD_QUOTIENT,
        }
    }

    /// The divisor setting how fast an inactive validator's balance leaks while
    /// the chain is failing to finalize.
    ///
    /// Altair and later scale the leak by a validator's own `inactivity_scores`
    /// entry rather than reading this directly, so in practice only phase0's
    /// inactivity penalty consults it. The later arms exist so that a caller
    /// asking for a fork's value gets the right answer rather than phase0's.
    pub fn inactivity_penalty_quotient(fork: ForkName) -> u64 {
        match fork {
            ForkName::Phase0 => super::INACTIVITY_PENALTY_QUOTIENT,
            ForkName::Altair => super::INACTIVITY_PENALTY_QUOTIENT_ALTAIR,
            _ => super::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use super::super::{
            INACTIVITY_PENALTY_QUOTIENT, INACTIVITY_PENALTY_QUOTIENT_ALTAIR,
            INACTIVITY_PENALTY_QUOTIENT_BELLATRIX, MIN_SLASHING_PENALTY_QUOTIENT,
            MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR, MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX,
            MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA, PROPORTIONAL_SLASHING_MULTIPLIER,
            PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR, PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
            WHISTLEBLOWER_REWARD_QUOTIENT, WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
        };

        /// Pins which constant each fork selects.
        ///
        /// The failure this guards against is a swapped or misplaced match arm, so
        /// the assertions name the constants rather than comparing numbers. An
        /// earlier version of this test compared values instead, asserting that
        /// slashing gets uniformly harsher across the forks. That holds under
        /// mainnet and is false under minimal, which overrides only phase0's
        /// values and inherits the rest, so phase0 to altair moves the other way
        /// there. Naming the constants is the only formulation that is both
        /// preset-independent and able to catch a swapped arm.
        #[test]
        fn every_fork_selects_its_own_constant() {
            let bellatrix_onward = [
                ForkName::Bellatrix,
                ForkName::Capella,
                ForkName::Deneb,
                ForkName::Electra,
                ForkName::Fulu,
            ];

            assert_eq!(
                proportional_slashing_multiplier(ForkName::Phase0),
                PROPORTIONAL_SLASHING_MULTIPLIER
            );
            assert_eq!(
                proportional_slashing_multiplier(ForkName::Altair),
                PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR
            );
            for fork in bellatrix_onward {
                assert_eq!(
                    proportional_slashing_multiplier(fork),
                    PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
                    "{fork} must use bellatrix's slashing multiplier",
                );
            }

            assert_eq!(
                inactivity_penalty_quotient(ForkName::Phase0),
                INACTIVITY_PENALTY_QUOTIENT
            );
            assert_eq!(
                inactivity_penalty_quotient(ForkName::Altair),
                INACTIVITY_PENALTY_QUOTIENT_ALTAIR
            );
            for fork in bellatrix_onward {
                assert_eq!(
                    inactivity_penalty_quotient(fork),
                    INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
                    "{fork} must use bellatrix's inactivity penalty quotient",
                );
            }

            assert_eq!(
                min_slashing_penalty_quotient(ForkName::Phase0),
                MIN_SLASHING_PENALTY_QUOTIENT
            );
            assert_eq!(
                min_slashing_penalty_quotient(ForkName::Altair),
                MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR
            );
            for fork in [ForkName::Bellatrix, ForkName::Capella, ForkName::Deneb] {
                assert_eq!(
                    min_slashing_penalty_quotient(fork),
                    MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX,
                    "{fork} must use bellatrix's penalty divisor",
                );
            }
            for fork in [ForkName::Electra, ForkName::Fulu] {
                assert_eq!(
                    min_slashing_penalty_quotient(fork),
                    MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
                    "{fork} must use electra's penalty divisor",
                );
            }

            for fork in [
                ForkName::Phase0,
                ForkName::Altair,
                ForkName::Bellatrix,
                ForkName::Capella,
                ForkName::Deneb,
            ] {
                assert_eq!(
                    whistleblower_reward_quotient(fork),
                    WHISTLEBLOWER_REWARD_QUOTIENT,
                    "{fork} predates electra's whistleblower reward change",
                );
            }
            for fork in [ForkName::Electra, ForkName::Fulu] {
                assert_eq!(
                    whistleblower_reward_quotient(fork),
                    WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
                    "{fork} must use electra's whistleblower reward quotient",
                );
            }
        }

        /// Every fork must get an answer from every selector. A `match` makes this
        /// true by construction today, but the selectors are the kind of code a
        /// later edit turns into a lookup with a fallible default.
        #[test]
        fn no_fork_is_left_without_a_value() {
            for fork in ForkName::ALL {
                assert_ne!(proportional_slashing_multiplier(fork), 0);
                assert_ne!(min_slashing_penalty_quotient(fork), 0);
                assert_ne!(whistleblower_reward_quotient(fork), 0);
                assert_ne!(inactivity_penalty_quotient(fork), 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{mainnet, minimal};

    /// Values pinned directly from the specification, so a typo or an accidental
    /// edit shows up as a failing test rather than a silent divergence from
    /// `presets/{mainnet,minimal}/*.yaml`.
    #[test]
    fn pinned_values() {
        assert_eq!(mainnet::SLOTS_PER_EPOCH, 32);
        assert_eq!(minimal::SLOTS_PER_EPOCH, 8);

        assert_eq!(mainnet::SYNC_COMMITTEE_SIZE, 512);
        assert_eq!(minimal::SYNC_COMMITTEE_SIZE, 32);

        assert_eq!(mainnet::MAX_COMMITTEES_PER_SLOT, 64);
        assert_eq!(minimal::MAX_COMMITTEES_PER_SLOT, 4);

        assert_eq!(mainnet::SLOTS_PER_HISTORICAL_ROOT, 8192);
        assert_eq!(minimal::SLOTS_PER_HISTORICAL_ROOT, 64);

        assert_eq!(mainnet::FIELD_ELEMENTS_PER_BLOB, 4096);
        assert_eq!(minimal::FIELD_ELEMENTS_PER_BLOB, 4096);

        assert_eq!(mainnet::MAX_VALIDATORS_PER_SLOT, 131_072);
        assert_eq!(minimal::MAX_VALIDATORS_PER_SLOT, 8192);
    }

    /// Every derived constant computed from more than one preset value, checked
    /// against the specification's formula spelled out arithmetically rather than
    /// copied as a literal.
    #[test]
    fn derived_values() {
        assert_eq!(
            mainnet::MAX_PENDING_ATTESTATIONS,
            mainnet::MAX_ATTESTATIONS * mainnet::SLOTS_PER_EPOCH as usize
        );
        assert_eq!(
            minimal::MAX_PENDING_ATTESTATIONS,
            minimal::MAX_ATTESTATIONS * minimal::SLOTS_PER_EPOCH as usize
        );

        assert_eq!(
            mainnet::SLOTS_PER_ETH1_VOTING_PERIOD,
            mainnet::EPOCHS_PER_ETH1_VOTING_PERIOD as usize * mainnet::SLOTS_PER_EPOCH as usize
        );
        assert_eq!(
            minimal::SLOTS_PER_ETH1_VOTING_PERIOD,
            minimal::EPOCHS_PER_ETH1_VOTING_PERIOD as usize * minimal::SLOTS_PER_EPOCH as usize
        );

        assert_eq!(
            mainnet::BYTES_PER_BLOB,
            32 * mainnet::FIELD_ELEMENTS_PER_BLOB
        );
        assert_eq!(
            minimal::BYTES_PER_BLOB,
            32 * minimal::FIELD_ELEMENTS_PER_BLOB
        );

        assert_eq!(
            mainnet::BYTES_PER_CELL,
            mainnet::FIELD_ELEMENTS_PER_CELL * crate::constants::BYTES_PER_FIELD_ELEMENT
        );
        assert_eq!(
            minimal::BYTES_PER_CELL,
            minimal::FIELD_ELEMENTS_PER_CELL * crate::constants::BYTES_PER_FIELD_ELEMENT
        );

        assert_eq!(
            mainnet::PROPOSER_LOOKAHEAD_LENGTH,
            (mainnet::MIN_SEED_LOOKAHEAD as usize + 1) * mainnet::SLOTS_PER_EPOCH as usize
        );
        assert_eq!(
            minimal::PROPOSER_LOOKAHEAD_LENGTH,
            (minimal::MIN_SEED_LOOKAHEAD as usize + 1) * minimal::SLOTS_PER_EPOCH as usize
        );

        assert_eq!(
            mainnet::MAX_VALIDATORS_PER_SLOT,
            mainnet::MAX_COMMITTEES_PER_SLOT * mainnet::MAX_VALIDATORS_PER_COMMITTEE
        );
        assert_eq!(
            minimal::MAX_VALIDATORS_PER_SLOT,
            minimal::MAX_COMMITTEES_PER_SLOT * minimal::MAX_VALIDATORS_PER_COMMITTEE
        );
    }

    /// Every name this module defines must resolve, at the same type, through
    /// both `mainnet::` and `minimal::`. Referencing every constant through both
    /// paths turns a name present in one preset but missing (or misspelled) in
    /// the other into a compile error here, rather than a runtime surprise for
    /// whichever fork first needs the missing side.
    #[test]
    fn same_names_in_both_presets() {
        let _: usize = mainnet::MAX_COMMITTEES_PER_SLOT;
        let _: usize = minimal::MAX_COMMITTEES_PER_SLOT;
        let _: u64 = mainnet::TARGET_COMMITTEE_SIZE;
        let _: u64 = minimal::TARGET_COMMITTEE_SIZE;
        let _: usize = mainnet::MAX_VALIDATORS_PER_COMMITTEE;
        let _: usize = minimal::MAX_VALIDATORS_PER_COMMITTEE;
        let _: u64 = mainnet::SHUFFLE_ROUND_COUNT;
        let _: u64 = minimal::SHUFFLE_ROUND_COUNT;
        let _: u64 = mainnet::HYSTERESIS_QUOTIENT;
        let _: u64 = minimal::HYSTERESIS_QUOTIENT;
        let _: u64 = mainnet::HYSTERESIS_DOWNWARD_MULTIPLIER;
        let _: u64 = minimal::HYSTERESIS_DOWNWARD_MULTIPLIER;
        let _: u64 = mainnet::HYSTERESIS_UPWARD_MULTIPLIER;
        let _: u64 = minimal::HYSTERESIS_UPWARD_MULTIPLIER;

        let _: u64 = mainnet::MIN_DEPOSIT_AMOUNT;
        let _: u64 = minimal::MIN_DEPOSIT_AMOUNT;
        let _: u64 = mainnet::MAX_EFFECTIVE_BALANCE;
        let _: u64 = minimal::MAX_EFFECTIVE_BALANCE;
        let _: u64 = mainnet::EFFECTIVE_BALANCE_INCREMENT;
        let _: u64 = minimal::EFFECTIVE_BALANCE_INCREMENT;

        let _: u64 = mainnet::MIN_ATTESTATION_INCLUSION_DELAY;
        let _: u64 = minimal::MIN_ATTESTATION_INCLUSION_DELAY;
        let _: u64 = mainnet::SLOTS_PER_EPOCH;
        let _: u64 = minimal::SLOTS_PER_EPOCH;
        let _: u64 = mainnet::MIN_SEED_LOOKAHEAD;
        let _: u64 = minimal::MIN_SEED_LOOKAHEAD;
        let _: u64 = mainnet::MAX_SEED_LOOKAHEAD;
        let _: u64 = minimal::MAX_SEED_LOOKAHEAD;
        let _: u64 = mainnet::EPOCHS_PER_ETH1_VOTING_PERIOD;
        let _: u64 = minimal::EPOCHS_PER_ETH1_VOTING_PERIOD;
        let _: usize = mainnet::SLOTS_PER_ETH1_VOTING_PERIOD;
        let _: usize = minimal::SLOTS_PER_ETH1_VOTING_PERIOD;
        let _: usize = mainnet::SLOTS_PER_HISTORICAL_ROOT;
        let _: usize = minimal::SLOTS_PER_HISTORICAL_ROOT;
        let _: u64 = mainnet::MIN_EPOCHS_TO_INACTIVITY_PENALTY;
        let _: u64 = minimal::MIN_EPOCHS_TO_INACTIVITY_PENALTY;

        let _: usize = mainnet::EPOCHS_PER_HISTORICAL_VECTOR;
        let _: usize = minimal::EPOCHS_PER_HISTORICAL_VECTOR;
        let _: usize = mainnet::EPOCHS_PER_SLASHINGS_VECTOR;
        let _: usize = minimal::EPOCHS_PER_SLASHINGS_VECTOR;
        let _: usize = mainnet::HISTORICAL_ROOTS_LIMIT;
        let _: usize = minimal::HISTORICAL_ROOTS_LIMIT;
        let _: usize = mainnet::VALIDATOR_REGISTRY_LIMIT;
        let _: usize = minimal::VALIDATOR_REGISTRY_LIMIT;

        let _: u64 = mainnet::BASE_REWARD_FACTOR;
        let _: u64 = minimal::BASE_REWARD_FACTOR;
        let _: u64 = mainnet::WHISTLEBLOWER_REWARD_QUOTIENT;
        let _: u64 = minimal::WHISTLEBLOWER_REWARD_QUOTIENT;
        let _: u64 = mainnet::PROPOSER_REWARD_QUOTIENT;
        let _: u64 = minimal::PROPOSER_REWARD_QUOTIENT;
        let _: u64 = mainnet::INACTIVITY_PENALTY_QUOTIENT;
        let _: u64 = minimal::INACTIVITY_PENALTY_QUOTIENT;
        let _: u64 = mainnet::MIN_SLASHING_PENALTY_QUOTIENT;
        let _: u64 = minimal::MIN_SLASHING_PENALTY_QUOTIENT;
        let _: u64 = mainnet::PROPORTIONAL_SLASHING_MULTIPLIER;
        let _: u64 = minimal::PROPORTIONAL_SLASHING_MULTIPLIER;

        let _: usize = mainnet::MAX_PROPOSER_SLASHINGS;
        let _: usize = minimal::MAX_PROPOSER_SLASHINGS;
        let _: usize = mainnet::MAX_ATTESTER_SLASHINGS;
        let _: usize = minimal::MAX_ATTESTER_SLASHINGS;
        let _: usize = mainnet::MAX_ATTESTATIONS;
        let _: usize = minimal::MAX_ATTESTATIONS;
        let _: usize = mainnet::MAX_PENDING_ATTESTATIONS;
        let _: usize = minimal::MAX_PENDING_ATTESTATIONS;
        let _: usize = mainnet::MAX_DEPOSITS;
        let _: usize = minimal::MAX_DEPOSITS;
        let _: usize = mainnet::MAX_VOLUNTARY_EXITS;
        let _: usize = minimal::MAX_VOLUNTARY_EXITS;

        let _: u64 = mainnet::INACTIVITY_PENALTY_QUOTIENT_ALTAIR;
        let _: u64 = minimal::INACTIVITY_PENALTY_QUOTIENT_ALTAIR;
        let _: u64 = mainnet::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR;
        let _: u64 = minimal::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR;
        let _: u64 = mainnet::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR;
        let _: u64 = minimal::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR;
        let _: usize = mainnet::SYNC_COMMITTEE_SIZE;
        let _: usize = minimal::SYNC_COMMITTEE_SIZE;
        let _: u64 = mainnet::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let _: u64 = minimal::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let _: u64 = mainnet::MIN_SYNC_COMMITTEE_PARTICIPANTS;
        let _: u64 = minimal::MIN_SYNC_COMMITTEE_PARTICIPANTS;
        let _: u64 = mainnet::UPDATE_TIMEOUT;
        let _: u64 = minimal::UPDATE_TIMEOUT;

        let _: u64 = mainnet::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
        let _: u64 = minimal::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
        let _: u64 = mainnet::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX;
        let _: u64 = minimal::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX;
        let _: u64 = mainnet::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX;
        let _: u64 = minimal::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX;
        let _: usize = mainnet::MAX_BYTES_PER_TRANSACTION;
        let _: usize = minimal::MAX_BYTES_PER_TRANSACTION;
        let _: usize = mainnet::MAX_TRANSACTIONS_PER_PAYLOAD;
        let _: usize = minimal::MAX_TRANSACTIONS_PER_PAYLOAD;
        let _: usize = mainnet::BYTES_PER_LOGS_BLOOM;
        let _: usize = minimal::BYTES_PER_LOGS_BLOOM;
        let _: usize = mainnet::MAX_EXTRA_DATA_BYTES;
        let _: usize = minimal::MAX_EXTRA_DATA_BYTES;

        let _: usize = mainnet::MAX_BLS_TO_EXECUTION_CHANGES;
        let _: usize = minimal::MAX_BLS_TO_EXECUTION_CHANGES;
        let _: usize = mainnet::MAX_WITHDRAWALS_PER_PAYLOAD;
        let _: usize = minimal::MAX_WITHDRAWALS_PER_PAYLOAD;
        let _: u64 = mainnet::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP;
        let _: u64 = minimal::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP;

        let _: usize = mainnet::MAX_BLOB_COMMITMENTS_PER_BLOCK;
        let _: usize = minimal::MAX_BLOB_COMMITMENTS_PER_BLOCK;
        let _: usize = mainnet::KZG_COMMITMENT_INCLUSION_PROOF_DEPTH;
        let _: usize = minimal::KZG_COMMITMENT_INCLUSION_PROOF_DEPTH;
        let _: usize = mainnet::FIELD_ELEMENTS_PER_BLOB;
        let _: usize = minimal::FIELD_ELEMENTS_PER_BLOB;
        let _: usize = mainnet::BYTES_PER_BLOB;
        let _: usize = minimal::BYTES_PER_BLOB;

        let _: u64 = mainnet::MIN_ACTIVATION_BALANCE;
        let _: u64 = minimal::MIN_ACTIVATION_BALANCE;
        let _: u64 = mainnet::MAX_EFFECTIVE_BALANCE_ELECTRA;
        let _: u64 = minimal::MAX_EFFECTIVE_BALANCE_ELECTRA;
        let _: u64 = mainnet::MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA;
        let _: u64 = minimal::MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA;
        let _: u64 = mainnet::WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
        let _: u64 = minimal::WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
        let _: usize = mainnet::PENDING_DEPOSITS_LIMIT;
        let _: usize = minimal::PENDING_DEPOSITS_LIMIT;
        let _: usize = mainnet::PENDING_PARTIAL_WITHDRAWALS_LIMIT;
        let _: usize = minimal::PENDING_PARTIAL_WITHDRAWALS_LIMIT;
        let _: usize = mainnet::PENDING_CONSOLIDATIONS_LIMIT;
        let _: usize = minimal::PENDING_CONSOLIDATIONS_LIMIT;
        let _: usize = mainnet::MAX_ATTESTER_SLASHINGS_ELECTRA;
        let _: usize = minimal::MAX_ATTESTER_SLASHINGS_ELECTRA;
        let _: usize = mainnet::MAX_ATTESTATIONS_ELECTRA;
        let _: usize = minimal::MAX_ATTESTATIONS_ELECTRA;
        let _: usize = mainnet::MAX_VALIDATORS_PER_SLOT;
        let _: usize = minimal::MAX_VALIDATORS_PER_SLOT;
        let _: usize = mainnet::MAX_DEPOSIT_REQUESTS_PER_PAYLOAD;
        let _: usize = minimal::MAX_DEPOSIT_REQUESTS_PER_PAYLOAD;
        let _: usize = mainnet::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD;
        let _: usize = minimal::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD;
        let _: usize = mainnet::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD;
        let _: usize = minimal::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD;
        let _: u64 = mainnet::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP;
        let _: u64 = minimal::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP;
        let _: u64 = mainnet::MAX_PENDING_DEPOSITS_PER_EPOCH;
        let _: u64 = minimal::MAX_PENDING_DEPOSITS_PER_EPOCH;

        let _: usize = mainnet::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH;
        let _: usize = minimal::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH;
        let _: usize = mainnet::FIELD_ELEMENTS_PER_CELL;
        let _: usize = minimal::FIELD_ELEMENTS_PER_CELL;
        let _: usize = mainnet::FIELD_ELEMENTS_PER_EXT_BLOB;
        let _: usize = minimal::FIELD_ELEMENTS_PER_EXT_BLOB;
        let _: usize = mainnet::CELLS_PER_EXT_BLOB;
        let _: usize = minimal::CELLS_PER_EXT_BLOB;
        let _: usize = mainnet::NUMBER_OF_COLUMNS;
        let _: usize = minimal::NUMBER_OF_COLUMNS;
        let _: usize = mainnet::BYTES_PER_CELL;
        let _: usize = minimal::BYTES_PER_CELL;
        let _: usize = mainnet::PROPOSER_LOOKAHEAD_LENGTH;
        let _: usize = minimal::PROPOSER_LOOKAHEAD_LENGTH;
    }
}
