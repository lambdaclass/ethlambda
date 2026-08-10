//! Spec constants: values the specification fixes outright, as opposed to
//! preset values (compile-time, see [`crate::preset`]) or configuration
//! values (runtime, per network, see [`crate::config`]).
//!
//! A value lives here only if the spec's own `.md` files list it under a
//! "Constants" heading (or, for domain types, wherever the fork first
//! introduces them; several forks file their `DOMAIN_*` additions under
//! "Custom types" instead, but they are the same kind of value as phase0's).
//!
//! One constant from phase0's table is deliberately not modeled:
//! `ENDIANNESS` ('little'). The specification needs to name it because Python
//! integer-to-bytes conversions take an explicit byte order argument; Rust
//! does not have that ambiguity; `to_le_bytes`/`from_le_bytes` (used
//! throughout this crate and by the SSZ codec) already commit to little-endian
//! in the function name, so there is no value for this constant to hold.

use crate::primitives::{DomainType, Epoch, Gwei, Slot};

// ---------------------------------------------------------------------------
// Misc (phase0)
// ---------------------------------------------------------------------------

/// The slot of the genesis block. Always zero: slots count up from genesis,
/// never down, so this is also the smallest valid `Slot`.
pub const GENESIS_SLOT: Slot = 0;

/// The epoch containing [`GENESIS_SLOT`].
pub const GENESIS_EPOCH: Epoch = 0;

/// A sentinel meaning "this has not happened (yet)".
///
/// Validator lifecycle fields (`activation_eligibility_epoch`, `exit_epoch`,
/// `withdrawable_epoch`, ...) hold this until the corresponding event is
/// scheduled. Comparisons like `validator.exit_epoch == FAR_FUTURE_EPOCH`
/// are how the spec asks "has this validator exited". [`crate::config`] reuses
/// the same sentinel for fork epochs that have not been scheduled, so that
/// `Config::fork_at_epoch` can skip them the same way.
pub const FAR_FUTURE_EPOCH: Epoch = Epoch::MAX;

/// The number of ways a single epoch's reward budget is split among
/// validators: proposer inclusion plus one share per attestation component
/// tracked before altair (source, target, head). Altair replaces the
/// three-way split with [`PARTICIPATION_FLAG_WEIGHTS`], but phase0's base
/// reward computation still divides by this constant.
pub const BASE_REWARDS_PER_EPOCH: u64 = 4;

/// The depth of the deposit contract's incremental merkle tree. Bounds the
/// length of a `Deposit`'s merkle proof (`DEPOSIT_CONTRACT_TREE_DEPTH + 1`
/// entries, the `+ 1` covers the mix-in of the deposit count), hence `usize`.
pub const DEPOSIT_CONTRACT_TREE_DEPTH: usize = 32;

/// The number of bits in `BeaconState.justification_bits`: one bit per each of
/// the four most recent epochs, tracking whether it was justified. Bounds a
/// `Bitvector`, hence `usize`.
pub const JUSTIFICATION_BITS_LENGTH: usize = 4;

/// `2**64 - 1`. Used only by [`crate::state_transition`]'s `integer_squareroot`
/// helper as the boundary past which the doubling-based Newton's method
/// bound is replaced by a precomputed answer; unrelated to
/// [`FAR_FUTURE_EPOCH`] despite the identical bit pattern.
pub const UINT64_MAX: u64 = u64::MAX;

/// `floor(sqrt(UINT64_MAX))`. The precomputed answer `integer_squareroot`
/// returns for an input of exactly [`UINT64_MAX`], where the general
/// algorithm's intermediate arithmetic would otherwise overflow.
pub const UINT64_MAX_SQRT: u64 = 4_294_967_295;

// ---------------------------------------------------------------------------
// Withdrawal prefixes
// ---------------------------------------------------------------------------
//
// The first byte of `Validator.withdrawal_credentials` selects how the rest
// of the 32 bytes are interpreted. Typed `u8`: each is compared against a
// single byte read out of a `Bytes32`, never SSZ-encoded on its own.

/// Marks credentials as a raw BLS withdrawal pubkey hash: withdrawals are
/// disabled until the validator submits a `BLSToExecutionChange` upgrading to
/// [`ETH1_ADDRESS_WITHDRAWAL_PREFIX`].
pub const BLS_WITHDRAWAL_PREFIX: u8 = 0x00;

/// Marks credentials as wrapping an execution-layer address: withdrawals (from
/// capella onward) pay out to that address, and the validator is capped at
/// `MAX_EFFECTIVE_BALANCE` (a preset value) until it upgrades further to
/// [`COMPOUNDING_WITHDRAWAL_PREFIX`].
pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;

/// Marks credentials as compounding (electra:EIP7251): balance above
/// `MIN_ACTIVATION_BALANCE` (a preset value) stays effective instead of
/// triggering an automatic partial withdrawal.
pub const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------
//
// A `DomainType` names one kind of signable message. `get_domain` mixes one
// of these with a fork version and the genesis validators root to produce the
// `Domain` that actually goes into a signing root, so the same message signed
// under two different forks (or two different chains) produces unrelated
// signatures.

/// Domain for a `BeaconBlock` proposal signature.
pub const DOMAIN_BEACON_PROPOSER: DomainType = [0x00, 0x00, 0x00, 0x00];
/// Domain for an `AttestationData` signature.
pub const DOMAIN_BEACON_ATTESTER: DomainType = [0x01, 0x00, 0x00, 0x00];
/// Domain for the per-epoch RANDAO reveal.
pub const DOMAIN_RANDAO: DomainType = [0x02, 0x00, 0x00, 0x00];
/// Domain for a `DepositMessage`. Unlike the others, deposit signatures are
/// verified with a fixed genesis-independent domain (`compute_domain` called
/// with no fork data), since a deposit must be valid before the chain it
/// targets has even started.
pub const DOMAIN_DEPOSIT: DomainType = [0x03, 0x00, 0x00, 0x00];
/// Domain for a `VoluntaryExit`.
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = [0x04, 0x00, 0x00, 0x00];
/// Domain for an aggregator's slot selection proof.
pub const DOMAIN_SELECTION_PROOF: DomainType = [0x05, 0x00, 0x00, 0x00];
/// Domain for an `AggregateAndProof`.
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = [0x06, 0x00, 0x00, 0x00];
/// Reserves the non-zero bits of the `DomainType` bitspace for
/// application-specific domains outside the specification. Every
/// specification-defined `DomainType` masks to zero against this; a
/// `DomainType` that does not is reserved for other uses (for example
/// re-purposing beacon chain signatures on an application layer) and this
/// crate never produces or expects one.
pub const DOMAIN_APPLICATION_MASK: DomainType = [0x00, 0x00, 0x00, 0x01];
/// Domain for a `SyncCommitteeMessage` (altair).
pub const DOMAIN_SYNC_COMMITTEE: DomainType = [0x07, 0x00, 0x00, 0x00];
/// Domain for a sync committee aggregator's selection proof (altair).
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = [0x08, 0x00, 0x00, 0x00];
/// Domain for a `ContributionAndProof` (altair).
pub const DOMAIN_CONTRIBUTION_AND_PROOF: DomainType = [0x09, 0x00, 0x00, 0x00];
/// Domain for a `BLSToExecutionChange` (capella). Signed with the validator's
/// original BLS withdrawal key, proving ownership before switching
/// [`BLS_WITHDRAWAL_PREFIX`] credentials over to
/// [`ETH1_ADDRESS_WITHDRAWAL_PREFIX`].
pub const DOMAIN_BLS_TO_EXECUTION_CHANGE: DomainType = [0x0a, 0x00, 0x00, 0x00];

// ---------------------------------------------------------------------------
// Participation flags and incentivization weights (altair)
// ---------------------------------------------------------------------------
//
// Altair replaces phase0's `PendingAttestation` bookkeeping with three
// per-validator, per-epoch bits (a `ParticipationFlags`), recording whether an
// attestation had the right source, target, and head, and how promptly it
// landed. `TIMELY_*_FLAG_INDEX` is the bit position within that
// `ParticipationFlags` byte for each of the three; `usize` because it is used
// as a shift amount and as an index, never SSZ-encoded on its own.

/// Bit index recording a timely, correct attestation source.
pub const TIMELY_SOURCE_FLAG_INDEX: usize = 0;
/// Bit index recording a timely, correct attestation target.
pub const TIMELY_TARGET_FLAG_INDEX: usize = 1;
/// Bit index recording a timely, correct attestation head vote.
pub const TIMELY_HEAD_FLAG_INDEX: usize = 2;

/// Reward share for a timely, correct source vote, out of [`WEIGHT_DENOMINATOR`].
pub const TIMELY_SOURCE_WEIGHT: u64 = 14;
/// Reward share for a timely, correct target vote, out of [`WEIGHT_DENOMINATOR`].
pub const TIMELY_TARGET_WEIGHT: u64 = 26;
/// Reward share for a timely, correct head vote, out of [`WEIGHT_DENOMINATOR`].
pub const TIMELY_HEAD_WEIGHT: u64 = 14;
/// Reward share for participating in the current sync committee, out of
/// [`WEIGHT_DENOMINATOR`].
pub const SYNC_REWARD_WEIGHT: u64 = 2;
/// Reward share paid to the block proposer for including attestations and
/// sync committee contributions, out of [`WEIGHT_DENOMINATOR`].
pub const PROPOSER_WEIGHT: u64 = 8;
/// The denominator every `*_WEIGHT` constant is a numerator over. The weights
/// sum to this value exactly, so together they partition the whole reward.
pub const WEIGHT_DENOMINATOR: u64 = 64;

/// [`TIMELY_SOURCE_WEIGHT`], [`TIMELY_TARGET_WEIGHT`], and
/// [`TIMELY_HEAD_WEIGHT`], indexed by [`TIMELY_SOURCE_FLAG_INDEX`],
/// [`TIMELY_TARGET_FLAG_INDEX`], and [`TIMELY_HEAD_FLAG_INDEX`]
/// respectively. `get_flag_index_deltas` walks this alongside the three flag
/// indices so the reward computation for each flag reads as one shared loop
/// rather than three near-identical copies.
pub const PARTICIPATION_FLAG_WEIGHTS: [u64; 3] = [
    TIMELY_SOURCE_WEIGHT,
    TIMELY_TARGET_WEIGHT,
    TIMELY_HEAD_WEIGHT,
];

// ---------------------------------------------------------------------------
// Fork choice (phase0)
// ---------------------------------------------------------------------------

/// The number of sub-slot ticks the fork choice store used to divide a slot
/// into (attest, aggregate, and the next slot's boundary). Deprecated in
/// favor of the millisecond-precision basis-point timings
/// (`ATTESTATION_DUE_BPS` and friends, in [`crate::config`]), but the
/// specification still lists it, and older fixtures may reference it.
pub const INTERVALS_PER_SLOT: u64 = 3;

/// The denominator the `*_DUE_BPS` configuration values (in [`crate::config`])
/// are numerators over, i.e. ten thousand basis points to a whole slot.
/// `get_slot_component_duration_ms` divides by this to turn a basis-point
/// share into a millisecond offset into the slot.
pub const BASIS_POINTS: u64 = 10_000;

// ---------------------------------------------------------------------------
// Blob (deneb)
// ---------------------------------------------------------------------------

/// The size of one BLS scalar field element in bytes.
///
/// A blob is a vector of field elements, so this is the factor relating a field
/// element count to a byte length: `BYTES_PER_BLOB` and `BYTES_PER_CELL` in
/// [`crate::preset`] are both derived from it. Fixed by the specification rather
/// than by preset, since it follows from the size of the BLS12-381 scalar field
/// and not from any network parameter. Bounds a `ByteVector`, hence `usize`.
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;

/// The version byte prepended to `hash(kzg_commitment)[1:]` to form a blob's
/// versioned hash. Lets the execution layer's transaction format distinguish
/// a KZG-backed versioned hash from other hash-derived identifiers it might
/// introduce later.
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

// ---------------------------------------------------------------------------
// Misc (electra)
// ---------------------------------------------------------------------------

/// Sentinel for `BeaconState.deposit_requests_start_index`: "no execution
/// layer deposit request has set the start index yet". Deposits before this
/// point in the deposit contract's log are still processed from
/// `Eth1Data` votes; once an execution layer `DepositRequest` is seen, the
/// state records its index here and processes deposits from execution layer
/// requests onward instead. Typed `u64` to match the field itself, a plain
/// index counter rather than an `Epoch`.
pub const UNSET_DEPOSIT_REQUESTS_START_INDEX: u64 = u64::MAX;

/// The amount that signals "withdraw this validator's entire balance"
/// (electra:EIP7002) rather than a partial withdrawal of the given amount.
/// Typed [`Gwei`], matching the `WithdrawalRequest.amount` field it is
/// compared against; the specification's own constants table writes it as a
/// plain `uint64`, but every place that reads it treats it as an amount.
pub const FULL_EXIT_REQUEST_AMOUNT: Gwei = 0;

/// The first byte of an execution layer request list entry (electra:EIP7685)
/// that identifies it as a deposit request. `u8`: a single tag byte compared
/// directly against the request's type byte, never SSZ-encoded on its own.
pub const DEPOSIT_REQUEST_TYPE: u8 = 0x00;
/// The first byte identifying an execution layer request as a withdrawal
/// request.
pub const WITHDRAWAL_REQUEST_TYPE: u8 = 0x01;
/// The first byte identifying an execution layer request as a consolidation
/// request.
pub const CONSOLIDATION_REQUEST_TYPE: u8 = 0x02;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participation_flag_weights_sum_to_the_denominator() {
        // The specification calls this out explicitly ("the sum of the
        // weights equal WEIGHT_DENOMINATOR"): together with SYNC_REWARD_WEIGHT
        // and PROPOSER_WEIGHT, the three flag weights must partition the
        // whole reward with nothing left over and nothing double-counted.
        let total: u64 =
            PARTICIPATION_FLAG_WEIGHTS.iter().sum::<u64>() + SYNC_REWARD_WEIGHT + PROPOSER_WEIGHT;
        assert_eq!(total, WEIGHT_DENOMINATOR);
    }

    #[test]
    fn domain_application_mask_is_reserved_correctly() {
        // Every specification-defined domain type must mask to zero: none of
        // them are "application" domains.
        for domain in [
            DOMAIN_BEACON_PROPOSER,
            DOMAIN_BEACON_ATTESTER,
            DOMAIN_RANDAO,
            DOMAIN_DEPOSIT,
            DOMAIN_VOLUNTARY_EXIT,
            DOMAIN_SELECTION_PROOF,
            DOMAIN_AGGREGATE_AND_PROOF,
            DOMAIN_SYNC_COMMITTEE,
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            DOMAIN_CONTRIBUTION_AND_PROOF,
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
        ] {
            let masked = [
                domain[0] & DOMAIN_APPLICATION_MASK[0],
                domain[1] & DOMAIN_APPLICATION_MASK[1],
                domain[2] & DOMAIN_APPLICATION_MASK[2],
                domain[3] & DOMAIN_APPLICATION_MASK[3],
            ];
            assert_eq!(masked, [0, 0, 0, 0]);
        }
    }
}
