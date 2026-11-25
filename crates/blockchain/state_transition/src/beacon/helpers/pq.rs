//! Helpers the PQ fork adds or modifies (consensus-specs
//! `specs/_features/pq/beacon-chain.md`, on the `pq` branch at
//! `b5d422b255db80c9bbc48f515370655ecc8bf6e5`).
//!
//! # Keys
//!
//! A PQ registry record holds its XMSS key in the 48-byte form a request names
//! it by, 16 zero bytes then the key (see `containers::pq`'s module doc). That
//! is why the specification's `XMSSPubkey(request.pubkey[16:])` comparisons
//! appear here as plain 48-byte comparisons against `validator.pubkey` once a
//! request has been checked not to be a legacy one ([`is_legacy_pubkey`]).
//!
//! # Signatures
//!
//! [`xmss_verify`] and [`verify_aggregates`] are the specification's
//! `xmss.Verify` and `stark.VerifyAggregates`, over `ethlambda_crypto`'s
//! leanXMSS. The specification's own test generator runs with XMSS inactive,
//! so its fixtures carry stub signatures and empty proofs that only an
//! inactive verifier accepts; [`disable_xmss_verification`], compiled only for
//! the spec-test binary, is that switch. `GetLeafIndex` and the empty-signature
//! comparison for self-built bids read the bytes either way, as the
//! specification's do.

use std::sync::atomic::{AtomicBool, Ordering};

use ethlambda_crypto::{lean_xmss, stark, vrf};

use crate::beacon::constants;
use crate::beacon::containers::{BeaconState, electra, pq};
use crate::beacon::error::{Error, Result};
use crate::beacon::fork::ForkName;
use crate::beacon::hash::hash;
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsPubkey, Bytes32, CommitteeIndex, Epoch, Root, Slot, ValidatorIndex, XmssPubkey,
    XmssSignature,
};

use super::accessors::{
    CommitteeCache, CommitteeCacheExt, get_block_root_at_slot, get_committee_count_per_slot,
    get_current_epoch, get_domain, get_seed,
};
use super::gloas::compute_balance_weighted_selection;
use super::misc::{compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch};

// ---------------------------------------------------------------------------
// XMSS and STARK verification
// ---------------------------------------------------------------------------

static XMSS_VERIFICATION: AtomicBool = AtomicBool::new(true);

/// Turns `xmss.Verify` and `stark.VerifyAggregates` into the specification's
/// inactive stubs, which accept everything, for the rest of the process.
///
/// The specification's test generator runs with XMSS inactive (key generation
/// takes minutes in its reference implementation), so the fixtures for the PQ
/// fork carry stub signatures and empty proofs. Only the spec-test binary can
/// reach this.
#[cfg(feature = "beacon-spec-tests")]
pub fn disable_xmss_verification() {
    XMSS_VERIFICATION.store(false, Ordering::Relaxed);
}

fn xmss_verification_enabled() -> bool {
    XMSS_VERIFICATION.load(Ordering::Relaxed)
}

/// The specification's `xmss.Verify`.
pub fn xmss_verify(
    pubkey: &XmssPubkey,
    leaf_index: u64,
    message: Root,
    signature: &XmssSignature,
) -> bool {
    if !xmss_verification_enabled() {
        return true;
    }
    lean_xmss::verify(&pubkey.0, leaf_index, &message.0, &signature.0)
}

/// The specification's `xmss.GetLeafIndex`: the leaf index a signature carries,
/// read without verifying it.
pub fn get_leaf_index(signature: &XmssSignature) -> u64 {
    lean_xmss::signature_index(&signature.0).expect("an XMSSSignature is longer than four bytes")
}

/// The specification's `XMSSAggregateStatement`.
pub type AggregateStatement = stark::AggregateStatement;

/// The specification's `stark.ProveAggregates`: one proof of every
/// statement's signatures, `signatures[i]` being those of `statements[i]`'s
/// keys, in their order.
pub fn prove_aggregates<S: AsRef<[u8]>>(
    statements: &[AggregateStatement],
    signatures: &[Vec<S>],
) -> std::result::Result<Vec<u8>, stark::ProveError> {
    stark::prove_aggregates(statements, signatures)
}

/// The specification's `stark.VerifyAggregates`.
pub fn verify_aggregates(statements: &[AggregateStatement], proof: &[u8]) -> bool {
    if !xmss_verification_enabled() {
        return true;
    }
    stark::verify_aggregates(statements, proof)
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// `compute_legacy_xmss_pubkey`: the XMSS key derived from a BLS key, which a
/// validator or builder that registered none takes at the fork. No signature
/// verifies against it.
pub fn compute_legacy_xmss_pubkey(pubkey: &BlsPubkey) -> XmssPubkey {
    XmssPubkey(legacy_digest(pubkey, constants::LEGACY_XMSS_PUBKEY_DOMAIN).0)
}

/// `compute_legacy_vrf_root`: the VRF root derived from a BLS key.
pub fn compute_legacy_vrf_root(pubkey: &BlsPubkey) -> Root {
    legacy_digest(pubkey, constants::LEGACY_VRF_ROOT_DOMAIN)
}

fn legacy_digest(pubkey: &BlsPubkey, domain: u8) -> Bytes32 {
    let mut input = Vec::with_capacity(pubkey.0.len() + 1);
    input.extend_from_slice(&pubkey.0);
    input.push(domain);
    hash(&input)
}

/// `is_legacy_pubkey`: whether a 48-byte request key names a BLS key (made
/// before the fork) rather than an XMSS one. A compressed BLS key's first byte
/// has its top bit set, so it never starts with the 16 zero bytes an XMSS key
/// is prefixed with.
pub fn is_legacy_pubkey(pubkey: &BlsPubkey) -> bool {
    pubkey.0[..constants::XMSS_DEPOSIT_PREFIX.len()] != constants::XMSS_DEPOSIT_PREFIX
}

/// `compute_deposit_pubkey`: the XMSS key a deposit naming `pubkey` is for.
pub fn compute_deposit_pubkey(pubkey: &BlsPubkey) -> XmssPubkey {
    if is_legacy_pubkey(pubkey) {
        compute_legacy_xmss_pubkey(pubkey)
    } else {
        XmssPubkey::from_request_key(pubkey)
    }
}

/// `compute_deposit_vrf_root`: the VRF root of the validator `deposit` creates,
/// the first 32 bytes of its signature field (or the legacy derivation).
pub fn compute_deposit_vrf_root(deposit: &electra::PendingDeposit) -> Root {
    if is_legacy_pubkey(&deposit.pubkey) {
        compute_legacy_vrf_root(&deposit.pubkey)
    } else {
        Root::from_slice(&deposit.signature.0[..32])
    }
}

/// `compute_xmss_attestation_leaf_index`: the leaf an attestation for target
/// `epoch` is signed at, one per target epoch past the reserved leaves.
pub fn compute_xmss_attestation_leaf_index(epoch: Epoch) -> Result<u64> {
    constants::XMSS_RESERVED_LEAVES
        .checked_add(epoch)
        .ok_or(Error::ArithmeticOverflow(
            "compute_xmss_attestation_leaf_index: XMSS_RESERVED_LEAVES + epoch",
        ))
}

/// `compute_xmss_leaf_index`: the leaf a message of the type `leaf_offset`
/// names is signed at for `slot`.
pub fn compute_xmss_leaf_index(slot: Slot, leaf_offset: u64) -> Result<u64> {
    slot.checked_mul(constants::XMSS_LEAVES_PER_SLOT)
        .and_then(|slot_leaves| {
            (constants::XMSS_RESERVED_LEAVES
                + constants::XMSS_ATTESTATION_LEAVES
                + constants::XMSS_BUILDER_BID_LEAVES)
                .checked_add(slot_leaves)
        })
        .and_then(|leaf| leaf.checked_add(leaf_offset))
        .ok_or(Error::ArithmeticOverflow(
            "compute_xmss_leaf_index: slot * XMSS_LEAVES_PER_SLOT + offsets",
        ))
}

/// `is_builder_bid_leaf_index`: whether `leaf_index` is one of the leaves
/// reserved for builder bids.
pub fn is_builder_bid_leaf_index(leaf_index: u64) -> bool {
    let start = constants::XMSS_RESERVED_LEAVES + constants::XMSS_ATTESTATION_LEAVES;
    (start..start + constants::XMSS_BUILDER_BID_LEAVES).contains(&leaf_index)
}

/// `is_valid_vrf_proof`: whether `proof` reveals the secret that the leaf at
/// index `slot` of the tree under the VRF root of the validator at
/// `validator_index` commits to.
///
/// The tree is hashed with Keccak-256, not the SHA-256 of
/// `is_valid_merkle_branch`, and its leaf is `compute_vrf_leaf` of the
/// revealed secret and the slot: the branch holds only commitments, so a
/// reveal gives away no other slot's secret.
pub fn is_valid_vrf_proof(
    state: &BeaconState,
    validator_index: ValidatorIndex,
    slot: Slot,
    proof: &pq::VrfProof,
) -> Result<bool> {
    let root = state.pq_validator(validator_index)?.vrf_root;
    let branch = proof[1..].iter().map(|sibling| &sibling.0);
    Ok(vrf::fold_vrf_branch(&proof[0].0, branch, slot) == root.0)
}

// ---------------------------------------------------------------------------
// Aggregation committees
// ---------------------------------------------------------------------------

/// `compute_aggregation_committee`: the aggregators of the beacon committee at
/// `slot` for `index`, `AGGREGATORS_PER_COMMITTEE` of them (fewer for a
/// smaller committee) sampled by effective balance without duplicates.
pub fn compute_aggregation_committee(
    state: &BeaconState,
    slot: Slot,
    index: CommitteeIndex,
    committees: &CommitteeCache,
) -> Result<pq::AggregationCommittee> {
    let epoch = compute_epoch_at_slot(slot);
    let mut seed_input = Vec::with_capacity(48);
    seed_input.extend_from_slice(&get_seed(state, epoch, constants::DOMAIN_SELECTION_PROOF).0);
    seed_input.extend_from_slice(&slot.to_le_bytes());
    seed_input.extend_from_slice(&index.to_le_bytes());
    let seed = hash(&seed_input);

    let mut candidates = committees
        .committees(state, epoch)
        .committee(slot, index)?
        .to_vec();
    let mut aggregators: Vec<ValidatorIndex> = Vec::new();
    while (aggregators.len() as u64) < constants::AGGREGATORS_PER_COMMITTEE
        && !candidates.is_empty()
    {
        let mut draw_input = Vec::with_capacity(40);
        draw_input.extend_from_slice(&seed.0);
        draw_input.extend_from_slice(&(aggregators.len() as u64).to_le_bytes());
        let aggregator =
            compute_balance_weighted_selection(state, &candidates, hash(&draw_input), 1, false)?[0];
        aggregators.push(aggregator);
        candidates.retain(|&candidate| candidate != aggregator);
    }
    Ok(pq::AggregationCommittee::from(aggregators))
}

/// `compute_aggregation_committees`: the aggregation committee of each beacon
/// committee at `slot`, in committee order.
pub fn compute_aggregation_committees(
    state: &BeaconState,
    slot: Slot,
    committees: &CommitteeCache,
) -> Result<pq::AggregationCommittees> {
    let committees_per_slot = get_committee_count_per_slot(state, compute_epoch_at_slot(slot));
    let mut out = Vec::with_capacity(committees_per_slot as usize);
    for index in 0..committees_per_slot {
        out.push(compute_aggregation_committee(
            state, slot, index, committees,
        )?);
    }
    Ok(pq::AggregationCommittees::from(out))
}

/// `get_aggregation_committee`: the aggregation committee of the beacon
/// committee at `slot` for `index`, read from the state's window. Defined for
/// the previous epoch through `MIN_SEED_LOOKAHEAD` epochs ahead.
pub fn get_aggregation_committee(
    state: &BeaconState,
    slot: Slot,
    index: CommitteeIndex,
) -> Result<pq::AggregationCommittee> {
    let BeaconState::Pq(inner) = state else {
        return Err(Error::UnsupportedForFork {
            function: "get_aggregation_committee",
            fork: state.fork_name(),
        });
    };
    let epoch = compute_epoch_at_slot(slot);
    let state_epoch = get_current_epoch(state);
    let position = if epoch < state_epoch {
        crate::beacon::verify(
            epoch + 1 == state_epoch,
            "get_aggregation_committee: epoch + 1 == state_epoch",
        )?;
        slot % preset::slots_per_epoch()
    } else {
        crate::beacon::verify(
            epoch <= state_epoch + preset::MIN_SEED_LOOKAHEAD,
            "get_aggregation_committee: epoch <= state_epoch + MIN_SEED_LOOKAHEAD",
        )?;
        (epoch - state_epoch + 1) * preset::slots_per_epoch() + slot % preset::slots_per_epoch()
    } as usize;
    let slot_committees = &inner.aggregation_committee_window[position];
    slot_committees
        .get(index as usize)
        .cloned()
        .ok_or(Error::IndexOutOfBounds {
            index: index as usize,
            len: slot_committees.len(),
        })
}

/// `initialize_aggregation_committee_window`: an empty previous epoch, then
/// the current and lookahead epochs' aggregation committees. What the fork
/// upgrade fills the window with.
pub fn initialize_aggregation_committee_window(
    state: &BeaconState,
) -> Result<pq::AggregationCommitteeWindow> {
    let committees = CommitteeCache::default();
    let current_epoch = get_current_epoch(state);
    let start_slot = compute_start_slot_at_epoch(current_epoch);
    let end_slot = compute_start_slot_at_epoch(current_epoch + preset::MIN_SEED_LOOKAHEAD + 1);
    let mut window = vec![pq::AggregationCommittees::default(); preset::slots_per_epoch() as usize];
    for slot in start_slot..end_slot {
        window.push(compute_aggregation_committees(state, slot, &committees)?);
    }
    Ok(pq::AggregationCommitteeWindow::try_from(window)
        .expect("one empty epoch and MIN_SEED_LOOKAHEAD + 1 computed ones fill the window"))
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// The signing root and leaf an attestation for `data` is signed at:
/// `compute_signing_root(data, get_domain(state, DOMAIN_BEACON_ATTESTER,
/// target.epoch))` and `compute_xmss_attestation_leaf_index(target.epoch)`.
pub fn attestation_message(
    state: &BeaconState,
    data: &crate::beacon::containers::shared::AttestationData,
) -> Result<(Root, u64)> {
    use crate::beacon::primitives::HashTreeRoot as _;
    let domain = get_domain(
        state,
        constants::DOMAIN_BEACON_ATTESTER,
        Some(data.target.epoch),
    );
    let message = compute_signing_root(data.hash_tree_root(), domain);
    Ok((
        message,
        compute_xmss_attestation_leaf_index(data.target.epoch)?,
    ))
}

/// The XMSS keys of `indices`, in order.
pub fn pubkeys_of(state: &BeaconState, indices: &[ValidatorIndex]) -> Result<Vec<[u8; 32]>> {
    indices
        .iter()
        .map(|&index| Ok(state.pq_validator(index)?.pubkey().0))
        .collect()
}

/// The committee indices `committee_bits` sets, in order.
pub fn get_committee_indices(committee_bits: &pq::CommitteeBits) -> Vec<CommitteeIndex> {
    (0..committee_bits.len())
        .filter(|&index| committee_bits.get(index).unwrap_or(false))
        .map(|index| index as CommitteeIndex)
        .collect()
}

/// `get_attestation_statements`: for each committee of `attestation` in
/// order, the statement its attesters' signatures prove.
pub fn get_attestation_statements(
    state: &BeaconState,
    attestation: &pq::Attestation,
    committees: &CommitteeCache,
) -> Result<Vec<AggregateStatement>> {
    let (message, leaf_index) = attestation_message(state, &attestation.data)?;
    let epoch_committees = committees.committees(state, attestation.data.target.epoch);
    let mut statements = Vec::new();
    let mut committee_offset = 0usize;
    for committee_index in get_committee_indices(&attestation.committee_bits) {
        let committee = epoch_committees.committee(attestation.data.slot, committee_index)?;
        let attesters: Vec<ValidatorIndex> = committee
            .iter()
            .enumerate()
            .filter(|(position, _)| {
                attestation
                    .aggregation_bits
                    .get(committee_offset + position)
                    .unwrap_or(false)
            })
            .map(|(_, &validator_index)| validator_index)
            .collect();
        statements.push(AggregateStatement {
            pubkeys: pubkeys_of(state, &attesters)?,
            leaf_index,
            message: message.0,
        });
        committee_offset += committee.len();
    }
    Ok(statements)
}

/// `get_attesting_indices`, sorted: the attesters `attestation`'s bits name in
/// the committees its `committee_bits` select, under the PQ fork's committee
/// count.
pub fn get_attesting_indices(
    state: &BeaconState,
    attestation: &pq::Attestation,
    committees: &CommitteeCache,
) -> Result<Vec<ValidatorIndex>> {
    let epoch_committees =
        committees.committees(state, compute_epoch_at_slot(attestation.data.slot));
    let mut indices = Vec::new();
    let mut committee_offset = 0usize;
    for committee_index in get_committee_indices(&attestation.committee_bits) {
        let committee = epoch_committees.committee(attestation.data.slot, committee_index)?;
        for (position, &validator_index) in committee.iter().enumerate() {
            if attestation
                .aggregation_bits
                .get(committee_offset + position)
                .unwrap_or(false)
            {
                indices.push(validator_index);
            }
        }
        committee_offset += committee.len();
    }
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

/// `is_valid_indexed_attestation`: not empty, sorted and unique indices within
/// the PQ bound, and a proof of one statement over the attesters' keys.
pub fn is_valid_indexed_attestation(
    state: &BeaconState,
    indexed_attestation: &pq::IndexedAttestation,
) -> Result<bool> {
    let indices: &[ValidatorIndex] = &indexed_attestation.attesting_indices;
    if indices.is_empty()
        || indices.len()
            > preset::MAX_VALIDATORS_PER_COMMITTEE * preset::max_committees_per_slot_pq()
        || !super::predicates::are_indices_sorted_and_unique(indices)
    {
        return Ok(false);
    }
    let (message, leaf_index) = attestation_message(state, &indexed_attestation.data)?;
    // An index outside the registry has no key: the attestation is invalid,
    // not the block's processing broken.
    let Ok(pubkeys) = pubkeys_of(state, indices) else {
        return Ok(false);
    };
    let statement = AggregateStatement {
        pubkeys,
        leaf_index,
        message: message.0,
    };
    Ok(verify_aggregates(&[statement], &indexed_attestation.proof))
}

// ---------------------------------------------------------------------------
// Preregistrations
// ---------------------------------------------------------------------------

/// The slot of the outstanding parent payload, whose execution requests are
/// the ones being applied: what a preregistration's expiry is compared with.
fn parent_payload_slot(state: &pq::BeaconState) -> Slot {
    state.latest_execution_payload_bid.slot
}

/// `is_active_validator_preregistration`.
pub fn is_active_validator_preregistration(
    state: &pq::BeaconState,
    preregistration: &pq::ValidatorPreregistration,
) -> bool {
    parent_payload_slot(state) < preregistration.expiry_slot
}

/// `is_active_builder_preregistration`.
pub fn is_active_builder_preregistration(
    state: &pq::BeaconState,
    preregistration: &pq::BuilderPreregistration,
) -> bool {
    parent_payload_slot(state) < preregistration.expiry_slot
}

/// `get_active_validator_preregistration`.
pub fn get_active_validator_preregistration(
    state: &pq::BeaconState,
    pubkey: &XmssPubkey,
) -> Option<pq::ValidatorPreregistration> {
    state
        .validator_preregistrations
        .iter()
        .find(|preregistration| preregistration.pubkey == *pubkey)
        .filter(|preregistration| is_active_validator_preregistration(state, preregistration))
        .cloned()
}

/// `get_active_builder_preregistration`.
pub fn get_active_builder_preregistration(
    state: &pq::BeaconState,
    pubkey: &XmssPubkey,
) -> Option<pq::BuilderPreregistration> {
    state
        .builder_preregistrations
        .iter()
        .find(|preregistration| preregistration.pubkey == *pubkey)
        .filter(|preregistration| is_active_builder_preregistration(state, preregistration))
        .cloned()
}

/// The PQ state, mutably, or an error naming the function that needs one.
pub(crate) fn pq_state<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut pq::BeaconState> {
    match state {
        BeaconState::Pq(inner) => Ok(inner),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// Whether `fork` signs with leanXMSS.
pub fn is_xmss_fork(fork: ForkName) -> bool {
    fork == ForkName::Pq
}

/// How many slots after its own an attestation can be included at the
/// earliest in a block on `state`, which is also the delay the timely-head
/// flag requires: `MIN_ATTESTATION_INCLUSION_DELAY_PQ` from PQ on, which
/// gives the proposer a slot to merge aggregates' proofs.
pub fn min_attestation_inclusion_delay(state: &BeaconState) -> u64 {
    match state {
        BeaconState::Pq(_) => preset::MIN_ATTESTATION_INCLUSION_DELAY_PQ,
        _ => preset::MIN_ATTESTATION_INCLUSION_DELAY,
    }
}

/// `get_latest_block_slot` (new in PQ): the slot of the latest block at or
/// before `slot`, where `parent_slot` is the slot of the parent of the block
/// being processed.
///
/// With a two-slot inclusion delay, the block a timely attestation votes for
/// may be the block being processed's grandparent, so its payload
/// availability is read at its own slot rather than the parent's. A skipped
/// slot repeats the previous block's root, which is what the walk back
/// follows; it stops at the oldest root `block_roots` still holds.
pub fn get_latest_block_slot(state: &BeaconState, slot: Slot, parent_slot: Slot) -> Result<Slot> {
    if parent_slot <= slot {
        return Ok(parent_slot);
    }
    let block_root = get_block_root_at_slot(state, slot)?;
    let mut slot = slot;
    while slot > 0
        && slot + preset::slots_per_historical_root() as u64 > state.slot()
        && get_block_root_at_slot(state, slot - 1)? == block_root
    {
        slot -= 1;
    }
    Ok(slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_ranges_are_disjoint_and_ordered() {
        let reserved_end = constants::XMSS_RESERVED_LEAVES;
        assert_eq!(
            compute_xmss_attestation_leaf_index(0).unwrap(),
            reserved_end
        );
        let bids_start = reserved_end + constants::XMSS_ATTESTATION_LEAVES;
        assert!(is_builder_bid_leaf_index(bids_start));
        assert!(!is_builder_bid_leaf_index(bids_start - 1));
        let slot_leaves_start = bids_start + constants::XMSS_BUILDER_BID_LEAVES;
        assert!(!is_builder_bid_leaf_index(slot_leaves_start));
        assert_eq!(compute_xmss_leaf_index(0, 0).unwrap(), slot_leaves_start);
        assert_eq!(
            compute_xmss_leaf_index(2, constants::LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE).unwrap(),
            slot_leaves_start + 2 * constants::XMSS_LEAVES_PER_SLOT + 4
        );
    }

    #[test]
    fn a_bls_key_is_legacy_and_an_xmss_one_is_not() {
        let mut bls = BlsPubkey::default();
        bls.0[0] = 0x80;
        assert!(is_legacy_pubkey(&bls));
        let xmss = XmssPubkey([7; 32]);
        assert!(!is_legacy_pubkey(&xmss.to_request_key()));
        assert_eq!(compute_deposit_pubkey(&xmss.to_request_key()), xmss);
        assert_eq!(
            compute_deposit_pubkey(&bls),
            compute_legacy_xmss_pubkey(&bls)
        );
        assert_ne!(
            compute_legacy_xmss_pubkey(&bls).0,
            compute_legacy_vrf_root(&bls).0
        );
    }

    /// A PQ state at `slot` whose block root at each earlier slot is
    /// `roots[slot]`: a skipped slot repeats the root before it.
    fn pq_state_with_roots(slot: Slot, roots: &[u8]) -> BeaconState {
        let mut state = crate::beacon::helpers::test_state::with_validators_at(ForkName::Pq, 8);
        *state.slot_mut() = slot;
        for (index, &root) in roots.iter().enumerate() {
            state.block_roots_mut()[index] = Root::repeat_byte(root);
        }
        state
    }

    #[test]
    fn the_latest_block_at_or_after_the_parent_is_the_parent() {
        let state = pq_state_with_roots(10, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(get_latest_block_slot(&state, 8, 8).unwrap(), 8);
        assert_eq!(get_latest_block_slot(&state, 9, 8).unwrap(), 8);
    }

    /// Blocks at 4 and 7, slots 5 and 6 skipped: an attestation to slot 6
    /// voted for the block at 4, so that is the slot whose payload counts.
    #[test]
    fn a_skipped_slot_resolves_to_the_block_before_it() {
        let state = pq_state_with_roots(9, &[1, 2, 3, 4, 5, 5, 5, 8, 9]);
        assert_eq!(get_latest_block_slot(&state, 6, 7).unwrap(), 4);
        assert_eq!(get_latest_block_slot(&state, 4, 7).unwrap(), 4);
    }

    /// The walk stops at the oldest root `block_roots` still holds rather
    /// than reading past it.
    #[test]
    fn the_walk_stops_at_the_oldest_root_kept() {
        let history = preset::slots_per_historical_root() as u64;
        let state = pq_state_with_roots(history + 2, &[]);
        // Every root is the default: the walk would run to slot 0 if it could.
        assert_eq!(get_latest_block_slot(&state, 3, history).unwrap(), 2);
    }

    #[test]
    fn only_a_pq_state_takes_the_two_slot_delay() {
        let pq = crate::beacon::helpers::test_state::with_validators_at(ForkName::Pq, 8);
        let gloas = crate::beacon::helpers::test_state::with_validators_at(ForkName::Gloas, 8);
        assert_eq!(min_attestation_inclusion_delay(&pq), 2);
        assert_eq!(min_attestation_inclusion_delay(&gloas), 1);
    }
}
