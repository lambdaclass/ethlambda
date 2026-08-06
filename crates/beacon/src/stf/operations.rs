//! Block operations: the five lists a proposer packs into a block body.
//!
//! Each list is processed independently and in a fixed order (proposer
//! slashings, then attester slashings, then attestations, then deposits, then
//! voluntary exits), which is why [`process_operations`] is nothing more than
//! five loops. What makes this section worth its own module is that three of
//! the five operations end in a slashing, one has a two-phase signature domain
//! rule unlike anything else in the state transition, and the deposit path
//! silently tolerates the one kind of invalidity (a bad signature) that every
//! other operation treats as fatal to the whole block. Getting each of those
//! exactly right is the point; the loops around them are incidental.

use std::collections::HashSet;

use crate::bls;
use crate::config::Config;
use crate::constants::{self, FAR_FUTURE_EPOCH};
use crate::containers::BeaconState;
use crate::containers::phase0;
use crate::containers::shared::{
    Deposit, DepositMessage, ProposerSlashing, SignedVoluntaryExit, Validator,
};
use crate::error::{Error, Result, verify};
use crate::fork::ForkName;
use crate::helpers::accessors::{
    get_beacon_committee, get_beacon_proposer_index, get_committee_count_per_slot,
    get_current_epoch, get_domain, get_previous_epoch,
};
use crate::helpers::attestation::{get_indexed_attestation, is_valid_indexed_attestation};
use crate::helpers::misc::{
    compute_deposit_domain, compute_epoch_at_slot, compute_signing_root, is_valid_merkle_branch,
};
use crate::helpers::mutators::{increase_balance, initiate_validator_exit, slash_validator};
use crate::helpers::predicates::{
    is_active_validator, is_slashable_attestation_data, is_slashable_validator,
};
use crate::preset;
use crate::primitives::{Gwei, HashTreeRoot as _, ValidatorIndex};

/// Runs every operation in a block, in the specification's order.
///
/// Takes each operation list as a slice rather than a whole body, which is
/// what lets this one function serve every fork through deneb even though
/// their body types are all distinct: nothing here needs to know what else a
/// fork's body carries alongside these five lists. Capella's body adds a sixth
/// list (BLS-to-execution changes), and electra reshapes the attestation types
/// this signature assumes, so both get their own `process_operations` once that
/// work lands, rather than this one growing parameters to cover them.
///
/// The deposit count check comes first and covers every deposit at once rather
/// than any one operation: a block must include exactly as many deposits as are
/// outstanding, up to the per-block cap, so a proposer cannot fall behind the
/// deposit contract by including too few, nor claim more than exist.
pub fn process_operations(
    state: &mut BeaconState,
    proposer_slashings: &[ProposerSlashing],
    attester_slashings: &[phase0::AttesterSlashing],
    attestations: &[phase0::Attestation],
    deposits: &[Deposit],
    voluntary_exits: &[SignedVoluntaryExit],
    config: &Config,
) -> Result<()> {
    // `eth1_deposit_index` only ever advances by one per processed deposit,
    // and `deposit_count` only ever grows, so in a correctly-derived state the
    // index never exceeds the count. Nothing here re-derives that invariant,
    // so a malformed pre-state (or a future bug) must not be allowed to wrap
    // this into a huge outstanding count that no block could ever satisfy.
    let outstanding = state
        .eth1_data()
        .deposit_count
        .checked_sub(state.eth1_deposit_index())
        .ok_or(Error::ArithmeticOverflow(
            "eth1_data.deposit_count - eth1_deposit_index",
        ))?;
    verify(
        deposits.len() as u64 == outstanding.min(preset::MAX_DEPOSITS as u64),
        "len(body.deposits) == min(MAX_DEPOSITS, eth1_data.deposit_count - eth1_deposit_index)",
    )?;

    for proposer_slashing in proposer_slashings {
        process_proposer_slashing(state, proposer_slashing, config)?;
    }
    for attester_slashing in attester_slashings {
        process_attester_slashing(state, attester_slashing, config)?;
    }
    for attestation in attestations {
        // Phase0 defers an attestation's reward to the epoch boundary, so it
        // needs its own version of this step (below); altair scores one the
        // moment it is processed instead, and nothing about that changed
        // through deneb, so every later fork this signature serves shares
        // altair's version rather than getting one of its own. This is the
        // same coexisting-by-fork pattern `crate::helpers::altair` and
        // `crate::stf::epoch::rewards` already use for the two
        // `get_base_reward` implementations: neither is renamed, and the call
        // site picks between them by fully-qualified path.
        if state.fork_name() == ForkName::Phase0 {
            process_attestation(state, attestation, config)?;
        } else {
            crate::stf::altair::process_attestation(state, attestation)?;
        }
    }
    for deposit in deposits {
        process_deposit(state, deposit, config)?;
    }
    for voluntary_exit in voluntary_exits {
        process_voluntary_exit(state, voluntary_exit, config)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Proposer slashings
// ---------------------------------------------------------------------------

/// Slashes a proposer caught signing two different headers for the same slot.
///
/// The two headers must actually differ: a proposer can be asked to co-sign
/// the same header twice (by different requesters, or the same one twice),
/// and that is not evidence of anything. Only a genuine equivocation, two
/// distinct headers for the one slot, is slashable.
pub fn process_proposer_slashing(
    state: &mut BeaconState,
    proposer_slashing: &ProposerSlashing,
    config: &Config,
) -> Result<()> {
    let header_1 = &proposer_slashing.signed_header_1.message;
    let header_2 = &proposer_slashing.signed_header_2.message;

    verify(
        header_1.slot == header_2.slot,
        "header_1.slot == header_2.slot",
    )?;
    verify(
        header_1.proposer_index == header_2.proposer_index,
        "header_1.proposer_index == header_2.proposer_index",
    )?;
    verify(header_1 != header_2, "header_1 != header_2")?;

    let proposer_index = header_1.proposer_index;
    let current_epoch = get_current_epoch(state);
    let proposer = state.validator(proposer_index)?;
    verify(
        is_slashable_validator(proposer, current_epoch),
        "is_slashable_validator(proposer, get_current_epoch(state))",
    )?;
    // Copied out rather than re-borrowed per iteration below: both signatures
    // are checked against the same proposer, and holding the borrow across
    // the loop would conflict with `get_domain`'s borrow of `state`.
    let pubkey = proposer.pubkey;

    for signed_header in [
        &proposer_slashing.signed_header_1,
        &proposer_slashing.signed_header_2,
    ] {
        let epoch = compute_epoch_at_slot(signed_header.message.slot);
        let domain = get_domain(state, constants::DOMAIN_BEACON_PROPOSER, Some(epoch));
        let signing_root = compute_signing_root(signed_header.message.hash_tree_root(), domain);
        verify(
            bls::verify(&pubkey, signing_root, &signed_header.signature),
            "bls.Verify(proposer.pubkey, signing_root, signed_header.signature)",
        )?;
    }

    slash_validator(state, proposer_index, None, config)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Attester slashings
// ---------------------------------------------------------------------------

/// Slashes every slashable validator in the overlap of two conflicting
/// attestations' attesting sets.
///
/// The two indexed attestations must each be independently valid (sorted,
/// unique, unslashed-signature-correct) before their overlap means anything:
/// evidence built from a forged or malformed attestation proves nothing.
/// It is not enough for the overlap to be non-empty either. If every
/// validator in it has already been slashed (and so is past
/// [`is_slashable_validator`]'s reach) or has already withdrawn, the
/// operation has no effect and including it would let a block waste space
/// (or, worse, let a proposer replay old evidence) for free.
pub fn process_attester_slashing(
    state: &mut BeaconState,
    attester_slashing: &phase0::AttesterSlashing,
    config: &Config,
) -> Result<()> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;

    verify(
        is_slashable_attestation_data(&attestation_1.data, &attestation_2.data),
        "is_slashable_attestation_data(attestation_1.data, attestation_2.data)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_1),
        "is_valid_indexed_attestation(state, attestation_1)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_2),
        "is_valid_indexed_attestation(state, attestation_2)",
    )?;

    let current_epoch = get_current_epoch(state);
    // `is_valid_indexed_attestation` already required both index lists to be
    // sorted and unique, so walking `attestation_1`'s list in order while
    // filtering by membership in `attestation_2`'s set yields the
    // intersection already sorted, matching the specification's
    // `sorted(indices)` without a separate sort.
    let indices_2: HashSet<ValidatorIndex> =
        attestation_2.attesting_indices.iter().copied().collect();

    let mut slashed_any = false;
    for &index in attestation_1.attesting_indices.iter() {
        if !indices_2.contains(&index) {
            continue;
        }
        if is_slashable_validator(state.validator(index)?, current_epoch) {
            slash_validator(state, index, None, config)?;
            slashed_any = true;
        }
    }
    verify(
        slashed_any,
        "at least one validator in the intersection of the two attesting index sets was slashed",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// Records an attestation for later reward accounting, and checks its
/// signature.
///
/// Phase0 cannot score an attestation on arrival, so this only validates its
/// shape (target epoch, inclusion window, committee) and its claimed source
/// checkpoint, then defers the actual reward to the epoch boundary by
/// appending a [`phase0::PendingAttestation`] to whichever of the state's two
/// attestation lists matches the target epoch. The specification checks the
/// signature last, after that append, so a block with a well-formed but
/// unsigned attestation still leaves the append in place before the whole
/// block is rejected; callers that need the pre-state intact must clone it
/// first (see [`crate::stf`]'s module documentation).
///
/// Takes `config` only for symmetry with the other operation processors
/// [`process_operations`] dispatches to uniformly; nothing this function
/// calls needs a runtime configuration value.
pub fn process_attestation(
    state: &mut BeaconState,
    attestation: &phase0::Attestation,
    _config: &Config,
) -> Result<()> {
    let data = attestation.data;
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);

    verify(
        data.target.epoch == previous_epoch || data.target.epoch == current_epoch,
        "data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))",
    )?;
    verify(
        data.target.epoch == compute_epoch_at_slot(data.slot),
        "data.target.epoch == compute_epoch_at_slot(data.slot)",
    )?;

    // Both bounds are driven directly by `data.slot`, which comes straight off
    // the wire, so a hostile value close to `u64::MAX` must not be allowed to
    // wrap either bound into something that vacuously accepts the attestation.
    let min_slot = data
        .slot
        .checked_add(preset::MIN_ATTESTATION_INCLUSION_DELAY)
        .ok_or(Error::ArithmeticOverflow(
            "data.slot + MIN_ATTESTATION_INCLUSION_DELAY",
        ))?;
    let max_slot = data
        .slot
        .checked_add(preset::SLOTS_PER_EPOCH)
        .ok_or(Error::ArithmeticOverflow("data.slot + SLOTS_PER_EPOCH"))?;
    verify(
        min_slot <= state.slot() && state.slot() <= max_slot,
        "data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot <= data.slot + SLOTS_PER_EPOCH",
    )?;
    verify(
        data.index < get_committee_count_per_slot(state, data.target.epoch),
        "data.index < get_committee_count_per_slot(state, data.target.epoch)",
    )?;

    let committee = get_beacon_committee(state, data.slot, data.index)?;
    verify(
        attestation.aggregation_bits.len() == committee.len(),
        "len(attestation.aggregation_bits) == len(committee)",
    )?;

    // Safe: `min_slot <= state.slot()` above and `min_slot >= data.slot`
    // (the inclusion delay is non-negative), so `data.slot <= state.slot()`.
    let pending_attestation = phase0::PendingAttestation {
        data,
        aggregation_bits: attestation.aggregation_bits.clone(),
        inclusion_delay: state.slot() - data.slot,
        proposer_index: get_beacon_proposer_index(state)?,
    };

    if data.target.epoch == current_epoch {
        verify(
            data.source == state.current_justified_checkpoint(),
            "data.source == state.current_justified_checkpoint",
        )?;
        super::phase0_state(state, "process_attestation")?
            .current_epoch_attestations
            .push(pending_attestation)?;
    } else {
        verify(
            data.source == state.previous_justified_checkpoint(),
            "data.source == state.previous_justified_checkpoint",
        )?;
        super::phase0_state(state, "process_attestation")?
            .previous_epoch_attestations
            .push(pending_attestation)?;
    }

    let indexed_attestation = get_indexed_attestation(state, attestation)?;
    verify(
        is_valid_indexed_attestation(state, &indexed_attestation),
        "is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))",
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Deposits
// ---------------------------------------------------------------------------

/// Builds the registry entry a new deposit creates.
///
/// The effective balance rounds the deposit amount down to a multiple of
/// `EFFECTIVE_BALANCE_INCREMENT` before capping it. Subtracting the remainder
/// can never underflow: a modulus is always at most the value it divides.
pub fn get_validator_from_deposit(
    pubkey: crate::primitives::BlsPubkey,
    withdrawal_credentials: crate::primitives::Bytes32,
    amount: Gwei,
) -> Validator {
    let effective_balance =
        (amount - amount % preset::EFFECTIVE_BALANCE_INCREMENT).min(preset::MAX_EFFECTIVE_BALANCE);

    Validator {
        pubkey,
        withdrawal_credentials,
        effective_balance,
        slashed: false,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    }
}

/// Appends a brand-new validator and its starting balance.
///
/// Every per-validator list is positionally parallel and must be grown
/// together; nothing about this operation should ever be run for a `pubkey`
/// already in the registry (see [`apply_deposit`], the only caller).
///
/// From altair on there are five such lists, not two. Altair adds
/// `previous_epoch_participation`, `current_epoch_participation`, and
/// `inactivity_scores`, each indexed by validator, and its specification grows
/// all three here alongside `validators` and `balances`. Missing them does not
/// fail loudly: every later read is bounds-checked, so the state simply carries
/// lists one entry short of the registry and produces a `hash_tree_root` that
/// disagrees with every other client. That is exactly how it showed up here,
/// as seven altair `deposit` cases failing on a post-state root with no other
/// symptom.
///
/// Electra replaces this function outright, since a deposit there is queued
/// rather than credited, so `crate::stf::electra` has its own; this one serves
/// phase0 through deneb. The altair branch still covers every later fork
/// anyway, because being conservative here costs nothing and a silent
/// length mismatch costs a great deal.
pub fn add_validator_to_registry(
    state: &mut BeaconState,
    pubkey: crate::primitives::BlsPubkey,
    withdrawal_credentials: crate::primitives::Bytes32,
    amount: Gwei,
) -> Result<()> {
    state.validators_mut().push(get_validator_from_deposit(
        pubkey,
        withdrawal_credentials,
        amount,
    ))?;
    state.balances_mut().push(amount)?;

    if state.fork_name() >= ForkName::Altair {
        let (previous, current, scores) = state.altair_validator_lists_mut()?;
        previous.push(0)?;
        current.push(0)?;
        scores.push(0)?;
    }
    Ok(())
}

/// Credits a deposit: to a new validator if the public key is unseen, or as a
/// balance top-up if it already has an entry.
///
/// The signature check here is the one place in the whole state transition
/// that does not use [`get_domain`]: a deposit is signed by a depositor who
/// has no way to know which fork, or even which chain, will eventually accept
/// it, so it cannot commit to a genesis validators root or a fork version the
/// way every other signed message does. [`compute_deposit_domain`] instead
/// mixes in only the network's genesis fork version with an all-zero
/// validators root, giving every deposit across every fork of one network the
/// same signing domain.
///
/// A signature that fails this check is not an error: the deposit is simply
/// not credited to a new validator; see [`process_deposit`], the only caller,
/// for why that is safe.
pub fn apply_deposit(
    state: &mut BeaconState,
    pubkey: crate::primitives::BlsPubkey,
    withdrawal_credentials: crate::primitives::Bytes32,
    amount: Gwei,
    signature: crate::primitives::BlsSignature,
    config: &Config,
) -> Result<()> {
    let existing_index = state
        .validators()
        .iter()
        .position(|validator| validator.pubkey == pubkey);

    match existing_index {
        None => {
            let deposit_message = DepositMessage {
                pubkey,
                withdrawal_credentials,
                amount,
            };
            let domain = compute_deposit_domain(config.genesis_fork_version);
            let signing_root = compute_signing_root(deposit_message.hash_tree_root(), domain);
            if bls::verify(&pubkey, signing_root, &signature) {
                add_validator_to_registry(state, pubkey, withdrawal_credentials, amount)?;
            }
        }
        Some(index) => {
            increase_balance(state, index as ValidatorIndex, amount)?;
        }
    }

    Ok(())
}

/// Verifies a deposit's merkle proof, then applies it.
///
/// The index advances before the deposit is applied, and advances
/// unconditionally, whether or not the signature inside turns out to be
/// valid. Deposits are processed strictly in the order the deposit contract
/// received them, so the index is really "how many deposits have been
/// consumed", not "how many produced a validator"; conflating the two would
/// let one depositor's bad signature desynchronize every subsequent deposit's
/// expected merkle position from the contract's own tree.
pub fn process_deposit(state: &mut BeaconState, deposit: &Deposit, config: &Config) -> Result<()> {
    verify(
        is_valid_merkle_branch(
            deposit.data.hash_tree_root(),
            &deposit.proof,
            (constants::DEPOSIT_CONTRACT_TREE_DEPTH + 1) as u64,
            state.eth1_deposit_index(),
            state.eth1_data().deposit_root,
        ),
        "is_valid_merkle_branch(hash_tree_root(deposit.data), deposit.proof, DEPOSIT_CONTRACT_TREE_DEPTH + 1, state.eth1_deposit_index, state.eth1_data.deposit_root)",
    )?;

    *state.eth1_deposit_index_mut() += 1;

    apply_deposit(
        state,
        deposit.data.pubkey,
        deposit.data.withdrawal_credentials,
        deposit.data.amount,
        deposit.data.signature,
        config,
    )
}

// ---------------------------------------------------------------------------
// Voluntary exits
// ---------------------------------------------------------------------------

/// Starts a validator's voluntary exit.
///
/// Four conditions gate it, each guarding against a different way an exit
/// could be abused: the validator must still be active (an exited or
/// unactivated validator has nothing left to exit from), not already
/// exiting (so this cannot be replayed to push the exit queue further out),
/// past its own requested epoch (an exit cannot be redeemed early), and past
/// `SHARD_COMMITTEE_PERIOD` since activation (so a validator cannot buy a
/// committee assignment and immediately leave before it can be held to
/// account for anything done in it).
pub fn process_voluntary_exit(
    state: &mut BeaconState,
    signed_voluntary_exit: &SignedVoluntaryExit,
    config: &Config,
) -> Result<()> {
    let voluntary_exit = signed_voluntary_exit.message;
    let current_epoch = get_current_epoch(state);
    let validator = state.validator(voluntary_exit.validator_index)?;

    verify(
        is_active_validator(validator, current_epoch),
        "is_active_validator(validator, get_current_epoch(state))",
    )?;
    verify(
        validator.exit_epoch == FAR_FUTURE_EPOCH,
        "validator.exit_epoch == FAR_FUTURE_EPOCH",
    )?;
    verify(
        current_epoch >= voluntary_exit.epoch,
        "get_current_epoch(state) >= voluntary_exit.epoch",
    )?;
    // `validator.activation_epoch` is settled, previously-validated state
    // (assigned by registry updates from the chain's own current epoch), not
    // a value an attacker supplies directly the way `data.slot` is above, but
    // checked anyway since the cost of doing so is free.
    let eligible_epoch = validator
        .activation_epoch
        .checked_add(config.shard_committee_period)
        .ok_or(Error::ArithmeticOverflow(
            "validator.activation_epoch + SHARD_COMMITTEE_PERIOD",
        ))?;
    verify(
        current_epoch >= eligible_epoch,
        "get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD",
    )?;

    let domain = get_domain(
        state,
        constants::DOMAIN_VOLUNTARY_EXIT,
        Some(voluntary_exit.epoch),
    );
    let signing_root = compute_signing_root(voluntary_exit.hash_tree_root(), domain);
    verify(
        bls::verify(
            &validator.pubkey,
            signing_root,
            &signed_voluntary_exit.signature,
        ),
        "bls.Verify(validator.pubkey, signing_root, signed_voluntary_exit.signature)",
    )?;

    initiate_validator_exit(state, voluntary_exit.validator_index, config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::*;
    use crate::containers::phase0::{AttesterSlashing, IndexedAttestation};
    use crate::containers::shared::{
        AttestationData, BeaconBlockHeader, Checkpoint, SignedBeaconBlockHeader,
    };
    use crate::primitives::{BlsPubkey, BlsSignature, Root};

    #[test]
    fn identical_proposer_slashing_headers_are_rejected() {
        let mut state = crate::helpers::test_state::with_validators(4);
        let config = Config::mainnet();

        let header = BeaconBlockHeader {
            slot: state.slot(),
            proposer_index: 0,
            ..Default::default()
        };
        let signed_header = SignedBeaconBlockHeader {
            message: header,
            signature: BlsSignature::default(),
        };
        // Two identical headers carry no evidence of equivocation: the spec
        // requires them to differ before anything else about the slashing
        // (proposer identity, signatures) is even inspected.
        let slashing = ProposerSlashing {
            signed_header_1: signed_header.clone(),
            signed_header_2: signed_header,
        };

        assert!(process_proposer_slashing(&mut state, &slashing, &config).is_err());
    }

    #[test]
    fn an_attester_slashing_that_slashes_nobody_is_rejected() {
        let mut state = crate::helpers::test_state::with_validators(4);
        let config = Config::mainnet();

        // A real key pair rather than a placeholder: `is_valid_indexed_attestation`
        // genuinely checks the aggregate signature, and only a valid one lets this
        // test reach (and so actually exercise) the "at least one validator
        // slashed" check rather than failing earlier for an unrelated reason.
        let secret_key = SecretKey::key_gen(&[7u8; 32], &[]).expect("32 bytes of key material");
        let public_key = secret_key.sk_to_pk();
        {
            let validator = state.validator_mut(0).expect("validator 0 exists");
            validator.pubkey = BlsPubkey(public_key.to_bytes());
            // Already slashed, so the one validator in the overlap of the two
            // attestations' attesting sets is not slashable, and the
            // operation must still be rejected even though the overlap
            // itself is non-empty.
            validator.slashed = true;
        }

        let target_epoch = 1;
        let data_1 = AttestationData {
            slot: preset::SLOTS_PER_EPOCH,
            index: 0,
            beacon_block_root: Root::repeat_byte(1),
            source: Checkpoint::default(),
            target: Checkpoint {
                epoch: target_epoch,
                root: Root::repeat_byte(1),
            },
        };
        // A double vote: same target epoch, different content, both from
        // validator 0. That is enough for `is_slashable_attestation_data`
        // without needing a surround vote's separate source/target spread.
        let data_2 = AttestationData {
            beacon_block_root: Root::repeat_byte(2),
            target: Checkpoint {
                epoch: target_epoch,
                root: Root::repeat_byte(2),
            },
            ..data_1
        };

        // Both attestations share a target epoch, so they share a domain;
        // signing under exactly what `is_valid_indexed_attestation` will
        // recompute is what makes these signatures genuinely valid rather
        // than merely well-formed.
        let domain = get_domain(
            &state,
            constants::DOMAIN_BEACON_ATTESTER,
            Some(target_epoch),
        );
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let sign = |data: &AttestationData| {
            let signing_root = compute_signing_root(data.hash_tree_root(), domain);
            BlsSignature(
                secret_key
                    .sign(signing_root.as_bytes(), DST, &[])
                    .to_bytes(),
            )
        };

        let attestation_1 = IndexedAttestation {
            attesting_indices: vec![0]
                .try_into()
                .expect("one index, far below the committee limit"),
            data: data_1,
            signature: sign(&data_1),
        };
        let attestation_2 = IndexedAttestation {
            attesting_indices: vec![0]
                .try_into()
                .expect("one index, far below the committee limit"),
            data: data_2,
            signature: sign(&data_2),
        };
        let slashing = AttesterSlashing {
            attestation_1,
            attestation_2,
        };

        assert!(process_attester_slashing(&mut state, &slashing, &config).is_err());
    }
}
