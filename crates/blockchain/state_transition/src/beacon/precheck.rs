//! The rules a beacon block can be judged by before its state transition runs.
//!
//! The specification lists these under `beacon_block` gossip validation
//! (`p2p-interface.md`), where they decide whether a block is worth
//! forwarding at all:
//!
//! - `[REJECT]` The block is from a higher slot than its parent.
//! - `[REJECT]` The block is proposed by the expected `proposer_index` for the
//!   block's slot in the context of the current shuffling. When that cannot be
//!   verified immediately, the block "MAY be queued for later processing" and
//!   is `IGNORE`d rather than rejected.
//! - `[REJECT]` The proposer signature is valid with respect to the
//!   `proposer_index` pubkey.
//!
//! The state transition checks each of these again, in `process_block_header`
//! and [`crate::beacon::stf::verify_block_signature`], so a block that passes
//! here can still fail its import. What this adds is timing: none of the rules
//! needs the block's post-state, only its parent's, and the signature alone
//! can be judged against any recent state. A caller can therefore refuse a
//! block before doing anything else with it, such as parking it until its
//! parent or its data columns arrive, which is exactly when a block that would
//! fail its import costs the most to keep.

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::DOMAIN_BEACON_PROPOSER;
use crate::beacon::containers::{BeaconState, SignedBeaconBlock};
use crate::beacon::helpers::misc::{
    compute_domain, compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch,
};
use crate::beacon::primitives::{Root, Slot, ValidatorIndex};

/// Which rule a block broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PrecheckError {
    #[error("slot {slot} is not after its parent's slot {parent_slot}")]
    NotAfterParent { slot: Slot, parent_slot: Slot },
    #[error(
        "proposer {proposer} is not the proposer {expected} the parent's state fixed for this slot"
    )]
    WrongProposer {
        proposer: ValidatorIndex,
        expected: ValidatorIndex,
    },
    /// Against [`Reference::Parent`], a refusal: the state the block builds
    /// on has no such validator. Against [`Reference::Recent`], only that
    /// this state cannot answer for the proposer (a validator newer than it),
    /// so the signature went unchecked; the caller decides what that costs
    /// the block.
    #[error("proposer {proposer} names no validator in the reference state")]
    UnknownProposer { proposer: ValidatorIndex },
    #[error("the signature is not the proposer's over this block")]
    BadSignature,
}

impl PrecheckError {
    /// A fixed name per rule, for a metric label: every variant maps to its
    /// own constant, so a block's contents cannot add a label value.
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotAfterParent { .. } => "not_after_parent",
            Self::WrongProposer { .. } => "wrong_proposer",
            Self::UnknownProposer { .. } => "unknown_proposer",
            Self::BadSignature => "bad_signature",
        }
    }
}

/// The state a block is judged against.
#[derive(Debug, Clone, Copy)]
pub enum Reference<'a> {
    /// The post-state of the block's own parent. Every rule applies.
    Parent(&'a BeaconState),
    /// Some recent state of the chain, for a block whose parent has no
    /// post-state yet. Only the signature is checked. Validator indices never
    /// move, so a key found here is the key the block was signed with. A
    /// validator newer than this state is one it cannot answer for, reported
    /// as [`PrecheckError::UnknownProposer`] rather than passed: `Ok` from
    /// this reference always means the signature verified.
    Recent(&'a BeaconState),
}

/// Judge `signed_block` by the rules in this module's documentation.
///
/// `block_root` must be `signed_block.message_hash_tree_root()`. It is taken
/// rather than recomputed because every caller already has it, and a mainnet
/// block's root is a merkleization of the whole body.
///
/// The signing domain comes from `config`'s fork schedule at the block's own
/// epoch, not from the reference state's `fork` field: the first block of a
/// new fork builds on a parent whose state has not been upgraded yet, and is
/// signed under the new fork's version.
pub fn precheck_block(
    signed_block: &SignedBeaconBlock,
    block_root: Root,
    reference: Reference<'_>,
    config: &Config,
) -> Result<(), PrecheckError> {
    let slot = signed_block.slot();
    let proposer = signed_block.proposer_index();

    let state = match reference {
        Reference::Parent(parent_state) => {
            let parent_slot = parent_state.slot();
            if slot <= parent_slot {
                return Err(PrecheckError::NotAfterParent { slot, parent_slot });
            }
            if let Some(expected) = fixed_proposer(parent_state, slot)
                && expected != proposer
            {
                return Err(PrecheckError::WrongProposer { proposer, expected });
            }
            parent_state
        }
        Reference::Recent(state) => state,
    };

    let pubkey = &state
        .validator(proposer)
        .map_err(|_| PrecheckError::UnknownProposer { proposer })?
        .pubkey;

    let fork_version = config.fork_version(config.fork_at_epoch(compute_epoch_at_slot(slot)));
    let domain = compute_domain(
        DOMAIN_BEACON_PROPOSER,
        fork_version,
        state.genesis_validators_root(),
    );
    let signing_root = compute_signing_root(block_root, domain);
    if !bls::verify(pubkey, signing_root, &signed_block.signature()) {
        return Err(PrecheckError::BadSignature);
    }
    Ok(())
}

/// The proposer `parent_state` has already fixed for `slot`, if it has.
///
/// Fulu's `proposer_lookahead` (EIP-7917) holds the proposers of the state's
/// current epoch and of the `MIN_SEED_LOOKAHEAD` epochs after it. Each entry
/// is fixed when it enters the window: epoch processing only shifts the
/// window along and appends a new last epoch. A slot inside the window is
/// therefore answered exactly as the state advanced to that slot would answer
/// it. Outside the window, and before fulu, answering means advancing the
/// state, which is the import's job; the specification lets such a block
/// through rather than rejecting it, and so does this.
pub(crate) fn fixed_proposer(parent_state: &BeaconState, slot: Slot) -> Option<ValidatorIndex> {
    let BeaconState::Fulu(state) = parent_state else {
        return None;
    };
    let window_start = compute_start_slot_at_epoch(compute_epoch_at_slot(state.slot));
    let offset = usize::try_from(slot.checked_sub(window_start)?).ok()?;
    state.proposer_lookahead.get(offset).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::containers::phase0;
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::test_state::{secret_key_for, with_validators_at};
    use crate::beacon::preset;
    use crate::beacon::primitives::{BlsPubkey, BlsSignature};

    /// A block by `proposer` at `slot`, signed by that validator's test key
    /// under `config`'s fork version for the block's epoch.
    ///
    /// Phase0-shaped whatever the slot's fork: these rules read the header
    /// fields and the block's root and never the body, so the cheapest body
    /// to build stands in for a fork-coherent one.
    fn signed_block(
        state: &BeaconState,
        config: &Config,
        slot: Slot,
        proposer: ValidatorIndex,
    ) -> SignedBeaconBlock {
        let mut block = phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: proposer,
                parent_root: Root::repeat_byte(0x11),
                state_root: Root::ZERO,
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: Root::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        };
        let root = SignedBeaconBlock::Phase0(block.clone()).message_hash_tree_root();
        block.signature = sign(state, config, slot, proposer, root);
        SignedBeaconBlock::Phase0(block)
    }

    fn sign(
        state: &BeaconState,
        config: &Config,
        slot: Slot,
        signer: ValidatorIndex,
        root: Root,
    ) -> BlsSignature {
        let fork_version = config.fork_version(config.fork_at_epoch(compute_epoch_at_slot(slot)));
        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER,
            fork_version,
            state.genesis_validators_root(),
        );
        let signing_root = compute_signing_root(root, domain);
        let signature =
            secret_key_for(signer as usize).sign(signing_root.as_slice(), bls::DST, &[]);
        BlsSignature(signature.to_bytes())
    }

    /// `with_validators_at(fork, 8)` with every validator given the public key
    /// of [`secret_key_for`] its index. Only the phase0 builder derives real
    /// keys; the later forks' leave them at the all-zero default, which no
    /// signature verifies against.
    fn keyed_state(fork: ForkName) -> BeaconState {
        let mut state = with_validators_at(fork, 8);
        for index in 0..8 {
            let pubkey = secret_key_for(index).sk_to_pk().to_bytes();
            state
                .validator_mut(index as ValidatorIndex)
                .expect("the state has eight validators")
                .pubkey = BlsPubkey(pubkey);
        }
        state
    }

    /// A fulu state whose lookahead names `proposer` for every slot.
    fn fulu_parent(proposer: ValidatorIndex) -> BeaconState {
        let mut state = keyed_state(ForkName::Fulu);
        if let BeaconState::Fulu(fulu_state) = &mut state {
            for entry in fulu_state.proposer_lookahead.iter_mut() {
                *entry = proposer;
            }
        }
        state
    }

    fn check(
        block: &SignedBeaconBlock,
        reference: Reference<'_>,
        config: &Config,
    ) -> Result<(), PrecheckError> {
        precheck_block(block, block.message_hash_tree_root(), reference, config)
    }

    #[test]
    fn a_block_signed_by_its_expected_proposer_passes() {
        let config = Config::mainnet();
        let parent = fulu_parent(3);
        let block = signed_block(&parent, &config, parent.slot() + 1, 3);
        assert_eq!(check(&block, Reference::Parent(&parent), &config), Ok(()));
    }

    /// The shape seen on mainnet: a real block's bytes altered after signing
    /// (one blob transaction re-encoded with its blobs), carrying the
    /// original signature. The root it now has was never signed.
    #[test]
    fn a_block_altered_after_signing_is_refused() {
        let config = Config::mainnet();
        let parent = fulu_parent(3);
        let SignedBeaconBlock::Phase0(mut block) =
            signed_block(&parent, &config, parent.slot() + 1, 3)
        else {
            unreachable!("signed_block builds a phase0 block");
        };
        block.message.body.graffiti = Root::repeat_byte(0xaa);
        let altered = SignedBeaconBlock::Phase0(block);
        assert_eq!(
            check(&altered, Reference::Parent(&parent), &config),
            Err(PrecheckError::BadSignature)
        );
        // Judged against a recent state instead, for a block whose parent has
        // not arrived, the signature alone still gives it away.
        assert_eq!(
            check(&altered, Reference::Recent(&parent), &config),
            Err(PrecheckError::BadSignature)
        );
    }

    #[test]
    fn a_validly_signed_block_from_the_wrong_proposer_is_refused() {
        let config = Config::mainnet();
        let parent = fulu_parent(3);
        let block = signed_block(&parent, &config, parent.slot() + 1, 5);
        assert_eq!(
            check(&block, Reference::Parent(&parent), &config),
            Err(PrecheckError::WrongProposer {
                proposer: 5,
                expected: 3
            })
        );
    }

    #[test]
    fn a_slot_past_the_lookahead_skips_the_proposer_rule_but_not_the_signature() {
        let config = Config::mainnet();
        let parent = fulu_parent(3);
        let window_start = compute_start_slot_at_epoch(compute_epoch_at_slot(parent.slot()));
        let beyond = window_start + preset::PROPOSER_LOOKAHEAD_LENGTH as Slot;
        let block = signed_block(&parent, &config, beyond, 5);
        assert_eq!(check(&block, Reference::Parent(&parent), &config), Ok(()));
    }

    #[test]
    fn a_block_not_after_its_parent_is_refused() {
        let config = Config::mainnet();
        let parent = fulu_parent(3);
        let block = signed_block(&parent, &config, parent.slot(), 3);
        assert_eq!(
            check(&block, Reference::Parent(&parent), &config),
            Err(PrecheckError::NotAfterParent {
                slot: parent.slot(),
                parent_slot: parent.slot()
            })
        );
    }

    #[test]
    fn a_proposer_missing_from_the_reference_state_is_unknown_to_both_references() {
        let config = Config::mainnet();
        // A pre-fulu parent, so the lookahead cannot answer first.
        let parent = keyed_state(ForkName::Electra);
        let block = signed_block(&parent, &config, parent.slot() + 1, 3);
        let SignedBeaconBlock::Phase0(mut unknown) = block else {
            unreachable!("signed_block builds a phase0 block");
        };
        unknown.message.proposer_index = 100;
        let unknown = SignedBeaconBlock::Phase0(unknown);
        assert_eq!(
            check(&unknown, Reference::Parent(&parent), &config),
            Err(PrecheckError::UnknownProposer { proposer: 100 })
        );
        // A recent state reports the same thing rather than passing the
        // block: its signature went unchecked, and `Ok` must never say
        // otherwise.
        assert_eq!(
            check(&unknown, Reference::Recent(&parent), &config),
            Err(PrecheckError::UnknownProposer { proposer: 100 })
        );
    }

    /// The first block of a fork is signed under the new version while its
    /// parent's state still carries the old `fork`, so reading the domain off
    /// the state would refuse every fork's first block.
    #[test]
    fn the_first_block_of_a_fork_is_judged_under_the_new_forks_version() {
        let parent = keyed_state(ForkName::Electra);
        let next_epoch = compute_epoch_at_slot(parent.slot()) + 1;
        let config = Config::mainnet().with_fork_epoch(ForkName::Fulu, next_epoch);
        let first_fulu_slot = compute_start_slot_at_epoch(next_epoch);
        assert_ne!(
            config.fork_version(ForkName::Fulu),
            config.fork_version(ForkName::Electra)
        );
        let block = signed_block(&parent, &config, first_fulu_slot, 3);
        assert_eq!(check(&block, Reference::Parent(&parent), &config), Ok(()));
    }
}
