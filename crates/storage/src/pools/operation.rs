//! Proposer slashings, attester slashings, voluntary exits and BLS changes
//! this node has validated, held until a block packs them.
//!
//! Only operations that already passed gossip (or Beacon API pool) validation
//! go in, so this is pure data: it never checks a signature. Each kind is
//! keyed by what makes a second entry redundant, and the first one wins.
//! [`OperationPool::prune`] drops what the head state already made pointless.

use std::collections::{BTreeMap, HashSet};

use ethlambda_types::{
    beacon::{
        constants::{BLS_WITHDRAWAL_PREFIX, FAR_FUTURE_EPOCH},
        containers::{
            BeaconState,
            capella::SignedBLSToExecutionChange,
            electra::AttesterSlashing,
            shared::{ProposerSlashing, SignedVoluntaryExit, Validator},
        },
        primitives::{Epoch, Root, ValidatorIndex},
        signing::compute_epoch_at_slot,
    },
    primitives::HashTreeRoot as _,
};

/// Operations awaiting inclusion in a block, one map per kind.
#[derive(Debug, Default)]
pub struct OperationPool {
    /// Keyed by the slashed proposer.
    proposer_slashings: BTreeMap<ValidatorIndex, ProposerSlashing>,
    /// Keyed by the slashing's `hash_tree_root`.
    attester_slashings: BTreeMap<Root, AttesterSlashing>,
    /// Keyed by the exiting validator.
    voluntary_exits: BTreeMap<ValidatorIndex, SignedVoluntaryExit>,
    /// Keyed by the validator whose credentials change.
    bls_to_execution_changes: BTreeMap<ValidatorIndex, SignedBLSToExecutionChange>,
}

/// The specification's `is_slashable_validator`.
fn is_slashable(validator: &Validator, epoch: Epoch) -> bool {
    !validator.slashed
        && validator.activation_epoch <= epoch
        && epoch < validator.withdrawable_epoch
}

impl OperationPool {
    /// Keeps the first slashing per proposer. Returns whether this one was new.
    /// Callers insert only validated operations.
    pub fn insert_proposer_slashing(&mut self, slashing: ProposerSlashing) -> bool {
        let key = slashing.signed_header_1.message.proposer_index;
        insert_first(&mut self.proposer_slashings, key, slashing)
    }

    /// Keeps the first slashing per `hash_tree_root`. Returns whether this one
    /// was new. Callers insert only validated operations.
    pub fn insert_attester_slashing(&mut self, slashing: AttesterSlashing) -> bool {
        let key = slashing.hash_tree_root();
        insert_first(&mut self.attester_slashings, key, slashing)
    }

    /// Keeps the first exit per validator. Returns whether this one was new.
    /// Callers insert only validated operations.
    pub fn insert_voluntary_exit(&mut self, exit: SignedVoluntaryExit) -> bool {
        let key = exit.message.validator_index;
        insert_first(&mut self.voluntary_exits, key, exit)
    }

    /// Keeps the first change per validator. Returns whether this one was new.
    /// Callers insert only validated operations.
    pub fn insert_bls_to_execution_change(&mut self, change: SignedBLSToExecutionChange) -> bool {
        let key = change.message.validator_index;
        insert_first(&mut self.bls_to_execution_changes, key, change)
    }

    /// Every proposer slashing held, in proposer order.
    pub fn proposer_slashings(&self) -> Vec<ProposerSlashing> {
        self.proposer_slashings.values().cloned().collect()
    }

    /// Every attester slashing held, in root order.
    pub fn attester_slashings(&self) -> Vec<AttesterSlashing> {
        self.attester_slashings.values().cloned().collect()
    }

    /// Every voluntary exit held, in validator order.
    pub fn voluntary_exits(&self) -> Vec<SignedVoluntaryExit> {
        self.voluntary_exits.values().cloned().collect()
    }

    /// Every BLS-to-execution change held, in validator order.
    pub fn bls_to_execution_changes(&self) -> Vec<SignedBLSToExecutionChange> {
        self.bls_to_execution_changes.values().cloned().collect()
    }

    /// Drop what `state` (the head state) already makes pointless: exits of
    /// validators whose `exit_epoch != FAR_FUTURE_EPOCH`, proposer slashings
    /// whose proposer is no longer slashable, attester slashings whose
    /// attesting-index intersection holds no slashable validator, and BLS
    /// changes whose validator's credentials no longer start with
    /// `BLS_WITHDRAWAL_PREFIX`. Slashable is the specification's
    /// `is_slashable_validator` at the state's current epoch. An index the
    /// state does not know is treated as pointless.
    pub fn prune(&mut self, state: &BeaconState) {
        let epoch = compute_epoch_at_slot(state.slot());
        let slashable = |index: ValidatorIndex| {
            state
                .validator(index)
                .is_ok_and(|validator| is_slashable(validator, epoch))
        };

        self.voluntary_exits.retain(|&index, _| {
            state
                .validator(index)
                .is_ok_and(|validator| validator.exit_epoch == FAR_FUTURE_EPOCH)
        });
        self.bls_to_execution_changes.retain(|&index, _| {
            state.validator(index).is_ok_and(|validator| {
                validator.withdrawal_credentials.0[0] == BLS_WITHDRAWAL_PREFIX
            })
        });
        self.proposer_slashings.retain(|&index, _| slashable(index));
        self.attester_slashings.retain(|_, slashing| {
            let first: HashSet<ValidatorIndex> = slashing
                .attestation_1
                .attesting_indices
                .iter()
                .copied()
                .collect();
            slashing
                .attestation_2
                .attesting_indices
                .iter()
                .any(|index| first.contains(index) && slashable(*index))
        });
    }
}

/// Inserts `value` unless `key` is taken; returns whether it was inserted.
fn insert_first<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, value: V) -> bool {
    match map.entry(key) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(value);
            true
        }
        std::collections::btree_map::Entry::Occupied(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::{
        containers::{
            capella::BLSToExecutionChange,
            electra::{AttestingIndices, IndexedAttestation},
            phase0,
            shared::{
                Balances, BeaconBlockHeader, BlockRoots, RandaoMixes, Slashings, StateRoots,
                Validators, VoluntaryExit,
            },
        },
        preset,
        primitives::{Bytes32, Gwei},
    };

    const NOW_EPOCH: Epoch = 10;

    fn active_validator() -> Validator {
        Validator {
            effective_balance: 32_000_000_000 as Gwei,
            activation_epoch: 0,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
            ..Default::default()
        }
    }

    /// A phase0 state at `NOW_EPOCH` holding `validators`. The pool reads only
    /// the registry and the slot, which every fork carries the same way.
    fn state_with(validators: Vec<Validator>) -> BeaconState {
        let count = validators.len();
        let validators: Validators = validators.try_into().expect("far below the limit");
        let balances: Balances = vec![0; count].try_into().expect("far below the limit");
        let roots: BlockRoots = vec![Root::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
            .try_into()
            .expect("built at exact length");
        let state_roots: StateRoots = roots.clone();
        let randao: RandaoMixes = vec![Bytes32::ZERO; preset::EPOCHS_PER_HISTORICAL_VECTOR]
            .try_into()
            .expect("built at exact length");
        let slashings: Slashings = vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
            .try_into()
            .expect("built at exact length");
        BeaconState::Phase0(phase0::BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::ZERO,
            slot: NOW_EPOCH * preset::SLOTS_PER_EPOCH,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: roots,
            state_roots,
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators,
            balances,
            randao_mixes: randao,
            slashings,
            previous_epoch_attestations: Default::default(),
            current_epoch_attestations: Default::default(),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
        })
    }

    fn exit(validator_index: ValidatorIndex, epoch: Epoch) -> SignedVoluntaryExit {
        SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch,
                validator_index,
            },
            signature: Default::default(),
        }
    }

    fn proposer_slashing(proposer_index: ValidatorIndex, slot: u64) -> ProposerSlashing {
        let mut slashing = ProposerSlashing::default();
        slashing.signed_header_1.message = BeaconBlockHeader {
            slot,
            proposer_index,
            ..Default::default()
        };
        slashing.signed_header_2.message = slashing.signed_header_1.message.clone();
        slashing
    }

    fn attester_slashing(first: &[u64], second: &[u64], slot: u64) -> AttesterSlashing {
        let attestation = |indices: &[u64]| {
            let attesting_indices: AttestingIndices =
                indices.to_vec().try_into().expect("far below the limit");
            let mut attestation = IndexedAttestation {
                attesting_indices,
                data: Default::default(),
                signature: Default::default(),
            };
            attestation.data.slot = slot;
            attestation
        };
        AttesterSlashing {
            attestation_1: attestation(first),
            attestation_2: attestation(second),
        }
    }

    /// `byte` goes into the target address, so two changes for one validator
    /// can differ.
    fn bls_change(validator_index: ValidatorIndex, byte: u8) -> SignedBLSToExecutionChange {
        let mut message = BLSToExecutionChange {
            validator_index,
            from_bls_pubkey: Default::default(),
            to_execution_address: Default::default(),
        };
        message.to_execution_address.0[0] = byte;
        SignedBLSToExecutionChange {
            message,
            signature: Default::default(),
        }
    }

    fn with_credentials(prefix: u8) -> Validator {
        let mut validator = active_validator();
        validator.withdrawal_credentials.0[0] = prefix;
        validator
    }

    #[test]
    fn the_first_exit_per_validator_is_kept() {
        let mut pool = OperationPool::default();
        assert!(pool.insert_voluntary_exit(exit(7, 1)));
        assert!(!pool.insert_voluntary_exit(exit(7, 2)));
        assert_eq!(pool.voluntary_exits(), vec![exit(7, 1)]);
    }

    #[test]
    fn prune_drops_exits_of_validators_already_exiting() {
        let mut pool = OperationPool::default();
        pool.insert_voluntary_exit(exit(0, 1));
        pool.insert_voluntary_exit(exit(1, 1));
        let mut exiting = active_validator();
        exiting.exit_epoch = NOW_EPOCH + 1;
        pool.prune(&state_with(vec![active_validator(), exiting]));
        assert_eq!(pool.voluntary_exits(), vec![exit(0, 1)]);
    }

    #[test]
    fn prune_drops_exits_of_unknown_validators() {
        let mut pool = OperationPool::default();
        pool.insert_voluntary_exit(exit(5, 1));
        pool.prune(&state_with(vec![active_validator()]));
        assert!(pool.voluntary_exits().is_empty());
    }

    #[test]
    fn the_first_proposer_slashing_per_proposer_is_kept() {
        let mut pool = OperationPool::default();
        assert!(pool.insert_proposer_slashing(proposer_slashing(3, 1)));
        assert!(!pool.insert_proposer_slashing(proposer_slashing(3, 2)));
        assert_eq!(pool.proposer_slashings(), vec![proposer_slashing(3, 1)]);
    }

    #[test]
    fn prune_drops_proposer_slashings_of_unslashable_proposers() {
        let mut pool = OperationPool::default();
        pool.insert_proposer_slashing(proposer_slashing(0, 1));
        pool.insert_proposer_slashing(proposer_slashing(1, 1));
        pool.insert_proposer_slashing(proposer_slashing(2, 1));
        let mut slashed = active_validator();
        slashed.slashed = true;
        let mut withdrawable = active_validator();
        withdrawable.withdrawable_epoch = NOW_EPOCH;
        pool.prune(&state_with(vec![active_validator(), slashed, withdrawable]));
        assert_eq!(pool.proposer_slashings(), vec![proposer_slashing(0, 1)]);
    }

    #[test]
    fn the_first_attester_slashing_per_root_is_kept() {
        let mut pool = OperationPool::default();
        assert!(pool.insert_attester_slashing(attester_slashing(&[1, 2], &[2, 3], 1)));
        assert!(!pool.insert_attester_slashing(attester_slashing(&[1, 2], &[2, 3], 1)));
        assert!(pool.insert_attester_slashing(attester_slashing(&[1, 2], &[2, 3], 2)));
        assert_eq!(pool.attester_slashings().len(), 2);
    }

    #[test]
    fn prune_keeps_an_attester_slashing_while_one_intersecting_validator_is_slashable() {
        let mut slashed = active_validator();
        slashed.slashed = true;
        // Validators 1 and 2 are in both attestations; 1 is slashed, 2 is not.
        let state = state_with(vec![active_validator(), slashed, active_validator()]);
        let mut pool = OperationPool::default();
        pool.insert_attester_slashing(attester_slashing(&[0, 1, 2], &[1, 2], 1));
        pool.prune(&state);
        assert_eq!(pool.attester_slashings().len(), 1);
    }

    #[test]
    fn prune_drops_an_attester_slashing_whose_intersection_is_all_slashed() {
        let mut slashed = active_validator();
        slashed.slashed = true;
        // Validator 0 is slashable but only in the first attestation.
        let state = state_with(vec![active_validator(), slashed.clone(), slashed]);
        let mut pool = OperationPool::default();
        pool.insert_attester_slashing(attester_slashing(&[0, 1, 2], &[1, 2], 1));
        pool.prune(&state);
        assert!(pool.attester_slashings().is_empty());
    }

    #[test]
    fn the_first_bls_change_per_validator_is_kept() {
        let mut pool = OperationPool::default();
        assert!(pool.insert_bls_to_execution_change(bls_change(4, 0)));
        assert!(!pool.insert_bls_to_execution_change(bls_change(4, 1)));
        assert_eq!(pool.bls_to_execution_changes().len(), 1);
    }

    #[test]
    fn prune_drops_bls_changes_whose_credentials_already_moved_on() {
        let mut pool = OperationPool::default();
        pool.insert_bls_to_execution_change(bls_change(0, 0));
        pool.insert_bls_to_execution_change(bls_change(1, 0));
        let state = state_with(vec![with_credentials(0x00), with_credentials(0x01)]);
        pool.prune(&state);
        assert_eq!(pool.bls_to_execution_changes(), vec![bls_change(0, 0)]);
    }
}
