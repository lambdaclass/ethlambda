//! Randomized equivalence of electra's fused epoch pass with the step-by-step
//! path it replaces.
//!
//! Each case builds an electra or fulu state at some epoch and runs steps 1-9
//! twice: through [`single_pass`]'s fused driver and through the
//! specification-shaped steps (with the reference participation code). Both
//! must succeed or both fail, and on success the full states must hash equal.
//!
//! The generator crafts what live chains rarely hold together: several
//! ejections in one epoch (so the exit-churn cursor moves), validators waiting
//! for the activation queue and for activation, slashed validators due and not
//! due for their penalty, a non-zero slashings vector, balances on both sides
//! of the hysteresis thresholds, and pending queues that hit every branch:
//! top-ups of active, exiting and withdrawn validators, a validator about to be
//! ejected, new pubkeys with valid and invalid signatures (twice for one
//! pubkey), an exhausted churn budget, unfinalized slots, and consolidations
//! that are processed, dropped as slashed, or stop the queue.

use super::electra;
use super::single_pass::{can_fuse, differing_fields, dispatch};
use crate::beacon::config::Config;
use crate::beacon::constants::{self, FAR_FUTURE_EPOCH};
use crate::beacon::containers::shared::{Checkpoint, DepositMessage};
use crate::beacon::containers::{BeaconState, electra as electra_containers};
use crate::beacon::fork::ForkName;
use crate::beacon::helpers::accessors::get_previous_epoch;
use crate::beacon::helpers::electra::ExitChurnCursor;
use crate::beacon::helpers::misc::{
    compute_deposit_domain, compute_signing_root, compute_start_slot_at_epoch,
};
use crate::beacon::helpers::test_state::{secret_key_for, sign_for, with_signing_validators_at};
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsPubkey, BlsSignature, Bytes32, Epoch, Gwei, HashTreeRoot as _, Root, ValidatorIndex,
};

/// Small deterministic generator, so a failing case reproduces from its seed
/// without a new dependency.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..bound`.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    /// True with probability `percent` in a hundred.
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

const INCREMENT: Gwei = preset::EFFECTIVE_BALANCE_INCREMENT;
const ETH: Gwei = 1_000_000_000;

/// Registry sizes the generator draws from, and how many cases each fork gets.
const SIZES: [usize; 3] = [40, 120, 300];
const CASES_PER_FORK: u64 = 400;

/// A signed deposit for the key with index `key` (kept clear of the registry's
/// own keys), or an unsigned one when `valid` is false.
fn deposit_for_key(
    key: usize,
    amount: Gwei,
    slot: u64,
    valid: bool,
    config: &Config,
) -> electra_containers::PendingDeposit {
    let pubkey = BlsPubkey(secret_key_for(key).sk_to_pk().to_bytes());
    let mut withdrawal_credentials = Bytes32::ZERO;
    withdrawal_credentials.0[0] = constants::COMPOUNDING_WITHDRAWAL_PREFIX;
    let message = DepositMessage {
        pubkey,
        withdrawal_credentials,
        amount,
    };
    let domain = compute_deposit_domain(config.genesis_fork_version);
    let signing_root = compute_signing_root(message.hash_tree_root(), domain);
    let signature = if valid {
        sign_for(key, signing_root)
    } else {
        BlsSignature::default()
    };
    electra_containers::PendingDeposit {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        slot,
    }
}

/// A random state derived from `base` (a registry of signing validators).
fn random_state(rng: &mut SplitMix64, base: &BeaconState, config: &Config) -> BeaconState {
    let mut state = base.clone();
    let count = state.validators().len();

    let epoch: Epoch = match rng.below(10) {
        // Genesis: the fused pass declines and the steps run one by one.
        0 => 0,
        1 => 1,
        2 => 2,
        // Far enough past the finalized checkpoint to leak.
        3 => preset::MIN_EPOCHS_TO_INACTIVITY_PENALTY + 3 + rng.below(4),
        _ => 3 + rng.below(40),
    };
    let offset = if rng.chance(90) {
        1 + rng.below(preset::SLOTS_PER_EPOCH - 1)
    } else {
        0
    };
    *state.slot_mut() = epoch * preset::SLOTS_PER_EPOCH + offset;
    let next_epoch = epoch + 1;

    let slashings_offset = (preset::EPOCHS_PER_SLASHINGS_VECTOR / 2) as Epoch;
    let hysteresis_down =
        INCREMENT / preset::HYSTERESIS_QUOTIENT * preset::HYSTERESIS_DOWNWARD_MULTIPLIER;
    let hysteresis_up =
        INCREMENT / preset::HYSTERESIS_QUOTIENT * preset::HYSTERESIS_UPWARD_MULTIPLIER;
    let participation_density = rng.pick(&[0, 30, 70, 95, 100]);
    // A balance within a hysteresis threshold of `u64::MAX` overflows the
    // effective-balance update and fails the whole epoch, so only a few states
    // carry one: enough to check both paths fail together, few enough to
    // leave the rest to compare.
    let extreme_balances = rng.chance(10);
    let near = |rng: &mut SplitMix64| (epoch + rng.below(5)).saturating_sub(2);

    // Finality first: the activation branch reads the finalized epoch. It
    // stays at or behind the previous epoch, as in any reachable state:
    // `get_finality_delay` subtracts it from the previous epoch, and fails
    // otherwise.
    let checkpoint = |epoch: u64| Checkpoint {
        epoch,
        root: Root::ZERO,
    };
    let previous_epoch = get_previous_epoch(&state);
    *state.previous_justified_checkpoint_mut() = checkpoint(epoch.saturating_sub(rng.below(4)));
    *state.current_justified_checkpoint_mut() = checkpoint(epoch.saturating_sub(rng.below(3)));
    let finalized_epoch = if rng.chance(30) {
        0
    } else {
        previous_epoch.saturating_sub(rng.below(3))
    };
    *state.finalized_checkpoint_mut() = checkpoint(finalized_epoch);
    for bit in 0..constants::JUSTIFICATION_BITS_LENGTH {
        let value = rng.chance(50);
        state.justification_bits_mut().set(bit, value).unwrap();
    }

    let mut balances: Vec<Gwei> = Vec::with_capacity(count);
    for index in 0..count {
        let validator = state.validator_mut(index as ValidatorIndex).unwrap();
        if rng.chance(30) {
            validator.withdrawal_credentials.0[0] = constants::COMPOUNDING_WITHDRAWAL_PREFIX;
        }
        validator.activation_eligibility_epoch = match rng.below(20) {
            0..=2 => FAR_FUTURE_EPOCH,
            3 => epoch,
            _ => 0,
        };
        validator.activation_epoch = match rng.below(20) {
            0..=2 => FAR_FUTURE_EPOCH,
            3 => near(rng),
            _ => 0,
        };
        validator.exit_epoch = match rng.below(20) {
            0 | 1 => near(rng),
            2 => near(rng) + 1,
            _ => FAR_FUTURE_EPOCH,
        };
        validator.slashed = rng.chance(8);
        validator.withdrawable_epoch = if validator.slashed && rng.chance(60) {
            (epoch + slashings_offset)
                .saturating_add(rng.pick(&[0, 0, 0, 1]))
                .saturating_sub(rng.pick(&[0, 0, 1]))
        } else {
            match rng.below(4) {
                0 => near(rng),
                1 => near(rng) + 1,
                _ => FAR_FUTURE_EPOCH,
            }
        };
        validator.effective_balance = match rng.below(20) {
            0 => 0,
            1..=3 => config.ejection_balance,
            4 => config.ejection_balance - INCREMENT,
            5 => config.ejection_balance + INCREMENT,
            6..=7 => preset::MAX_EFFECTIVE_BALANCE_ELECTRA,
            8 => (1 + rng.below(preset::MAX_EFFECTIVE_BALANCE_ELECTRA / INCREMENT)) * INCREMENT,
            9 => rng.below(preset::MAX_EFFECTIVE_BALANCE_ELECTRA),
            _ => preset::MIN_ACTIVATION_BALANCE,
        };
        let effective = validator.effective_balance;
        balances.push(match rng.below(14) {
            0 => 0,
            1 => rng.below(5_000),
            2 => effective.saturating_sub(hysteresis_down + 1),
            3 => effective.saturating_sub(hysteresis_down),
            4 => effective + hysteresis_up + 1,
            5 => effective + hysteresis_up,
            6 => effective + rng.below(3 * INCREMENT),
            7 if extreme_balances && rng.chance(20) => u64::MAX - rng.below(3),
            _ => effective,
        });
    }
    *state.balances_mut() = balances.try_into().unwrap();

    // Participation lists and scores, all bit patterns.
    let lists: Vec<Vec<u8>> = (0..2)
        .map(|_| {
            (0..count)
                .map(|_| {
                    if rng.chance(participation_density) {
                        if rng.chance(50) {
                            0b111 | (rng.below(32) as u8) << 3
                        } else {
                            rng.below(256) as u8
                        }
                    } else {
                        0
                    }
                })
                .collect()
        })
        .collect();
    let scores: Vec<u64> = (0..count)
        .map(|_| match rng.below(10) {
            0..=2 => 0,
            3..=6 => rng.below(64),
            _ => rng.below(1 << 20),
        })
        .collect();
    let (previous, current, inactivity) = state.altair_validator_lists_mut().unwrap();
    *previous = lists[0].clone().try_into().unwrap();
    *current = lists[1].clone().try_into().unwrap();
    *inactivity = scores.try_into().unwrap();

    // A few states the fused pass declines: a short list.
    if rng.chance(3) {
        let keep = rng.below(count as u64) as usize;
        let mut balances = state.balances().to_vec();
        balances.truncate(keep);
        *state.balances_mut() = balances.try_into().unwrap();
    }

    // The slashings vector.
    if rng.chance(60) {
        for _ in 0..rng.below(12) {
            let at = rng.below(preset::EPOCHS_PER_SLASHINGS_VECTOR as u64) as usize;
            state.slashings_mut()[at] = rng.below(400 * ETH);
        }
        if rng.chance(3) {
            state.slashings_mut()[0] = u64::MAX;
            state.slashings_mut()[1] = u64::MAX;
        }
    }

    // The exit-churn cursor.
    ExitChurnCursor {
        earliest_exit_epoch: (epoch + rng.below(10)).saturating_sub(2),
        exit_balance_to_consume: rng.below(200 * ETH),
    }
    .write(&mut state)
    .unwrap();

    // Pending consolidations.
    let mut consolidations = Vec::new();
    for _ in 0..rng.pick(&[0, 0, 1, 3, 6]) {
        let source = rng.below(count as u64);
        let target = if rng.chance(3) {
            count as u64 + rng.below(3)
        } else {
            rng.below(count as u64)
        };
        let validator = state.validator_mut(source).unwrap();
        match rng.below(4) {
            // Processed.
            0 | 1 => {
                validator.slashed = false;
                validator.withdrawable_epoch = rng.pick(&[epoch, next_epoch, 0]);
            }
            // Dropped as slashed.
            2 => validator.slashed = true,
            // Not withdrawable yet: stops the queue.
            _ => {
                validator.slashed = false;
                validator.withdrawable_epoch = next_epoch + 1 + rng.below(3);
            }
        }
        consolidations.push(electra_containers::PendingConsolidation {
            source_index: source,
            target_index: target,
        });
    }

    // Pending deposits.
    let finalized_slot = compute_start_slot_at_epoch(finalized_epoch);
    let mut deposits: Vec<electra_containers::PendingDeposit> = Vec::new();
    let mut fresh_keys: Vec<usize> = Vec::new();
    for _ in 0..rng.pick(&[0, 0, 1, 2, 4, 8, 17, 20]) {
        let random_amount = INCREMENT * (1 + rng.below(150));
        let amount = rng.pick(&[ETH, 32 * ETH, random_amount, u64::MAX / 2]);
        let slot = match rng.below(10) {
            0 => finalized_slot + 1 + rng.below(3),
            1..=2 if finalized_slot > 0 => 1 + rng.below(finalized_slot),
            _ => constants::GENESIS_SLOT,
        };
        let pick_validator = |rng: &mut SplitMix64| rng.below(count as u64);
        let deposit = match rng.below(9) {
            // An existing validator, whatever its state.
            0 | 1 => {
                let index = pick_validator(rng);
                let validator = state.validator(index).unwrap();
                electra_containers::PendingDeposit {
                    pubkey: validator.pubkey,
                    withdrawal_credentials: validator.withdrawal_credentials,
                    amount,
                    signature: BlsSignature::default(),
                    slot,
                }
            }
            // An exiting validator, not yet withdrawable.
            2 => {
                let index = pick_validator(rng);
                let validator = state.validator_mut(index).unwrap();
                validator.exit_epoch = epoch + 3;
                validator.withdrawable_epoch = epoch + 10;
                electra_containers::PendingDeposit {
                    pubkey: validator.pubkey,
                    withdrawal_credentials: validator.withdrawal_credentials,
                    amount,
                    signature: BlsSignature::default(),
                    slot,
                }
            }
            // A withdrawn validator.
            3 => {
                let index = pick_validator(rng);
                let validator = state.validator_mut(index).unwrap();
                validator.exit_epoch = 0;
                validator.withdrawable_epoch = 0;
                electra_containers::PendingDeposit {
                    pubkey: validator.pubkey,
                    withdrawal_credentials: validator.withdrawal_credentials,
                    amount,
                    signature: BlsSignature::default(),
                    slot,
                }
            }
            // A validator this very epoch ejects, sometimes with a
            // withdrawable epoch that only looks withdrawn until it is.
            4 => {
                let index = pick_validator(rng);
                let validator = state.validator_mut(index).unwrap();
                validator.activation_epoch = 0;
                validator.exit_epoch = FAR_FUTURE_EPOCH;
                validator.effective_balance = config.ejection_balance;
                validator.activation_eligibility_epoch = 0;
                if rng.chance(50) {
                    validator.withdrawable_epoch = 0;
                }
                electra_containers::PendingDeposit {
                    pubkey: validator.pubkey,
                    withdrawal_credentials: validator.withdrawal_credentials,
                    amount,
                    signature: BlsSignature::default(),
                    slot,
                }
            }
            // A new pubkey, valid or not.
            5 | 6 => {
                let key = 10_000 + fresh_keys.len();
                fresh_keys.push(key);
                deposit_for_key(key, amount.min(600 * ETH), slot, rng.chance(70), config)
            }
            // Another deposit for a pubkey already queued.
            _ => match fresh_keys.last() {
                Some(&key) => {
                    deposit_for_key(key, ETH * (1 + rng.below(40)), slot, rng.chance(70), config)
                }
                None => deposit_for_key(10_000, amount.min(600 * ETH), slot, true, config),
            },
        };
        deposits.push(deposit);
    }

    match &mut state {
        BeaconState::Electra(inner) => {
            if rng.chance(10) {
                inner.eth1_deposit_index = 3;
                inner.deposit_requests_start_index = 5;
            } else {
                inner.eth1_deposit_index = 5;
                inner.deposit_requests_start_index = 5;
            }
            inner.deposit_balance_to_consume = rng.pick(&[0, 0, 10 * ETH, 500 * ETH]);
            inner.pending_deposits = deposits.try_into().unwrap();
            inner.pending_consolidations = consolidations.try_into().unwrap();
        }
        BeaconState::Fulu(inner) => {
            if rng.chance(10) {
                inner.eth1_deposit_index = 3;
                inner.deposit_requests_start_index = 5;
            } else {
                inner.eth1_deposit_index = 5;
                inner.deposit_requests_start_index = 5;
            }
            inner.deposit_balance_to_consume = rng.pick(&[0, 0, 10 * ETH, 500 * ETH]);
            inner.pending_deposits = deposits.try_into().unwrap();
            inner.pending_consolidations = consolidations.try_into().unwrap();
        }
        _ => unreachable!("the bases are electra or fulu"),
    }
    if rng.chance(2) {
        // Overflows `deposit_balance_to_consume + churn`.
        match &mut state {
            BeaconState::Electra(inner) => inner.deposit_balance_to_consume = u64::MAX - 5,
            BeaconState::Fulu(inner) => inner.deposit_balance_to_consume = u64::MAX - 5,
            _ => unreachable!(),
        }
    }
    state
}

#[derive(Default, Debug)]
struct Coverage {
    cases: u32,
    fused: u32,
    both_failed: u32,
    ejected: u32,
    activated: u32,
    queued: u32,
    validators_created: u32,
    deposits_consumed: u32,
    consolidations_consumed: u32,
    effective_balance_moved: u32,
    scores_moved: u32,
}

#[test]
fn fused_pass_matches_the_unfused_steps() {
    let config = Config::mainnet();
    let mut coverage = Coverage::default();
    for (fork_number, fork) in [ForkName::Electra, ForkName::Fulu].into_iter().enumerate() {
        let bases: Vec<BeaconState> = SIZES
            .iter()
            .map(|&size| with_signing_validators_at(fork, size))
            .collect();
        for case in 0..CASES_PER_FORK {
            let seed = (fork_number as u64) << 32 | case;
            let mut rng = SplitMix64(seed);
            let base = &bases[rng.below(bases.len() as u64) as usize];
            let state = random_state(&mut rng, base, &config);

            let mut fused = state.clone();
            let mut unfused = state.clone();
            let fused_result = dispatch(&mut fused, &config);
            let unfused_result = electra::process_unfused_steps(&mut unfused, &config, true);

            coverage.cases += 1;
            coverage.fused += can_fuse(&state) as u32;
            assert_eq!(
                fused_result.is_ok(),
                unfused_result.is_ok(),
                "outcome differs, seed {seed}: fused {fused_result:?} vs unfused {unfused_result:?}"
            );
            if fused_result.is_err() {
                coverage.both_failed += 1;
                continue;
            }

            fused.apply_pending_mutations();
            unfused.apply_pending_mutations();
            if fused.hash_tree_root() != unfused.hash_tree_root() {
                panic!(
                    "states differ, seed {seed}: {}",
                    differing_fields(&mut fused, &mut unfused).join(", ")
                );
            }

            let before: Vec<_> = state.validators().iter().collect();
            let after: Vec<_> = fused.validators().iter().collect();
            for (old, new) in before.iter().zip(after.iter()) {
                coverage.ejected += (old.exit_epoch == FAR_FUTURE_EPOCH
                    && new.exit_epoch != FAR_FUTURE_EPOCH)
                    as u32;
                coverage.activated += (old.activation_epoch == FAR_FUTURE_EPOCH
                    && new.activation_epoch != FAR_FUTURE_EPOCH)
                    as u32;
                coverage.queued += (old.activation_eligibility_epoch == FAR_FUTURE_EPOCH
                    && new.activation_eligibility_epoch != FAR_FUTURE_EPOCH)
                    as u32;
                coverage.effective_balance_moved +=
                    (old.effective_balance != new.effective_balance) as u32;
            }
            coverage.validators_created += (after.len() > before.len()) as u32;
            let queue_len = |state: &mut BeaconState| {
                let mut state = state.clone();
                let mut fields = super::electra::pending_queue_fields(&mut state, "test").unwrap();
                (
                    fields.pending_deposits_mut().len(),
                    fields.pending_consolidations_mut().len(),
                )
            };
            let (deposits_before, consolidations_before) = queue_len(&mut state.clone());
            let (deposits_after, consolidations_after) = queue_len(&mut fused);
            coverage.deposits_consumed += (deposits_after < deposits_before) as u32;
            coverage.consolidations_consumed +=
                (consolidations_after < consolidations_before) as u32;
            let (_, _, scores_before) = state.altair_validator_lists().unwrap();
            let (_, _, scores_after) = fused.altair_validator_lists().unwrap();
            coverage.scores_moved += (scores_before != scores_after) as u32;
        }
    }

    println!("{coverage:?}");
    let total = coverage.cases;
    assert!(
        coverage.fused * 10 > total * 8,
        "too few fused cases: {coverage:?}"
    );
    assert!(
        coverage.both_failed * 5 < total,
        "too many errors: {coverage:?}"
    );
    assert!(coverage.ejected > 100, "{coverage:?}");
    assert!(coverage.activated > 100, "{coverage:?}");
    assert!(coverage.queued > 100, "{coverage:?}");
    assert!(coverage.validators_created > 40, "{coverage:?}");
    assert!(coverage.deposits_consumed > 100, "{coverage:?}");
    assert!(coverage.consolidations_consumed > 50, "{coverage:?}");
    assert!(coverage.effective_balance_moved > 500, "{coverage:?}");
    assert!(coverage.scores_moved > 200, "{coverage:?}");
}

/// The public entry point (the one `process_epoch` calls) also runs its own
/// debug oracle; a fixed case drives it through both forks' drivers.
#[test]
fn drivers_run_the_oracle_on_a_crafted_epoch() {
    let config = Config::mainnet();
    for (fork_number, fork) in [ForkName::Electra, ForkName::Fulu].into_iter().enumerate() {
        let base = with_signing_validators_at(fork, 40);
        for case in 0..20u64 {
            let mut rng = SplitMix64(0xD00D << 16 | (fork_number as u64) << 8 | case);
            let mut state = random_state(&mut rng, &base, &config);
            // The oracle panics on divergence; errors are allowed.
            let _ =
                super::single_pass::process_steps_through_effective_balances(&mut state, &config);
        }
    }
}
