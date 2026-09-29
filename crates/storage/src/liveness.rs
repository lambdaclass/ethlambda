//! Validators this node has seen act, by epoch, for the Beacon API's
//! `POST /eth/v1/validator/liveness/{epoch}`.
//!
//! The endpoint's answer is this node's own view, which the Beacon API allows
//! to come from the network, the chain or the API. The head state's
//! participation flags already cover the chain, but only once a block has
//! included a vote; this set covers what the node sees before that: accepted
//! gossip, imported blocks' proposers, and what validator clients submit
//! through this node's own API (gossip never delivers a node its own
//! messages). The endpoint ORs the two.
//!
//! Held by the `Store` because P2P, the chain actor and the RPC all write or
//! read it, and all three already hold a clone.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ethlambda_types::beacon::primitives::{Epoch, ValidatorIndex};

/// How many epochs are kept, counting back from the newest one recorded.
///
/// The endpoint answers the previous, current and next epoch; the next one has
/// nothing to observe yet, so the newest epoch and the two before it cover
/// every epoch it can be asked about, with one to spare at a boundary.
const RETAINED_EPOCHS: u64 = 3;

/// The largest validator index recorded, exclusive.
///
/// Every writer records an index that passed validation against a state, so
/// this is a guard rather than a limit anything should reach: it bounds one
/// epoch's bitset at 2 MiB whatever an index turns out to be. Mainnet has
/// about 2.4 million validators, well under it.
const MAX_TRACKED_INDEX: ValidatorIndex = 1 << 24;

/// One bitset per retained epoch, indexed by validator index.
///
/// A bitset rather than a set of indices: on mainnet an epoch sees most of
/// the registry act, which is about 300 KB as bits and tens of megabytes as a
/// hash set.
#[derive(Default)]
pub struct ObservedLiveness(Mutex<BTreeMap<Epoch, Vec<u64>>>);

impl ObservedLiveness {
    /// Record that `validator` did something in `epoch`.
    pub fn record(&self, epoch: Epoch, validator: ValidatorIndex) {
        self.record_all(epoch, [validator]);
    }

    /// Record every one of `validators` for `epoch`, under one lock.
    ///
    /// An epoch older than the retained window is ignored rather than
    /// recorded and immediately pruned: a block imported during range sync
    /// names an epoch nobody will ask about.
    pub fn record_all(&self, epoch: Epoch, validators: impl IntoIterator<Item = ValidatorIndex>) {
        let mut epochs = self.0.lock().expect("liveness lock poisoned");
        let newest = epochs
            .keys()
            .next_back()
            .copied()
            .unwrap_or(epoch)
            .max(epoch);
        let floor = newest.saturating_sub(RETAINED_EPOCHS - 1);
        if epoch < floor {
            return;
        }
        let bits = epochs.entry(epoch).or_default();
        for validator in validators {
            if validator >= MAX_TRACKED_INDEX {
                continue;
            }
            let word = (validator / 64) as usize;
            if bits.len() <= word {
                bits.resize(word + 1, 0);
            }
            bits[word] |= 1 << (validator % 64);
        }
        epochs.retain(|&kept, _| kept >= floor);
    }

    /// Whether `validator` was recorded for `epoch`.
    pub fn is_live(&self, epoch: Epoch, validator: ValidatorIndex) -> bool {
        let epochs = self.0.lock().expect("liveness lock poisoned");
        epochs
            .get(&epoch)
            .and_then(|bits| bits.get((validator / 64) as usize))
            .is_some_and(|word| word & (1 << (validator % 64)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_validator_is_live_in_that_epoch_only() {
        let observed = ObservedLiveness::default();
        observed.record(5, 70);
        assert!(observed.is_live(5, 70));
        assert!(!observed.is_live(5, 71), "a neighbouring bit");
        assert!(!observed.is_live(4, 70), "another epoch");
        assert!(!observed.is_live(5, 6_000), "past the recorded words");
    }

    #[test]
    fn record_all_sets_every_index() {
        let observed = ObservedLiveness::default();
        observed.record_all(5, [0, 63, 64, 1_000_000]);
        for index in [0, 63, 64, 1_000_000] {
            assert!(observed.is_live(5, index), "{index}");
        }
        assert!(!observed.is_live(5, 1));
    }

    #[test]
    fn epochs_older_than_the_window_are_pruned() {
        let observed = ObservedLiveness::default();
        observed.record(10, 1);
        observed.record(11, 1);
        observed.record(12, 1);
        assert!(observed.is_live(10, 1), "10, 11 and 12 fit the window");

        observed.record(13, 1);
        assert!(!observed.is_live(10, 1), "13 pushes 10 out");
        assert!(observed.is_live(11, 1));
    }

    #[test]
    fn an_epoch_below_the_window_is_not_recorded() {
        let observed = ObservedLiveness::default();
        observed.record(20, 1);
        observed.record(5, 2);
        assert!(!observed.is_live(5, 2));
        assert!(observed.is_live(20, 1), "and nothing newer is disturbed");
    }

    #[test]
    fn an_index_past_the_guard_is_ignored() {
        let observed = ObservedLiveness::default();
        observed.record(5, MAX_TRACKED_INDEX);
        assert!(!observed.is_live(5, MAX_TRACKED_INDEX));
    }
}
