//! The validator's finality signing record and the attestation rules that
//! read it (validator.md: `FinalitySigningRecord`, `get_finality_vote`,
//! `get_height_vote`, `get_finality_attestation_data`,
//! `record_finality_attestation`), and the slashing conditions they avoid
//! (beacon-chain.md: `is_double_target_vote`,
//! `is_conflicting_with_finality_pair`, `is_slashable_attestation_data`).
//!
//! The record is owned by whoever holds the key and persists across restarts.
//! Finality signing locks do not expire: there is deliberately no way to prune
//! the record, in particular none keyed on a height a beacon node supplies.

use std::collections::{BTreeMap, BTreeSet};

use ethlambda_types::primitives::H256;
use serde::{Deserialize, Serialize};

use crate::duties::FinalityAttestationInput;
use crate::types::{AttestationData, Height, HeightCheckpoint};

/// `FinalitySigningRecord`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalitySigningRecord {
    /// `targets[h]`: the first target voted for at height `h`.
    pub targets: BTreeMap<Height, H256>,
    /// `timeouts`: heights at which a timeout was signed.
    pub timeouts: BTreeSet<Height>,
    /// `finality_locks[h]`: the block named by a finality vote at height `h`.
    pub finality_locks: BTreeMap<Height, H256>,
    /// `entries[h]`: entries named by any height vote at height `h`.
    pub entries: BTreeMap<Height, BTreeSet<H256>>,
}

impl FinalitySigningRecord {
    /// `get_finality_vote(record, justified, finalized_height)`: the finality
    /// pair, or the empty checkpoint.
    pub fn get_finality_vote(
        &self,
        justified: HeightCheckpoint,
        finalized_height: Height,
    ) -> HeightCheckpoint {
        let (height, root) = (justified.height, justified.root);
        if height <= finalized_height {
            return HeightCheckpoint::empty();
        }
        if self
            .targets
            .get(&height)
            .is_some_and(|&target| target != root)
        {
            return HeightCheckpoint::empty();
        }
        if self.timeouts.contains(&height) {
            return HeightCheckpoint::empty();
        }
        if self
            .finality_locks
            .get(&height)
            .is_some_and(|&lock| lock != root)
        {
            return HeightCheckpoint::empty();
        }
        justified
    }

    /// `get_height_vote(record, target, finality)`: `(target, timeout)`, or
    /// `None` to cast no height vote.
    ///
    /// ```text
    /// timeouts ∋ h   lock at h      targets[h]     result
    /// yes            —              —              timeout
    /// no             = root         —              target vote
    /// no             ≠ root         —              none
    /// no             none           none or root   target vote
    /// no             none           other root     timeout
    /// ```
    ///
    /// The lock at `h` is the candidate finality pair when it is at `h`.
    pub fn get_height_vote(
        &self,
        target: HeightCheckpoint,
        finality: HeightCheckpoint,
    ) -> Option<(HeightCheckpoint, bool)> {
        let (height, root) = (target.height, target.root);
        if height == 0 || root == H256::ZERO {
            return None;
        }
        let mut lock = self.finality_locks.get(&height).copied();
        if !finality.is_empty() && finality.height == height {
            lock = Some(finality.root);
        }
        if self.timeouts.contains(&height) {
            return Some((target, true));
        }
        if let Some(lock) = lock {
            return (lock == root).then_some((target, false));
        }
        match self.targets.get(&height) {
            None => Some((target, false)),
            Some(&recorded) if recorded == root => Some((target, false)),
            Some(_) => Some((target, true)),
        }
    }

    /// `get_finality_attestation_data(record, target, justified,
    /// finalized_height)`: `None` sends no attestation. An entry already named
    /// at the height is never named again, and a second target vote at a
    /// height is never cast, even for the same root.
    pub fn get_finality_attestation_data(
        &self,
        target: HeightCheckpoint,
        justified: HeightCheckpoint,
        finalized_height: Height,
    ) -> Option<AttestationData> {
        let mut finality = self.get_finality_vote(justified, finalized_height);
        let (target, timeout) = self.get_height_vote(target, finality)?;
        let entries = self.entries.get(&target.height);
        let named = entries.is_some_and(|entries| entries.contains(&target.root));
        let any = entries.is_some_and(|entries| !entries.is_empty());
        if (!timeout && any) || named {
            return None;
        }
        if !finality.is_empty() && target.height <= finality.height {
            finality = HeightCheckpoint::empty();
        }
        Some(AttestationData {
            target,
            timeout,
            finality,
        })
    }

    /// `record_finality_attestation(record, data)`: the only writer of the
    /// record, run before signing.
    pub fn record_finality_attestation(&mut self, data: &AttestationData) {
        let (height, root) = (data.target.height, data.target.root);
        self.entries.entry(height).or_default().insert(root);
        if !data.finality.is_empty() {
            self.finality_locks
                .insert(data.finality.height, data.finality.root);
        }
        if data.timeout {
            self.timeouts.insert(height);
        } else {
            self.targets.entry(height).or_insert(root);
        }
    }

    /// Select and record in one step, as validator.md requires per key:
    /// returns the data to sign, or `None` to send nothing. Persist the record
    /// before signing.
    pub fn attest(&mut self, input: &FinalityAttestationInput) -> Option<AttestationData> {
        let data = self.get_finality_attestation_data(
            input.target,
            input.justified,
            input.finalized_height,
        )?;
        self.record_finality_attestation(&data);
        Some(data)
    }
}

/// `is_double_target_vote(data_1, data_2)`: target votes for different roots
/// at one height.
pub fn is_double_target_vote(left: &AttestationData, right: &AttestationData) -> bool {
    !left.timeout
        && !right.timeout
        && left.target.height == right.target.height
        && left.target.root != right.target.root
}

/// `is_conflicting_with_finality_pair(data, finality)`: `data` votes at the
/// height of the non-empty finality pair without a target vote for its root.
pub fn is_conflicting_with_finality_pair(
    data: &AttestationData,
    finality: &HeightCheckpoint,
) -> bool {
    if finality.is_empty() || data.target.height != finality.height {
        return false;
    }
    data.timeout || data.target.root != finality.root
}

/// `is_slashable_attestation_data(data_1, data_2)`.
pub fn is_slashable_attestation_data(left: &AttestationData, right: &AttestationData) -> bool {
    is_double_target_vote(left, right)
        || is_conflicting_with_finality_pair(left, &right.finality)
        || is_conflicting_with_finality_pair(right, &left.finality)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(height: Height, byte: u8) -> HeightCheckpoint {
        HeightCheckpoint::new(height, H256([byte; 32]))
    }

    fn input(
        target: HeightCheckpoint,
        justified: HeightCheckpoint,
        h_f: Height,
    ) -> FinalityAttestationInput {
        FinalityAttestationInput {
            target,
            justified,
            finalized_height: h_f,
        }
    }

    #[test]
    fn a_fresh_record_targets_the_source_and_carries_the_finality_pair() {
        let mut record = FinalitySigningRecord::default();
        let data = record.attest(&input(cp(3, 1), cp(2, 9), 1)).unwrap();
        assert_eq!(
            data,
            AttestationData {
                target: cp(3, 1),
                timeout: false,
                finality: cp(2, 9),
            }
        );
        assert_eq!(record.targets.get(&3), Some(&H256([1; 32])));
        assert_eq!(record.finality_locks.get(&2), Some(&H256([9; 32])));
        assert!(record.entries[&3].contains(&H256([1; 32])));
    }

    #[test]
    fn get_finality_vote_follows_the_record() {
        let mut record = FinalitySigningRecord::default();
        // At or below the finalized height: none.
        assert!(record.get_finality_vote(cp(2, 1), 2).is_empty());
        assert_eq!(record.get_finality_vote(cp(2, 1), 1), cp(2, 1));
        // A target vote for another root at that height forbids it.
        record.targets.insert(2, H256([7; 32]));
        assert!(record.get_finality_vote(cp(2, 1), 1).is_empty());
        record.targets.clear();
        // So does a timeout at that height.
        record.timeouts.insert(2);
        assert!(record.get_finality_vote(cp(2, 1), 1).is_empty());
        record.timeouts.clear();
        // And a finality lock on another root.
        record.finality_locks.insert(2, H256([7; 32]));
        assert!(record.get_finality_vote(cp(2, 1), 1).is_empty());
        assert_eq!(record.get_finality_vote(cp(2, 7), 1), cp(2, 7));
    }

    #[test]
    fn get_height_vote_follows_the_table() {
        let mut record = FinalitySigningRecord::default();
        let empty = HeightCheckpoint::empty();
        // No source: none.
        assert_eq!(
            record.get_height_vote(HeightCheckpoint::empty(), empty),
            None
        );
        assert_eq!(record.get_height_vote(cp(3, 0), empty), None);
        // Fresh: target vote.
        assert_eq!(
            record.get_height_vote(cp(3, 1), empty),
            Some((cp(3, 1), false))
        );
        // The candidate finality pair at the same height is a lock.
        assert_eq!(
            record.get_height_vote(cp(3, 1), cp(3, 1)),
            Some((cp(3, 1), false))
        );
        assert_eq!(record.get_height_vote(cp(3, 1), cp(3, 2)), None);
        // A recorded lock elsewhere abstains.
        record.finality_locks.insert(3, H256([2; 32]));
        assert_eq!(record.get_height_vote(cp(3, 1), empty), None);
        record.finality_locks.clear();
        // A recorded target elsewhere times out.
        record.targets.insert(3, H256([2; 32]));
        assert_eq!(
            record.get_height_vote(cp(3, 1), empty),
            Some((cp(3, 1), true))
        );
        assert_eq!(
            record.get_height_vote(cp(3, 2), empty),
            Some((cp(3, 2), false))
        );
        // A timeout at the height repeats, whatever else.
        record.timeouts.insert(3);
        assert_eq!(
            record.get_height_vote(cp(3, 2), empty),
            Some((cp(3, 2), true))
        );
    }

    #[test]
    fn entries_suppress_repeats_and_second_targets() {
        let mut record = FinalitySigningRecord::default();
        let empty = HeightCheckpoint::empty();
        assert!(record.attest(&input(cp(3, 1), empty, 0)).is_some());
        // The same entry again: suppressed, the whole attestation with it,
        // even when it would carry a new finality pair.
        assert_eq!(record.attest(&input(cp(3, 1), cp(2, 5), 1)), None);
        assert!(!record.finality_locks.contains_key(&2));
        // Another entry at the same height times out once...
        let timeout = record.attest(&input(cp(3, 2), empty, 0)).unwrap();
        assert!(timeout.timeout);
        // ...and never again for that entry.
        assert_eq!(record.attest(&input(cp(3, 2), empty, 0)), None);
        // A third entry is a new timeout.
        assert!(record.attest(&input(cp(3, 4), empty, 0)).unwrap().timeout);

        // A second target vote at a height is never cast: after a timeout at
        // height 5 named entry 1, a target vote is impossible, and a timeout
        // naming entry 1 again is suppressed.
        let mut record = FinalitySigningRecord::default();
        record.record_finality_attestation(&AttestationData {
            target: cp(5, 1),
            timeout: true,
            finality: empty,
        });
        assert_eq!(
            record.get_finality_attestation_data(cp(5, 1), empty, 0),
            None
        );
        let mut record = FinalitySigningRecord::default();
        record.entries.entry(6).or_default().insert(H256([3; 32]));
        // With an entry recorded but no target or timeout, a target vote for
        // a new root is still suppressed: entries are non-empty.
        assert_eq!(
            record.get_finality_attestation_data(cp(6, 1), empty, 0),
            None
        );
    }

    #[test]
    fn the_finality_pair_is_dropped_when_not_below_the_target() {
        let record = FinalitySigningRecord::default();
        // Candidate finality pair at the target's height: it locks the height
        // vote, then is removed from the data.
        let data = record
            .get_finality_attestation_data(cp(3, 1), cp(3, 1), 2)
            .unwrap();
        assert_eq!(data.target, cp(3, 1));
        assert!(!data.timeout);
        assert!(data.finality.is_empty());
        // A finality pair above the target is dropped too.
        let data = record
            .get_finality_attestation_data(cp(3, 1), cp(4, 9), 2)
            .unwrap();
        assert!(data.finality.is_empty());
    }

    #[test]
    fn slashing_conditions() {
        let empty = HeightCheckpoint::empty();
        let target = |height, byte, timeout| AttestationData {
            target: cp(height, byte),
            timeout,
            finality: empty,
        };
        assert!(is_double_target_vote(
            &target(3, 1, false),
            &target(3, 2, false)
        ));
        assert!(!is_double_target_vote(
            &target(3, 1, false),
            &target(3, 2, true)
        ));
        assert!(!is_double_target_vote(
            &target(3, 1, false),
            &target(4, 2, false)
        ));
        let with_finality = AttestationData {
            target: cp(4, 9),
            timeout: false,
            finality: cp(3, 1),
        };
        assert!(is_slashable_attestation_data(
            &with_finality,
            &target(3, 2, false)
        ));
        assert!(is_slashable_attestation_data(
            &target(3, 1, true),
            &with_finality
        ));
        assert!(!is_slashable_attestation_data(
            &target(3, 1, false),
            &with_finality
        ));
    }

    #[test]
    fn honest_records_never_produce_slashable_pairs() {
        // Drive one record through many input combinations over a few heights
        // and roots, and check no two emitted attestations are slashable.
        let mut record = FinalitySigningRecord::default();
        let mut emitted = Vec::new();
        for step in 0..600u32 {
            let height = Height::from(step % 4 + 1);
            let root = (step / 4 % 3) as u8 + 1;
            let justified_height = Height::from(step % 3 + 1);
            let justified_root = (step / 3 % 2) as u8 + 1;
            let finalized = justified_height.saturating_sub(1 + Height::from(step % 5 == 0));
            let justified = cp(justified_height, justified_root);
            if let Some(data) = record.attest(&input(cp(height, root), justified, finalized)) {
                emitted.push(data);
            }
        }
        assert!(emitted.len() > 10);
        for a in &emitted {
            for b in &emitted {
                assert!(!is_slashable_attestation_data(a, b), "{a:?} vs {b:?}");
            }
        }
    }
}
