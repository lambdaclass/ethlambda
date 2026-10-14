//! The validator client's anti-slashing record Λ and the attestation rules
//! that read it (the specification's figure 4).
//!
//! This is the hardened, store-free half of the attestation duty: it takes the
//! vote information the node derived from its store ([`AttestationInput`]),
//! decides the height and finality pairs, records the attestation, and only
//! then releases it. `record_attestation` is the only writer of the record.
//! A validator that follows these rules never produces E1 or E2 evidence.
//!
//! The client sends an attestation only with a height pair. It sends a
//! target at a height only as its first vote at that height, and it names
//! each entry at most once at a height, so a validator whose chain makes no
//! height progress stops attesting by itself. It attaches the finality pair
//! only when the pair is below the height of the height pair.

use std::collections::{BTreeMap, BTreeSet};

use ethlambda_types::primitives::H256;
use serde::{Deserialize, Serialize};

use crate::types::{
    Attestation, AttestationData, FinalityVote, Height, HeightVote, Slot, ValidatorIndex,
};

/// What the node's store hands the validator client at the FG action `a_r`:
/// the height fields of the source's state (or `None` when the AC has no
/// source), and the finality fields of the head's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationInput {
    /// The slot of the action time this input is for. Not part of the
    /// attestation: it lets a validator client check that a node answered
    /// for the slot it asked about.
    pub slot: Slot,
    /// `(h_c, T_c)` from the source's state: its height and the height's
    /// entry.
    pub source: Option<SourceFields>,
    /// `(h_j, J, h_F)` from the head's chain state.
    pub justified_height: Height,
    pub justified: H256,
    pub finalized_height: Height,
}

/// `(σ[source].h, σ[source].T_h)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFields {
    pub height: Height,
    pub entry: H256,
}

/// The anti-slashing record Λ = `(target[·], timeout[·], lock[·], sent)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// `target[h]`: the validator's first target at height `h`.
    pub target: BTreeMap<Height, H256>,
    /// `timeout[h]`: whether it sent a timeout at height `h`.
    pub timeout: BTreeSet<Height>,
    /// `lock[h]`: the target of its first finality pair at height `h`.
    pub lock: BTreeMap<Height, H256>,
    /// `sent`: the contents (height pair and finality pair) of the
    /// attestations it sent.
    #[serde(default)]
    pub sent: BTreeSet<(HeightVote, Option<FinalityVote>)>,
}

impl Record {
    /// `finality_pair(Λ, h_j, J, h_F)`: a justification not yet finalized,
    /// when the record allows it.
    pub fn finality_pair(
        &self,
        justified_height: Height,
        justified: H256,
        finalized_height: Height,
    ) -> Option<FinalityVote> {
        if justified_height <= finalized_height {
            return None;
        }
        let target_allows = self
            .target
            .get(&justified_height)
            .is_none_or(|&target| target == justified);
        let lock_allows = self
            .lock
            .get(&justified_height)
            .is_none_or(|&lock| lock == justified);
        let no_timeout = !self.timeout.contains(&justified_height);
        (target_allows && no_timeout && lock_allows).then_some(FinalityVote {
            height: justified_height,
            target: justified,
        })
    }

    /// `height_pair(Λ, h_c, T_c, h_f, T_f)`.
    ///
    /// ```text
    /// timeout[h_c]  lock           target[h_c]       result
    /// true          —              —                 timeout at h_c
    /// false         = T_c          —                 target (h_c, T_c)
    /// false         ≠ ⊥, ≠ T_c     —                 none: wait out the height
    /// false         ⊥              ⊥ or T_c          target (h_c, T_c)
    /// false         ⊥              another entry     timeout at h_c
    /// ```
    ///
    /// The lock at `h_c` is this attestation's own finality pair when the two
    /// heights agree, so one attestation never forms E1 evidence.
    pub fn height_pair(
        &self,
        source: Option<SourceFields>,
        finality: Option<FinalityVote>,
    ) -> Option<HeightVote> {
        let source = source?;
        let (height, entry) = (source.height, source.entry);
        let vote = |timeout| HeightVote {
            height,
            entry,
            timeout,
        };
        let lock = match finality {
            Some(pair) if pair.height == height => Some(pair.target),
            _ => self.lock.get(&height).copied(),
        };
        if self.timeout.contains(&height) {
            return Some(vote(true));
        }
        if let Some(lock) = lock {
            return (lock == entry).then(|| vote(false));
        }
        match self.target.get(&height) {
            None => Some(vote(false)),
            Some(&recorded) if recorded == entry => Some(vote(false)),
            Some(_) => Some(vote(true)),
        }
    }

    /// `create_attestation(Λ, h_c, T_c, h_j, J, h_F)`: decide the pairs,
    /// record, then release. `None` without a height pair, or when the height
    /// pair would repeat: a target only as the first vote at its height, and
    /// no entry twice at a height.
    pub fn create_attestation(
        &mut self,
        validator: ValidatorIndex,
        input: &AttestationInput,
    ) -> Option<Attestation> {
        let finality = self.finality_pair(
            input.justified_height,
            input.justified,
            input.finalized_height,
        );
        let height = self.height_pair(input.source, finality)?;
        let repeats = self.sent.iter().any(|(sent, _)| {
            sent.height == height.height && (!height.timeout || sent.entry == height.entry)
        });
        if repeats {
            return None;
        }
        let finality = finality.filter(|pair| pair.height < height.height);
        let data = AttestationData::new(height, finality);
        self.record(&data);
        Some(Attestation { validator, data })
    }

    /// `record_attestation(Λ, a)`: the only writer of the record.
    pub fn record(&mut self, data: &AttestationData) {
        let height = data.height_pair();
        let finality = data.finality_pair();
        self.sent.insert((height, finality));
        if let Some(pair) = finality {
            self.lock.insert(pair.height, pair.target);
        }
        if height.timeout {
            self.timeout.insert(height.height);
        } else {
            self.target.entry(height.height).or_insert(height.entry);
        }
    }

    /// Drop entries below `height`. Heights at or below the finalized height
    /// can never be voted again, so the record does not need them.
    pub fn prune_below(&mut self, height: Height) {
        self.target = self.target.split_off(&height);
        self.lock = self.lock.split_off(&height);
        self.timeout = self.timeout.split_off(&height);
        self.sent.retain(|(vote, _)| vote.height >= height);
    }
}

/// E1: one finality pair `(h, T)` and, at the same height, a timeout or a
/// target vote for another entry. The two occurrences may be one attestation.
pub fn e1(left: &AttestationData, right: &AttestationData) -> bool {
    let conflicts = |finality: Option<FinalityVote>, vote: HeightVote| {
        finality.is_some_and(|pair| {
            vote.height == pair.height && (vote.timeout || vote.entry != pair.target)
        })
    };
    conflicts(left.finality_pair(), right.height_pair())
        || conflicts(right.finality_pair(), left.height_pair())
}

/// E2: two target votes at one height naming different entries. A timeout is
/// never an E2 occurrence.
pub fn e2(left: &AttestationData, right: &AttestationData) -> bool {
    let (a, b) = (left.height_pair(), right.height_pair());
    !a.timeout && !b.timeout && a.height == b.height && a.entry != b.entry
}

/// Two attestations by one signer are slashable under E1 or E2.
pub fn slashable(left: &Attestation, right: &Attestation) -> bool {
    left.validator == right.validator
        && (e1(&left.data, &right.data) || e2(&left.data, &right.data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(byte: u8) -> H256 {
        H256([byte; 32])
    }

    fn input(
        source: Option<(Height, u8)>,
        justified: (Height, u8),
        h_f: Height,
    ) -> AttestationInput {
        AttestationInput {
            slot: 0,
            source: source.map(|(height, entry)| SourceFields {
                height,
                entry: root(entry),
            }),
            justified_height: justified.0,
            justified: root(justified.1),
            finalized_height: h_f,
        }
    }

    #[test]
    fn a_fresh_record_targets_the_chains_entry() {
        let mut record = Record::default();
        let att = record
            .create_attestation(7, &input(Some((3, 1)), (2, 9), 1))
            .expect("a first attestation");
        assert_eq!(
            att.data.height_pair(),
            HeightVote {
                height: 3,
                entry: root(1),
                timeout: false
            }
        );
        assert_eq!(
            att.data.finality_pair(),
            Some(FinalityVote {
                height: 2,
                target: root(9)
            })
        );
        assert_eq!(record.target.get(&3), Some(&root(1)));
        assert_eq!(record.lock.get(&2), Some(&root(9)));
    }

    #[test]
    fn a_height_is_targeted_once() {
        let mut record = Record::default();
        let first = input(Some((3, 1)), (2, 9), 1);
        assert!(record.create_attestation(0, &first).is_some());
        assert!(record.create_attestation(0, &first).is_none());
        // A new justification alone is not a reason to attest again at the
        // same height: the finality pair rides on the next height pair.
        let next = input(Some((3, 1)), (3, 1), 2);
        assert!(record.create_attestation(0, &next).is_none());
        let higher = input(Some((4, 2)), (3, 1), 2);
        let att = record.create_attestation(0, &higher).expect("a new height");
        assert_eq!(att.data.finality_pair().map(|p| p.height), Some(3));
    }

    #[test]
    fn no_source_means_no_attestation() {
        let mut record = Record::default();
        assert!(
            record
                .create_attestation(0, &input(None, (2, 9), 1))
                .is_none()
        );
        assert_eq!(record, Record::default());
    }

    #[test]
    fn the_finality_pair_is_dropped_unless_below_the_height_pair() {
        let mut record = Record::default();
        // Source at height 3, justification at height 3 naming the same
        // block: the target stands, the finality pair is dropped.
        let att = record
            .create_attestation(0, &input(Some((3, 1)), (3, 1), 2))
            .expect("a target");
        assert!(!att.data.height_pair().timeout);
        assert_eq!(att.data.finality_pair(), None);
        assert!(att.data.is_well_formed());
    }

    #[test]
    fn a_different_entry_at_a_voted_height_times_out_once() {
        let mut record = Record::default();
        record.create_attestation(0, &input(Some((3, 1)), (0, 0), 0));
        let att = record
            .create_attestation(0, &input(Some((3, 2)), (0, 0), 0))
            .expect("a reorg to another entry times out");
        assert!(att.data.height_pair().timeout);
        // Once timed out, the height stays timed out, and each entry is
        // named once: entry 1 by the target, entry 2 by the timeout.
        for entry in [2, 1] {
            assert!(
                record
                    .create_attestation(0, &input(Some((3, entry)), (0, 0), 0))
                    .is_none()
            );
        }
        let third = record
            .create_attestation(0, &input(Some((3, 3)), (0, 0), 0))
            .expect("a timeout naming a third entry is new");
        assert!(third.data.height_pair().timeout);
    }

    #[test]
    fn a_lock_elsewhere_abstains() {
        let mut record = Record::default();
        // A finality pair locks height 3 on entry 1.
        record
            .create_attestation(0, &input(Some((4, 5)), (3, 1), 2))
            .expect("a target with a finality pair");
        assert_eq!(record.lock.get(&3), Some(&root(1)));
        assert!(
            record
                .create_attestation(0, &input(Some((3, 2)), (0, 0), 0))
                .is_none()
        );
    }

    #[test]
    fn a_timeout_blocks_the_finality_pair() {
        let mut record = Record::default();
        record.create_attestation(0, &input(Some((3, 1)), (0, 0), 0));
        record.create_attestation(0, &input(Some((3, 2)), (0, 0), 0));
        assert!(record.timeout.contains(&3));
        assert_eq!(record.finality_pair(3, root(1), 2), None);
    }

    #[test]
    fn honest_records_never_produce_evidence() {
        // Drive one record through every combination of inputs over a few
        // heights and entries and check no two emitted attestations are
        // slashable, nor any single one with itself, and every one is well
        // formed.
        let mut record = Record::default();
        let mut emitted = Vec::new();
        for step in 0..400u32 {
            let h = Height::from(step % 4 + 1);
            let entry = (step / 4 % 3) as u8;
            let jh = Height::from(step % 3 + 1);
            let j = (step / 3 % 2) as u8;
            let source = (step % 5 != 0).then_some((h, entry));
            emitted.extend(record.create_attestation(0, &input(source, (jh, j), jh - 1)));
        }
        assert!(!emitted.is_empty());
        for a in &emitted {
            assert!(a.data.is_well_formed(), "{a:?}");
            for b in &emitted {
                assert!(!slashable(a, b), "{a:?} vs {b:?}");
            }
        }
    }
}
