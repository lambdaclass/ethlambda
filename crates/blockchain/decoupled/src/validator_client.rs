//! The validator client's anti-slashing record Λ and the attestation rules
//! that read it (PROTOCOL.md §1.2, figure `alg:attn-full`, appendix A.10).
//!
//! This is the hardened, store-free half of the attestation duty: it takes the
//! vote information the node derived from its store ([`AttestationInput`]),
//! decides the height and finality pairs, records the attestation, and only
//! then releases it. `record_attestation` is the only writer of the record.
//! A validator that follows these rules never produces E1 or E2 evidence
//! (the formalization's `voteSafetyOfClients`).

use std::collections::{BTreeMap, BTreeSet};

use ethlambda_types::primitives::H256;
use serde::{Deserialize, Serialize};

use crate::types::{
    Attestation, AttestationData, FinalityVote, Height, HeightVote, Round, ValidatorIndex,
};

/// What the node's store hands the validator client at the attestation time
/// `a_r` (`attest()` in §2.3): the safe block, the height fields of the
/// FG source (or `None` when there is no fresh grade-2 quorum), and the
/// finality fields of the fork-choice head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationInput {
    pub round: Round,
    /// `C_sg`, from `get_sg_vote`.
    pub safe: H256,
    /// `(h_c, T_c, ν)` from `get_fg_vote`: the source's height, its height
    /// entry, and its nonjustifiable flag.
    pub source: Option<SourceFields>,
    /// `(h_j, J, h_F)` from the head's chain state.
    pub justified_height: Height,
    pub justified: H256,
    pub finalized_height: Height,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFields {
    pub height: Height,
    pub entry: H256,
    pub nonjustifiable: bool,
}

/// The anti-slashing record Λ = `(target[·], timeout[·], lock[·], timeouts)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// `target[h]`: the validator's first target at height `h`.
    pub target: BTreeMap<Height, H256>,
    /// `timeout[h]`: whether it emitted a timeout at height `h`.
    pub timeout: BTreeSet<Height>,
    /// `lock[h]`: the target of its first finality pair at height `h`.
    pub lock: BTreeMap<Height, H256>,
    /// `timeouts`: the `(h, T)` entries its timeouts have named.
    pub timeouts: BTreeSet<(Height, H256)>,
}

impl Record {
    /// `finality_pair(Λ, h_j, J, h_F)`.
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

    /// `height_pair(Λ, h_c, T_c, ν, h_f, T_f)`.
    ///
    /// ```text
    /// timeout[h_c]  lock           target[h_c]       ν      result
    /// true          —              —                 —      timeout at h_c
    /// false         = T_c          —                 —      target (h_c, T_c)
    /// false         ≠ ⊥, ≠ T_c     —                 —      empty: wait out the height
    /// false         ⊥              = T_c             —      target (h_c, T_c)
    /// false         ⊥              ≠ ⊥, ≠ T_c        —      timeout at h_c
    /// false         ⊥              ⊥                 false  target (h_c, T_c)
    /// false         ⊥              ⊥                 true   timeout at h_c
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
        let height = source.height;
        let entry = source.entry;
        let target = HeightVote {
            height,
            entry,
            timeout: false,
        };
        let timeout = HeightVote {
            height,
            entry,
            timeout: true,
        };
        if self.timeout.contains(&height) {
            // A timeout repeats, naming the current entry.
            return Some(timeout);
        }
        let lock = match finality {
            Some(pair) if pair.height == height => Some(pair.target),
            _ => self.lock.get(&height).copied(),
        };
        if let Some(lock) = lock {
            return (lock == entry).then_some(target);
        }
        match self.target.get(&height) {
            Some(&recorded) if recorded == entry => Some(target),
            Some(_) => Some(timeout),
            None if !source.nonjustifiable => Some(target),
            None => Some(timeout),
        }
    }

    /// `record_attestation(Λ, a)`: the only writer of the record.
    pub fn record(&mut self, data: &AttestationData) {
        if let Some(pair) = data.finality_pair() {
            self.lock.insert(pair.height, pair.target);
        }
        if let Some(vote) = data.height_pair() {
            if vote.timeout {
                self.timeout.insert(vote.height);
                self.timeouts.insert((vote.height, vote.entry));
            } else {
                self.target.entry(vote.height).or_insert(vote.entry);
            }
        }
    }

    /// `create_attestation(Λ, r, safe, h_c, T_c, ν, h_j, J, h_F)`: decide the
    /// pairs, record, then release.
    pub fn create_attestation(
        &mut self,
        validator: ValidatorIndex,
        input: &AttestationInput,
    ) -> Attestation {
        let finality = self.finality_pair(
            input.justified_height,
            input.justified,
            input.finalized_height,
        );
        let height = self.height_pair(input.source, finality);
        let data = AttestationData::new(input.round, Some(input.safe), height, finality);
        self.record(&data);
        Attestation { validator, data }
    }

    /// Drop entries below `height`. Heights at or below the finalized height
    /// can never be voted again, so the record does not need them.
    pub fn prune_below(&mut self, height: Height) {
        self.target = self.target.split_off(&height);
        self.lock = self.lock.split_off(&height);
        self.timeout = self.timeout.split_off(&height);
        self.timeouts = self.timeouts.split_off(&(height, H256::ZERO));
    }
}

/// E1: one finality pair `(h, T)` and, at the same height, a timeout or a
/// target vote for another entry. The two occurrences may be one attestation.
pub fn e1(left: &AttestationData, right: &AttestationData) -> bool {
    let conflicts =
        |finality: Option<FinalityVote>, height: Option<HeightVote>| match (finality, height) {
            (Some(pair), Some(vote)) => {
                vote.height == pair.height && (vote.timeout || vote.entry != pair.target)
            }
            _ => false,
        };
    conflicts(left.finality_pair(), right.height_pair())
        || conflicts(right.finality_pair(), left.height_pair())
}

/// E2: two target votes at one height naming different entries. A timeout is
/// never an E2 occurrence.
pub fn e2(left: &AttestationData, right: &AttestationData) -> bool {
    match (left.height_pair(), right.height_pair()) {
        (Some(a), Some(b)) => {
            !a.timeout && !b.timeout && a.height == b.height && a.entry != b.entry
        }
        _ => false,
    }
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
        source: Option<(Height, u8, bool)>,
        justified: (Height, u8),
        h_f: Height,
    ) -> AttestationInput {
        AttestationInput {
            round: 1,
            safe: root(0xaa),
            source: source.map(|(height, entry, nj)| SourceFields {
                height,
                entry: root(entry),
                nonjustifiable: nj,
            }),
            justified_height: justified.0,
            justified: root(justified.1),
            finalized_height: h_f,
        }
    }

    #[test]
    fn a_fresh_record_targets_the_chains_entry() {
        let mut record = Record::default();
        let att = record.create_attestation(7, &input(Some((3, 1, false)), (2, 9), 1));
        assert_eq!(
            att.data.height_pair(),
            Some(HeightVote {
                height: 3,
                entry: root(1),
                timeout: false
            })
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
    fn a_different_entry_at_a_voted_height_times_out() {
        let mut record = Record::default();
        record.create_attestation(0, &input(Some((3, 1, false)), (0, 0), 0));
        let att = record.create_attestation(0, &input(Some((3, 2, false)), (0, 0), 0));
        assert!(att.data.height_pair().unwrap().timeout);
        // Once timed out, the height stays timed out.
        let again = record.create_attestation(0, &input(Some((3, 1, false)), (0, 0), 0));
        assert!(again.data.height_pair().unwrap().timeout);
    }

    #[test]
    fn a_lock_elsewhere_abstains() {
        let mut record = Record::default();
        // Finality pair locks height 3 on entry 1.
        record.create_attestation(0, &input(None, (3, 1), 2));
        let att = record.create_attestation(0, &input(Some((3, 2, false)), (0, 0), 0));
        assert_eq!(att.data.height_pair(), None);
    }

    #[test]
    fn a_timeout_blocks_the_finality_pair() {
        let mut record = Record::default();
        record.create_attestation(0, &input(Some((3, 1, true)), (0, 0), 0));
        assert!(record.timeout.contains(&3));
        assert_eq!(record.finality_pair(3, root(1), 2), None);
    }

    #[test]
    fn honest_records_never_produce_evidence() {
        // Drive one record through every combination of inputs over a few
        // heights and entries and check no two emitted attestations are
        // slashable, nor any single one with itself.
        let mut record = Record::default();
        let mut emitted = Vec::new();
        for step in 0..400u32 {
            let h = Height::from(step % 4 + 1);
            let entry = (step / 4 % 3) as u8;
            let nj = step % 7 == 0;
            let jh = Height::from(step % 3 + 1);
            let j = (step / 3 % 2) as u8;
            let source = (step % 5 != 0).then_some((h, entry, nj));
            let att = record.create_attestation(0, &input(source, (jh, j), jh - 1));
            emitted.push(att);
        }
        for a in &emitted {
            for b in &emitted {
                assert!(!slashable(a, b), "{a:?} vs {b:?}");
            }
        }
    }
}
