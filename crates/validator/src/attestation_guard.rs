//! An in-process guard against signing two conflicting attestations.
//!
//! # What this is not
//!
//! **This is not slashing protection.** It holds no history on disk, so it
//! knows nothing about what a previous run of this process signed, and nothing
//! about what another process holding the same keys is signing right now. A
//! restart empties it. Its records are gone the moment the process is.
//!
//! This client keeps no signing history by design (see the crate
//! documentation). That decision is not reversed here and this module is not a
//! step toward reversing it: durable slashing protection is a different thing,
//! with a durability requirement this deliberately does not have.
//!
//! # What it is
//!
//! A cheap check that closes the double-vote shapes this client can reach
//! *within one run*, which were otherwise reachable through ordinary
//! operation rather than through operator error:
//!
//! - **A backward wall-clock step.** The duty loop derives its slot from
//!   `SystemTime::now()`, which is not monotonic. An NTP correction of a few
//!   seconds re-enters a slot already attested, and the re-fetched attestation
//!   data can differ if a block arrived in between. Two different attestations
//!   under one target epoch is a double vote.
//! - **A schedule replaced mid-epoch.** A duty refresh that fails at an epoch
//!   boundary and succeeds a few slots later can move a validator to a
//!   different slot in the *same* epoch, and the loop then attests a second
//!   time under that target.
//!
//! Neither needs a hostile beacon node or a second instance. Both are ordinary
//! things that happen to running systems.
//!
//! # The rule
//!
//! EIP-3076's minimal variant, per validator: remember the highest source and
//! target epoch signed, and refuse anything that does not strictly advance the
//! target or that would reach back below the source.
//!
//! That is deliberately more conservative than the full slashing conditions,
//! which would need the whole history to evaluate. With one record per
//! validator it cannot distinguish "surrounds an attestation from six epochs
//! ago" from "surrounds nothing"; requiring monotonic progress makes the
//! question unnecessary. An honest validator's attestations already advance
//! this way, so the conservatism costs nothing in normal operation.
//!
//! Refusing is always safe here: a skipped attestation is a missed reward, and
//! a double vote is a slashing.

use std::collections::HashMap;

use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch};

/// The highest source and target epoch signed for one validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Signed {
    source: Epoch,
    target: Epoch,
}

/// Why an attestation was refused.
///
/// Carried out of [`AttestationGuard::check`] so the caller can log which rule
/// fired rather than a bare "refused". The two are different operational
/// situations: a repeated target usually means the clock moved or a schedule
/// was replaced, while a regressed source means something stranger and is
/// worth looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The target epoch is at or below one already signed for this validator.
    ///
    /// The double-vote shape. Equality is refused as well as regression: the
    /// same target signed twice is a double vote unless the two attestations
    /// are byte-identical, and this guard deliberately does not keep enough to
    /// tell those apart. Re-signing identical data would be harmless but is
    /// also pointless, since the client does not retry within a slot.
    TargetNotAdvanced { signed: Epoch, proposed: Epoch },
    /// The source epoch is below one already signed for this validator.
    ///
    /// The surround shape: a lower source with a higher target surrounds the
    /// earlier attestation.
    SourceRegressed { signed: Epoch, proposed: Epoch },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetNotAdvanced { signed, proposed } => write!(
                f,
                "target epoch {proposed} does not advance past {signed}, already signed this run"
            ),
            Self::SourceRegressed { signed, proposed } => write!(
                f,
                "source epoch {proposed} is below {signed}, already signed this run"
            ),
        }
    }
}

/// Per-validator record of the highest attestation signed in this run.
///
/// Not `Clone`: one guard per process is the point. A copy would be a second
/// opinion about what has been signed, which is worse than no opinion.
#[derive(Debug, Default)]
pub struct AttestationGuard {
    signed: HashMap<BlsPubkey, Signed>,
}

impl AttestationGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `data` may be signed for `pubkey`, without recording anything.
    ///
    /// Separate from [`Self::record`] so a caller can decide before paying for
    /// a signature, and so this stays a pure function over the guard's state
    /// and therefore directly testable.
    pub fn check(&self, pubkey: &BlsPubkey, data: &AttestationData) -> Result<(), Refusal> {
        let Some(signed) = self.signed.get(pubkey) else {
            // Nothing signed for this validator this run. Note what this does
            // *not* mean: a previous run may have signed anything at all. That
            // gap is the crate-level scope decision, not an oversight here.
            return Ok(());
        };

        if data.target.epoch <= signed.target {
            return Err(Refusal::TargetNotAdvanced {
                signed: signed.target,
                proposed: data.target.epoch,
            });
        }
        if data.source.epoch < signed.source {
            return Err(Refusal::SourceRegressed {
                signed: signed.source,
                proposed: data.source.epoch,
            });
        }
        Ok(())
    }

    /// Record that `data` was signed for `pubkey`.
    ///
    /// Takes the maximum of each epoch rather than overwriting, so that a
    /// caller recording out of order cannot lower the bar. Nothing does that
    /// today; the guard is cheap to make order-independent and expensive to
    /// debug if it ever is not.
    pub fn record(&mut self, pubkey: BlsPubkey, data: &AttestationData) {
        let entry = self.signed.entry(pubkey).or_insert(Signed {
            source: data.source.epoch,
            target: data.target.epoch,
        });
        entry.source = entry.source.max(data.source.epoch);
        entry.target = entry.target.max(data.target.epoch);
    }

    /// Check and record in one step, for the common call site.
    ///
    /// Recording only on success is what makes a refusal idempotent: a
    /// refused attestation must not move the bar it was measured against.
    pub fn check_and_record(
        &mut self,
        pubkey: &BlsPubkey,
        data: &AttestationData,
    ) -> Result<(), Refusal> {
        self.check(pubkey, data)?;
        self.record(*pubkey, data);
        Ok(())
    }

    /// How many validators have signed something this run. For metrics.
    pub fn len(&self) -> usize {
        self.signed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signed.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::containers::shared::Checkpoint;
    use ethlambda_types::beacon::primitives::{H256, Root};

    use super::*;

    fn pubkey(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    /// An attestation at `slot` voting source `source` and target `target`.
    ///
    /// `beacon_block_root` is a parameter because the double-vote case that
    /// matters most is two attestations with one target epoch and *different*
    /// roots, which is what a re-fetch after a block arrival produces.
    fn data(slot: u64, source: Epoch, target: Epoch, root: u8) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: H256([root; 32]),
            source: Checkpoint {
                epoch: source,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: target,
                root: Root::ZERO,
            },
        }
    }

    #[test]
    fn a_first_attestation_is_allowed() {
        let mut guard = AttestationGuard::new();
        assert!(
            guard
                .check_and_record(&pubkey(1), &data(96, 2, 3, 0xaa))
                .is_ok()
        );
    }

    #[test]
    fn advancing_the_target_is_allowed() {
        let mut guard = AttestationGuard::new();
        guard
            .check_and_record(&pubkey(1), &data(96, 2, 3, 0xaa))
            .expect("first");

        assert!(
            guard
                .check_and_record(&pubkey(1), &data(128, 3, 4, 0xbb))
                .is_ok()
        );
    }

    /// The backward-clock-step case. Same validator, same target epoch, a
    /// different block root because the data was re-fetched after a block
    /// arrived. This is the double vote the guard exists to stop.
    #[test]
    fn re_attesting_one_target_with_different_data_is_refused() {
        let mut guard = AttestationGuard::new();
        guard
            .check_and_record(&pubkey(1), &data(96, 2, 3, 0xaa))
            .expect("first");

        let err = guard
            .check_and_record(&pubkey(1), &data(96, 2, 3, 0xbb))
            .expect_err("a second vote for one target must be refused");

        assert_eq!(
            err,
            Refusal::TargetNotAdvanced {
                signed: 3,
                proposed: 3
            }
        );
    }

    /// The mid-epoch schedule replacement case: a different *slot* in the same
    /// epoch, which is still one target epoch and still a double vote.
    #[test]
    fn a_different_slot_in_the_same_target_epoch_is_refused() {
        let mut guard = AttestationGuard::new();
        guard
            .check_and_record(&pubkey(1), &data(96, 2, 3, 0xaa))
            .expect("first");

        assert!(
            guard
                .check_and_record(&pubkey(1), &data(101, 2, 3, 0xbb))
                .is_err(),
            "a second slot under one target epoch is a double vote"
        );
    }

    #[test]
    fn a_regressed_target_is_refused() {
        let mut guard = AttestationGuard::new();
        guard
            .check_and_record(&pubkey(1), &data(128, 3, 4, 0xaa))
            .expect("first");

        assert!(
            guard
                .check_and_record(&pubkey(1), &data(96, 2, 3, 0xbb))
                .is_err()
        );
    }

    /// The surround shape: a later target with an earlier source surrounds the
    /// attestation already signed.
    #[test]
    fn a_regressed_source_under_an_advancing_target_is_refused() {
        let mut guard = AttestationGuard::new();
        guard
            .check_and_record(&pubkey(1), &data(128, 3, 4, 0xaa))
            .expect("first");

        let err = guard
            .check_and_record(&pubkey(1), &data(160, 1, 5, 0xbb))
            .expect_err("a surrounding vote must be refused");

        assert_eq!(
            err,
            Refusal::SourceRegressed {
                signed: 3,
                proposed: 1
            }
        );
    }

    /// The property that makes this per-validator rather than per-slot: two
    /// validators in one epoch attest at different slots, and the second must
    /// not be blocked by the first.
    #[test]
    fn one_validator_does_not_block_another_in_the_same_epoch() {
        let mut guard = AttestationGuard::new();
        guard
            .check_and_record(&pubkey(1), &data(96, 2, 3, 0xaa))
            .expect("first validator");

        assert!(
            guard
                .check_and_record(&pubkey(2), &data(101, 2, 3, 0xaa))
                .is_ok(),
            "a second validator attesting later in the same epoch must be allowed"
        );
    }

    /// A refusal must not move the bar, or one refused attestation would
    /// change what the next check compares against.
    #[test]
    fn a_refusal_records_nothing() {
        let mut guard = AttestationGuard::new();
        guard
            .check_and_record(&pubkey(1), &data(128, 3, 4, 0xaa))
            .expect("first");

        guard
            .check_and_record(&pubkey(1), &data(160, 1, 5, 0xbb))
            .expect_err("surround refused");

        // The recorded source must still be 3, not 1: a valid attestation
        // advancing from the real record is still accepted.
        assert!(
            guard
                .check_and_record(&pubkey(1), &data(160, 3, 5, 0xcc))
                .is_ok(),
            "the refused attempt must not have lowered the recorded source"
        );
    }

    #[test]
    fn check_alone_does_not_record() {
        let guard = AttestationGuard::new();
        let data = data(96, 2, 3, 0xaa);

        guard.check(&pubkey(1), &data).expect("allowed");
        guard
            .check(&pubkey(1), &data)
            .expect("still allowed, because check records nothing");
    }

    #[test]
    fn recording_out_of_order_does_not_lower_the_bar() {
        let mut guard = AttestationGuard::new();
        guard.record(pubkey(1), &data(128, 3, 4, 0xaa));
        guard.record(pubkey(1), &data(96, 2, 3, 0xbb));

        assert!(
            guard.check(&pubkey(1), &data(101, 2, 3, 0xcc)).is_err(),
            "the earlier record must not have displaced the later one"
        );
    }
}
