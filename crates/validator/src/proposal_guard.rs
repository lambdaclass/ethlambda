//! An in-process guard against signing two blocks for one slot.
//!
//! The proposal-shaped counterpart to [`crate::attestation_guard`], and the
//! same disclaimer applies in full: **this is not slashing protection.** It
//! holds nothing on disk, so it knows nothing about a previous run of this
//! process or about another process holding the same keys. A restart empties
//! it.
//!
//! # Why it is a separate guard rather than a field on the other one
//!
//! The two answer different questions and would answer them badly if merged.
//! An attestation is judged on its source and target *epochs*; a block is
//! judged on its *slot*, and a validator can legitimately propose in an epoch
//! it also attests in. Keying both off one record would either refuse a legal
//! proposal or admit an illegal one, depending on which field won.
//!
//! # The rule
//!
//! EIP-3076's minimal variant for blocks, per validator: remember the highest
//! slot proposed, and refuse anything that does not strictly advance it.
//!
//! One record per validator, like the attestation guard, and for the same
//! reason: the full condition ("never two distinct blocks for one slot") needs
//! the whole history to evaluate, while "the slot must strictly advance" needs
//! one number and is strictly more conservative. An honest proposer's blocks
//! already advance this way, since a validator is assigned at most one slot per
//! epoch and epochs only move forward.
//!
//! # What it actually closes
//!
//! The same two shapes the attestation guard closes, reached the same ways:
//!
//! - **A backward wall-clock step.** The duty loop takes its slot from
//!   `SystemTime::now()`, which is not monotonic. An NTP correction can
//!   re-enter a slot already proposed, and the block produced the second time
//!   will differ from the first, because the beacon node has since seen more
//!   attestations and a different head. Two distinct blocks for one slot from
//!   one validator is a slashable proposer offence, and unlike a double vote it
//!   needs no second validator to be caught: the two signed headers are the
//!   whole evidence.
//! - **A proposer schedule replaced mid-epoch.** Proposer duties are only
//!   final once the epoch's randao is fixed, so a refresh that lands late can
//!   move a validator between slots within the epoch. Acting on both is two
//!   blocks from one key.
//!
//! Refusing is always safe here, and cheaper than it is for an attestation: a
//! skipped proposal costs one block reward, and a proposer slashing is the most
//! expensive thing a validator can do.

use std::collections::HashMap;

use ethlambda_types::beacon::primitives::{BlsPubkey, Slot};

/// Why a proposal was refused.
///
/// One variant, unlike [`crate::attestation_guard::Refusal`]'s two, because
/// there is only one rule to break. It stays an enum rather than a struct so
/// that the call site's `match`/`Display` shape matches the attestation path's,
/// and so a second rule can be added without changing the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The slot is at or below one already proposed for this validator.
    ///
    /// Equality is refused as well as regression. The same slot proposed twice
    /// is a slashable offence unless the two blocks are byte-identical, and
    /// this guard deliberately does not keep enough to tell those apart. Nor
    /// would it help: a block re-produced for the same slot is almost never
    /// identical, since the beacon node packs whatever attestations have
    /// arrived since.
    SlotNotAdvanced { signed: Slot, proposed: Slot },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SlotNotAdvanced { signed, proposed } => write!(
                f,
                "slot {proposed} does not advance past {signed}, already proposed this run"
            ),
        }
    }
}

/// Per-validator record of the highest slot proposed in this run.
///
/// Not `Clone`, for the reason [`crate::attestation_guard::AttestationGuard`]
/// is not: one guard per process is the point, and a copy would be a second
/// opinion about what has been signed.
#[derive(Debug, Default)]
pub struct ProposalGuard {
    proposed: HashMap<BlsPubkey, Slot>,
}

impl ProposalGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a block for `slot` may be signed for `pubkey`, recording
    /// nothing.
    ///
    /// Separate from [`Self::record`] so a caller can decide before paying for
    /// a block production round trip, which is far more expensive than the
    /// attestation equivalent: it costs the beacon node an execution-layer
    /// payload build.
    pub fn check(&self, pubkey: &BlsPubkey, slot: Slot) -> Result<(), Refusal> {
        let Some(&signed) = self.proposed.get(pubkey) else {
            // Nothing proposed for this validator this run. As with the
            // attestation guard, that says nothing about previous runs; the
            // gap is the crate-level scope decision, not an oversight here.
            return Ok(());
        };

        if slot <= signed {
            return Err(Refusal::SlotNotAdvanced {
                signed,
                proposed: slot,
            });
        }
        Ok(())
    }

    /// Record that a block for `slot` was signed for `pubkey`.
    ///
    /// Takes the maximum rather than overwriting, so a caller recording out of
    /// order cannot lower the bar. Nothing does that today; making it
    /// order-independent is one `max` and removes a class of bug that would
    /// only ever appear under a clock step, which is the exact situation the
    /// guard exists for.
    pub fn record(&mut self, pubkey: BlsPubkey, slot: Slot) {
        let entry = self.proposed.entry(pubkey).or_insert(slot);
        *entry = (*entry).max(slot);
    }

    /// Check and record in one step, for the common call site.
    ///
    /// Recording only on success is what makes a refusal idempotent: a refused
    /// proposal must not move the bar it was measured against.
    pub fn check_and_record(&mut self, pubkey: &BlsPubkey, slot: Slot) -> Result<(), Refusal> {
        self.check(pubkey, slot)?;
        self.record(*pubkey, slot);
        Ok(())
    }

    /// How many validators have proposed something this run. For metrics.
    pub fn len(&self) -> usize {
        self.proposed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proposed.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    #[test]
    fn a_first_proposal_is_allowed() {
        let mut guard = ProposalGuard::new();
        assert!(guard.check_and_record(&pubkey(1), 96).is_ok());
    }

    #[test]
    fn advancing_the_slot_is_allowed() {
        let mut guard = ProposalGuard::new();
        guard.check_and_record(&pubkey(1), 96).expect("first");
        assert!(guard.check_and_record(&pubkey(1), 128).is_ok());
    }

    /// The backward-clock-step case: the same slot re-entered after an NTP
    /// correction. The block produced the second time is a different block,
    /// because the beacon node has packed whatever arrived in between, so this
    /// is the proposer slashing the guard exists to stop.
    #[test]
    fn proposing_the_same_slot_twice_is_refused() {
        let mut guard = ProposalGuard::new();
        guard.check_and_record(&pubkey(1), 96).expect("first");

        let err = guard
            .check_and_record(&pubkey(1), 96)
            .expect_err("a second block for one slot must be refused");

        assert_eq!(
            err,
            Refusal::SlotNotAdvanced {
                signed: 96,
                proposed: 96
            }
        );
    }

    #[test]
    fn a_regressed_slot_is_refused() {
        let mut guard = ProposalGuard::new();
        guard.check_and_record(&pubkey(1), 128).expect("first");
        assert!(guard.check_and_record(&pubkey(1), 96).is_err());
    }

    /// The property that makes this per-validator rather than global: two of
    /// this client's validators can be assigned different slots in one epoch,
    /// and the second must not be blocked by the first.
    #[test]
    fn one_validator_does_not_block_another() {
        let mut guard = ProposalGuard::new();
        guard
            .check_and_record(&pubkey(1), 128)
            .expect("first validator");

        assert!(
            guard.check_and_record(&pubkey(2), 96).is_ok(),
            "a second validator proposing an earlier slot must be allowed"
        );
    }

    #[test]
    fn a_refusal_records_nothing() {
        let mut guard = ProposalGuard::new();
        guard.check_and_record(&pubkey(1), 128).expect("first");
        guard
            .check_and_record(&pubkey(1), 96)
            .expect_err("regression refused");

        // Still measured against 128, not against the refused 96: a proposal
        // at 100 must still be refused.
        assert!(
            guard.check_and_record(&pubkey(1), 100).is_err(),
            "the refused attempt must not have lowered the recorded slot"
        );
    }

    #[test]
    fn check_alone_does_not_record() {
        let guard = ProposalGuard::new();
        guard.check(&pubkey(1), 96).expect("allowed");
        guard
            .check(&pubkey(1), 96)
            .expect("still allowed, because check records nothing");
    }

    #[test]
    fn recording_out_of_order_does_not_lower_the_bar() {
        let mut guard = ProposalGuard::new();
        guard.record(pubkey(1), 128);
        guard.record(pubkey(1), 96);

        assert!(
            guard.check(&pubkey(1), 100).is_err(),
            "the earlier record must not have displaced the later one"
        );
    }

    /// Slot 0 is a real slot, and `HashMap`'s absent-versus-zero distinction is
    /// exactly the kind of thing a `unwrap_or_default()` would quietly erase.
    /// A validator that proposed slot 0 must not be allowed to propose it
    /// again.
    #[test]
    fn slot_zero_is_recorded_like_any_other() {
        let mut guard = ProposalGuard::new();
        guard.check_and_record(&pubkey(1), 0).expect("first");
        assert!(
            guard.check_and_record(&pubkey(1), 0).is_err(),
            "slot 0 proposed twice must be refused, not treated as never proposed"
        );
    }
}
