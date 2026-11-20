//! The signatures a block's processing defers, so they can be checked together.
//!
//! The specification checks every signature the moment its operation is
//! processed, and each check is a full pairing. A block carries from a dozen
//! signature sets to well over a hundred (the RANDAO reveal, every attestation,
//! up to 128 of them before electra, the sync aggregate, any exits and
//! slashings), and checking them in one random-linear-combination
//! batch costs a fraction of checking them one by one (see
//! [`ethlambda_crypto::bls::verify_signature_sets`]). So processing *builds*
//! each set where the specification verifies it and pushes it here, and the
//! [`SignatureBatch`] is verified wherever waiting longer would let an
//! unverified signature decide what the block writes, and once more when
//! processing ends.
//!
//! # What may be deferred
//!
//! A signature may be deferred only when its failure rejects the block, since
//! then the late rejection and the early one end in the same place: the state
//! the block was applied to is discarded either way. Block import runs the
//! transition on a clone of the parent's state, and `transition_block` in
//! `fork_choice.rs` hands no state back with an error. What must stay
//! immediate is a signature whose failure does *not* reject the block but
//! changes what happens next: a deposit with a bad signature is skipped and
//! the block carries on, so that check cannot wait.
//!
//! Deferring a signature lets its operation write before the signature is
//! known to be good, and lets the operations after it run on that write. That
//! is confined to votes, and to one write nothing reads before its check:
//!
//! - an attestation's participation flags and the inclusion reward it pays
//!   the proposer, which are what honest votes for the same data write;
//! - the sync aggregate's rewards and penalties, the last step of a block, so
//!   nothing runs after them;
//! - gloas's payload attestations, which write nothing;
//! - gloas's execution payload bid, which records the builder's payment and
//!   the bid itself before its signature is checked, but is checked right
//!   after, with the RANDAO reveal, before any operation runs. That holds
//!   whenever the reveal is verified, which block import always does; only
//!   block production skips the reveal, for a block it is building itself,
//!   and then the bid is checked when the block ends.
//!
//! Everything else checks its own set, together with every set still pending,
//! before it writes, through [`SignatureBatch::verify_pending`]:
//!
//! - the RANDAO reveal, so the mix is never fed an unverified reveal;
//! - proposer and attester slashings, voluntary exits and BLS-to-execution
//!   changes, the operations that change a validator's record.
//!
//! So no operation that slashes, exits or redirects a validator writes on a
//! forged signature, or runs on a state an earlier forged signature wrote to:
//! a block cannot combine forged slashings, exits and credential changes into
//! a state no set of honest signers produces. A block of ordinary votes still
//! checks all of its attestations and its sync aggregate in one batch.
//!
//! # What a forged block costs
//!
//! Rejecting a block whose body carries a bad signature costs the processing
//! up to the check that catches it, that batch, and finding the bad set in it.
//! The processing is bounded as it was with immediate checks, which also ran
//! every operation before reaching the sync aggregate's signature, the last
//! one a block carries. A forged slashing, exit or credential change is caught
//! at its own operation, before anything after it runs. Finding the bad set
//! bisects the failed batch rather than re-checking each set on its own (see
//! [`SignatureBatch::verify_pending`]): about the batch's cost again, where
//! the re-check cost a full pairing per set.
//!
//! # What a late failure names
//!
//! Every error is the check's own label (the same `&'static str` the immediate
//! check would have failed with), so a rejected block's error still says which
//! signature was bad. A batch that fails does not know which set did, so it
//! looks for the first failing set in push order, which is also the one the
//! immediate checks would have stopped at. The order between a bad signature
//! and some *other* check later in the block can differ from the immediate
//! path: a block with two defects may now be rejected for the later one, or
//! the signature, depending on which the driver reaches first. Which defect is
//! named was never part of the specification, only that the block is invalid.

use ethlambda_crypto::bls::{SignatureSet, verify_signature_sets};
use tracing::error;

use crate::metrics::{StfPhase, timed};

use crate::beacon::error::{Result, verify};

/// The signatures a block's processing defers, checked together once it ends.
///
/// See the module documentation for what may be deferred and why. Outside
/// this crate there are two ways to get one, and both check every set pushed:
/// [`Self::deferred`] verifies the batch once its closure returns, and
/// [`Self::immediate`] checks each set as it is pushed, which is for the
/// callers that apply an operation to a scratch state and must learn at once
/// whether it was accepted. A deferring batch that could be dropped
/// unverified would turn every function taking one into "valid except for
/// its signatures", which is also why it does not implement `Default`: a
/// public `default()` would be exactly such a batch. Inside the crate the
/// same holds outside tests: [`Self::new`] exists only under `cfg(test)`, so
/// no production path can hold a deferring batch [`Self::deferred`] did not
/// make.
pub struct SignatureBatch {
    sets: Vec<SignatureSet>,
    /// `sets[i]`'s label, apart from the sets so the batch check reads them
    /// without a copy.
    labels: Vec<&'static str>,
    immediate: bool,
}

impl SignatureBatch {
    fn empty(immediate: bool) -> Self {
        Self {
            sets: Vec::new(),
            labels: Vec::new(),
            immediate,
        }
    }

    /// An empty batch that defers every set pushed to it, for tests that run
    /// one operation and then [`Self::verify`] (or inspect) what it deferred.
    /// Test-only, so production code defers only through [`Self::deferred`].
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::empty(false)
    }

    /// Runs `f` with a batch that defers every set pushed to it, then verifies
    /// what is still pending: what a block's driver does, and the only way
    /// outside tests to defer signatures. An error from `f` is returned as is,
    /// since it rejects whatever `f` was processing whatever the signatures
    /// say.
    pub fn deferred<T>(f: impl FnOnce(&mut SignatureBatch) -> Result<T>) -> Result<T> {
        let mut batch = Self::empty(false);
        let out = f(&mut batch)?;
        batch.verify_pending()?;
        Ok(out)
    }

    /// An empty batch that checks each set the moment it is pushed.
    ///
    /// Block production's operation packer applies candidates one after the
    /// other to a scratch state and keeps the ones that are accepted. A
    /// candidate rejected only at the end of a deferred batch would already
    /// have written to the scratch state, which the packer relies on never
    /// happening, so its calls check as they go and behave exactly as the
    /// immediate checks did.
    pub fn immediate() -> Self {
        Self::empty(true)
    }

    /// Defers `set`, or rejects now with `what` when the set could not be built
    /// (an invalid key or signature, an empty signer list): the same moment and
    /// the same label the immediate check fails with.
    pub fn push(&mut self, set: Option<SignatureSet>, what: &'static str) -> Result<()> {
        let Some(set) = set else {
            return verify(false, what);
        };
        if self.immediate {
            return verify(set.verify(), what);
        }
        self.sets.push(set);
        self.labels.push(what);
        Ok(())
    }

    /// Checks every set pushed since the last check, now and in one batch,
    /// and rejects with the first failing set's `what` in push order: the
    /// check the immediate path would have stopped at.
    ///
    /// For an operation about to write something no unverified signature may
    /// decide (see the module documentation). It pushes its own set, then
    /// calls this before writing, so its set and every one still pending are
    /// checked first. A batch that checks at push time has nothing pending, so
    /// for it this costs nothing.
    ///
    /// A failed batch is bisected to find its first failing set (see
    /// [`first_failing`]), which costs about what the batch did, rather than
    /// re-checking each set on its own, which costs a whole pairing per set on
    /// top of the batch.
    pub(crate) fn verify_pending(&mut self) -> Result<()> {
        debug_assert_eq!(self.sets.len(), self.labels.len(), "one label per set");
        let outcome = timed(StfPhase::BatchSignatures, || {
            check(&self.sets, &self.labels)
        });
        self.sets.clear();
        self.labels.clear();
        outcome
    }

    /// [`Self::verify_pending`], for a test's batch nothing is pushed to
    /// afterwards.
    #[cfg(test)]
    pub(crate) fn verify(mut self) -> Result<()> {
        self.verify_pending()
    }

    /// Whether no set is pending.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }
}

/// [`SignatureBatch::verify_pending`]'s check of `sets`, `labels[i]` naming
/// `sets[i]`.
fn check(sets: &[SignatureSet], labels: &[&'static str]) -> Result<()> {
    if verify_signature_sets(sets) {
        return Ok(());
    }
    if let Some(first_bad) = first_failing(sets) {
        return verify(false, labels[first_bad]);
    }
    // A batch of valid sets always passes, so the search should have landed
    // on a set that fails alone. It did not, which is a bug in the batch
    // check: the block is still rejected rather than accepted, but loudly,
    // since a block every single check accepts is valid and rejecting it can
    // fork this node off.
    error!(
        sets = sets.len(),
        "Signature batch failed but the set it was narrowed to verifies on its own; rejecting the block"
    );
    crate::metrics::inc_signature_batch_disagreements();
    let last = labels.last().copied().unwrap_or("block signatures");
    verify(false, last)
}

/// The position of the first set in `sets` that fails on its own, given that
/// `sets` failed as one batch. `None` when the set that search lands on
/// verifies after all, which only a bug in the batch check can cause.
///
/// Bisects: each step checks, as one batch, the first half of the range known
/// to hold the first failing set, and keeps that half if it fails or the
/// other if it passes. Each half checked is half the size of the one before,
/// so together they hold fewer sets than `sets` does, at one final
/// exponentiation per step: about 8 for the ~130 sets of a full pre-electra
/// block, where checking every set on its own costs 130 pairings (each its
/// own final exponentiation, and a Miller loop more than the set costs in a
/// batch, for its signature).
fn first_failing(sets: &[SignatureSet]) -> Option<usize> {
    if sets.is_empty() {
        return None;
    }
    // Every set before `start` verifies, and `sets[start..end]` holds the
    // first that does not. `failed` is whether `sets[start..end]` itself was
    // the last batch checked, and failed.
    let (mut start, mut end) = (0, sets.len());
    let mut failed = true;
    while end - start > 1 {
        let middle = start + (end - start) / 2;
        if verify_signature_sets(&sets[start..middle]) {
            start = middle;
            failed = false;
        } else {
            end = middle;
            failed = true;
        }
    }
    // A batch of one is that set's own check, so a range of one that failed
    // as a batch needs no second look.
    (failed || !sets[start].verify()).then_some(start)
}

/// [`SignatureBatch::deferred`], under the short name the single-operation
/// tests use: they only mean "accepted" once their deferred signatures have
/// been checked.
#[cfg(test)]
pub(crate) fn checked<T>(f: impl FnOnce(&mut SignatureBatch) -> Result<T>) -> Result<T> {
    SignatureBatch::deferred(f)
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::*;
    use crate::beacon::bls::DST;
    use crate::beacon::primitives::{BlsPubkey, BlsSignature, Root};

    fn set(seed: u8, valid: bool) -> SignatureSet {
        let key = SecretKey::key_gen(&[seed + 1; 32], &[]).unwrap();
        let pubkey = BlsPubkey(key.sk_to_pk().to_bytes());
        let message = Root::repeat_byte(seed);
        let signed = if valid {
            message
        } else {
            Root::repeat_byte(seed ^ 0xff)
        };
        let signature = BlsSignature(key.sign(signed.as_slice(), DST, &[]).to_bytes());
        SignatureSet::single(&pubkey, message, &signature).unwrap()
    }

    #[test]
    fn an_empty_batch_verifies() {
        assert!(SignatureBatch::new().verify().is_ok());
    }

    #[test]
    fn valid_sets_verify_together() {
        let mut batch = SignatureBatch::new();
        for seed in 0..5 {
            batch.push(Some(set(seed, true)), "valid").unwrap();
        }
        assert!(batch.verify().is_ok());
    }

    #[test]
    fn a_set_that_could_not_be_built_rejects_at_once_with_its_label() {
        let mut batch = SignatureBatch::new();
        let err = batch.push(None, "unbuildable").unwrap_err();
        assert!(format!("{err:?}").contains("unbuildable"), "{err:?}");
    }

    #[test]
    fn a_failing_batch_names_the_first_bad_set() {
        let mut batch = SignatureBatch::new();
        batch.push(Some(set(0, true)), "first good").unwrap();
        batch.push(Some(set(1, false)), "first bad").unwrap();
        batch.push(Some(set(2, true)), "second good").unwrap();
        batch.push(Some(set(3, false)), "second bad").unwrap();
        let err = batch.verify().unwrap_err();
        assert!(format!("{err:?}").contains("first bad"), "{err:?}");
    }

    /// The bisection lands on the first bad set wherever it sits and however
    /// many bad sets follow it, for batch sizes that halve evenly and that do
    /// not.
    #[test]
    fn bisection_finds_the_first_bad_set_at_every_position() {
        for len in [1u8, 2, 3, 7, 8, 13] {
            for first_bad in 0..len {
                for later_bad in [None, Some(len - 1)] {
                    let sets: Vec<SignatureSet> = (0..len)
                        .map(|i| set(i, i != first_bad && Some(i) != later_bad))
                        .collect();
                    assert_eq!(
                        first_failing(&sets),
                        Some(usize::from(first_bad)),
                        "len {len}, first bad {first_bad}, later bad {later_bad:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn verifying_clears_what_was_pending() {
        let mut batch = SignatureBatch::new();
        batch.push(Some(set(0, true)), "good").unwrap();
        batch.verify_pending().unwrap();
        assert!(batch.is_empty());
        // A bad set pushed after a check fails the next one, and only it.
        batch.push(Some(set(1, false)), "bad").unwrap();
        let err = batch.verify_pending().unwrap_err();
        assert!(format!("{err:?}").contains("bad"), "{err:?}");
        assert!(batch.is_empty());
        assert!(batch.verify().is_ok());
    }

    #[test]
    fn a_deferred_failure_carries_the_label_an_immediate_one_does() {
        let mut immediate = SignatureBatch::immediate();
        let early = immediate
            .push(Some(set(1, false)), "the label")
            .unwrap_err();

        let mut deferred = SignatureBatch::new();
        deferred.push(Some(set(1, false)), "the label").unwrap();
        let late = deferred.verify().unwrap_err();

        assert_eq!(format!("{early:?}"), format!("{late:?}"));
    }

    #[test]
    fn one_bad_signature_among_several_rejects_the_batch() {
        let mut batch = SignatureBatch::new();
        for seed in 0..6 {
            batch
                .push(Some(set(seed, seed != 4)), "attestation")
                .unwrap();
        }
        assert!(batch.verify().is_err());
    }

    #[test]
    fn an_immediate_batch_rejects_on_push() {
        let mut batch = SignatureBatch::immediate();
        batch.push(Some(set(0, true)), "good").unwrap();
        let err = batch.push(Some(set(1, false)), "bad").unwrap_err();
        assert!(format!("{err:?}").contains("bad"), "{err:?}");
    }
}
