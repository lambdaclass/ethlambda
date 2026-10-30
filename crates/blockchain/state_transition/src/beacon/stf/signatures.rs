//! The signatures a block's processing defers, so they can be checked together.
//!
//! The specification checks every signature the moment its operation is
//! processed, and each check is a full pairing. A block carries a dozen or so
//! signature sets (the RANDAO reveal, every attestation, the sync aggregate,
//! any exits and slashings), and checking them in one random-linear-combination
//! batch costs a fraction of checking them one by one (see
//! [`ethlambda_crypto::bls::verify_signature_sets`]). So processing *builds*
//! each set where the specification verifies it, pushes it here, and the block
//! driver verifies the whole [`SignatureBatch`] once processing ends.
//!
//! # What may be deferred
//!
//! A signature may be deferred exactly when its failure rejects the block, since
//! then the late rejection and the early one end in the same place: the state
//! the block was applied to is discarded either way. Block import runs the
//! transition on a clone of the parent's state (`transition_block` in
//! `fork_choice.rs`) and never reads that clone after an error, so a state
//! left partly mutated by a block that is rejected a few steps later is never
//! observed. What must stay immediate is a signature whose failure does *not*
//! reject the block but changes what happens next: a deposit with a bad
//! signature is skipped and the block carries on, so that check cannot wait.
//!
//! # What a late failure names
//!
//! Every error is the check's own label (the same `&'static str` the immediate
//! check would have failed with), so a rejected block's error still says which
//! signature was bad. A batch that fails does not know which set did, so it
//! re-checks the sets one at a time in push order and reports the first that
//! fails, which is also the one the immediate checks would have stopped at.
//! The order between a bad signature and some *other* check later in the block
//! can differ from the immediate path: a block with two defects may now be
//! rejected for the later one, or the signature, depending on which the
//! driver reaches first. Which defect is named was never part of the
//! specification, only that the block is invalid.

use ethlambda_crypto::bls::{SignatureSet, verify_signature_sets};

use crate::beacon::error::{Result, verify};

/// The signatures a block's processing defers, checked together once it ends.
///
/// See the module documentation for what may be deferred and why. A batch
/// built with [`Self::new`] verifies nothing until [`Self::verify`]; one built
/// with [`Self::immediate`] checks each set as it is pushed, which is for the
/// callers that apply an operation to a scratch state and must learn at once
/// whether it was accepted.
#[derive(Default)]
pub struct SignatureBatch {
    sets: Vec<(SignatureSet, &'static str)>,
    immediate: bool,
}

impl SignatureBatch {
    /// An empty batch that defers every set pushed to it.
    pub fn new() -> Self {
        Self::default()
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
        Self {
            sets: Vec::new(),
            immediate: true,
        }
    }

    /// Defers `set`, or rejects now with `what` when the set could not be built
    /// (an invalid key or signature, an empty signer list): the same moment and
    /// the same label today's immediate check fails with.
    pub fn push(&mut self, set: Option<SignatureSet>, what: &'static str) -> Result<()> {
        let Some(set) = set else {
            return verify(false, what);
        };
        if self.immediate {
            return verify(set.verify(), what);
        }
        self.sets.push((set, what));
        Ok(())
    }

    /// One batch check. On failure, re-checks the sets one by one and rejects with
    /// the first failing set's `what`, so the error names the same check it does
    /// today.
    pub fn verify(self) -> Result<()> {
        let sets: Vec<SignatureSet> = self.sets.iter().map(|(set, _)| *set).collect();
        if verify_signature_sets(&sets) {
            return Ok(());
        }
        // A batch of valid sets always passes, so one of these fails. Should
        // none do (which would be a bug in the batch check), the block is
        // still rejected, with the last label, rather than accepted.
        let mut last = "block signatures";
        for (set, what) in &self.sets {
            last = what;
            verify(set.verify(), what)?;
        }
        verify(false, last)
    }
}

/// Runs `f` against a fresh batch and verifies the batch, the way a block's
/// driver does: for tests of a single operation, which only mean "accepted"
/// once their deferred signatures have been checked.
#[cfg(test)]
pub(crate) fn checked<T>(f: impl FnOnce(&mut SignatureBatch) -> Result<T>) -> Result<T> {
    let mut batch = SignatureBatch::new();
    let out = f(&mut batch)?;
    batch.verify()?;
    Ok(out)
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
