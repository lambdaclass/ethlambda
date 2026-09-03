//! XMSS signature aggregation and verification, wrapping leanVM.
//!
//! [`init_leanvm`] must be called once at startup, before anything else here: it compiles
//! the aggregation bytecode and fixes the prover's allocator. Proving panics without it,
//! and decoding a stored proof misreports as a corrupt proof. Binaries call it straight
//! after argument parsing; tests that touch a proof call it themselves.
//!
//! Everything else assumes it has run. Aggregation produces Type-1 proofs (one message,
//! one slot) and Type-2 proofs (several messages merged); both travel without their
//! participant pubkeys, which a receiver rebuilds from its own validator registry.
//!
//! # One aggregate type, grouped by slot
//!
//! leanVM has a single `AggregateSignature`, whose XMSS claims are grouped by
//! epoch: one [`XmssGroup`] per slot, carrying the one message signed at it and
//! the group's strictly sorted, deduplicated keys. Type-1 and Type-2 are the
//! same object here, one group versus several, and the wrappers below only
//! differ in how many groups they build.
//!
//! Two consequences run through everything in this module:
//!
//! - **A slot carries one message.** Several distinct `AttestationData` at one
//!   slot have no representation inside a single aggregate; that is
//!   [`ConflictingMessages`].
//! - **The binding travels out of band.** The without-pubkeys wire form carries
//!   neither the keys nor the `(slot, message)` pairs, so a decode has to
//!   rebuild the whole signer set from the caller's own view of it (a
//!   [`SignerSet`] per claim). A set or binding other than the one aggregated
//!   decodes fine and fails verification, since the proof binds a hash of the
//!   structure: the `(message, slot)` check is inside the SNARK now, not a
//!   cheap field compare ahead of it.

use ethlambda_types::{block::ByteList512KiB, primitives::H256};

use crate::signature::{ValidatorPublicKey, ValidatorSignature};
use leanvm::{AggregateSignature, WireKeys, XmssGroup, aggregate, xmss};
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;
use tracing::error;

pub mod signature;

#[cfg(feature = "shadow-integration")]
pub mod shadow_cost;

/// log(1/rate) for the WHIR commitment scheme used inside the aggregation prover.
const LOG_INV_RATE: usize = 2;

/// Raw XMSS input as [`aggregate`] takes it: the key, the epoch it signed at,
/// the message, and the signature.
type RawXmss = Vec<(
    xmss::XmssPublicKey,
    xmss::Epoch,
    xmss::Message,
    xmss::XmssSignature,
)>;

/// Initializes the leanVM backend. Call once at startup, before any other function here.
///
/// Everything downstream assumes this has run: proving panics without the aggregation
/// bytecode, and decoding a stored proof needs it too, since a decode rebuilds the
/// bytecode claim and fails without it, which surfaces as a bogus
/// `DeserializationFailed`. Doing it up front keeps the cost off the first duty.
///
/// `use_arena` picks the prover's allocator. leanVM's arena recycles the prover's large
/// transient buffers across proofs instead of re-faulting them, so its pages stay
/// resident for the lifetime of the node; the system allocator trades throughput for
/// memory that comes back.
///
/// Idempotent: every step is `Once`/`OnceLock` guarded.
pub fn init_leanvm(use_arena: bool) {
    if use_arena {
        leanvm::setup_prover();
    } else {
        leanvm::setup_prover_without_arena();
    }
}

/// Claims the exclusive right to prove.
///
/// leanVM allows one proof at a time per process; a second concurrent one panics.
/// Proving is legal only while the returned guard is alive, so take it immediately
/// before the prove call: decoding and argument conversion need no permit.
///
/// The permit guards no data, so a poisoned lock is recovered rather than propagated:
/// one panicking prover must not brick every later proof. It is still an incident.
fn acquire_prover() -> MutexGuard<'static, ()> {
    static PROVER_PERMIT: Mutex<()> = Mutex::new(());
    PROVER_PERMIT.lock().unwrap_or_else(|poisoned| {
        error!("a previous proving job panicked while holding the permit; continuing");
        poisoned.into_inner()
    })
}

/// One claim inside an aggregate: the `(message, slot)` a set of validators
/// signed, and the keys of those validators.
///
/// Both halves are needed to decode a stored proof, and neither is on the wire:
/// see the module docs.
#[derive(Clone, Debug)]
pub struct SignerSet {
    /// The signed message: an `AttestationData` root, or a block root.
    pub message: H256,
    /// The slot the signature was made at, which is the XMSS epoch.
    pub slot: u32,
    /// The validators the claim binds, in any order and with duplicates allowed;
    /// [`wire_keys`] sorts and deduplicates as leanVM's signer set requires.
    pub public_keys: Vec<ValidatorPublicKey>,
}

impl SignerSet {
    pub fn new(message: H256, slot: u32, public_keys: Vec<ValidatorPublicKey>) -> Self {
        Self {
            message,
            slot,
            public_keys,
        }
    }
}

/// Two claims at one slot carrying different messages.
///
/// leanVM keys an aggregate's XMSS groups by epoch, so inside one proof the
/// message is a function of the slot. Nothing in this crate can work around it:
/// the group holds a single message, so the second claim has nowhere to go.
#[derive(Debug, Clone, Copy, Error)]
#[error("slot {slot} carries two different messages in one aggregate")]
pub struct ConflictingMessages {
    pub slot: u32,
}

/// Error type for signature aggregation operations.
#[derive(Debug, Error)]
pub enum AggregationError {
    #[error("empty input")]
    EmptyInput,

    #[error("public key count ({0}) does not match signature count ({1})")]
    CountMismatch(usize, usize),

    #[error("proof size too big: {0} bytes")]
    ProofTooBig(usize),

    #[error("child proof deserialization failed at index {0}")]
    ChildDeserializationFailed(usize),

    #[error("outer proof deserialization failed")]
    DeserializationFailed,

    #[error("need at least 2 children for recursive aggregation, got {0}")]
    InsufficientChildren(usize),

    #[error(transparent)]
    ConflictingMessages(#[from] ConflictingMessages),

    #[error("split-by-message target not found in the aggregate's signer set")]
    UnknownMessage,

    #[error("split-by-message target matched several slots")]
    MultipleMessages,

    #[error("prover failure: {0}")]
    ProverFailure(String),
}

/// Error type for signature verification operations.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("proof deserialization failed")]
    DeserializationFailed,

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error(transparent)]
    ConflictingMessages(#[from] ConflictingMessages),
}

// =====================================================================
// Helpers
// =====================================================================

/// The signer set leanVM binds, built from the caller's view of the claims.
///
/// One group per slot, holding that slot's message and its keys strictly sorted
/// and deduplicated, with the groups themselves sorted by slot. Claims sharing a
/// slot merge into one group, so their keys are unioned; claims sharing a slot
/// under different messages are [`ConflictingMessages`].
///
/// Getting this structure wrong is not caught at decode: it changes the digest
/// the proof is checked against, so it surfaces as a verification failure.
fn wire_keys(components: &[SignerSet]) -> Result<WireKeys, ConflictingMessages> {
    let mut groups: Vec<XmssGroup> = Vec::with_capacity(components.len());
    for component in components {
        let keys = component.public_keys.iter().map(|pk| pk.as_inner().clone());
        match groups.iter_mut().find(|(slot, ..)| *slot == component.slot) {
            Some((_, message, group_keys)) => {
                if *message != component.message.0 {
                    return Err(ConflictingMessages {
                        slot: component.slot,
                    });
                }
                group_keys.extend(keys);
            }
            None => groups.push((component.slot, component.message.0, keys.collect())),
        }
    }
    for (_, _, keys) in &mut groups {
        sort_dedup(keys);
    }
    groups.sort_unstable_by_key(|(slot, ..)| *slot);
    Ok((groups, Vec::new()))
}

/// [`wire_keys`] for a single claim, which cannot conflict with itself.
fn one_group(message: &H256, slot: u32, public_keys: &[ValidatorPublicKey]) -> WireKeys {
    let mut keys: Vec<_> = public_keys.iter().map(|pk| pk.as_inner().clone()).collect();
    sort_dedup(&mut keys);
    (vec![(slot, message.0, keys)], Vec::new())
}

/// A group's keys as leanVM's signer set requires them: strictly sorted, so the
/// list's length is a count of distinct claims and no key is covered twice.
///
/// The aggregator does the same to its raw inputs, so a verifier that skips this
/// hands over a different digest and fails a proof that is in fact valid.
fn sort_dedup(keys: &mut Vec<xmss::XmssPublicKey>) {
    keys.sort_unstable();
    keys.dedup();
}

/// Pair raw XMSS keys with their signatures for [`aggregate`], all at one
/// `(message, slot)`.
fn raw_xmss_inputs(
    public_keys: Vec<ValidatorPublicKey>,
    signatures: Vec<ValidatorSignature>,
    message: &H256,
    slot: u32,
) -> RawXmss {
    public_keys
        .into_iter()
        .zip(signatures)
        .map(|(pk, sig)| (pk.into_inner(), slot, message.0, sig.into_inner()))
        .collect()
}

/// Decompress the stored Type-1 children of a recursive aggregation, all of
/// which share one `(message, slot)`.
fn decompress_children(
    children: Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)>,
    message: &H256,
    slot: u32,
) -> Result<Vec<AggregateSignature>, AggregationError> {
    children
        .into_iter()
        .enumerate()
        .map(|(index, (pubkeys, proof_bytes))| {
            let keys = one_group(message, slot, &pubkeys);
            AggregateSignature::from_bytes_without_pubkeys(proof_bytes.iter().as_slice(), keys)
                .map_err(|_| AggregationError::ChildDeserializationFailed(index))
        })
        .collect()
}

fn compress_to_byte_list(sig: &AggregateSignature) -> Result<ByteList512KiB, AggregationError> {
    let serialized = sig.to_bytes_without_pubkeys();
    let len = serialized.len();
    ByteList512KiB::try_from(serialized).map_err(|_| AggregationError::ProofTooBig(len))
}

/// leanVM's aggregation errors, kept as their own text.
///
/// They cover both proving failures and malformed requests (a slot carrying two
/// messages, a child that does not verify, too many children); the message says
/// which, and no caller here branches on the distinction.
fn aggregation_failed(err: leanvm::AggregationError) -> AggregationError {
    AggregationError::ProverFailure(err.to_string())
}

// =====================================================================
// Type-1 aggregation (single message, single slot)
// =====================================================================

/// Aggregate multiple XMSS signatures into a single Type-1 proof.
///
/// All signatures must bind to the same `(message, slot)` pair, which becomes
/// the aggregate's one [`XmssGroup`].
///
/// Returns the leanVM `AggregateSignature::to_bytes_without_pubkeys()` bytes,
/// packed as `ByteList512KiB` for the on-wire SSZ proof field. The participant
/// pubkeys stay off the wire: a receiver rebuilds the set from the aggregation
/// bits and its own validator registry.
pub fn aggregate_signatures(
    public_keys: Vec<ValidatorPublicKey>,
    signatures: Vec<ValidatorSignature>,
    message: &H256,
    slot: u32,
) -> Result<ByteList512KiB, AggregationError> {
    if public_keys.len() != signatures.len() {
        return Err(AggregationError::CountMismatch(
            public_keys.len(),
            signatures.len(),
        ));
    }
    if public_keys.is_empty() {
        return Err(AggregationError::EmptyInput);
    }

    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let agg_n = public_keys.len();
        let count_bytes = public_keys.len().to_le_bytes();
        let slot_bytes = slot.to_le_bytes();
        let dummy = crate::shadow_cost::fill_fake_proof(
            crate::shadow_cost::fake_proof_size(),
            &[&message.0, &slot_bytes, &count_bytes],
        );
        crate::shadow_cost::sleep(crate::shadow_cost::aggregate_delay(agg_n));
        return Ok(dummy);
    }

    let raw_xmss = raw_xmss_inputs(public_keys, signatures, message, slot);

    let _permit = acquire_prover();

    let proof = aggregate(&[], raw_xmss, vec![], None, LOG_INV_RATE).map_err(aggregation_failed)?;

    compress_to_byte_list(&proof)
}

/// Aggregate both existing Type-1 proofs (children) and raw XMSS signatures.
///
/// Existing Type-1s are reused as recursive children; raw XMSS are mixed in.
/// All inputs must bind to the same `(message, slot)`.
///
/// Requires at least one raw signature OR at least 2 children. A lone child is
/// already a valid Type-1; further aggregation is wasted work.
pub fn aggregate_mixed(
    children: Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)>,
    raw_public_keys: Vec<ValidatorPublicKey>,
    raw_signatures: Vec<ValidatorSignature>,
    message: &H256,
    slot: u32,
) -> Result<ByteList512KiB, AggregationError> {
    if raw_public_keys.len() != raw_signatures.len() {
        return Err(AggregationError::CountMismatch(
            raw_public_keys.len(),
            raw_signatures.len(),
        ));
    }
    if raw_public_keys.is_empty() && children.len() < 2 {
        return Err(AggregationError::InsufficientChildren(children.len()));
    }

    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let agg_n = raw_public_keys.len();
        let count_bytes = raw_public_keys.len().to_le_bytes();
        let slot_bytes = slot.to_le_bytes();
        let mut parts: Vec<&[u8]> = vec![&message.0, &slot_bytes];
        for (_, proof) in &children {
            parts.push(proof.iter().as_slice());
        }
        parts.push(&count_bytes);
        let dummy =
            crate::shadow_cost::fill_fake_proof(crate::shadow_cost::fake_proof_size(), &parts);
        crate::shadow_cost::sleep(crate::shadow_cost::aggregate_delay(agg_n));
        return Ok(dummy);
    }

    let children_native = decompress_children(children, message, slot)?;
    let raw_xmss = raw_xmss_inputs(raw_public_keys, raw_signatures, message, slot);

    let _permit = acquire_prover();

    let proof = aggregate(&children_native, raw_xmss, vec![], None, LOG_INV_RATE)
        .map_err(aggregation_failed)?;

    compress_to_byte_list(&proof)
}

/// Recursively aggregate two or more already-aggregated Type-1 proofs into one.
///
/// All children must bind to the same `(message, slot)`. Used during block
/// building to compact multiple proofs sharing an `AttestationData`.
pub fn aggregate_proofs(
    children: Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)>,
    message: &H256,
    slot: u32,
) -> Result<ByteList512KiB, AggregationError> {
    if children.len() < 2 {
        return Err(AggregationError::InsufficientChildren(children.len()));
    }

    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let agg_n = children.len();
        let slot_bytes = slot.to_le_bytes();
        let mut parts: Vec<&[u8]> = vec![&message.0, &slot_bytes];
        for (_, proof) in &children {
            parts.push(proof.iter().as_slice());
        }
        let dummy =
            crate::shadow_cost::fill_fake_proof(crate::shadow_cost::fake_proof_size(), &parts);
        crate::shadow_cost::sleep(crate::shadow_cost::aggregate_delay(agg_n));
        return Ok(dummy);
    }

    let children_native = decompress_children(children, message, slot)?;

    let _permit = acquire_prover();

    let proof = aggregate(&children_native, vec![], vec![], None, LOG_INV_RATE)
        .map_err(aggregation_failed)?;

    compress_to_byte_list(&proof)
}

/// Verify a Type-1 aggregated signature proof.
///
/// Cryptographically verifies that every `public_key` signed `message` at `slot`.
///
/// The binding is checked by being supplied: `(message, slot)` and the key set
/// go into the signer set the proof's digest commits to, so a proof reused from
/// another binding context fails inside the SNARK verifier rather than at a
/// field compare ahead of it.
pub fn verify_aggregated_signature(
    proof_data: &ByteList512KiB,
    public_keys: Vec<ValidatorPublicKey>,
    message: &H256,
    slot: u32,
) -> Result<(), VerificationError> {
    // Skip the real verifier under fake-XMSS; otherwise verify for real.
    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let verify_n = public_keys.len();
        // Model verify cost on the virtual clock (no-op unless a rate is set).
        crate::shadow_cost::sleep(crate::shadow_cost::verify_delay(verify_n));
        return Ok(());
    }

    let keys = one_group(message, slot, &public_keys);
    let sig = AggregateSignature::from_bytes_without_pubkeys(proof_data.iter().as_slice(), keys)
        .map_err(|_| VerificationError::DeserializationFailed)?;

    sig.verify()
        .map_err(|err| VerificationError::VerificationFailed(format!("{err:?}")))
}

// =====================================================================
// Type-2 merge / verify / split (block-level merged proofs)
// =====================================================================

/// Merge many independent Type-1 multi-signatures into a single Type-2 proof.
///
/// Each input is `(claim, type_1_proof_bytes)` where the bytes are the
/// `to_bytes_without_pubkeys()` form of an aggregate over exactly that claim.
///
/// The returned blob is the `to_bytes_without_pubkeys()` form of the merged
/// aggregate, whose signer set is the union of the claims grouped by slot. A
/// verifier decoding it back needs the same claims, in any order.
///
/// Two claims at one slot under different messages cannot be merged at all:
/// leanVM rejects the pair rather than producing a proof (see the module docs).
pub fn merge_type_1s_into_type_2(
    type_1s: Vec<(SignerSet, ByteList512KiB)>,
) -> Result<ByteList512KiB, AggregationError> {
    if type_1s.is_empty() {
        return Err(AggregationError::EmptyInput);
    }

    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let merge_n = type_1s.len();
        let count_bytes = type_1s.len().to_le_bytes();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(type_1s.len() + 1);
        for (_, proof) in &type_1s {
            parts.push(proof.iter().as_slice());
        }
        parts.push(&count_bytes);
        let dummy =
            crate::shadow_cost::fill_fake_proof(crate::shadow_cost::fake_proof_size(), &parts);
        crate::shadow_cost::sleep(crate::shadow_cost::merge_delay(merge_n));
        return Ok(dummy);
    }

    let type_1s_native: Vec<AggregateSignature> = type_1s
        .iter()
        .enumerate()
        .map(|(index, (claim, proof_bytes))| {
            let keys = one_group(&claim.message, claim.slot, &claim.public_keys);
            AggregateSignature::from_bytes_without_pubkeys(proof_bytes.iter().as_slice(), keys)
                .map_err(|_| AggregationError::ChildDeserializationFailed(index))
        })
        .collect::<Result<_, _>>()?;

    let _permit = acquire_prover();

    let merged = aggregate(&type_1s_native, vec![], vec![], None, LOG_INV_RATE)
        .map_err(aggregation_failed)?;

    compress_to_byte_list(&merged)
}

/// Verify a Type-2 merged proof against the claims the caller expects it to carry.
///
/// The claims are rebuilt from the block body, grouped by slot into the signer
/// set the proof's digest commits to, so a proof over other keys, other
/// messages or other slots fails the SNARK verifier.
pub fn verify_type_2_signature(
    proof_data: &[u8],
    components: &[SignerSet],
) -> Result<(), VerificationError> {
    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        return Ok(());
    }

    let keys = wire_keys(components)?;
    let sig = AggregateSignature::from_bytes_without_pubkeys(proof_data, keys)
        .map_err(|_| VerificationError::DeserializationFailed)?;

    sig.verify()
        .map_err(|err| VerificationError::VerificationFailed(format!("{err:?}")))
}

/// Narrow a Type-2 merged proof down to the single claim bound to `message`,
/// yielding a Type-1 for it. Generates a fresh SNARK; expensive.
///
/// Mirrors leanSpec PR #717 `split_multi_message_aggregate_by_message`: the
/// caller supplies the expected message (an attestation data root or the block
/// root) and the wrapper narrows the aggregate to the unique slot carrying it.
/// leanVM does this by re-aggregating the parent with a declaration of what to
/// keep, so the result is a proof over that group alone.
///
/// `components` gives every claim the parent carries, in any order; they are not
/// on the wire, so decoding needs them all even though only one survives.
pub fn split_type_2_by_message(
    proof_data: &[u8],
    components: &[SignerSet],
    message: &H256,
) -> Result<ByteList512KiB, AggregationError> {
    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        return Ok(crate::shadow_cost::fill_fake_proof(
            crate::shadow_cost::fake_proof_size(),
            &[proof_data, &message.0],
        ));
    }

    let keys = wire_keys(components)?;
    let type_2 = AggregateSignature::from_bytes_without_pubkeys(proof_data, keys)
        .map_err(|_| AggregationError::DeserializationFailed)?;

    // A slot carries one message, so a message that appears at all appears in
    // exactly one group unless two slots signed the very same bytes.
    let mut matches = type_2
        .xmss_signers()
        .iter()
        .filter(|(_, group_message, _)| *group_message == message.0);
    let group = match (matches.next(), matches.next()) {
        (Some(group), None) => group.clone(),
        (None, _) => return Err(AggregationError::UnknownMessage),
        (Some(_), Some(_)) => return Err(AggregationError::MultipleMessages),
    };

    let declare: WireKeys = (vec![group], Vec::new());

    let _permit = acquire_prover();

    let component = aggregate(&[type_2], vec![], vec![], Some(&declare), LOG_INV_RATE)
        .map_err(aggregation_failed)?;

    compress_to_byte_list(&component)
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanvm::xmss::{Encode as _, key_gen_from_seed};

    /// Generate a test keypair and sign a message.
    ///
    /// Note: This is slow because XMSS key generation is computationally expensive.
    fn generate_keypair_and_sign(
        seed: u64,
        first_slot: u32,
        signing_slot: u32,
        message: &H256,
    ) -> (ValidatorPublicKey, ValidatorSignature) {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());

        // Small slot range (starting at `first_slot` and covering the signing
        // slot) for fast key generation.
        let (sk, pk) =
            key_gen_from_seed(seed_bytes, first_slot, first_slot + 63).expect("valid slot range");

        let sig =
            xmss::sign(&mut leanvm::rand::rng(), &sk, &message.0, signing_slot).expect("sign");

        // Convert to ethlambda types via SSZ wire bytes.
        let validator_pk = ValidatorPublicKey::from_bytes(&pk.as_ssz_bytes()).unwrap();
        let validator_sig = ValidatorSignature::from_bytes(&sig.as_ssz_bytes()).unwrap();

        (validator_pk, validator_sig)
    }

    /// Stands in for the startup call every binary makes. Without it the prover panics
    /// on the missing aggregation bytecode.
    fn init() {
        init_leanvm(false);
    }

    /// A claim over one validator, the shape every Type-2 component takes here.
    fn claim(message: H256, slot: u32, pk: &ValidatorPublicKey) -> SignerSet {
        SignerSet::new(message, slot, vec![pk.clone()])
    }

    #[test]
    #[ignore = "slow: compiles the leanVM aggregation bytecode (needs a release-sized stack)"]
    fn test_setup_is_idempotent() {
        // Should not panic when called multiple times. The first call compiles
        // the self-referential aggregation bytecode; subsequent calls are cheap
        // (`OnceLock::get_or_init`).
        init_leanvm(false);
        init_leanvm(false);

        // The permit is dropped between acquisitions: it is not reentrant, so holding
        // both at once would deadlock. That also covers release-on-drop.
        drop(acquire_prover());
        drop(acquire_prover());
    }

    /// The claim list a decode rebuilds has to match what was aggregated, and
    /// the shapes leanVM's signer set requires are this wrapper's job: one
    /// group per slot, keys sorted and deduplicated, groups sorted by slot.
    #[test]
    fn wire_keys_groups_by_slot_and_sorts() {
        let pk = |byte: u8| {
            ValidatorPublicKey::from_bytes(&[byte; 32]).expect("any 32 bytes decode as a pubkey")
        };
        let msg_a = H256::from([0xaau8; 32]);
        let msg_b = H256::from([0xbbu8; 32]);

        // Slot 9 twice (keys unioned) and slot 4 once, handed over out of order.
        let components = vec![
            SignerSet::new(msg_b, 9, vec![pk(3), pk(1)]),
            SignerSet::new(msg_a, 4, vec![pk(2)]),
            SignerSet::new(msg_b, 9, vec![pk(1), pk(2)]),
        ];
        let (groups, sphincs) = wire_keys(&components).expect("one message per slot");

        assert!(sphincs.is_empty(), "ethlambda signs XMSS only");
        let slots: Vec<u32> = groups.iter().map(|(slot, ..)| *slot).collect();
        assert_eq!(slots, vec![4, 9], "groups sorted by slot");
        assert_eq!(groups[0].1, msg_a.0);
        assert_eq!(groups[1].1, msg_b.0);
        assert_eq!(groups[0].2.len(), 1);
        // Keys 1, 2, 3 unioned across the two slot-9 claims, deduplicated.
        assert_eq!(groups[1].2.len(), 3);
        assert!(
            groups[1].2.windows(2).all(|w| w[0] < w[1]),
            "keys strictly sorted"
        );
    }

    /// Distinct `AttestationData` at one slot cannot share an aggregate, so the
    /// wrapper says so instead of handing leanVM a set it cannot represent.
    #[test]
    fn wire_keys_rejects_two_messages_at_one_slot() {
        let pk = ValidatorPublicKey::from_bytes(&[7u8; 32]).expect("32 bytes decode");
        let components = vec![
            SignerSet::new(H256::from([1u8; 32]), 6, vec![pk.clone()]),
            SignerSet::new(H256::from([2u8; 32]), 6, vec![pk]),
        ];
        let err = wire_keys(&components).expect_err("one slot, two messages");
        assert_eq!(err.slot, 6);
    }

    #[test]
    #[ignore = "too slow"]
    fn test_aggregate_single_signature() {
        init();
        let message = H256::from([42u8; 32]);
        let slot = 10u32;

        let (pk, sig) = generate_keypair_and_sign(1, 5, slot, &message);

        let result = aggregate_signatures(vec![pk.clone()], vec![sig], &message, slot);
        assert!(result.is_ok(), "Aggregation failed: {:?}", result.err());

        let proof_data = result.unwrap();

        // Verify the aggregated signature
        let verify_result =
            verify_aggregated_signature(&proof_data, vec![pk.clone()], &message, slot);
        assert!(
            verify_result.is_ok(),
            "Verification failed: {:?}",
            verify_result.err()
        );
    }

    #[test]
    #[ignore = "too slow"]
    fn test_aggregate_multiple_signatures() {
        init();
        let message = H256::from([42u8; 32]);
        let slot = 15u32;

        // Generate 3 keypairs whose ranges all cover the signing slot.
        let configs = vec![
            (1u64, 5u32),  // seed, first signable slot
            (2u64, 8u32),  // seed, first signable slot
            (3u64, 10u32), // seed, first signable slot
        ];

        let mut pubkeys = Vec::new();
        let mut signatures = Vec::new();

        for (seed, first_slot) in configs {
            let (pk, sig) = generate_keypair_and_sign(seed, first_slot, slot, &message);
            pubkeys.push(pk);
            signatures.push(sig);
        }

        let result = aggregate_signatures(pubkeys.clone(), signatures, &message, slot);
        assert!(result.is_ok(), "Aggregation failed: {:?}", result.err());

        let proof_data = result.unwrap();

        // Verify the aggregated signature
        let verify_result = verify_aggregated_signature(&proof_data, pubkeys, &message, slot);
        assert!(
            verify_result.is_ok(),
            "Verification failed: {:?}",
            verify_result.err()
        );
    }

    #[test]
    #[ignore = "too slow"]
    fn test_verify_wrong_message_fails() {
        init();
        let message = H256::from([42u8; 32]);
        let wrong_message = H256::from([43u8; 32]);
        let slot = 10u32;

        let (pk, sig) = generate_keypair_and_sign(1, 5, slot, &message);

        let proof_data = aggregate_signatures(vec![pk.clone()], vec![sig], &message, slot).unwrap();

        // Verify with wrong message should fail
        let verify_result =
            verify_aggregated_signature(&proof_data, vec![pk.clone()], &wrong_message, slot);
        assert!(
            verify_result.is_err(),
            "Verification should have failed with wrong message"
        );
    }

    #[test]
    #[ignore = "too slow"]
    fn test_verify_wrong_slot_fails() {
        init();
        let message = H256::from([42u8; 32]);
        let slot = 10u32;
        let wrong_slot = 11u32;

        let (pk, sig) = generate_keypair_and_sign(1, 5, slot, &message);

        let proof_data = aggregate_signatures(vec![pk.clone()], vec![sig], &message, slot).unwrap();

        // Verify with wrong slot should fail
        let verify_result =
            verify_aggregated_signature(&proof_data, vec![pk.clone()], &message, wrong_slot);
        assert!(
            verify_result.is_err(),
            "Verification should have failed with wrong slot"
        );
    }

    /// The signer set is not carried on the wire, so it is the caller-supplied
    /// set that binds a proof to its participants. Supplying a different set of
    /// the same size must be rejected: the proof commits to a hash of the set,
    /// so it fails inside the SNARK verifier rather than at decode.
    #[test]
    #[ignore = "too slow"]
    fn test_verify_wrong_pubkey_set_fails() {
        init();
        let message = H256::from([42u8; 32]);
        let slot = 10u32;

        let (pk, sig) = generate_keypair_and_sign(1, 5, slot, &message);
        let (other_pk, _) = generate_keypair_and_sign(2, 5, slot, &message);

        let proof_data = aggregate_signatures(vec![pk], vec![sig], &message, slot).unwrap();

        let verify_result =
            verify_aggregated_signature(&proof_data, vec![other_pk], &message, slot);
        assert!(
            verify_result.is_err(),
            "Verification should have failed with a different signer set"
        );
    }

    /// End-to-end Type-2 round-trip: produce two Type-1s (different (msg, slot)),
    /// merge them into a Type-2, verify the Type-2, then split out one component
    /// and verify it as a Type-1.
    #[test]
    #[ignore = "too slow"]
    fn test_type_2_merge_verify_split_round_trip() {
        init();
        let msg_a = H256::from([0x11u8; 32]);
        let msg_b = H256::from([0x22u8; 32]);
        let slot_a: u32 = 7;
        let slot_b: u32 = 11;

        let (pk_a, sig_a) = generate_keypair_and_sign(101, 5, slot_a, &msg_a);
        let (pk_b, sig_b) = generate_keypair_and_sign(102, 5, slot_b, &msg_b);

        let pa = aggregate_signatures(vec![pk_a.clone()], vec![sig_a], &msg_a, slot_a).unwrap();
        let pb = aggregate_signatures(vec![pk_b.clone()], vec![sig_b], &msg_b, slot_b).unwrap();

        let components = vec![claim(msg_a, slot_a, &pk_a), claim(msg_b, slot_b, &pk_b)];
        let merged = merge_type_1s_into_type_2(vec![
            (components[0].clone(), pa),
            (components[1].clone(), pb),
        ])
        .expect("merge");

        verify_type_2_signature(merged.iter().as_slice(), &components).expect("verify type-2");

        let split =
            split_type_2_by_message(merged.iter().as_slice(), &components, &msg_a).expect("split");

        verify_aggregated_signature(&split, vec![pk_a], &msg_a, slot_a).expect("verify split");
    }
}
