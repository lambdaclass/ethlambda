//! Gossip validation for the `execution_proof` topic (EIP-8025, as EIP-8440
//! modifies it): a prover's signed execution chain proof.
//!
//! The rules are the specification's `validate_execution_proof_gossip`
//! (`specs/_features/eip8440/p2p-interface.md`), split like
//! [`super::payload_attestation`]'s: [`cheap_checks`] reads the message, the
//! seen caches and what the store already holds; [`stateful_checks`] reads
//! the head block's post-state, verifies the prover's signature and asks the
//! proof engine. The specification marks the proof and the prover seen before
//! the engine runs, so a prover gets one attempt per block and type whether
//! or not its proof verifies; the caller records both on any outcome past
//! the signature check, which [`stateful_checks`] reports through
//! [`Outcome`] as the proof engine's own reasons.
//!
//! Deliberate departures: the head block's post-state is read from the state
//! cache, never rebuilt, and a miss is `IGNORE` (the specification's
//! "has not been validated" ignore covers it); an engine that cannot answer
//! is `IGNORE`, since nothing says the proof is bad.

use std::num::NonZeroUsize;

use ethlambda_storage::CacheKey;
use lru::LruCache;

use super::{IgnoreReason, Outcome, RejectReason};
use crate::beacon::bls;
use crate::beacon::constants::{DOMAIN_EXECUTION_PROOF, is_supported_execution_proof_type};
use crate::beacon::containers::execution_proof::{ProofType, SignedExecutionProof};
use crate::beacon::execution_proofs::{ExecutionProofEngine, ProofVerdict};
use crate::beacon::fork_choice::Store;
use crate::beacon::helpers::accessors::{get_current_epoch, get_domain};
use crate::beacon::helpers::misc::compute_signing_root;
use crate::beacon::helpers::predicates::is_active_validator;
use crate::beacon::primitives::{HashTreeRoot as _, Root, ValidatorIndex};

/// The proofs and provers already judged: the specification's
/// `seen.execution_proof_roots` (one entry per `(head block, proof root)`)
/// and `seen.execution_proof_provers` (one per `(head block, proof type,
/// validator)`).
///
/// Bounded the same way as [`super::SeenBlocks`].
pub struct SeenExecutionProofs {
    roots: LruCache<(Root, Root), ()>,
    provers: LruCache<(Root, ProofType, ValidatorIndex), ()>,
}

impl SeenExecutionProofs {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            roots: LruCache::new(capacity),
            provers: LruCache::new(capacity),
        }
    }

    /// Whether `proof_root` was already processed for `head_block_root`.
    pub fn contains_proof(&self, head_block_root: Root, proof_root: Root) -> bool {
        self.roots.contains(&(head_block_root, proof_root))
    }

    /// Whether `validator_index` already sent a proof of `proof_type` for
    /// `head_block_root`.
    pub fn contains_prover(
        &self,
        head_block_root: Root,
        proof_type: ProofType,
        validator_index: ValidatorIndex,
    ) -> bool {
        self.provers
            .contains(&(head_block_root, proof_type, validator_index))
    }

    /// Record an authenticated proof and its prover's attempt. Returns `false`,
    /// changing nothing, when the proof was already recorded.
    pub fn record(&mut self, signed_proof: &SignedExecutionProof) -> bool {
        let proof = &signed_proof.message;
        let key = (proof.head_block_root, proof.hash_tree_root());
        if self.roots.contains(&key) {
            return false;
        }
        self.roots.put(key, ());
        self.provers.put(
            (
                proof.head_block_root,
                proof.proof_type,
                signed_proof.validator_index,
            ),
            (),
        );
        true
    }
}

/// The rules that read only the message, the seen caches and what the store
/// already holds. The caller records the proof in `seen` once
/// [`stateful_checks`] has authenticated it.
pub fn cheap_checks(
    seen: &SeenExecutionProofs,
    store: &Store,
    signed_proof: &SignedExecutionProof,
) -> Result<(), Outcome> {
    let proof = &signed_proof.message;
    // [REJECT] The proof data is non-empty.
    if proof.proof_data.is_empty() {
        return Err(Outcome::Reject(RejectReason::EmptyExecutionProof));
    }
    // [REJECT] The proof type is supported.
    if !is_supported_execution_proof_type(proof.proof_type) {
        return Err(Outcome::Reject(RejectReason::UnsupportedProofType));
    }
    let head_block_root = proof.head_block_root;
    // [IGNORE] The proof's beacon block has been seen.
    if !store.has_block(&head_block_root) {
        return Err(Outcome::Ignore(IgnoreReason::UnknownBlock));
    }
    // [IGNORE] No valid proof is known for this beacon block and proof type.
    if store.has_execution_proof(&head_block_root, proof.proof_type) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadyStored));
    }
    // [IGNORE] The proof has not already been processed.
    if seen.contains_proof(head_block_root, proof.hash_tree_root()) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] This is the prover's first valid or invalid proof for this key.
    if seen.contains_prover(
        head_block_root,
        proof.proof_type,
        signed_proof.validator_index,
    ) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    Ok(())
}

/// The rules that need the head block's post-state and the proof engine.
/// Runs on a blocking thread. `proof_engine` is `None` on a node that
/// verifies no proofs, which ignores every proof it is sent.
pub fn stateful_checks(
    store: &Store,
    signed_proof: &SignedExecutionProof,
    proof_engine: Option<&dyn ExecutionProofEngine>,
) -> Outcome {
    let proof = &signed_proof.message;
    // [IGNORE] The proof's beacon block has been validated: see the module
    // documentation for why an uncached state is an ignore too.
    let Some(state) = store.cached_state(CacheKey::BlockState(proof.head_block_root)) else {
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
    };
    // [REJECT] The signed execution proof passes validation: the prover is a
    // known, active validator and signed the proof (the message checks ran
    // in `cheap_checks`).
    let Ok(validator) = state.validator(signed_proof.validator_index) else {
        return Outcome::Reject(RejectReason::UnknownValidator);
    };
    if !is_active_validator(validator, get_current_epoch(&state)) {
        return Outcome::Reject(RejectReason::InactiveValidator);
    }
    let domain = get_domain(&state, DOMAIN_EXECUTION_PROOF, None);
    let signing_root = compute_signing_root(proof.hash_tree_root(), domain);
    if !bls::verify(&validator.pubkey, signing_root, &signed_proof.signature) {
        return Outcome::Reject(RejectReason::BadSignature);
    }
    // [REJECT] The execution proof is valid.
    let Some(engine) = proof_engine else {
        return Outcome::Ignore(IgnoreReason::NoConsumer);
    };
    let public_input = proof.public_input(store.config().deposit_chain_id);
    match engine.verify_execution_proof(proof, &public_input) {
        Ok(ProofVerdict::Valid) => Outcome::Accept,
        Ok(ProofVerdict::Invalid) => Outcome::Reject(RejectReason::InvalidExecutionProof),
        Err(_) => Outcome::Ignore(IgnoreReason::ProofEngineUnavailable),
    }
}

/// Whether `outcome` came after the prover's signature verified, when the
/// specification marks the proof and the prover as seen whatever the proof
/// engine then says. Everything [`stateful_checks`] answers past that point.
pub fn authenticated(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Accept
            | Outcome::Reject(RejectReason::InvalidExecutionProof)
            | Outcome::Ignore(IgnoreReason::NoConsumer)
            | Outcome::Ignore(IgnoreReason::ProofEngineUnavailable)
    )
}

/// [`cheap_checks`] then [`stateful_checks`], for callers with no reason to
/// split them: the specification's `validate_execution_proof_gossip`. The
/// caller records the proof in `seen` when [`authenticated`] says so.
pub fn validate(
    seen: &SeenExecutionProofs,
    store: &Store,
    signed_proof: &SignedExecutionProof,
    proof_engine: Option<&dyn ExecutionProofEngine>,
) -> Outcome {
    if let Err(outcome) = cheap_checks(seen, store, signed_proof) {
        return outcome;
    }
    stateful_checks(store, signed_proof, proof_engine)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::checkpoint::Checkpoint;

    use super::*;
    use crate::beacon::config::Config;
    use crate::beacon::containers::{BeaconState, SignedBeaconBlock, electra};
    use crate::beacon::execution_proofs::{ExecutionProof, MockExecutionProofEngine};
    use crate::beacon::fork::ForkName;
    use crate::beacon::gossip::test_support::{GENESIS_TIME, store};
    use crate::beacon::helpers::test_state::{sign_for, with_signing_validators_at};
    use crate::beacon::primitives::Slot;

    const BLOCK_ROOT: Root = Root::repeat_byte(7);
    const CHAIN_ID: u64 = 11_155_111;

    fn fulu_block(slot: Slot) -> SignedBeaconBlock {
        SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        })
    }

    fn seen() -> SeenExecutionProofs {
        SeenExecutionProofs::new(NonZeroUsize::new(16).expect("non-zero"))
    }

    /// A store gloas from genesis on chain `CHAIN_ID`, holding `BLOCK_ROOT`
    /// with a signing registry of four validators as its post-state.
    fn gloas_store() -> (Store, BeaconState) {
        let mut config = Config::mainnet()
            .with_fork_epoch(ForkName::Fulu, 0)
            .with_fork_epoch(ForkName::Gloas, 0);
        config.deposit_chain_id = CHAIN_ID;
        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            GENESIS_TIME,
            config,
            Root::ZERO,
            Checkpoint {
                root: Root::ZERO,
                slot: 0,
            },
            0,
        );
        store
            .insert_pending_block(BLOCK_ROOT, fulu_block(5))
            .expect("insert the block");
        let state = with_signing_validators_at(ForkName::Gloas, 4);
        store
            .insert_state(BLOCK_ROOT, state.clone())
            .expect("insert the state");
        (store, state)
    }

    /// A proof for `BLOCK_ROOT` of `proof_type`, signed by `validator` under
    /// `state`, claiming chain `chain_id`'s public input.
    fn proof(
        state: &BeaconState,
        proof_type: ProofType,
        validator: ValidatorIndex,
        chain_id: u64,
    ) -> SignedExecutionProof {
        let mut message = ExecutionProof {
            proof_data: Default::default(),
            proof_type,
            origin_block_root: Root::repeat_byte(1),
            head_block_root: BLOCK_ROOT,
        };
        message.proof_data =
            MockExecutionProofEngine::proof_claiming(&message.public_input(chain_id))
                .try_into()
                .expect("fits");
        let domain = get_domain(state, DOMAIN_EXECUTION_PROOF, None);
        SignedExecutionProof {
            message: message.clone(),
            validator_index: validator,
            signature: sign_for(
                validator as usize,
                compute_signing_root(message.hash_tree_root(), domain),
            ),
        }
    }

    #[test]
    fn cheap_checks_run_before_any_state_lookup() {
        let (store, state) = gloas_store();
        let good = proof(&state, 1, 2, CHAIN_ID);

        let mut empty = good.clone();
        empty.message.proof_data = Default::default();
        assert_eq!(
            cheap_checks(&seen(), &store, &empty),
            Err(Outcome::Reject(RejectReason::EmptyExecutionProof))
        );
        let mut unsupported = good.clone();
        unsupported.message.proof_type = 0;
        assert_eq!(
            cheap_checks(&seen(), &store, &unsupported),
            Err(Outcome::Reject(RejectReason::UnsupportedProofType))
        );
        let mut unknown = good.clone();
        unknown.message.head_block_root = Root::repeat_byte(0xaa);
        assert_eq!(
            cheap_checks(&seen(), &store, &unknown),
            Err(Outcome::Ignore(IgnoreReason::UnknownBlock))
        );
        // The proof itself, then the prover, already seen.
        let mut seen_proof = seen();
        assert!(seen_proof.record(&good));
        assert!(!seen_proof.record(&good));
        assert_eq!(
            cheap_checks(&seen_proof, &store, &good),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );
        let mut other_data = good.clone();
        other_data.message.proof_data = vec![9].try_into().expect("fits");
        assert_eq!(
            cheap_checks(&seen_proof, &store, &other_data),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen)),
            "same prover, block and type"
        );
        assert_eq!(cheap_checks(&seen(), &store, &good), Ok(()));
    }

    #[test]
    fn a_verified_proof_of_the_type_already_held_is_ignored() {
        let (mut store, state) = gloas_store();
        let good = proof(&state, 1, 2, CHAIN_ID);
        assert!(store.insert_execution_proof(BLOCK_ROOT, 5, good.clone()));
        assert_eq!(
            cheap_checks(&seen(), &store, &good),
            Err(Outcome::Ignore(IgnoreReason::AlreadyStored))
        );
        let other_type = proof(&state, 2, 2, CHAIN_ID);
        assert_eq!(cheap_checks(&seen(), &store, &other_type), Ok(()));
    }

    #[test]
    fn a_proof_for_a_block_without_a_cached_state_is_ignored() {
        let mut store = store(0);
        store
            .insert_pending_block(BLOCK_ROOT, fulu_block(5))
            .expect("insert the block");
        let state = with_signing_validators_at(ForkName::Gloas, 4);
        let signed = proof(&state, 1, 2, CHAIN_ID);
        assert_eq!(
            stateful_checks(&store, &signed, Some(&MockExecutionProofEngine)),
            Outcome::Ignore(IgnoreReason::StateUnavailable)
        );
    }

    #[test]
    fn the_prover_must_be_a_known_active_validator_with_a_valid_signature() {
        let (store, state) = gloas_store();
        let engine = MockExecutionProofEngine;
        let mut unknown = proof(&state, 1, 2, CHAIN_ID);
        unknown.validator_index = 4;
        assert_eq!(
            stateful_checks(&store, &unknown, Some(&engine)),
            Outcome::Reject(RejectReason::UnknownValidator)
        );
        let mut tampered = proof(&state, 1, 2, CHAIN_ID);
        tampered.message.origin_block_root = Root::repeat_byte(2);
        assert_eq!(
            stateful_checks(&store, &tampered, Some(&engine)),
            Outcome::Reject(RejectReason::BadSignature)
        );
        // An exited validator, in a state the store serves for the block.
        let (mut exited_store, mut exited_state) = gloas_store();
        exited_state.validator_mut(2).expect("in range").exit_epoch = 0;
        exited_store
            .insert_state(BLOCK_ROOT, exited_state.clone())
            .expect("replace the state");
        assert_eq!(
            stateful_checks(
                &exited_store,
                &proof(&exited_state, 1, 2, CHAIN_ID),
                Some(&engine)
            ),
            Outcome::Reject(RejectReason::InactiveValidator)
        );
    }

    #[test]
    fn the_proof_engine_has_the_last_word() {
        let (store, state) = gloas_store();
        let good = proof(&state, 1, 2, CHAIN_ID);
        assert_eq!(
            validate(&seen(), &store, &good, Some(&MockExecutionProofEngine)),
            Outcome::Accept
        );
        // Public values of another chain: authenticated, then refused.
        let other_chain = proof(&state, 1, 3, CHAIN_ID + 1);
        let outcome = stateful_checks(&store, &other_chain, Some(&MockExecutionProofEngine));
        assert_eq!(
            outcome,
            Outcome::Reject(RejectReason::InvalidExecutionProof)
        );
        assert!(authenticated(outcome));
        // No engine: the proof is authenticated but nobody judges it.
        let outcome = stateful_checks(&store, &good, None);
        assert_eq!(outcome, Outcome::Ignore(IgnoreReason::NoConsumer));
        assert!(authenticated(outcome));
        assert!(!authenticated(Outcome::Reject(RejectReason::BadSignature)));
        assert!(!authenticated(Outcome::Ignore(
            IgnoreReason::StateUnavailable
        )));
    }
}
