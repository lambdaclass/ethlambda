//! EIP-8440 execution chain proofs: authenticating a gossiped proof against
//! the beacon state, the public input it must verify against, and the proof
//! engine that verifies it.
//!
//! The specification's `verify_signed_execution_proof` and
//! `process_execution_proof` (`specs/_features/eip8440/beacon-chain.md`) and
//! its `ProofEngine` (`proof-engine.md`). A proof never changes beacon state,
//! fork choice or a payload's status here: the execution client's verdict
//! stays authoritative, and a verified proof is kept for the Beacon API, where
//! a node that cannot execute reads it.

use std::fmt;

use libssz::{SszDecode as _, SszEncode as _};

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::{DOMAIN_EXECUTION_PROOF, is_supported_execution_proof_type};
use crate::beacon::containers::BeaconState;
pub use crate::beacon::containers::execution_proof::{
    ExecutionProof, ExecutionProofPublicInput, MockExecutionProof, ProofData, ProofType,
    SignedExecutionProof,
};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::{get_current_epoch, get_domain};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::helpers::predicates::is_active_validator;
use crate::beacon::primitives::HashTreeRoot as _;

/// The specification's `verify_signed_execution_proof`: the prover is an
/// active validator of `state` and signed the proof under
/// [`DOMAIN_EXECUTION_PROOF`] at the state's epoch, and the proof is non-empty
/// and of a supported type. `state` is the post-state of the proof's head
/// block. Says nothing about the proof's validity, which is the proof
/// engine's to judge.
pub fn verify_signed_execution_proof(
    state: &BeaconState,
    signed_proof: &SignedExecutionProof,
) -> Result<()> {
    let proof = &signed_proof.message;
    let validator = state
        .validator(signed_proof.validator_index)
        .map_err(|_| Error::SpecAssert("signed_proof.validator_index < len(state.validators)"))?;
    verify(!proof.proof_data.is_empty(), "len(proof.proof_data) != 0")?;
    verify(
        is_supported_execution_proof_type(proof.proof_type),
        "proof.proof_type in get_supported_proof_types()",
    )?;
    // Verify the prover is an active validator
    verify(
        is_active_validator(validator, get_current_epoch(state)),
        "is_active_validator(validator, get_current_epoch(state))",
    )?;
    // Verify the prover signature
    let domain = get_domain(
        state,
        DOMAIN_EXECUTION_PROOF,
        Some(compute_epoch_at_slot(state.slot())),
    );
    let signing_root = compute_signing_root(proof.hash_tree_root(), domain);
    verify(
        bls::verify(&validator.pubkey, signing_root, &signed_proof.signature),
        "bls.Verify(validator.pubkey, signing_root, signed_proof.signature)",
    )
}

/// The specification's `process_execution_proof`: authenticate
/// `signed_proof` against `state`, then have `proof_engine` verify the proof
/// against the public input built from its roots and `config`'s chain id.
pub fn process_execution_proof(
    state: &BeaconState,
    signed_proof: &SignedExecutionProof,
    config: &Config,
    proof_engine: &dyn ExecutionProofEngine,
) -> Result<()> {
    verify_signed_execution_proof(state, signed_proof)?;
    let proof = &signed_proof.message;
    let public_input = proof.public_input(config.deposit_chain_id);
    let verdict = proof_engine
        .verify_execution_proof(proof, &public_input)
        .map_err(|_| Error::SpecAssert("proof_engine answered verify_execution_proof"))?;
    verify(
        verdict == ProofVerdict::Valid,
        "proof_engine.verify_execution_proof(signed_proof.message)",
    )
}

/// A proof engine's answer about a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerdict {
    /// The proof verifies against the public input.
    Valid,
    /// It does not: a proof of other payloads, of another chain, or no proof
    /// at all.
    Invalid,
}

/// Why a proof engine could not answer. Distinct from [`ProofVerdict::Invalid`]:
/// nothing here says the proof is bad, so a caller ignores the proof rather
/// than penalising whoever sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofEngineError {
    /// The engine has no verifier for this proof type.
    UnsupportedProofType(ProofType),
    /// The engine could not be reached or failed.
    Unavailable(String),
}

impl fmt::Display for ProofEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProofType(proof_type) => {
                write!(f, "no verifier for execution proof type {proof_type}")
            }
            Self::Unavailable(reason) => write!(f, "proof engine unavailable: {reason}"),
        }
    }
}

impl std::error::Error for ProofEngineError {}

/// The specification's `ProofEngine`. Verification is synchronous because
/// the gossip rules call it from a blocking thread; an engine that talks to a
/// sidecar does its own waiting.
pub trait ExecutionProofEngine: Send + Sync {
    /// `verify_execution_proof`: whether `proof` verifies against
    /// `public_input`, which the caller built from the proof's roots and the
    /// chain's constants.
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
        public_input: &ExecutionProofPublicInput,
    ) -> std::result::Result<ProofVerdict, ProofEngineError>;

    /// A short name for logs and status.
    fn name(&self) -> &'static str;
}

/// Accepts a [`MockExecutionProof`] whose public values are the SSZ encoding
/// of the expected public input, which is what the guest programs shipped so
/// far commit to. Zero padding past the encoding is tolerated, as the OpenVM
/// and ZisK verifiers return fixed-size public values. Devnets only: it
/// proves nothing, and anything that is not a mock proof is `Invalid`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MockExecutionProofEngine;

impl MockExecutionProofEngine {
    /// A mock proof claiming `public_input`, what a mock prover sends.
    pub fn proof_claiming(public_input: &ExecutionProofPublicInput) -> Vec<u8> {
        MockExecutionProof {
            public_values: public_input
                .to_ssz()
                .try_into()
                .expect("a public input is far below the proof size bound"),
            proof: b"mock".to_vec().try_into().expect("four bytes fit"),
        }
        .to_ssz()
    }
}

impl ExecutionProofEngine for MockExecutionProofEngine {
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
        public_input: &ExecutionProofPublicInput,
    ) -> std::result::Result<ProofVerdict, ProofEngineError> {
        let Ok(mock) = MockExecutionProof::from_ssz_bytes(&proof.proof_data) else {
            return Ok(ProofVerdict::Invalid);
        };
        let expected = public_input.to_ssz();
        let committed: &[u8] = &mock.public_values;
        let matches = committed.len() >= expected.len()
            && committed[..expected.len()] == expected[..]
            && committed[expected.len()..].iter().all(|byte| *byte == 0);
        Ok(if matches {
            ProofVerdict::Valid
        } else {
            ProofVerdict::Invalid
        })
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::test_state::{sign_for, with_signing_validators_at};
    use crate::beacon::primitives::Root;

    const CHAIN_ID: u64 = 11_155_111;

    fn proof_for(origin: Root, head: Root, proof_data: Vec<u8>) -> ExecutionProof {
        ExecutionProof {
            proof_data: proof_data.try_into().expect("fits"),
            proof_type: 1,
            origin_block_root: origin,
            head_block_root: head,
        }
    }

    /// A proof over `state`'s chain signed by validator `index`, with mock
    /// proof data claiming its own public input.
    fn signed_by(state: &BeaconState, index: u64) -> SignedExecutionProof {
        let head = Root::repeat_byte(0x33);
        let input = proof_for(head, head, Vec::new()).public_input(CHAIN_ID);
        let message = proof_for(head, head, MockExecutionProofEngine::proof_claiming(&input));
        let domain = get_domain(state, DOMAIN_EXECUTION_PROOF, None);
        let signing_root = compute_signing_root(message.hash_tree_root(), domain);
        SignedExecutionProof {
            message,
            validator_index: index,
            signature: sign_for(index as usize, signing_root),
        }
    }

    fn config() -> Config {
        let mut config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        config.deposit_chain_id = CHAIN_ID;
        config
    }

    fn failed_assertion<T>(result: Result<T>) -> Option<&'static str> {
        match result {
            Err(Error::SpecAssert(what)) => Some(what),
            _ => None,
        }
    }

    #[test]
    fn a_proof_signed_by_an_active_validator_authenticates() {
        let state = with_signing_validators_at(ForkName::Gloas, 4);
        let signed = signed_by(&state, 2);
        verify_signed_execution_proof(&state, &signed).expect("authentic");
        process_execution_proof(&state, &signed, &config(), &MockExecutionProofEngine)
            .expect("verified");
    }

    #[test]
    fn a_tampered_proof_fails_its_signature() {
        let state = with_signing_validators_at(ForkName::Gloas, 4);
        let mut signed = signed_by(&state, 2);
        signed.message.origin_block_root = Root::repeat_byte(0x44);
        assert_eq!(
            failed_assertion(verify_signed_execution_proof(&state, &signed)),
            Some("bls.Verify(validator.pubkey, signing_root, signed_proof.signature)")
        );
    }

    #[test]
    fn an_unknown_empty_or_unsupported_proof_is_refused_before_the_signature() {
        let state = with_signing_validators_at(ForkName::Gloas, 4);
        let mut unknown = signed_by(&state, 2);
        unknown.validator_index = 4;
        assert_eq!(
            failed_assertion(verify_signed_execution_proof(&state, &unknown)),
            Some("signed_proof.validator_index < len(state.validators)")
        );
        let mut empty = signed_by(&state, 2);
        empty.message.proof_data = ProofData::default();
        assert_eq!(
            failed_assertion(verify_signed_execution_proof(&state, &empty)),
            Some("len(proof.proof_data) != 0")
        );
        let mut unsupported = signed_by(&state, 2);
        unsupported.message.proof_type = 0;
        assert_eq!(
            failed_assertion(verify_signed_execution_proof(&state, &unsupported)),
            Some("proof.proof_type in get_supported_proof_types()")
        );
    }

    #[test]
    fn an_exited_validator_cannot_prove() {
        let mut state = with_signing_validators_at(ForkName::Gloas, 4);
        state.validator_mut(2).expect("in range").exit_epoch = 0;
        let signed = signed_by(&state, 2);
        assert_eq!(
            failed_assertion(verify_signed_execution_proof(&state, &signed)),
            Some("is_active_validator(validator, get_current_epoch(state))")
        );
    }

    #[test]
    fn the_mock_engine_accepts_only_its_own_public_values() {
        let head = Root::repeat_byte(0x33);
        let input = proof_for(head, head, Vec::new()).public_input(CHAIN_ID);
        let proof = proof_for(head, head, MockExecutionProofEngine::proof_claiming(&input));
        let engine = MockExecutionProofEngine;
        assert_eq!(
            engine.verify_execution_proof(&proof, &input),
            Ok(ProofVerdict::Valid)
        );
        // Another chain: other public values.
        let other_chain = proof.public_input(CHAIN_ID + 1);
        assert_eq!(
            engine.verify_execution_proof(&proof, &other_chain),
            Ok(ProofVerdict::Invalid)
        );
        // Zero padding after the values, as fixed-size verifiers return them.
        let mut padded = input.to_ssz();
        padded.extend_from_slice(&[0; 21]);
        let padded_proof = proof_for(
            head,
            head,
            MockExecutionProof {
                public_values: padded.try_into().expect("fits"),
                proof: Vec::new().try_into().expect("fits"),
            }
            .to_ssz(),
        );
        assert_eq!(
            engine.verify_execution_proof(&padded_proof, &input),
            Ok(ProofVerdict::Valid)
        );
        // Bytes that are not a mock proof at all.
        let garbage = proof_for(head, head, vec![1, 2, 3]);
        assert_eq!(
            engine.verify_execution_proof(&garbage, &input),
            Ok(ProofVerdict::Invalid)
        );
        // The engine's refusal is a specification assertion for the caller.
        let state = with_signing_validators_at(ForkName::Gloas, 4);
        let mut signed = signed_by(&state, 1);
        signed.message.proof_data = vec![1, 2, 3].try_into().expect("fits");
        let domain = get_domain(&state, DOMAIN_EXECUTION_PROOF, None);
        signed.signature = sign_for(
            1,
            compute_signing_root(signed.message.hash_tree_root(), domain),
        );
        assert_eq!(
            failed_assertion(process_execution_proof(&state, &signed, &config(), &engine)),
            Some("proof_engine.verify_execution_proof(signed_proof.message)")
        );
    }
}
