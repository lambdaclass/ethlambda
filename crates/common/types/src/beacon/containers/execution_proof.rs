//! EIP-8440 execution chain proofs: the containers a prover gossips and the
//! public input a proof commits to.
//!
//! An execution chain proof attests that every execution payload from the
//! beacon block at `origin_block_root` to the one at `head_block_root`
//! executed validly and is bound to its beacon block. A node that sees a
//! verified proof whose origin is at or before its trusted checkpoint has
//! established valid execution up to the proof's head without executing
//! anything. The containers follow consensus-specs PR #5725
//! (`specs/_features/eip8440/beacon-chain.md`), which replaces EIP-8025's
//! single-payload `ExecutionProofEnvelope`; that earlier shape never shipped
//! here.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use crate::beacon::constants::{MAX_PROOF_SIZE, STATELESS_INPUT_SCHEMA_ID};
use crate::beacon::primitives::{BlsSignature, Root, ValidatorIndex};

/// `ProofType`: the proof system, guest program and version a proof was made
/// with. An assignment names an immutable combination and is never reused.
pub type ProofType = u8;

/// `ProofData`: the opaque proof bytes, bounded by [`MAX_PROOF_SIZE`].
pub type ProofData = SszList<u8, { MAX_PROOF_SIZE }>;

/// `ExecutionProof`: what a prover's guest program produced, and the two
/// beacon blocks it spans.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct ExecutionProof {
    #[serde(with = "crate::beacon::serde_helpers::ssz_hex")]
    pub proof_data: ProofData,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub proof_type: ProofType,
    /// The beacon block the prover started its recursion at. A proof that
    /// starts a recursion has it equal to `head_block_root`.
    pub origin_block_root: Root,
    /// The beacon block whose payload the proof's last step proved.
    pub head_block_root: Root,
}

impl ExecutionProof {
    /// The public input this proof must verify against on the chain whose
    /// `DEPOSIT_CHAIN_ID` is `chain_id`: the specification's
    /// `verify_execution_proof` builds it from the proof's two roots and the
    /// chain's constants, never from anything else the prover sent.
    pub fn public_input(&self, chain_id: u64) -> ExecutionProofPublicInput {
        ExecutionProofPublicInput {
            origin_block_root: self.origin_block_root,
            head_block_root: self.head_block_root,
            chain_id,
            schema_id: STATELESS_INPUT_SCHEMA_ID,
        }
    }

    /// Whether this proof starts a recursion rather than extending one.
    pub fn starts_recursion(&self) -> bool {
        self.origin_block_root == self.head_block_root
    }
}

/// `SignedExecutionProof`: a proof with the active validator that put it on
/// the wire. The signature gates gossip; it says nothing about the proof's
/// validity, which only the proof engine judges.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct SignedExecutionProof {
    pub message: ExecutionProof,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_index: ValidatorIndex,
    pub signature: BlsSignature,
}

/// `PublicInput`: the `ProgressiveContainer` a chain proof is verified
/// against. Its `hash_tree_root` is the proof system's public input, and its
/// SSZ encoding is what the guest programs shipped so far commit to.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(progressive_container)]
pub struct ExecutionProofPublicInput {
    pub origin_block_root: Root,
    pub head_block_root: Root,
    /// `DEPOSIT_CHAIN_ID` of the chain the proof is for.
    pub chain_id: u64,
    /// [`STATELESS_INPUT_SCHEMA_ID`]: the execution rules the guest applied.
    pub schema_id: u16,
}

/// The proof a mock zkVM emits in place of a real one (zkboost's `MockProof`):
/// the public values a real proof of the same payloads would commit to, and
/// bytes that prove nothing. Only a proof engine told to accept mock proofs
/// reads it, and only a devnet should run one.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct MockExecutionProof {
    pub public_values: SszList<u8, { MAX_PROOF_SIZE }>,
    pub proof: SszList<u8, { MAX_PROOF_SIZE }>,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;
    use crate::beacon::constants::MAX_SIGNED_EXECUTION_PROOF_SIZE;
    use crate::beacon::primitives::HashTreeRoot as _;

    fn proof(data: &[u8]) -> ExecutionProof {
        ExecutionProof {
            proof_data: data.to_vec().try_into().expect("within the bound"),
            proof_type: 2,
            origin_block_root: Root::repeat_byte(1),
            head_block_root: Root::repeat_byte(2),
        }
    }

    /// The vector `ethrex`'s partial stateful node pins for the same
    /// container, so both ends of an EIP-8440 exchange agree on the root a
    /// proof engine is asked about. `libssz-merkle` has these roots checked
    /// against the reference implementation.
    #[test]
    fn public_input_root_matches_the_reference_vector() {
        let input = proof(&[1]).public_input(11_155_111);
        assert_eq!(input.schema_id, 0x1501);
        assert_eq!(
            format!("{:x}", input.hash_tree_root()),
            "b3bcb392d38b0de2ac42676fedbd236cd676c249fa72e3ab1af73dd1b41e634e"
        );
    }

    #[test]
    fn public_input_ssz_is_the_fields_in_order() {
        let input = proof(&[1]).public_input(7);
        let mut expected = Vec::new();
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&[2; 32]);
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&0x1501u16.to_le_bytes());
        assert_eq!(input.to_ssz(), expected);
        assert_eq!(
            ExecutionProofPublicInput::from_ssz_bytes(&expected).expect("decodes"),
            input
        );
    }

    #[test]
    fn a_signed_proof_round_trips_through_json_and_ssz() {
        let signed = SignedExecutionProof {
            message: proof(&[0xaa, 0xbb]),
            validator_index: 42,
            signature: BlsSignature([9; 96]),
        };
        let json = serde_json::to_value(&signed).expect("serializes");
        assert_eq!(json["message"]["proof_data"], "0xaabb");
        assert_eq!(json["message"]["proof_type"], "2");
        assert_eq!(json["validator_index"], "42");
        let back: SignedExecutionProof = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, signed);
        let back = SignedExecutionProof::from_ssz_bytes(&signed.to_ssz()).expect("decodes");
        assert_eq!(back, signed);
    }

    #[test]
    fn the_wire_bound_is_the_size_of_a_full_proof() {
        let signed = SignedExecutionProof {
            message: proof(&vec![0; MAX_PROOF_SIZE]),
            validator_index: 0,
            signature: BlsSignature([0; 96]),
        };
        assert_eq!(signed.to_ssz().len(), MAX_SIGNED_EXECUTION_PROOF_SIZE);
        assert!(ProofData::try_from(vec![0; MAX_PROOF_SIZE + 1]).is_err());
    }

    /// The layout `decodeMockProof` in other clients relies on: two offsets,
    /// the first of them 8, then the public values, then the proof bytes.
    #[test]
    fn a_mock_proof_encodes_as_two_offset_lists() {
        let mock = MockExecutionProof {
            public_values: vec![1, 2, 3].try_into().expect("fits"),
            proof: vec![9].try_into().expect("fits"),
        };
        let bytes = mock.to_ssz();
        assert_eq!(&bytes[0..4], &8u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &11u32.to_le_bytes());
        assert_eq!(&bytes[8..], &[1, 2, 3, 9]);
        assert_eq!(
            MockExecutionProof::from_ssz_bytes(&bytes).expect("decodes"),
            mock
        );
    }
}
