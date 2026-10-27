//! The `merkle_proof` runner, for fulu's `blob_kzg_commitments` branch.
//!
//! Each case carries a `BeaconBlockBody` and the branch proving its
//! `blob_kzg_commitments` list root sits at its claimed position. This is the
//! one suite that pins the two numbers
//! `verify_data_column_sidecar_inclusion_proof` hard-codes: the depth, and the
//! subtree index the branch was generated for. A wrong index verifies nothing
//! and rejects every honest sidecar.
//!
//! The fixture's `leaf_index` is the *generalized* index, so the subtree index
//! is that minus the tree's leaf offset, which is two to the
//! `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH`th power: Fulu's body's field count
//! rounds up to that many leaves.
//!
//! Cases are selected by name, not fork: deneb and electra ship a differently
//! shaped suite, `blob_kzg_commitment_merkle_proof`, singular: a branch per
//! commitment rather than one for the whole list, which is what fulu's plural
//! `blob_kzg_commitments_merkle_proof` replaced. A later fork reusing fulu's
//! shape would match the same name pattern and land on `case_trial`'s own
//! ignored-until-implemented gate, rather than being dropped here without a
//! trace.
//!
//! Each case also requires the branch `data_columns` builds for the proposer
//! side to equal the fixture's, byte for byte.
//!
//! Each case checks `is_valid_merkle_branch` directly against the fixture's
//! own numbers first, then again through `verify_data_column_sidecar_inclusion_proof`
//! itself with a sidecar built from the fixture: the first half proves the
//! depth and index are right in isolation, the second proves the production
//! function is actually wired to them, and that pairing a valid column with
//! an unrelated block's header is rejected.

use ethlambda_state_transition::beacon::containers::electra::BeaconBlockBody;
use ethlambda_state_transition::beacon::containers::{
    BeaconBlockHeader, SignedBeaconBlockHeader, fulu,
};
use ethlambda_state_transition::beacon::data_columns::blob_kzg_commitments_inclusion_proof;
use ethlambda_state_transition::beacon::fork_choice::verify_data_column_sidecar_inclusion_proof;
use ethlambda_state_transition::beacon::helpers::misc::is_valid_merkle_branch;
use ethlambda_state_transition::beacon::preset;
use ethlambda_state_transition::beacon::primitives::{Bytes32, HashTreeRoot as _};
use libssz::SszDecode as _;
use libtest_mimic::Trial;

use super::{PRESET, collect};

#[derive(serde::Deserialize)]
struct Proof {
    leaf: String,
    leaf_index: u64,
    branch: Vec<String>,
}

/// Parses a fixture's `0x`-prefixed 32-byte hex string.
///
/// Duplicated rather than shared, matching how each runner in this test suite
/// keeps its own parse-and-strip helper (see `fork_choice`'s `parse_root`).
fn bytes32(hex_string: &str) -> Bytes32 {
    let stripped = hex_string.strip_prefix("0x").unwrap_or(hex_string);
    let bytes = hex::decode(stripped).expect("a hex-encoded 32-byte value");
    Bytes32::from_slice(&bytes)
}

pub fn trials() -> Vec<Trial> {
    let cases: Vec<_> = collect(PRESET, "merkle_proof", "single_merkle_proof")
        .into_iter()
        .filter(|case| case.name.contains("blob_kzg_commitments_"))
        .collect();

    let mut trials = vec![super::discovery_trial("merkle_proof", cases.len())];

    for case in cases {
        trials.push(super::case_trial("merkle_proof", case, move |case| {
            let body = BeaconBlockBody::from_ssz_bytes(&case.ssz_bytes("object"))
                .map_err(|err| format!("body decode failed: {err:?}"))?;
            let proof: Proof = case.yaml("proof");

            let leaf = body.blob_kzg_commitments.hash_tree_root();
            if leaf != bytes32(&proof.leaf) {
                return Err(format!(
                    "the commitments list root {leaf:?} is not the fixture's leaf {}",
                    proof.leaf
                ));
            }

            let depth = preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH as u64;
            let subtree_index = proof.leaf_index - 2u64.pow(depth as u32);
            let branch: Vec<Bytes32> = proof.branch.iter().map(|node| bytes32(node)).collect();

            if branch.len() as u64 != depth {
                return Err(format!(
                    "the fixture branch is {} deep, the preset says {depth}",
                    branch.len()
                ));
            }

            if !is_valid_merkle_branch(leaf, &branch, depth, subtree_index, body.hash_tree_root()) {
                return Err("the fixture branch did not verify against the body root".to_string());
            }

            // The branch the proposer side builds must be the fixture's own.
            let built = blob_kzg_commitments_inclusion_proof(&body);
            if built.iter().copied().collect::<Vec<_>>() != branch {
                return Err(format!(
                    "built branch {built:?} differs from the fixture's {branch:?}"
                ));
            }

            // The index is load-bearing, not decoration: the same branch at a
            // neighbouring position must fail, or the check proves nothing.
            if is_valid_merkle_branch(
                leaf,
                &branch,
                depth,
                subtree_index ^ 1,
                body.hash_tree_root(),
            ) {
                return Err("the branch verified at the wrong index".to_string());
            }

            // The checks above only prove is_valid_merkle_branch itself is
            // sound at this depth and index; they never call
            // verify_data_column_sidecar_inclusion_proof, so a wrong constant
            // wired into *that* function would slip past every case above.
            // Build a sidecar naming this body's root and drive the real
            // function with it, fields verify_data_column_sidecar (the
            // structural check) already owns left at defaults.
            let sidecar = fulu::DataColumnSidecar {
                index: 0,
                column: Default::default(),
                kzg_commitments: body.blob_kzg_commitments.clone(),
                kzg_proofs: Default::default(),
                signed_block_header: SignedBeaconBlockHeader {
                    message: BeaconBlockHeader {
                        slot: 0,
                        proposer_index: 0,
                        parent_root: Bytes32::ZERO,
                        state_root: Bytes32::ZERO,
                        body_root: body.hash_tree_root(),
                    },
                    signature: Default::default(),
                },
                kzg_commitments_inclusion_proof: branch
                    .try_into()
                    .map_err(|err| format!("branch is not depth-sized: {err:?}"))?,
            };

            if !verify_data_column_sidecar_inclusion_proof(&sidecar) {
                return Err(
                    "verify_data_column_sidecar_inclusion_proof rejected a fixture-valid sidecar"
                        .to_string(),
                );
            }

            // The property this whole check exists for: pairing a genuinely
            // valid column with a different block's header must fail, since
            // the KZG checks alone cannot tell the two apart.
            let mut wrong_block = sidecar;
            wrong_block.signed_block_header.message.body_root = Bytes32::repeat_byte(0xff);
            if verify_data_column_sidecar_inclusion_proof(&wrong_block) {
                return Err(
                    "verify_data_column_sidecar_inclusion_proof accepted a sidecar against an \
                     unrelated block"
                        .to_string(),
                );
            }

            Ok(())
        }));
    }

    trials
}
