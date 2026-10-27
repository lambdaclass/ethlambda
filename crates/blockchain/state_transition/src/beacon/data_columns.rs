//! Data column sidecars for a proposer's block: built from the block and its
//! blobs, and verified before they are gossiped.
//!
//! Mirrors "Constructing the sidecars" in the fulu `validator.md`. The
//! execution client hands a proposer the blobs and one KZG proof per cell
//! (`BlobsBundleV2`); the node turns those into one [`DataColumnSidecar`] per
//! column. The proofs come from an external party, so
//! [`verified_sidecars`] checks them against the block's own commitments
//! before anything is built, instead of gossiping sidecars that every peer
//! would reject.

use libssz_types::{SszList, SszVector};
use rayon::prelude::*;

use crate::beacon::containers::deneb::{Blob, KzgCommitments};
use crate::beacon::containers::fulu::{self, DataColumnSidecar, KzgCommitmentsInclusionProof};
use crate::beacon::containers::{BeaconBlockHeader, SignedBeaconBlockHeader, electra};
use crate::beacon::fork_choice::BLOB_KZG_COMMITMENTS_SUBTREE_INDEX;
use crate::beacon::hash::hash_concat;
use crate::beacon::kzg::{self, CellsPerExtBlob};
use crate::beacon::preset::{
    CELLS_PER_EXT_BLOB, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH, NUMBER_OF_COLUMNS,
};
use crate::beacon::primitives::{Bytes32, HashTreeRoot as _, KzgProof, Root};

/// One blob's cell proofs, one per cell.
pub type ProofsPerBlob = [KzgProof; CELLS_PER_EXT_BLOB];

// The sidecar loop runs over columns and indexes cells and proofs by column,
// which is only sound while the two counts coincide.
const _: () = assert!(NUMBER_OF_COLUMNS == CELLS_PER_EXT_BLOB);

/// Leaves of the body's merkle tree: its field count rounded up to a power of
/// two, which is what `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH` counts.
const BODY_LEAVES: usize = 1 << KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH;

/// Why a block's blob material cannot become sidecars.
#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    /// Counts that disagree: blobs vs commitments, or proofs vs
    /// `blobs * CELLS_PER_EXT_BLOB`. The message names which.
    #[error("{0}")]
    Shape(&'static str),
    /// A blob is not a valid polynomial evaluation (`compute_cells` failed).
    #[error("a blob is not a valid polynomial evaluation")]
    InvalidBlob,
    /// The batch cell-proof check failed: some proof does not open its cell
    /// against its blob's commitment.
    #[error("the cell proofs do not verify against the block's commitments")]
    InvalidProofs,
}

/// The `blob_kzg_commitments` branch of `body`: `compute_merkle_proof(body,
/// get_generalized_index(BeaconBlockBody, "blob_kzg_commitments"))`.
///
/// Built from the body's field roots rather than a generic proof routine, since
/// the position is a fixed constant; the folded root is asserted against
/// `body.hash_tree_root()` in debug builds so a field-order mistake fails
/// loudly in tests.
pub fn blob_kzg_commitments_inclusion_proof(
    body: &electra::BeaconBlockBody,
) -> KzgCommitmentsInclusionProof {
    let (branch, root) = inclusion_proof_and_body_root(body);
    debug_assert_eq!(root, body.hash_tree_root());
    branch
}

/// The branch together with the body root it was folded up to, so a caller
/// that needs both does not merkleize the body twice.
fn inclusion_proof_and_body_root(
    body: &electra::BeaconBlockBody,
) -> (KzgCommitmentsInclusionProof, Root) {
    let leaves: [Root; BODY_LEAVES] = [
        body.randao_reveal.hash_tree_root(),
        body.eth1_data.hash_tree_root(),
        body.graffiti.hash_tree_root(),
        body.proposer_slashings.hash_tree_root(),
        body.attester_slashings.hash_tree_root(),
        body.attestations.hash_tree_root(),
        body.deposits.hash_tree_root(),
        body.voluntary_exits.hash_tree_root(),
        body.sync_aggregate.hash_tree_root(),
        body.execution_payload.hash_tree_root(),
        body.bls_to_execution_changes.hash_tree_root(),
        body.blob_kzg_commitments.hash_tree_root(),
        body.execution_requests.hash_tree_root(),
        Root::ZERO,
        Root::ZERO,
        Root::ZERO,
    ];
    let mut layer = leaves.to_vec();
    let mut index = BLOB_KZG_COMMITMENTS_SUBTREE_INDEX as usize;
    let mut branch: Vec<Bytes32> = Vec::with_capacity(KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH);
    while layer.len() > 1 {
        branch.push(layer[index ^ 1]);
        layer = layer
            .chunks(2)
            .map(|pair| hash_concat(pair[0].as_slice(), pair[1].as_slice()))
            .collect();
        index /= 2;
    }
    let branch = branch
        .try_into()
        .expect("the branch has exactly KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH nodes");
    (branch, layer[0])
}

/// `compute_signed_block_header`: the block's header with its body replaced by
/// the body's root, under the block's own signature.
pub fn signed_block_header(block: &electra::SignedBeaconBlock) -> SignedBeaconBlockHeader {
    header_with_body_root(block, block.message.body.hash_tree_root())
}

fn header_with_body_root(
    block: &electra::SignedBeaconBlock,
    body_root: Root,
) -> SignedBeaconBlockHeader {
    let message = &block.message;
    SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot: message.slot,
            proposer_index: message.proposer_index,
            parent_root: message.parent_root,
            state_root: message.state_root,
            body_root,
        },
        signature: block.signature,
    }
}

/// The specification's `get_data_column_sidecars`. `cells_and_proofs[i]` is
/// blob `i`'s cells and its `CELLS_PER_EXT_BLOB` proofs.
///
/// # Panics
///
/// If `cells_and_proofs` and `kzg_commitments` differ in length, the
/// specification's own assertion; [`verified_sidecars`] checks it first.
pub fn get_data_column_sidecars(
    signed_block_header: &SignedBeaconBlockHeader,
    kzg_commitments: &KzgCommitments,
    inclusion_proof: &KzgCommitmentsInclusionProof,
    cells_and_proofs: &[(Box<CellsPerExtBlob>, &ProofsPerBlob)],
) -> Vec<DataColumnSidecar> {
    assert_eq!(
        cells_and_proofs.len(),
        kzg_commitments.len(),
        "one cells-and-proofs entry per commitment"
    );
    (0..NUMBER_OF_COLUMNS)
        .map(|column_index| {
            let column: Vec<fulu::Cell> = cells_and_proofs
                .iter()
                .map(|(cells, _)| {
                    SszVector::try_from(cells[column_index].to_bytes().to_vec())
                        .expect("a c-kzg cell is BYTES_PER_CELL bytes")
                })
                .collect();
            let kzg_proofs: Vec<KzgProof> = cells_and_proofs
                .iter()
                .map(|(_, proofs)| proofs[column_index])
                .collect();
            DataColumnSidecar {
                index: column_index as u64,
                column: SszList::try_from(column)
                    .expect("a block holds at most MAX_BLOB_COMMITMENTS_PER_BLOCK blobs"),
                kzg_commitments: kzg_commitments.clone(),
                kzg_proofs: SszList::try_from(kzg_proofs)
                    .expect("a block holds at most MAX_BLOB_COMMITMENTS_PER_BLOCK blobs"),
                signed_block_header: signed_block_header.clone(),
                kzg_commitments_inclusion_proof: inclusion_proof.clone(),
            }
        })
        .collect()
}

/// The specification's `get_data_column_sidecars_from_block`.
///
/// # Panics
///
/// If `cells_and_proofs` and the block's commitments differ in length; see
/// [`get_data_column_sidecars`].
pub fn get_data_column_sidecars_from_block(
    block: &electra::SignedBeaconBlock,
    cells_and_proofs: &[(Box<CellsPerExtBlob>, &ProofsPerBlob)],
) -> Vec<DataColumnSidecar> {
    let (inclusion_proof, body_root) = inclusion_proof_and_body_root(&block.message.body);
    get_data_column_sidecars(
        &header_with_body_root(block, body_root),
        &block.message.body.blob_kzg_commitments,
        &inclusion_proof,
        cells_and_proofs,
    )
}

/// What a proposer's node runs before gossiping a block it was handed with
/// its blobs: check the counts, compute every blob's cells (in parallel, one
/// blob per task), batch-verify every cell proof against the block's
/// commitments, then build all `NUMBER_OF_COLUMNS` sidecars. Nothing is built
/// unless everything verifies. A block with zero blobs yields no sidecars:
/// `verify_data_column_sidecar` rejects a sidecar with zero commitments, so
/// there is nothing to publish. `cell_proofs` is flattened blob by blob, as
/// `BlobsBundleV2` and fulu's `BlockContents` carry it.
pub fn verified_sidecars(
    block: &electra::SignedBeaconBlock,
    blobs: &[Blob],
    cell_proofs: &[KzgProof],
) -> Result<Vec<DataColumnSidecar>, SidecarError> {
    let commitments = &block.message.body.blob_kzg_commitments;
    if blobs.len() != commitments.len() {
        return Err(SidecarError::Shape(
            "the number of blobs differs from the block's commitments",
        ));
    }
    if cell_proofs.len() != blobs.len() * CELLS_PER_EXT_BLOB {
        return Err(SidecarError::Shape(
            "the number of cell proofs is not blobs * CELLS_PER_EXT_BLOB",
        ));
    }
    if blobs.is_empty() {
        return Ok(Vec::new());
    }

    let all_cells: Vec<Box<CellsPerExtBlob>> = blobs
        .par_iter()
        .map(|blob| kzg::compute_cells(&blob[..]).map_err(|_| SidecarError::InvalidBlob))
        .collect::<Result<_, _>>()?;

    let mut batch_commitments = Vec::with_capacity(cell_proofs.len());
    let mut batch_indices = Vec::with_capacity(cell_proofs.len());
    let mut batch_cells = Vec::with_capacity(cell_proofs.len());
    for (commitment, cells) in commitments.iter().zip(&all_cells) {
        for (cell_index, cell) in cells.iter().enumerate() {
            batch_commitments.push(*commitment);
            batch_indices.push(cell_index as u64);
            batch_cells.push(*cell);
        }
    }
    let verified = kzg::verify_cell_kzg_proof_batch(
        &batch_commitments,
        &batch_indices,
        &batch_cells,
        cell_proofs,
    )
    .map_err(|_| SidecarError::InvalidProofs)?;
    if !verified {
        return Err(SidecarError::InvalidProofs);
    }

    // The shape check above made the length an exact multiple, so no remainder.
    let (proof_chunks, _) = cell_proofs.as_chunks::<CELLS_PER_EXT_BLOB>();
    let cells_and_proofs: Vec<(Box<CellsPerExtBlob>, &ProofsPerBlob)> =
        all_cells.into_iter().zip(proof_chunks).collect();
    Ok(get_data_column_sidecars_from_block(
        block,
        &cells_and_proofs,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::config::Config;
    use crate::beacon::fork_choice::{
        verify_data_column_sidecar, verify_data_column_sidecar_inclusion_proof,
        verify_data_column_sidecar_kzg_proofs,
    };
    use crate::beacon::preset::BYTES_PER_BLOB;
    use crate::beacon::primitives::{BLS_SIGNATURE_SIZE, BlsSignature};

    /// A blob whose every field element is below the BLS modulus: the first
    /// byte of each 32-byte element is zero, the rest are `seed`-derived.
    fn blob(seed: u8) -> Blob {
        let mut bytes = vec![0u8; BYTES_PER_BLOB];
        for (i, element) in bytes.chunks_mut(32).enumerate() {
            element[1] = seed;
            element[2] = i as u8;
            element[3] = (i >> 8) as u8;
        }
        SszVector::try_from(bytes).expect("exactly BYTES_PER_BLOB bytes")
    }

    /// A fulu signed block whose body commits to `blobs`, plus every blob's
    /// cell proofs flattened blob by blob, as `getPayloadV5` returns them.
    fn block_with(blobs: &[Blob]) -> (electra::SignedBeaconBlock, Vec<KzgProof>) {
        let commitments: Vec<_> = blobs
            .iter()
            .map(|blob| kzg::blob_to_kzg_commitment(&blob[..]).unwrap())
            .collect();
        let proofs: Vec<KzgProof> = blobs
            .iter()
            .flat_map(|blob| {
                kzg::compute_cells_and_kzg_proofs(&blob[..])
                    .unwrap()
                    .1
                    .to_vec()
            })
            .collect();
        let mut body = electra::BeaconBlockBody::empty();
        body.blob_kzg_commitments = SszList::try_from(commitments).unwrap();
        let block = electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot: 1,
                proposer_index: 0,
                parent_root: Root::repeat_byte(0x11),
                state_root: Root::repeat_byte(0x22),
                body,
            },
            signature: BlsSignature([0x33; BLS_SIGNATURE_SIZE]),
        };
        (block, proofs)
    }

    #[test]
    fn every_sidecar_of_a_two_blob_block_verifies() {
        let blobs = [blob(1), blob(2)];
        let (block, proofs) = block_with(&blobs);
        let sidecars = verified_sidecars(&block, &blobs, &proofs).unwrap();
        assert_eq!(sidecars.len(), NUMBER_OF_COLUMNS);
        for (index, sidecar) in sidecars.iter().enumerate() {
            assert_eq!(sidecar.index, index as u64);
            assert_eq!(sidecar.column.len(), 2);
            assert_eq!(
                sidecar.signed_block_header.message.hash_tree_root(),
                block.message.hash_tree_root()
            );
            assert_eq!(sidecar.signed_block_header.signature, block.signature);
            assert!(verify_data_column_sidecar(sidecar, &Config::mainnet()));
            assert!(verify_data_column_sidecar_inclusion_proof(sidecar));
            assert!(verify_data_column_sidecar_kzg_proofs(sidecar).unwrap());
        }
    }

    #[test]
    fn a_wrong_cell_proof_fails_verification() {
        let blobs = [blob(1), blob(2)];
        let (block, mut proofs) = block_with(&blobs);
        proofs.swap(0, 1);
        assert!(matches!(
            verified_sidecars(&block, &blobs, &proofs),
            Err(SidecarError::InvalidProofs)
        ));
    }

    #[test]
    fn a_block_without_blobs_has_no_sidecars() {
        let (block, proofs) = block_with(&[]);
        assert!(verified_sidecars(&block, &[], &proofs).unwrap().is_empty());
    }

    #[test]
    fn mismatched_lengths_are_refused_before_any_kzg_work() {
        let blobs = [blob(1)];
        let (block, proofs) = block_with(&blobs);
        assert!(matches!(
            verified_sidecars(&block, &[], &proofs),
            Err(SidecarError::Shape(_))
        ));
        assert!(matches!(
            verified_sidecars(&block, &blobs, &proofs[..proofs.len() - 1]),
            Err(SidecarError::Shape(_))
        ));
    }

    #[test]
    fn shape_is_checked_before_the_blobs_are_looked_at() {
        let (block, proofs) = block_with(&[blob(1)]);
        let mut bad = blob(1);
        bad[0] = 0xff;
        assert!(matches!(
            verified_sidecars(&block, &[bad], &proofs[..proofs.len() - 1]),
            Err(SidecarError::Shape(_))
        ));
    }

    #[test]
    fn a_non_canonical_field_element_is_an_invalid_blob() {
        let (block, proofs) = block_with(&[blob(1)]);
        let mut bad = blob(1);
        bad[0] = 0xff;
        assert!(matches!(
            verified_sidecars(&block, &[bad], &proofs),
            Err(SidecarError::InvalidBlob)
        ));
    }
}
