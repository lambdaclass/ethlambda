//! What `produceBlockV3` returns and `publishBlockV2` takes, as SSZ.
//!
//! The SSZ counterpart to [`super::dto`], and here for the same reason those
//! types are: these are shapes of one transport, not of the chain. The
//! difference is that this transport is the one that matters for a block.
//!
//! # Why SSZ rather than the JSON this crate uses everywhere else
//!
//! To sign a block this client must compute its `hash_tree_root`, and a root
//! can only be computed from the typed container. Going through JSON would
//! mean hand-writing a field-for-field mapping of an entire `BeaconBlockBody`,
//! its `ExecutionPayload`, and every operation list inside them, and then
//! trusting that mapping to be exact: a single wrong field order, a missing
//! list, one integer read as decimal that was meant as hex, and the client
//! signs a root that is not the block's. The failure is silent at the point it
//! happens and shows up as a block the network rejects.
//!
//! Decoding the specification's own serialization removes that whole class of
//! bug. The bytes the beacon node sent *are* the block; the root falls out of
//! it.
//!
//! The endpoints support it: `Accept: application/octet-stream` on
//! `produceBlockV3`, `Content-Type: application/octet-stream` on
//! `publishBlockV2`.
//!
//! # `BlockContents` is not a consensus container
//!
//! It is defined in `ethereum/beacon-APIs` and nowhere else. `consensus-specs`
//! never mentions the name, and therefore never states its SSZ encoding
//! either: the three-field container below is what every implementation
//! encodes and decodes, but it is convention rather than specification. That is
//! precisely why it lives in this crate rather than in `ethlambda-types`, which
//! is the authority on containers the chain itself agrees about.
//!
//! # What the block is wrapped in, per fork
//!
//! From Deneb onward a produced block does not travel alone: it comes with the
//! blobs it commits to and the proofs for them, because the beacon node has to
//! broadcast those alongside the block and cannot reconstruct them from the
//! block itself.
//!
//! | Fork | Produced | Published |
//! |---|---|---|
//! | Deneb, Electra, Fulu | `BlockContents` | `SignedBlockContents` |
//! | Gloas and later | `GloasBlockContents` (block and self-built envelope) or a bare block | bare signed block, then the envelope separately |
//!
//! # Gloas
//!
//! The block no longer carries the payload (EIP-7732): it commits to a bid, and
//! the payload travels in an `ExecutionPayloadEnvelope` the builder reveals
//! afterwards. With `include_payload=true` the node hands back the block and the
//! envelope for a self-built payload together as [`GloasBlockContents`], and
//! says so in `Eth-Execution-Payload-Included`; without it the body is a bare
//! block and the envelope is fetched separately. Publication is split the same
//! way: the bare signed block first, then the signed envelope, with the blobs
//! and cell proofs moving into the envelope's contents.
//!
//! Deneb shares that envelope but not the block inside it: its
//! `BeaconBlockBody` has twelve fields where electra's has thirteen, so the two
//! have different fixed-size prefixes and a deneb body cannot be decoded as an
//! electra one. Rather than carry a second container pair, this client refuses
//! deneb outright. It could not serve such a chain anyway: the attestations it
//! submits are electra's `SingleAttestation`, which has no pre-electra form.
//!
//! Fulu is the trap. PeerDAS did **not** turn the response back into a bare
//! block, which is the natural guess given that fulu moves blob distribution to
//! column sampling. The container is unchanged in shape. What changed is
//! `kzg_proofs`: it carries one proof per *cell* rather than one per blob, so
//! its element count is `CELLS_PER_EXT_BLOB` times larger and its SSZ list
//! limit is `FIELD_ELEMENTS_PER_EXT_BLOB * MAX_BLOB_COMMITMENTS_PER_BLOCK`
//! rather than `MAX_BLOB_COMMITMENTS_PER_BLOCK`.
//!
//! The limit is where reusing one type for both forks goes wrong, and it is
//! worth being precise about when. An SSZ list's limit bounds how many
//! elements decode, so the electra container rejects any body carrying more
//! than `MAX_BLOB_COMMITMENTS_PER_BLOCK` proofs. A fulu block carries
//! `CELLS_PER_EXT_BLOB` of them per blob, so the two limits agree until a
//! block holds more than `MAX_BLOB_COMMITMENTS_PER_BLOCK / CELLS_PER_EXT_BLOB`
//! blobs, which is thirty-two.
//!
//! Today's blocks are nowhere near that, so a single shared type would appear
//! to work. It would stop working silently, because fulu made the per-block
//! blob limit a function of the epoch rather than a fixed preset, precisely so
//! that later forks can raise it without a new container. The first block past
//! thirty-two blobs would fail to decode, in a client that had been correct for
//! months.

use ethlambda_types::beacon::containers::deneb::Blob;
use ethlambda_types::beacon::containers::electra::{BeaconBlock, SignedBeaconBlock};
use ethlambda_types::beacon::containers::gloas;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{BlsSignature, KzgProof};
use libssz::{SszDecode, SszEncode};
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszList;

// `Result` is deliberately not imported. `libssz_derive`'s generated code
// names `Result` unqualified and means `std`'s, so this crate's one-argument
// alias in scope would make every derive in this file fail to compile.
use crate::error::Error;

/// One proof per blob, as deneb and electra produce them.
pub type BlobKzgProofs = SszList<KzgProof, { preset::MAX_BLOB_COMMITMENTS_PER_BLOCK }>;

/// One proof per *cell*, as fulu produces them under EIP-7594.
///
/// The limit is `FIELD_ELEMENTS_PER_EXT_BLOB * MAX_BLOB_COMMITMENTS_PER_BLOCK`,
/// which is the bound `CellKZGProofs` carries in the fulu validator guide. It
/// is far larger than the count any real block holds (`CELLS_PER_EXT_BLOB` per
/// blob, so 768 for six blobs) because an SSZ limit bounds the type, not the
/// value.
pub type CellKzgProofs = SszList<
    KzgProof,
    { preset::FIELD_ELEMENTS_PER_EXT_BLOB * preset::MAX_BLOB_COMMITMENTS_PER_BLOCK },
>;

pub type Blobs = SszList<Blob, { preset::MAX_BLOB_COMMITMENTS_PER_BLOCK }>;

/// `produceBlockV3`'s body for deneb and electra.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode)]
pub struct BlockContents {
    pub block: BeaconBlock,
    pub kzg_proofs: BlobKzgProofs,
    pub blobs: Blobs,
}

/// `publishBlockV2`'s body for deneb and electra.
///
/// The same three fields with the block signed. Field order and names are
/// load-bearing: SSZ encodes by declaration order, so swapping two fields
/// produces bytes a node decodes into a different block without complaining.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode)]
pub struct SignedBlockContents {
    pub signed_block: SignedBeaconBlock,
    pub kzg_proofs: BlobKzgProofs,
    pub blobs: Blobs,
}

/// `produceBlockV3`'s body for fulu. See the module doc for why this is not
/// [`BlockContents`].
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode)]
pub struct FuluBlockContents {
    pub block: BeaconBlock,
    pub kzg_proofs: CellKzgProofs,
    pub blobs: Blobs,
}

/// `publishBlockV2`'s body for fulu.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode)]
pub struct FuluSignedBlockContents {
    pub signed_block: SignedBeaconBlock,
    pub kzg_proofs: CellKzgProofs,
    pub blobs: Blobs,
}

/// `produceBlockV4`'s body for gloas when the node includes the payload: the
/// block, the envelope revealing the self-built payload it commits to, and the
/// blob material that goes out with the envelope. Not a consensus container; see
/// the module doc.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode)]
pub struct GloasBlockContents {
    pub block: gloas::BeaconBlock,
    pub execution_payload_envelope: gloas::ExecutionPayloadEnvelope,
    pub kzg_proofs: CellKzgProofs,
    pub blobs: Blobs,
}

/// `publishExecutionPayloadEnvelope`'s body for gloas when the client supplies
/// the blobs (`Eth-Blob-Data-Included: true`).
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode)]
pub struct SignedExecutionPayloadEnvelopeContents {
    pub signed_execution_payload_envelope: gloas::SignedExecutionPayloadEnvelope,
    pub kzg_proofs: CellKzgProofs,
    pub blobs: Blobs,
}

/// The envelope and blob material that came with a gloas block, kept apart from
/// the block because it is published separately and after it.
#[derive(Debug, Clone, PartialEq)]
pub struct GloasPayload {
    pub envelope: gloas::ExecutionPayloadEnvelope,
    pub kzg_proofs: CellKzgProofs,
    pub blobs: Blobs,
}

impl GloasPayload {
    /// Attach `signature` and encode the body for `Eth-Blob-Data-Included: true`.
    pub fn into_signed_contents_ssz(self, signature: BlsSignature) -> Vec<u8> {
        SignedExecutionPayloadEnvelopeContents {
            signed_execution_payload_envelope: gloas::SignedExecutionPayloadEnvelope {
                message: self.envelope,
                signature,
            },
            kzg_proofs: self.kzg_proofs,
            blobs: self.blobs,
        }
        .to_ssz()
    }
}

/// Encode a bare signed envelope, the body for `Eth-Blob-Data-Included: false`,
/// where the node attaches the blobs it cached at production time.
pub fn signed_envelope_ssz(
    envelope: gloas::ExecutionPayloadEnvelope,
    signature: BlsSignature,
) -> Vec<u8> {
    gloas::SignedExecutionPayloadEnvelope {
        message: envelope,
        signature,
    }
    .to_ssz()
}

/// A block a beacon node produced, with whatever travelled alongside it.
///
/// The proofs and blobs are kept in the shape they arrived in rather than
/// merged into one type, because the two shapes have different SSZ list limits
/// and merging them would mean re-encoding a fulu block's proofs under deneb's
/// tree depth.
#[derive(Debug, Clone, PartialEq)]
pub struct ProducedBlock {
    /// The fork the beacon node named, kept because publishing has to name the
    /// same one back.
    ///
    /// Not recomputed from the slot. The publish body is a re-encoding of
    /// exactly what the node produced, under the container its header selected,
    /// so the header sent with it must be that same fork; deriving it from this
    /// client's own schedule instead could only ever disagree.
    ///
    /// It is finer-grained than [`Contents`] on purpose: deneb and electra
    /// share a payload shape but are different forks, and the wire needs to be
    /// told which.
    pub fork: ForkName,
    pub contents: Contents,
}

/// The block and the blob material that came with it.
#[derive(Debug, Clone, PartialEq)]
pub enum Contents {
    /// Deneb or electra: one proof per blob.
    WithBlobProofs {
        block: BeaconBlock,
        kzg_proofs: BlobKzgProofs,
        blobs: Blobs,
    },
    /// Fulu: one proof per cell.
    WithCellProofs {
        block: BeaconBlock,
        kzg_proofs: CellKzgProofs,
        blobs: Blobs,
    },
    /// Gloas: a bare block, and the self-built payload's envelope when the
    /// node included it.
    Gloas {
        block: gloas::BeaconBlock,
        payload: Option<Box<GloasPayload>>,
    },
}

impl ProducedBlock {
    /// Decode a `produceBlockV3` body, choosing the container by the fork the
    /// node named in `Eth-Consensus-Version`.
    ///
    /// The fork cannot be recovered from the bytes: SSZ carries no type tag,
    /// and a deneb and a fulu `BlockContents` differ only in a list limit that
    /// does not appear in the encoding. It has to come from the header, which
    /// is exactly why that header is required.
    ///
    /// Forks before electra are refused rather than decoded, deneb included.
    /// Deneb's block body is a field shorter than electra's, so it needs its
    /// own container pair; the rest need four more. None of them would buy
    /// anything, because the attestations this client submits are electra's
    /// `SingleAttestation` and have no earlier form, so a pre-electra chain is
    /// one it cannot serve whatever it does with blocks.
    pub fn from_ssz(fork: ForkName, bytes: &[u8]) -> crate::error::Result<Self> {
        let decode = |what: &str, err: libssz::DecodeError| {
            Error::Decode(format!(
                "produced block: {what} for fork {} did not decode: {err:?}",
                fork.as_str()
            ))
        };

        match fork {
            ForkName::Electra => {
                let contents = BlockContents::from_ssz_bytes(bytes)
                    .map_err(|err| decode("block contents", err))?;
                Ok(Self {
                    fork,
                    contents: Contents::WithBlobProofs {
                        block: contents.block,
                        kzg_proofs: contents.kzg_proofs,
                        blobs: contents.blobs,
                    },
                })
            }
            ForkName::Fulu => {
                let contents = FuluBlockContents::from_ssz_bytes(bytes)
                    .map_err(|err| decode("fulu block contents", err))?;
                Ok(Self {
                    fork,
                    contents: Contents::WithCellProofs {
                        block: contents.block,
                        kzg_proofs: contents.kzg_proofs,
                        blobs: contents.blobs,
                    },
                })
            }
            // Gloas needs one more fact than the fork: whether the node
            // included the payload, which only the response header says. See
            // `Self::from_gloas_ssz`.
            ForkName::Gloas => Err(Error::InconsistentResponse(
                "a gloas block cannot be decoded without Eth-Execution-Payload-Included"
                    .to_string(),
            )),
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Lean => Err(Error::InconsistentResponse(format!(
                "beacon node produced a block for fork {}, which this client does not propose \
                 under; electra is the earliest supported",
                fork.as_str()
            ))),
        }
    }

    /// Decode a gloas `produceBlockV4` body. `payload_included` is the node's
    /// `Eth-Execution-Payload-Included`, which selects between
    /// [`GloasBlockContents`] and a bare block: SSZ carries no tag, so a wrong
    /// guess would decode garbage or fail in a way that names neither.
    pub fn from_gloas_ssz(payload_included: bool, bytes: &[u8]) -> crate::error::Result<Self> {
        let decode = |what: &str, err: libssz::DecodeError| {
            Error::Decode(format!(
                "produced gloas block: {what} did not decode: {err:?}"
            ))
        };
        let (block, payload) = if payload_included {
            let contents = GloasBlockContents::from_ssz_bytes(bytes)
                .map_err(|err| decode("block contents", err))?;
            (
                contents.block,
                Some(Box::new(GloasPayload {
                    envelope: contents.execution_payload_envelope,
                    kzg_proofs: contents.kzg_proofs,
                    blobs: contents.blobs,
                })),
            )
        } else {
            let block = gloas::BeaconBlock::from_ssz_bytes(bytes)
                .map_err(|err| decode("bare block", err))?;
            (block, None)
        };
        Ok(Self {
            fork: ForkName::Gloas,
            contents: Contents::Gloas { block, payload },
        })
    }

    /// The block's slot, whichever fork's block it is.
    pub fn slot(&self) -> ethlambda_types::beacon::primitives::Slot {
        match &self.contents {
            Contents::WithBlobProofs { block, .. } | Contents::WithCellProofs { block, .. } => {
                block.slot
            }
            Contents::Gloas { block, .. } => block.slot,
        }
    }

    /// The proposer the block names.
    pub fn proposer_index(&self) -> ethlambda_types::beacon::primitives::ValidatorIndex {
        match &self.contents {
            Contents::WithBlobProofs { block, .. } | Contents::WithCellProofs { block, .. } => {
                block.proposer_index
            }
            Contents::Gloas { block, .. } => block.proposer_index,
        }
    }

    /// The block's `hash_tree_root`, taken from the decoded container of
    /// whichever fork it is, which is what gets signed.
    pub fn block_root(&self) -> ethlambda_types::beacon::primitives::Root {
        use ethlambda_types::beacon::primitives::HashTreeRoot as _;
        match &self.contents {
            Contents::WithBlobProofs { block, .. } | Contents::WithCellProofs { block, .. } => {
                block.hash_tree_root()
            }
            Contents::Gloas { block, .. } => block.hash_tree_root(),
        }
    }

    /// Where the block pays its execution-layer rewards: the payload's fee
    /// recipient before gloas, the bid's from it on.
    pub fn fee_recipient(&self) -> ethlambda_types::beacon::primitives::ExecutionAddress {
        match &self.contents {
            Contents::WithBlobProofs { block, .. } | Contents::WithCellProofs { block, .. } => {
                block.body.execution_payload.fee_recipient
            }
            Contents::Gloas { block, .. } => {
                block
                    .body
                    .signed_execution_payload_bid
                    .message
                    .fee_recipient
            }
        }
    }

    /// The builder the gloas bid names, `None` before gloas. The self-build
    /// sentinel means this client's own proposer key signs the envelope.
    pub fn builder_index(&self) -> Option<gloas::BuilderIndex> {
        match &self.contents {
            Contents::Gloas { block, .. } => Some(
                block
                    .body
                    .signed_execution_payload_bid
                    .message
                    .builder_index,
            ),
            _ => None,
        }
    }

    /// Take the envelope and blob material out of a gloas block, leaving the
    /// block to be signed and published alone. `None` for every earlier fork
    /// and for a gloas block the node returned without its payload.
    pub fn take_gloas_payload(&mut self) -> Option<GloasPayload> {
        match &mut self.contents {
            Contents::Gloas { payload, .. } => payload.take().map(|payload| *payload),
            _ => None,
        }
    }

    /// How many blobs came with the block. For logging.
    pub fn blob_count(&self) -> usize {
        match &self.contents {
            Contents::WithBlobProofs { blobs, .. } | Contents::WithCellProofs { blobs, .. } => {
                blobs.len()
            }
            Contents::Gloas { payload, .. } => {
                payload.as_ref().map_or(0, |payload| payload.blobs.len())
            }
        }
    }

    /// Attach `signature` and encode the body `publishBlockV2` expects.
    ///
    /// Consumes the block: the proofs and blobs are moved into the published
    /// body rather than copied, and a blob is 128 KiB, so a six-blob block
    /// would otherwise be three quarters of a megabyte cloned for nothing.
    pub fn into_signed_ssz(self, signature: BlsSignature) -> Vec<u8> {
        match self.contents {
            Contents::WithBlobProofs {
                block,
                kzg_proofs,
                blobs,
            } => SignedBlockContents {
                signed_block: SignedBeaconBlock {
                    message: block,
                    signature,
                },
                kzg_proofs,
                blobs,
            }
            .to_ssz(),
            Contents::WithCellProofs {
                block,
                kzg_proofs,
                blobs,
            } => FuluSignedBlockContents {
                signed_block: SignedBeaconBlock {
                    message: block,
                    signature,
                },
                kzg_proofs,
                blobs,
            }
            .to_ssz(),
            // Bare: the envelope and blobs are published on their own, after
            // this body, and are expected to have been taken out already by
            // `take_gloas_payload`.
            Contents::Gloas { block, .. } => gloas::SignedBeaconBlock {
                message: block,
                signature,
            }
            .to_ssz(),
        }
    }
}

/// The smallest well-formed electra block: every list empty, every scalar zero,
/// with the slot and proposer a caller cares about.
///
/// Lives here rather than in the test module below so that
/// [`crate::beacon_node::mock::MockBeaconNode`] can answer `produce_block` with
/// the same fixture these tests decode, instead of a second one that could
/// drift from it.
///
/// Spelled out field by field because neither `ExecutionPayload` nor
/// `ExecutionRequests` derives `Default`, which is the right call in that
/// crate: a zeroed execution payload is not one any chain would accept, and a
/// `Default` would let one be constructed by accident.
#[cfg(test)]
pub fn empty_block_for(
    slot: ethlambda_types::beacon::primitives::Slot,
    proposer_index: ethlambda_types::beacon::primitives::ValidatorIndex,
) -> BeaconBlock {
    use ethlambda_types::beacon::containers::deneb::ExecutionPayload;
    use ethlambda_types::beacon::containers::electra::{BeaconBlockBody, ExecutionRequests};

    let payload = ExecutionPayload {
        parent_hash: Default::default(),
        fee_recipient: Default::default(),
        state_root: Default::default(),
        receipts_root: Default::default(),
        logs_bloom: vec![0u8; preset::BYTES_PER_LOGS_BLOOM]
            .try_into()
            .expect("a logs bloom is BYTES_PER_LOGS_BLOOM long by construction"),
        prev_randao: Default::default(),
        block_number: 0,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: Default::default(),
        base_fee_per_gas: Default::default(),
        block_hash: Default::default(),
        transactions: Default::default(),
        withdrawals: Default::default(),
        blob_gas_used: 0,
        excess_blob_gas: 0,
    };

    BeaconBlock {
        slot,
        proposer_index,
        parent_root: Default::default(),
        state_root: Default::default(),
        body: BeaconBlockBody {
            randao_reveal: BlsSignature([0; 96]),
            eth1_data: Default::default(),
            graffiti: Default::default(),
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
            sync_aggregate: Default::default(),
            execution_payload: payload,
            bls_to_execution_changes: Default::default(),
            blob_kzg_commitments: Default::default(),
            execution_requests: ExecutionRequests {
                deposits: Default::default(),
                withdrawals: Default::default(),
                consolidations: Default::default(),
            },
        },
    }
}

/// The smallest gloas block for `slot` and `proposer_index`, whose bid names
/// `builder_index`.
#[cfg(test)]
pub fn empty_gloas_block_for(
    slot: ethlambda_types::beacon::primitives::Slot,
    proposer_index: ethlambda_types::beacon::primitives::ValidatorIndex,
    builder_index: gloas::BuilderIndex,
) -> gloas::BeaconBlock {
    let mut block = gloas::BeaconBlock {
        slot,
        proposer_index,
        ..Default::default()
    };
    block
        .body
        .signed_execution_payload_bid
        .message
        .builder_index = builder_index;
    block
}

/// A gloas envelope for the block whose root is `beacon_block_root`, with an
/// otherwise zeroed payload.
#[cfg(test)]
pub fn empty_gloas_envelope_for(
    beacon_block_root: ethlambda_types::beacon::primitives::Root,
    builder_index: gloas::BuilderIndex,
) -> gloas::ExecutionPayloadEnvelope {
    let payload = gloas::ExecutionPayload {
        parent_hash: Default::default(),
        fee_recipient: Default::default(),
        state_root: Default::default(),
        receipts_root: Default::default(),
        logs_bloom: vec![0u8; preset::BYTES_PER_LOGS_BLOOM]
            .try_into()
            .expect("a logs bloom is BYTES_PER_LOGS_BLOOM long by construction"),
        prev_randao: Default::default(),
        block_number: 0,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: Default::default(),
        base_fee_per_gas: Default::default(),
        block_hash: Default::default(),
        transactions: Default::default(),
        withdrawals: Default::default(),
        blob_gas_used: 0,
        excess_blob_gas: 0,
        block_access_list: Default::default(),
        slot_number: 0,
    };
    gloas::ExecutionPayloadEnvelope {
        payload,
        execution_requests: Default::default(),
        builder_index,
        beacon_block_root,
        parent_beacon_block_root: Default::default(),
    }
}

/// A zeroed blob. `Blob` deliberately has no `Default`, because zeroing 128 KiB
/// by accident is exactly the mistake that derive would invite.
#[cfg(test)]
pub fn empty_blob() -> Blob {
    vec![0u8; preset::BYTES_PER_BLOB]
        .try_into()
        .expect("a blob is BYTES_PER_BLOB long by construction")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::primitives::HashTreeRoot as _;

    fn empty_block() -> BeaconBlock {
        empty_block_for(1234, 7)
    }

    fn blob() -> Blob {
        empty_blob()
    }

    fn contents_bytes(proofs: usize, blobs: usize) -> Vec<u8> {
        BlockContents {
            block: empty_block(),
            kzg_proofs: vec![KzgProof([3; 48]); proofs]
                .try_into()
                .expect("in bounds"),
            blobs: vec![blob(); blobs].try_into().expect("in bounds"),
        }
        .to_ssz()
    }

    #[test]
    fn an_electra_block_round_trips_through_the_contents_container() {
        let bytes = contents_bytes(2, 2);
        let produced = ProducedBlock::from_ssz(ForkName::Electra, &bytes).expect("decodes");

        assert_eq!(produced.slot(), 1234);
        assert_eq!(produced.proposer_index(), 7);
        assert_eq!(produced.blob_count(), 2);
        assert_eq!(produced.fork, ForkName::Electra);
        assert!(matches!(produced.contents, Contents::WithBlobProofs { .. }));
    }

    /// The property the whole module exists for: the root this client signs
    /// must be the root of the block the node produced, not of anything this
    /// code reassembled. Decoding and re-encoding must leave it untouched.
    #[test]
    fn the_blocks_root_survives_decoding_and_signing() {
        let block = empty_block();
        let expected = block.hash_tree_root();

        let bytes = contents_bytes(1, 1);
        let produced = ProducedBlock::from_ssz(ForkName::Electra, &bytes).expect("decodes");
        assert_eq!(produced.block_root(), expected);

        let signed = produced.into_signed_ssz(BlsSignature([9; 96]));
        let decoded = SignedBlockContents::from_ssz_bytes(&signed).expect("decodes");
        assert_eq!(
            decoded.signed_block.message.hash_tree_root(),
            expected,
            "signing must not disturb the block the root was taken over"
        );
        assert_eq!(decoded.signed_block.signature, BlsSignature([9; 96]));
    }

    /// Fulu's proofs and blobs must reach the published body unchanged. A
    /// dropped proof is a block the network rejects for unavailable data.
    #[test]
    fn a_fulu_blocks_cell_proofs_and_blobs_survive_the_round_trip() {
        let bytes = FuluBlockContents {
            block: empty_block(),
            kzg_proofs: vec![KzgProof([5; 48]); 256].try_into().expect("in bounds"),
            blobs: vec![blob(); 2].try_into().expect("in bounds"),
        }
        .to_ssz();

        let produced = ProducedBlock::from_ssz(ForkName::Fulu, &bytes).expect("decodes");
        assert_eq!(produced.fork, ForkName::Fulu);
        assert!(matches!(produced.contents, Contents::WithCellProofs { .. }));
        assert_eq!(produced.blob_count(), 2);

        let signed = produced.into_signed_ssz(BlsSignature([1; 96]));
        let decoded = FuluSignedBlockContents::from_ssz_bytes(&signed).expect("decodes");
        assert_eq!(decoded.kzg_proofs.len(), 256);
        assert_eq!(decoded.blobs.len(), 2);
    }

    /// Where the two containers actually diverge, and the reason they are two
    /// containers.
    ///
    /// A six-blob fulu block carries 768 cell proofs, which still fits
    /// electra's limit; an earlier draft of this test asserted otherwise and
    /// was wrong. The limits agree until a block holds more than
    /// `MAX_BLOB_COMMITMENTS_PER_BLOCK / CELLS_PER_EXT_BLOB` blobs, so the
    /// fixture is one blob past that. Fulu made the per-block blob limit
    /// depend on the epoch so later forks can raise it, which is what makes
    /// this a future a client will meet rather than a hypothetical.
    #[test]
    fn a_block_past_thirty_two_blobs_does_not_fit_the_electra_container() {
        let blobs = preset::MAX_BLOB_COMMITMENTS_PER_BLOCK / preset::CELLS_PER_EXT_BLOB + 1;
        let count = blobs * preset::CELLS_PER_EXT_BLOB;
        assert!(
            count > preset::MAX_BLOB_COMMITMENTS_PER_BLOCK,
            "the fixture must exceed electra's limit, or this test proves nothing"
        );

        let bytes = FuluBlockContents {
            block: empty_block(),
            kzg_proofs: vec![KzgProof([5; 48]); count]
                .try_into()
                .expect("in bounds"),
            blobs: vec![blob(); blobs].try_into().expect("in bounds"),
        }
        .to_ssz();

        ProducedBlock::from_ssz(ForkName::Fulu, &bytes).expect("fulu decodes it");
        ProducedBlock::from_ssz(ForkName::Electra, &bytes)
            .expect_err("electra's proof limit must reject it");
    }

    /// The other side of the same boundary: an ordinary fulu block's cell
    /// proofs do fit electra's limit, so nothing here can be relied on to
    /// catch a fork mix-up at everyday blob counts. The fork header is the
    /// only thing that distinguishes them.
    #[test]
    fn an_ordinary_fulu_blocks_proofs_still_fit_the_electra_container() {
        let count = 6 * preset::CELLS_PER_EXT_BLOB;
        assert!(count < preset::MAX_BLOB_COMMITMENTS_PER_BLOCK);

        let bytes = FuluBlockContents {
            block: empty_block(),
            kzg_proofs: vec![KzgProof([5; 48]); count]
                .try_into()
                .expect("in bounds"),
            blobs: vec![blob(); 6].try_into().expect("in bounds"),
        }
        .to_ssz();

        ProducedBlock::from_ssz(ForkName::Electra, &bytes)
            .expect("at six blobs the electra container accepts fulu's proofs");
    }

    #[test]
    fn a_pre_electra_fork_is_refused_rather_than_decoded() {
        for fork in [ForkName::Capella, ForkName::Deneb] {
            let err =
                ProducedBlock::from_ssz(fork, &contents_bytes(0, 0)).expect_err("must refuse");
            assert!(
                matches!(err, Error::InconsistentResponse(_)),
                "{} gave {err:?}",
                fork.as_str()
            );
        }
    }

    #[test]
    fn a_truncated_body_is_a_decode_error_not_a_panic() {
        let bytes = contents_bytes(1, 1);
        let err = ProducedBlock::from_ssz(ForkName::Electra, &bytes[..bytes.len() / 2])
            .expect_err("must fail");
        assert!(matches!(err, Error::Decode(_)), "got {err:?}");
    }

    fn gloas_contents_bytes(
        builder_index: u64,
        proofs: usize,
        blobs: usize,
    ) -> (Vec<u8>, ethlambda_types::beacon::primitives::Root) {
        let block = empty_gloas_block_for(77, 5, builder_index);
        let root = block.hash_tree_root();
        let bytes = GloasBlockContents {
            block,
            execution_payload_envelope: empty_gloas_envelope_for(root, builder_index),
            kzg_proofs: vec![KzgProof([3; 48]); proofs]
                .try_into()
                .expect("in bounds"),
            blobs: vec![blob(); blobs].try_into().expect("in bounds"),
        }
        .to_ssz();
        (bytes, root)
    }

    /// With the payload included the body is the contents container, and the
    /// envelope, proofs and blobs come out in one piece for the second
    /// publication.
    #[test]
    fn a_gloas_block_with_its_payload_decodes_and_hands_the_payload_over() {
        let (bytes, root) = gloas_contents_bytes(u64::MAX, 3, 2);
        let mut produced = ProducedBlock::from_gloas_ssz(true, &bytes).expect("decodes");

        assert_eq!(produced.fork, ForkName::Gloas);
        assert_eq!(produced.slot(), 77);
        assert_eq!(produced.proposer_index(), 5);
        assert_eq!(produced.block_root(), root);
        assert_eq!(produced.blob_count(), 2);
        assert_eq!(produced.builder_index(), Some(u64::MAX));

        let payload = produced
            .take_gloas_payload()
            .expect("the payload came along");
        assert_eq!(payload.envelope.beacon_block_root, root);
        assert_eq!(payload.kzg_proofs.len(), 3);
        assert_eq!(payload.blobs.len(), 2);
        assert!(produced.take_gloas_payload().is_none(), "taken once");

        // The block published afterwards is bare, and its root is untouched.
        let signed = produced.into_signed_ssz(BlsSignature([4; 96]));
        let decoded =
            gloas::SignedBeaconBlock::from_ssz_bytes(&signed).expect("a bare gloas block");
        assert_eq!(decoded.message.hash_tree_root(), root);
        assert_eq!(decoded.signature, BlsSignature([4; 96]));
    }

    #[test]
    fn a_bare_gloas_block_has_no_payload_to_hand_over() {
        let block = empty_gloas_block_for(78, 6, 1);
        let mut produced = ProducedBlock::from_gloas_ssz(false, &block.to_ssz()).expect("decodes");
        assert_eq!(produced.slot(), 78);
        assert_eq!(produced.blob_count(), 0);
        assert!(produced.take_gloas_payload().is_none());
    }

    /// The header selects the container, so a wrong value is a decode error and
    /// not a block that silently differs.
    #[test]
    fn the_included_header_selects_the_container() {
        let (bytes, _) = gloas_contents_bytes(u64::MAX, 0, 0);
        let err =
            ProducedBlock::from_gloas_ssz(false, &bytes).expect_err("contents are not a block");
        assert!(matches!(err, Error::Decode(_)), "got {err:?}");
    }

    #[test]
    fn a_gloas_body_cannot_be_decoded_without_the_included_header() {
        let (bytes, _) = gloas_contents_bytes(u64::MAX, 0, 0);
        let err = ProducedBlock::from_ssz(ForkName::Gloas, &bytes).expect_err("must refuse");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
    }

    /// From gloas the fee recipient lives in the bid, not in a payload the
    /// block no longer carries.
    #[test]
    fn a_gloas_blocks_fee_recipient_is_the_bids() {
        let mut block = empty_gloas_block_for(1, 1, u64::MAX);
        block
            .body
            .signed_execution_payload_bid
            .message
            .fee_recipient = ethlambda_types::beacon::primitives::H160([0xcd; 20]);
        let produced = ProducedBlock::from_gloas_ssz(false, &block.to_ssz()).expect("decodes");
        assert_eq!(
            produced.fee_recipient(),
            ethlambda_types::beacon::primitives::H160([0xcd; 20])
        );
    }

    /// An envelope contents body is the signed envelope, then proofs, then
    /// blobs, and decodes back to what was put in.
    #[test]
    fn the_envelope_contents_round_trip() {
        let (bytes, root) = gloas_contents_bytes(u64::MAX, 2, 1);
        let mut produced = ProducedBlock::from_gloas_ssz(true, &bytes).expect("decodes");
        let payload = produced.take_gloas_payload().expect("payload");
        let signed = payload.into_signed_contents_ssz(BlsSignature([8; 96]));
        let decoded = SignedExecutionPayloadEnvelopeContents::from_ssz_bytes(&signed).expect("ok");
        assert_eq!(
            decoded
                .signed_execution_payload_envelope
                .message
                .beacon_block_root,
            root
        );
        assert_eq!(
            decoded.signed_execution_payload_envelope.signature,
            BlsSignature([8; 96])
        );
        assert_eq!(decoded.kzg_proofs.len(), 2);
        assert_eq!(decoded.blobs.len(), 1);
    }
}
