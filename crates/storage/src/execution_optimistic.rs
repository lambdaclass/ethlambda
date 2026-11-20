//! The `execution_optimistic` flag the Beacon API and its event stream carry.
//!
//! Before gloas a block's payload ran inside the block, so the flag is whether
//! that block sits in the store's optimistic set
//! ([`Store::is_beacon_optimistic`]). From gloas on the payload travels in a
//! separate envelope that may arrive late or never, and a gloas block never
//! enters that set: its import asks the execution layer nothing. Its
//! payload's verdict is recorded apart, in
//! [`Store::beacon_block_payload_status`]. So two different questions share
//! the flag:
//!
//! - an envelope is optimistic iff that payload's verdict is not `VALID`
//!   ([`Store::is_beacon_payload_optimistic`]);
//! - a block, state, header or head is optimistic iff the latest FULL payload
//!   the block builds on is not `VALID`
//!   ([`Store::is_beacon_block_optimistic`]). The block's own payload does not
//!   count: the block itself was imported without it, and a withheld payload
//!   must not make the chain look unverified.
//!
//! Here rather than in the API crate because both the Beacon API and the
//! chain actor's event stream answer the question, and the chain actor's
//! crate cannot depend on the API's.
//!
//! Everything here only reads the store, and an answer that cannot be worked
//! out is optimistic: this flag gates signing, so an unknown gets the cautious
//! reading. The payload links are therefore looked up or derived here instead
//! of through fork choice, whose `ensure_payload_link` records what it derives
//! and panics on a failed read.

use ethlambda_types::{
    beacon::{
        containers::SignedBeaconBlock,
        fork_choice::{BlockPayloadLink, PayloadStatus, PayloadStatusEnum},
    },
    primitives::H256,
};

use crate::Store;

impl Store {
    /// Whether the payload of the block at `root` is not yet vouched for by
    /// the execution layer: the flag an envelope response or event carries.
    ///
    /// An unrecorded gloas verdict reads as `NOT_VALIDATED`, so an envelope
    /// the store holds but has no verdict for is optimistic.
    pub fn is_beacon_payload_optimistic(&self, root: H256) -> bool {
        self.payload_is_not_valid(root)
    }

    /// Whether the block at `root` rests on a payload that is not `VALID`: the
    /// flag a block, state, header or head response or event carries.
    ///
    /// Walks back from `root` through the blocks whose payload branch the
    /// child skipped (`Empty`) until it reaches the FULL payload the chain
    /// actually builds on, then reads that payload's verdict. A pre-gloas
    /// block is its own payload, so it reads the optimistic set. A chain that
    /// runs out (an anchor whose parent is below the retained window) has
    /// nothing left to doubt, so it is not optimistic. A block or link that
    /// cannot be read is optimistic.
    pub fn is_beacon_block_optimistic(&self, root: H256) -> bool {
        let mut current = root;
        loop {
            let Some(link) = self.payload_link_or_derived(current) else {
                return true;
            };
            if !link.is_gloas() {
                return self.is_beacon_optimistic(current);
            }
            let parent = match self.get_signed_block(&current) {
                Ok(Some(block)) => block.parent_root(),
                Ok(None) | Err(_) => return true,
            };
            match link.parent_status() {
                Some(PayloadStatus::Full) => return self.payload_is_not_valid(parent),
                Some(PayloadStatus::Empty) => current = parent,
                // A pending parent status never comes out of a block's own bid.
                Some(PayloadStatus::Pending) | None => return false,
            }
        }
    }

    /// `root`'s payload link: the one fork choice recorded, or one derived
    /// from the stored blocks without recording it. `None` when it cannot be
    /// worked out.
    ///
    /// The derivation is `derive_payload_link`'s: a gloas block's parent
    /// status is FULL when its bid names the parent's block hash (or the
    /// parent is pre-gloas), and unknown when the parent is not stored, which
    /// is the anchor.
    fn payload_link_or_derived(&self, root: H256) -> Option<BlockPayloadLink> {
        if let Some(link) = self.payload_link(&root) {
            return Some(link);
        }
        match self.get_signed_block(&root).ok()?? {
            SignedBeaconBlock::Phase0(_)
            | SignedBeaconBlock::Altair(_)
            | SignedBeaconBlock::Bellatrix(_)
            | SignedBeaconBlock::Capella(_)
            | SignedBeaconBlock::Deneb(_)
            | SignedBeaconBlock::Electra(_)
            | SignedBeaconBlock::Fulu(_) => Some(BlockPayloadLink::PreGloas),
            SignedBeaconBlock::Gloas(block) => {
                let parent_status = match self.get_signed_block(&block.message.parent_root).ok()? {
                    None => None,
                    Some(SignedBeaconBlock::Gloas(parent)) => {
                        let wanted = block
                            .message
                            .body
                            .signed_execution_payload_bid
                            .message
                            .parent_block_hash;
                        let held = parent
                            .message
                            .body
                            .signed_execution_payload_bid
                            .message
                            .block_hash;
                        Some(if wanted == held {
                            PayloadStatus::Full
                        } else {
                            PayloadStatus::Empty
                        })
                    }
                    Some(_) => Some(PayloadStatus::Full),
                };
                Some(BlockPayloadLink::Gloas { parent_status })
            }
            // A lean block is never in a beacon store.
            SignedBeaconBlock::Lean(_) => None,
        }
    }

    /// Whether the payload of the block at `root` is not (known to be)
    /// `VALID`.
    ///
    /// A pre-gloas block's payload is its own, so it reads the optimistic
    /// set; a gloas root reads its recorded verdict, where none recorded is
    /// `NOT_VALIDATED`. Unknown links are not valid.
    fn payload_is_not_valid(&self, root: H256) -> bool {
        match self.payload_link_or_derived(root) {
            Some(BlockPayloadLink::PreGloas) => self.is_beacon_optimistic(root),
            Some(BlockPayloadLink::Gloas { .. }) => {
                self.beacon_block_payload_status(root) != PayloadStatusEnum::Valid
            }
            None => true,
        }
    }
}
