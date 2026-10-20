//! The `block_id` and `state_id` path parameters, parsed once for both surfaces.
//!
//! Parsing is chain-agnostic; resolution is not. Lean resolves a slot through
//! the head state's `historical_block_hashes` (see `crate::blocks`), beacon
//! through `Store::canonical_root_at_slot`, and the lean path stays where it
//! is: `Store::head_state` panics on a beacon store, and `BlockRoots` covers
//! the branch ending at the head rather than everything a lean store was
//! bootstrapped with, so repointing lean at it would change a working
//! endpoint's answers below the anchor.

use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;

/// The block at `slot` among the roots this store can name, or `None`.
///
/// `Table::BlockRoots` is the slot index, and `Store::update_checkpoints` is
/// its only writer. That writer diffs the old head against the new one and
/// writes nothing when they are the same root, which is the situation at
/// bootstrap: `Store::init_beacon` seeds `KEY_HEAD` with the anchor. So the
/// anchor's own slot is missing from the index even though its block is on
/// disk, and `canonical_root_at_slot` alone cannot find it.
///
/// That slot is not a curiosity. `bin/ethlambda/src/checkpoint_sync.rs` reads
/// a peer's finalized state, takes the anchor slot from it, and asks that peer
/// for `/eth/v2/beacon/blocks/{anchor_slot}`. Answering 404 there makes this
/// node unusable as a checkpoint-sync source for any client, ethlambda
/// included.
///
/// Each candidate is **checked** rather than assumed: `block_entry` gives the
/// root's real slot, and a candidate is accepted only when it equals the slot
/// asked for. A store that holds nothing at `slot` therefore still answers
/// `None`, rather than the nearest checkpoint. At most three index reads, and
/// only on a miss.
fn anchored_root_at_slot(store: &Store, slot: u64) -> Option<H256> {
    let named = [
        store
            .latest_finalized()
            .ok()
            .map(|checkpoint| checkpoint.root),
        store
            .latest_justified()
            .ok()
            .map(|checkpoint| checkpoint.root),
        store.beacon_head().map(|(_slot, root)| root),
    ];

    named
        .into_iter()
        .flatten()
        .find(|root| store.block_entry(root).is_some_and(|(at, _)| at == slot))
}

/// A `block_id` path parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockId {
    Head,
    Genesis,
    Finalized,
    Justified,
    Slot(u64),
    Root(H256),
}

/// Why an id could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdError {
    /// The id is not one this API defines. 400.
    Malformed,
    /// Well-formed, but nothing is stored under it. 404.
    NotFound,
}

impl BlockId {
    /// Parse without touching the store.
    pub(crate) fn parse(raw: &str) -> Result<Self, IdError> {
        match raw {
            "head" => return Ok(BlockId::Head),
            "genesis" => return Ok(BlockId::Genesis),
            "finalized" => return Ok(BlockId::Finalized),
            "justified" => return Ok(BlockId::Justified),
            _ => {}
        }

        if let Some(hex_body) = raw.strip_prefix("0x") {
            let bytes = hex::decode(hex_body).map_err(|_| IdError::Malformed)?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| IdError::Malformed)?;
            return Ok(BlockId::Root(H256(arr)));
        }

        if !raw.is_empty() && raw.chars().all(|c| c.is_ascii_digit()) {
            return raw
                .parse()
                .map(BlockId::Slot)
                .map_err(|_| IdError::Malformed);
        }

        Err(IdError::Malformed)
    }

    /// Resolve to a block root against a **beacon** store.
    ///
    /// `genesis` is always refused; see the `BlockId::Genesis` arm below for
    /// why.
    pub(crate) fn resolve_beacon(&self, store: &Store) -> Result<H256, IdError> {
        match self {
            BlockId::Root(root) => Ok(*root),
            BlockId::Head => store
                .beacon_head()
                .map(|(_slot, root)| root)
                .ok_or(IdError::NotFound),
            BlockId::Finalized => Ok(store
                .latest_finalized()
                .map_err(|_| IdError::NotFound)?
                .root),
            BlockId::Justified => Ok(store
                .latest_justified()
                .map_err(|_| IdError::NotFound)?
                .root),
            // A beacon store cannot answer `genesis`. `BlockRoots` indexes the
            // canonical branch above the store's anchor, and the anchor's own
            // slot is never written to it: `update_checkpoints` is that
            // index's only writer and it walks from the old head to the new
            // one, which at bootstrap are the same root. A checkpoint-synced
            // directory has no genesis block to return either way. Refusing
            // is better than resolving it to the anchor and calling that
            // genesis.
            BlockId::Genesis => Err(IdError::NotFound),
            BlockId::Slot(slot) => {
                if let Some(root) = store
                    .canonical_root_at_slot(*slot)
                    .map_err(|_| IdError::NotFound)?
                {
                    return Ok(root);
                }
                anchored_root_at_slot(store, *slot).ok_or(IdError::NotFound)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_ids_parse() {
        assert_eq!(BlockId::parse("head").unwrap(), BlockId::Head);
        assert_eq!(BlockId::parse("genesis").unwrap(), BlockId::Genesis);
        assert_eq!(BlockId::parse("finalized").unwrap(), BlockId::Finalized);
        assert_eq!(BlockId::parse("justified").unwrap(), BlockId::Justified);
    }

    #[test]
    fn a_slot_and_a_root_parse() {
        assert_eq!(BlockId::parse("4096").unwrap(), BlockId::Slot(4096));
        let root = format!("0x{}", "ab".repeat(32));
        assert_eq!(
            BlockId::parse(&root).unwrap(),
            BlockId::Root(H256([0xab; 32]))
        );
    }

    #[test]
    fn malformed_ids_are_rejected() {
        assert!(BlockId::parse("not-an-id").is_err());
        assert!(BlockId::parse("0xdeadbeef").is_err(), "wrong length");
        assert!(BlockId::parse("0xzz").is_err(), "not hex");
        assert!(BlockId::parse("").is_err());
    }

    #[test]
    fn genesis_is_refused_on_a_beacon_store() {
        // Deliberate, not incidental: see the `BlockId::Genesis` arm of
        // `resolve_beacon` for why the anchor slot can never be reached
        // through `BlockRoots`.
        let fixture = crate::test_utils::beacon_fixture(64);
        assert_eq!(
            BlockId::Genesis.resolve_beacon(&fixture.store),
            Err(IdError::NotFound)
        );
    }
}
