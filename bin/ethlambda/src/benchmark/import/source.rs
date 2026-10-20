//! Where a corpus's bytes come from.
//!
//! A trait rather than a bare reqwest client so the anchor rule below is
//! testable without a live server or a new dev-dependency. `HttpSource` is
//! the only production implementation.
//!
//! `CorpusSource`'s methods are native `async fn`s in the trait (stable since
//! edition 2024): nothing here needs `dyn CorpusSource` (`resolve_anchor`
//! takes `&impl CorpusSource`, and `fetch` does the same), so there is no
//! reason to pay for `async-trait`'s boxing.

use ethlambda_p2p::beacon::decode;
use ethlambda_types::beacon::config::Config;

use super::corpus::hex_root;

/// How many epochs [`resolve_anchor`] steps back past an empty first slot
/// before giving up.
///
/// An empty first slot is rare and a run of them rarer still, so a source
/// with none holding a block across this many epochs most likely does not
/// hold the history at all. Its 404s are indistinguishable from empty slots,
/// and without a bound the walk would continue back to genesis.
const MAX_ANCHOR_EPOCHS_BACK: u64 = 8;

/// One block's identity, as much of it as a fetch needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockRef {
    pub root: String,
    pub slot: u64,
    pub parent_root: String,
}

/// The anchor a replay starts from: a block and its own post-state.
#[derive(Debug, Clone)]
pub(crate) struct AnchorRef {
    pub root: String,
    pub slot: u64,
}

pub(crate) trait CorpusSource {
    /// The slot of the source's current head block.
    async fn head_slot(&self) -> eyre::Result<u64>;
    /// The block at `slot`, or `None` if that slot is empty.
    async fn block_at_slot(&self, slot: u64) -> eyre::Result<Option<BlockRef>>;
    /// The block at `slot` together with its raw SSZ, or `None` if that slot
    /// is empty. The identity rides along so `fetch` can check each block's
    /// parent link without decoding the bytes a second time.
    async fn block_with_bytes_at_slot(
        &self,
        slot: u64,
    ) -> eyre::Result<Option<(BlockRef, Vec<u8>)>>;
    /// The raw SSZ of the block with `root`.
    async fn block_bytes_by_root(&self, root: &str) -> eyre::Result<Vec<u8>>;
    /// The raw SSZ of the state at `slot`.
    async fn state_bytes_at_slot(&self, slot: u64) -> eyre::Result<Vec<u8>>;
}

/// Resolve the anchor a range starting at `from` must be replayed from.
///
/// The anchor has to sit on the first slot of an epoch. `get_forkchoice_store`
/// makes it the store's justified and finalized checkpoint at the anchor
/// state's own epoch, and every import then asks `get_checkpoint_block` for
/// the finalized checkpoint's block, which walks back from the new block to
/// that epoch's first slot. From an anchor past that slot the walk steps
/// below the anchor, onto a block the store never held, and the very first
/// import fails its `root in store.blocks` assertion. The specification has
/// the same requirement, since its anchor is a checkpoint, which is also why a
/// checkpoint-synced node anchors on the finalized checkpoint's state.
///
/// So the anchor is the block at the first slot of the epoch holding
/// `from - 1`, and every block between it and `from` becomes a warm-up block
/// the replay imports but does not sample. An empty first slot would be
/// anchorable too, through the slot-advanced state `get_forkchoice_store`
/// accepts, but only from a source that serves states at empty slots; stepping
/// back one more epoch needs nothing beyond what the block loop already asks
/// for.
///
/// `from` itself must hold a block: it is the first sample, and a range that
/// opens on nothing is more likely a typo than an intent.
pub(crate) async fn resolve_anchor(
    source: &impl CorpusSource,
    from: u64,
    slots_per_epoch: u64,
) -> eyre::Result<AnchorRef> {
    eyre::ensure!(from > 0, "--from 0 is genesis, which nothing precedes");
    source
        .block_at_slot(from)
        .await?
        .ok_or_else(|| eyre::eyre!("slot {from} holds no block; a range must start at one"))?;

    let mut epoch_start = (from - 1) / slots_per_epoch * slots_per_epoch;
    for _ in 0..MAX_ANCHOR_EPOCHS_BACK {
        if let Some(block) = source.block_at_slot(epoch_start).await? {
            // A source that answered an empty slot with the latest block
            // before it would put the anchor mid-epoch again.
            eyre::ensure!(
                block.slot == epoch_start,
                "asked for the block at slot {epoch_start}, got one at slot {}",
                block.slot
            );
            return Ok(AnchorRef {
                root: block.root,
                slot: block.slot,
            });
        }
        let Some(earlier) = epoch_start.checked_sub(slots_per_epoch) else {
            break;
        };
        epoch_start = earlier;
    }
    eyre::bail!(
        "no block at the first slot of any of the {MAX_ANCHOR_EPOCHS_BACK} epochs up to slot \
         {from}; the anchor must sit on one, and a source missing that many in a row most \
         likely does not hold history that far back"
    )
}

/// The Beacon API implementation.
///
/// Reuses `checkpoint_sync`'s client: a `BeaconState` is hundreds of
/// megabytes, and that client is already built with a connect timeout plus an
/// inactivity read timeout, so a healthy slow transfer is not killed by a
/// total-time limit.
pub(crate) struct HttpSource {
    client: reqwest::Client,
    base_url: String,
    /// Needed to pick the fork a decoded block's slot names; see
    /// `decode::decode_block`.
    config: Config,
}

impl HttpSource {
    pub(crate) fn new(base_url: String, config: Config) -> eyre::Result<Self> {
        let client = crate::checkpoint_sync::build_client()?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            config,
        })
    }

    fn block_url(&self, id: &str) -> String {
        format!("{}/eth/v2/beacon/blocks/{id}", self.base_url)
    }

    fn state_url(&self, id: &str) -> String {
        format!("{}/eth/v2/debug/beacon/states/{id}", self.base_url)
    }

    /// GET `url` with an `application/octet-stream` accept header, mapping a
    /// `404` to `None`. Any other non-2xx status is an error.
    async fn fetch_bytes(&self, url: &str) -> eyre::Result<Option<Vec<u8>>> {
        let response = self
            .client
            .get(url)
            .header("Accept", "application/octet-stream")
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let bytes = response.error_for_status()?.bytes().await?;
        Ok(Some(bytes.to_vec()))
    }

    /// Fetch and decode the block the Beacon API's block-id grammar names
    /// (a slot number, a `0x`-prefixed root, or `head`), or `None` if absent.
    ///
    /// Roots are formatted with `hex_root`, the same helper the manifest
    /// uses, so a `parent_root` this method hands back compares equal to the
    /// `root` of the block it names.
    async fn fetch_block(&self, id: &str) -> eyre::Result<Option<(BlockRef, Vec<u8>)>> {
        let Some(bytes) = self.fetch_bytes(&self.block_url(id)).await? else {
            return Ok(None);
        };
        let block = decode::decode_block(&self.config, &bytes)
            .map_err(|err| eyre::eyre!("block {id} did not decode: {err}"))?;
        let block_ref = BlockRef {
            root: hex_root(block.message_hash_tree_root()),
            slot: block.slot(),
            parent_root: hex_root(block.parent_root()),
        };
        Ok(Some((block_ref, bytes)))
    }
}

impl CorpusSource for HttpSource {
    async fn head_slot(&self) -> eyre::Result<u64> {
        let url = self.block_url("head");
        let (head, _) = self
            .fetch_block("head")
            .await?
            .ok_or_else(|| eyre::eyre!("the source has no head block at {url}"))?;
        Ok(head.slot)
    }

    async fn block_at_slot(&self, slot: u64) -> eyre::Result<Option<BlockRef>> {
        let block = self.fetch_block(&slot.to_string()).await?;
        Ok(block.map(|(block_ref, _)| block_ref))
    }

    async fn block_with_bytes_at_slot(
        &self,
        slot: u64,
    ) -> eyre::Result<Option<(BlockRef, Vec<u8>)>> {
        self.fetch_block(&slot.to_string()).await
    }

    async fn block_bytes_by_root(&self, root: &str) -> eyre::Result<Vec<u8>> {
        let url = self.block_url(root);
        self.fetch_bytes(&url)
            .await?
            .ok_or_else(|| eyre::eyre!("block {root} not found at {url}"))
    }

    async fn state_bytes_at_slot(&self, slot: u64) -> eyre::Result<Vec<u8>> {
        let url = self.state_url(&slot.to_string());
        // A source having no historical state this old is the most likely
        // failure in practice: most beacon nodes only serve recent states.
        // Name the endpoint so the operator knows which one to check.
        self.fetch_bytes(&url)
            .await?
            .ok_or_else(|| eyre::eyre!("state at slot {slot} not found at {url}"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Mainnet's epoch length, so the slot numbers below read the way a real
    /// range would.
    pub(crate) const SLOTS_PER_EPOCH: u64 = 32;

    /// A linear chain with a block at each of a given set of slots.
    pub(crate) struct FakeSource {
        blocks_by_slot: HashMap<u64, BlockRef>,
        blocks_by_root: HashMap<String, BlockRef>,
    }

    fn fake_root(slot: u64) -> String {
        format!("0x{slot:064x}")
    }

    impl FakeSource {
        /// A block at each of `slots`, each naming the one before it as its
        /// parent, so a slot absent from `slots` is an empty slot on this
        /// chain rather than a missing block.
        pub(crate) fn chain(slots: &[u64]) -> Self {
            let mut blocks_by_slot = HashMap::new();
            let mut blocks_by_root = HashMap::new();
            let mut parent_root = fake_root(u64::MAX);
            for &slot in slots {
                let block = BlockRef {
                    root: fake_root(slot),
                    slot,
                    parent_root: parent_root.clone(),
                };
                parent_root = block.root.clone();
                blocks_by_slot.insert(slot, block.clone());
                blocks_by_root.insert(block.root.clone(), block);
            }
            Self {
                blocks_by_slot,
                blocks_by_root,
            }
        }

        /// Point the block at `slot` at a parent the chain does not hold, as
        /// a reorg landing between two requests would.
        pub(crate) fn with_foreign_parent_at(mut self, slot: u64) -> Self {
            let block = self
                .blocks_by_slot
                .get_mut(&slot)
                .expect("the slot holds a block");
            block.parent_root = fake_root(u64::MAX - 1);
            self.blocks_by_root
                .insert(block.root.clone(), block.clone());
            self
        }
    }

    impl CorpusSource for FakeSource {
        async fn head_slot(&self) -> eyre::Result<u64> {
            self.blocks_by_slot
                .keys()
                .max()
                .copied()
                .ok_or_else(|| eyre::eyre!("empty chain"))
        }

        async fn block_at_slot(&self, slot: u64) -> eyre::Result<Option<BlockRef>> {
            Ok(self.blocks_by_slot.get(&slot).cloned())
        }

        async fn block_with_bytes_at_slot(
            &self,
            slot: u64,
        ) -> eyre::Result<Option<(BlockRef, Vec<u8>)>> {
            Ok(self
                .blocks_by_slot
                .get(&slot)
                .map(|block| (block.clone(), block.root.as_bytes().to_vec())))
        }

        async fn block_bytes_by_root(&self, root: &str) -> eyre::Result<Vec<u8>> {
            self.blocks_by_root
                .get(root)
                .map(|block| block.root.as_bytes().to_vec())
                .ok_or_else(|| eyre::eyre!("no block with root {root}"))
        }

        /// Real, decodable bytes rather than a placeholder: `fetch_corpus`
        /// decodes whatever this returns as a `BeaconState` to read the
        /// network fingerprint before it ever touches a block, so a fake
        /// source needs a fake state that survives that decode too. The
        /// binary already embeds mainnet's genesis state for `ethlambda
        /// beacon`'s own use, which is a real, spec-shaped state with a known
        /// `genesis_time`/`genesis_validators_root` pair (see
        /// `crate::beacon::mainnet_genesis`), so it is reused here rather
        /// than hand-building a minimal one field by field.
        async fn state_bytes_at_slot(&self, _slot: u64) -> eyre::Result<Vec<u8>> {
            Ok(crate::beacon::mainnet_genesis_state()?.to_ssz())
        }
    }

    #[tokio::test]
    async fn the_anchor_is_the_block_at_the_first_slot_of_the_epoch_before_from() {
        // 66 is empty. The first block's parent is 65, but an anchor there
        // would sit mid-epoch; the anchor is epoch 2's first slot instead.
        let source = FakeSource::chain(&[64, 65, 67, 68]);

        let anchor = resolve_anchor(&source, 67, SLOTS_PER_EPOCH)
            .await
            .expect("anchor");

        assert_eq!(anchor.slot, 64);
        assert_eq!(anchor.root, fake_root(64));
    }

    #[tokio::test]
    async fn a_range_opening_one_slot_past_an_epoch_start_anchors_on_it() {
        let source = FakeSource::chain(&[64, 65, 66]);

        let anchor = resolve_anchor(&source, 65, SLOTS_PER_EPOCH)
            .await
            .expect("anchor");

        assert_eq!(anchor.slot, 64);
    }

    #[tokio::test]
    async fn a_range_opening_on_an_epoch_start_anchors_on_the_epoch_before() {
        // `from - 1` is the anchor's upper bound: the block at `from` is the
        // first sample, never the anchor.
        let source = FakeSource::chain(&[32, 40, 64, 65]);

        let anchor = resolve_anchor(&source, 64, SLOTS_PER_EPOCH)
            .await
            .expect("anchor");

        assert_eq!(anchor.slot, 32);
    }

    #[tokio::test]
    async fn an_empty_epoch_start_steps_back_to_the_one_before() {
        let source = FakeSource::chain(&[32, 40, 63, 65, 66]);

        let anchor = resolve_anchor(&source, 66, SLOTS_PER_EPOCH)
            .await
            .expect("anchor");

        assert_eq!(anchor.slot, 32, "64 is empty, so the anchor is epoch 1's");
    }

    #[tokio::test]
    async fn a_source_missing_that_history_is_reported_rather_than_walked_to_genesis() {
        // Nothing at any epoch start: exactly what a node that never held
        // this history answers, since its 404s read as empty slots.
        let source = FakeSource::chain(&[1001, 1002]);

        let err = resolve_anchor(&source, 1002, SLOTS_PER_EPOCH)
            .await
            .expect_err("no epoch start holds a block");

        assert!(
            err.to_string().contains("history"),
            "the error names the likely cause: {err}"
        );
    }

    #[tokio::test]
    async fn a_range_starting_at_an_empty_slot_is_rejected() {
        let source = FakeSource::chain(&[64, 65, 67]);

        let err = resolve_anchor(&source, 66, SLOTS_PER_EPOCH)
            .await
            .expect_err("66 is empty");

        assert!(
            err.to_string().contains("66"),
            "the error names the slot: {err}"
        );
    }
}
