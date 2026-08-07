//! In-process ethrex execution engine.
//!
//! Wraps an ethrex [`Blockchain`] + [`Store`] and exposes the three operations
//! the Lean consensus slot loop needs — build a payload, execute one, move the
//! head — driven entirely in-process by direct library calls.
//!
//! The interface is deliberately *not* Engine-API shaped. Running in-process
//! removes the reasons that protocol is a two-step, stateless exchange: there is
//! no latency to hide, so a payload is built and returned in one call, with no
//! payload id and no server-side cache to hold it in the meantime.
//!
//! Consensus types cross the boundary ([`ExecutionPayloadV3`], [`LeanH256`]);
//! ethrex's own types stay behind it.

mod conversion;

use std::sync::Arc;

use ethlambda_types::execution_payload::ExecutionPayloadV3;
use ethlambda_types::primitives::H256 as LeanH256;
use ethrex_blockchain::{
    Blockchain,
    error::{ChainError, InvalidForkChoice},
    fork_choice::apply_fork_choice,
    payload::{BuildPayloadArgs, BuildPayloadArgsError, create_payload},
};
use ethrex_common::{
    Address, Bytes, H256,
    types::{DEFAULT_BUILDER_GAS_CEIL, ELASTICITY_MULTIPLIER, Genesis, Withdrawal},
};
use ethrex_storage::{EngineType, Store, error::StoreError};

use crate::conversion::{block_to_payload, payload_to_block};

/// Version byte tag used when deriving payload ids inside ethrex, matching the
/// Cancun/Prague V3 attributes shape ethlambda produces. It only feeds ethrex's
/// internal id derivation — block validity comes from the store's chain config.
const PAYLOAD_VERSION: u8 = 3;

/// Errors surfaced by [`EthrexEngine`], one variant per underlying ethrex
/// failure domain plus the local guards.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
    #[error("fork choice error: {0}")]
    ForkChoice(#[from] InvalidForkChoice),
    #[error("payload id error: {0}")]
    PayloadId(#[from] BuildPayloadArgsError),
    #[error("store has no canonical head block")]
    NoCanonicalHead,
    #[error("payload conversion error: {0}")]
    Conversion(String),
    #[error("genesis load error: {0}")]
    GenesisLoad(String),
}

/// In-process ethrex execution engine backed by an in-memory store.
pub struct EthrexEngine {
    blockchain: Arc<Blockchain>,
    store: Store,
    extra_data: Bytes,
    gas_ceil: u64,
}

impl EthrexEngine {
    /// Bootstrap an engine from an EL genesis JSON file (the format ethrex and
    /// other execution clients consume).
    ///
    /// The genesis must be **Cancun**: a Prague genesis makes ethrex require a
    /// `requests_hash` in the block header that the Cancun-shaped
    /// [`ExecutionPayloadV3`] cannot carry, and every payload is then rejected.
    pub async fn from_genesis_path(path: impl AsRef<std::path::Path>) -> Result<Self, EngineError> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)
            .map_err(|err| EngineError::GenesisLoad(format!("open {}: {err}", path.display())))?;
        let genesis: Genesis = serde_json::from_reader(std::io::BufReader::new(file))
            .map_err(|err| EngineError::GenesisLoad(format!("parse {}: {err}", path.display())))?;
        Self::from_genesis(genesis).await
    }

    /// Bootstrap an engine with an in-memory store initialised from `genesis`.
    pub async fn from_genesis(genesis: Genesis) -> Result<Self, EngineError> {
        let mut store = Store::new("", EngineType::InMemory)?;
        store.add_initial_state(genesis).await?;
        let blockchain = Arc::new(Blockchain::default_with_store(store.clone()));
        Ok(Self {
            blockchain,
            store,
            extra_data: Bytes::new(),
            gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
        })
    }

    /// Hash of the current canonical head block.
    ///
    /// Immediately after [`Self::from_genesis`] this is the EL genesis block
    /// hash, which is what seeds the consensus genesis anchor.
    pub async fn head_hash(&self) -> Result<LeanH256, EngineError> {
        let hash = self
            .store
            .get_latest_canonical_block_hash()
            .await?
            .ok_or(EngineError::NoCanonicalHead)?;
        Ok(LeanH256(hash.0))
    }

    /// Number (height) of the current canonical head block.
    pub async fn head_number(&self) -> Result<u64, EngineError> {
        Ok(self.store.get_latest_block_number().await?)
    }

    /// Build the execution payload for a block being proposed on top of the
    /// current canonical head.
    ///
    /// One call: ethrex creates the payload skeleton and fills it synchronously,
    /// so unlike the Engine API there is no id to hold onto and no second fetch.
    ///
    /// `beacon_root` follows the lean-parent-root convention — it is the
    /// proposed block's `parent_root`, and must be the same value later passed
    /// to [`Self::execute_payload`], or the EL's block-hash check fails.
    pub async fn build_payload(
        &self,
        timestamp: u64,
        prev_randao: LeanH256,
        beacon_root: LeanH256,
        fee_recipient: [u8; 20],
    ) -> Result<ExecutionPayloadV3, EngineError> {
        let parent = self
            .store
            .get_latest_canonical_block_hash()
            .await?
            .ok_or(EngineError::NoCanonicalHead)?;
        let args = BuildPayloadArgs {
            parent,
            timestamp,
            fee_recipient: Address::from_slice(&fee_recipient),
            random: H256(prev_randao.0),
            withdrawals: Some(Vec::<Withdrawal>::new()),
            beacon_root: Some(H256(beacon_root.0)),
            slot_number: None,
            version: PAYLOAD_VERSION,
            elasticity_multiplier: ELASTICITY_MULTIPLIER,
            gas_ceil: self.gas_ceil,
        };
        let skeleton = create_payload(&args, &self.store, self.extra_data.clone())?;
        let built = self.blockchain.build_payload(skeleton)?.payload;
        Ok(block_to_payload(built))
    }

    /// Execute a payload and import the resulting block.
    ///
    /// `Ok(())` means the execution layer accepted it. An `Err` means the
    /// payload is unexecutable on this chain — the caller decides what that
    /// implies for consensus (today: drop the block, but never stall).
    pub fn execute_payload(
        &self,
        payload: &ExecutionPayloadV3,
        parent_beacon_block_root: LeanH256,
    ) -> Result<(), EngineError> {
        let block = payload_to_block(payload, parent_beacon_block_root)?;
        self.blockchain.add_block(block)?;
        Ok(())
    }

    /// Point the execution layer at the given head / safe / finalized blocks.
    pub async fn set_head(
        &self,
        head: LeanH256,
        safe: LeanH256,
        finalized: LeanH256,
    ) -> Result<(), EngineError> {
        apply_fork_choice(&self.store, H256(head.0), H256(safe.0), H256(finalized.0)).await?;
        Ok(())
    }
}
