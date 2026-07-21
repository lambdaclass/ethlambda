//! In-process ethrex execution engine.
//!
//! Wraps an ethrex [`Blockchain`] + [`Store`] and exposes the minimal
//! build / execute / fork-choice operations the Lean consensus slot loop
//! needs, driven entirely in-process — no Engine API / JSON-RPC hop.
//!
//! This is the #367-independent core: it speaks ethrex-native types
//! ([`Block`], [`H256`]). The thin ethlambda `ExecutionPayloadV3` ⇄ ethrex
//! `Block` conversion and the `ExecutionEngine` trait impl are layered on top
//! once this crate is stacked on the Engine-API integration branch.

use std::sync::Arc;

use ethrex_blockchain::{
    Blockchain,
    error::{ChainError, InvalidForkChoice},
    fork_choice::apply_fork_choice,
    payload::{BuildPayloadArgs, BuildPayloadArgsError, create_payload},
};
use ethrex_common::{
    Address, Bytes, H256,
    types::{Block, DEFAULT_BUILDER_GAS_CEIL, ELASTICITY_MULTIPLIER, Genesis},
};
use ethrex_storage::{EngineType, Store, error::StoreError};

/// Version byte tag used when deriving payload ids, matching the Cancun/Prague
/// V3 attributes shape ethlambda produces. It only feeds id derivation — block
/// validity comes from the store's chain config, not this byte.
const PAYLOAD_VERSION: u8 = 3;

/// Errors surfaced by [`EthrexEngine`], one variant per underlying ethrex
/// failure domain plus a store-consistency guard.
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
}

/// In-process ethrex execution engine backed by an in-memory store.
pub struct EthrexEngine {
    blockchain: Arc<Blockchain>,
    store: Store,
    extra_data: Bytes,
    gas_ceil: u64,
}

impl EthrexEngine {
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
    pub async fn head_hash(&self) -> Result<H256, EngineError> {
        self.store
            .get_latest_canonical_block_hash()
            .await?
            .ok_or(EngineError::NoCanonicalHead)
    }

    /// Number (height) of the current canonical head block.
    pub async fn head_number(&self) -> Result<u64, EngineError> {
        Ok(self.store.get_latest_block_number().await?)
    }

    /// Build — but do not import — a block on top of the current canonical head.
    ///
    /// Mirrors the Engine-API `forkchoiceUpdated(build) + getPayload` pair, but
    /// synchronously: it creates the payload skeleton and fills it in one shot.
    pub async fn build_block(
        &self,
        timestamp: u64,
        prev_randao: H256,
        beacon_root: H256,
        fee_recipient: Address,
    ) -> Result<Block, EngineError> {
        let parent = self.head_hash().await?;
        let args = BuildPayloadArgs {
            parent,
            timestamp,
            fee_recipient,
            random: prev_randao,
            withdrawals: Some(Vec::new()),
            beacon_root: Some(beacon_root),
            slot_number: None,
            version: PAYLOAD_VERSION,
            elasticity_multiplier: ELASTICITY_MULTIPLIER,
            gas_ceil: self.gas_ceil,
        };
        let skeleton = create_payload(&args, &self.store, self.extra_data.clone())?;
        let result = self.blockchain.build_payload(skeleton)?;
        Ok(result.payload)
    }

    /// Execute and import a block, persisting it to the store.
    pub fn import_block(&self, block: Block) -> Result<(), EngineError> {
        self.blockchain.add_block(block)?;
        Ok(())
    }

    /// Apply a fork-choice update, making `head` the canonical head.
    pub async fn set_forkchoice(
        &self,
        head: H256,
        safe: H256,
        finalized: H256,
    ) -> Result<(), EngineError> {
        apply_fork_choice(&self.store, head, safe, finalized).await?;
        Ok(())
    }
}
