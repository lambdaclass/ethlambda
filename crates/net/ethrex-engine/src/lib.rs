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

mod conversion;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ethlambda_ethrex_client::{
    EngineClientError, ExecutionEngine, ExecutionPayloadV3, ForkChoiceState,
    ForkChoiceUpdatedResponse, PayloadAttributesV3, PayloadId, PayloadStatus, PayloadStatusKind,
};
use ethlambda_types::primitives::H256 as LeanH256;
use ethrex_blockchain::{
    Blockchain,
    error::{ChainError, InvalidForkChoice},
    fork_choice::apply_fork_choice,
    payload::{BuildPayloadArgs, BuildPayloadArgsError, create_payload},
};
use ethrex_common::{
    Address, Bytes, H256,
    types::{Block, DEFAULT_BUILDER_GAS_CEIL, ELASTICITY_MULTIPLIER, Genesis, Withdrawal},
};
use ethrex_storage::{EngineType, Store, error::StoreError};

use crate::conversion::{block_to_payload, payload_to_block};

/// Map an internal engine failure onto the client error surface. The trait
/// only exposes `EngineClientError`, which has no dedicated "internal" variant,
/// so reuse the most general one (`Rpc`) with a synthetic server-error code.
fn internal_error(message: String) -> EngineClientError {
    EngineClientError::Rpc {
        code: -32000,
        message,
        data: None,
    }
}

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
    /// Payloads built during `forkchoice_updated_v3` (build mode), keyed by the
    /// raw 8 payload-id bytes and drained by `get_payload`. `PayloadId` itself
    /// isn't `Hash`, so key on its inner bytes.
    built_payloads: Mutex<HashMap<[u8; 8], ExecutionPayloadV3>>,
}

impl EthrexEngine {
    /// Bootstrap an engine from an EL genesis JSON file (the format ethrex and
    /// other ELs consume). Convenience wrapper over [`Self::from_genesis`] used
    /// by the CLI `--execution-mode inprocess` path.
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
            built_payloads: Mutex::new(HashMap::new()),
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

/// Convert an ethlambda `H256` into an ethrex `H256` (both wrap `[u8; 32]`).
fn to_ethrex_h256(h: LeanH256) -> H256 {
    H256(h.0)
}

#[async_trait::async_trait]
impl ExecutionEngine for EthrexEngine {
    async fn forkchoice_updated_v3(
        &self,
        state: ForkChoiceState,
        payload_attributes: Option<PayloadAttributesV3>,
    ) -> Result<ForkChoiceUpdatedResponse, EngineClientError> {
        let head = to_ethrex_h256(state.head_block_hash);
        let safe = to_ethrex_h256(state.safe_block_hash);
        let finalized = to_ethrex_h256(state.finalized_block_hash);

        // Best-effort fork-choice application: a head we can't yet apply (e.g.
        // its block hasn't been imported) must not fail the update.
        let _ = apply_fork_choice(&self.store, head, safe, finalized).await;

        let head_status = PayloadStatus {
            status: PayloadStatusKind::Valid,
            latest_valid_hash: Some(state.head_block_hash),
            validation_error: None,
        };

        let Some(attributes) = payload_attributes else {
            return Ok(ForkChoiceUpdatedResponse {
                payload_status: head_status,
                payload_id: None,
            });
        };

        let payload_id = self
            .build_from_attributes(head, &attributes)
            .map_err(|err| internal_error(err.to_string()))?;

        Ok(ForkChoiceUpdatedResponse {
            payload_status: head_status,
            payload_id: Some(payload_id),
        })
    }

    async fn get_payload(
        &self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayloadV3, EngineClientError> {
        self.built_payloads
            .lock()
            .expect("built_payloads mutex poisoned")
            .remove(&payload_id.0)
            .ok_or_else(|| internal_error(format!("unknown payload id {}", payload_id.to_hex())))
    }

    async fn new_payload(
        &self,
        payload: &ExecutionPayloadV3,
        parent_beacon_block_root: LeanH256,
    ) -> Result<PayloadStatus, EngineClientError> {
        let block = match payload_to_block(payload, parent_beacon_block_root) {
            Ok(block) => block,
            Err(err) => {
                return Ok(PayloadStatus {
                    status: PayloadStatusKind::Invalid,
                    latest_valid_hash: None,
                    validation_error: Some(err.to_string()),
                });
            }
        };

        let block_hash = block.hash();
        match self.blockchain.add_block(block) {
            Ok(()) => Ok(PayloadStatus {
                status: PayloadStatusKind::Valid,
                latest_valid_hash: Some(LeanH256(block_hash.0)),
                validation_error: None,
            }),
            Err(err) => Ok(PayloadStatus {
                status: PayloadStatusKind::Invalid,
                latest_valid_hash: None,
                validation_error: Some(err.to_string()),
            }),
        }
    }
}

impl EthrexEngine {
    /// Build the next block on top of `parent` from the requested attributes,
    /// convert it to a payload, cache it, and return its derived id.
    fn build_from_attributes(
        &self,
        parent: H256,
        attributes: &PayloadAttributesV3,
    ) -> Result<PayloadId, EngineError> {
        let withdrawals = attributes
            .withdrawals
            .iter()
            .map(|w| Withdrawal {
                index: w.index,
                validator_index: w.validator_index,
                address: Address::from_slice(&w.address),
                amount: w.amount,
            })
            .collect();
        let args = BuildPayloadArgs {
            parent,
            timestamp: attributes.timestamp,
            fee_recipient: Address::from_slice(&attributes.suggested_fee_recipient),
            random: to_ethrex_h256(attributes.prev_randao),
            withdrawals: Some(withdrawals),
            beacon_root: Some(to_ethrex_h256(attributes.parent_beacon_block_root)),
            slot_number: None,
            version: PAYLOAD_VERSION,
            elasticity_multiplier: ELASTICITY_MULTIPLIER,
            gas_ceil: self.gas_ceil,
        };
        // The id derivation matches the Engine API convention (a hash over the
        // build args); as an in-process opaque token its only requirement is
        // uniqueness per distinct build request.
        let payload_id = PayloadId(args.id()?.to_be_bytes());

        let skeleton = create_payload(&args, &self.store, self.extra_data.clone())?;
        let block = self.blockchain.build_payload(skeleton)?.payload;
        let payload = block_to_payload(block);

        self.built_payloads
            .lock()
            .expect("built_payloads mutex poisoned")
            .insert(payload_id.0, payload);

        Ok(payload_id)
    }
}
