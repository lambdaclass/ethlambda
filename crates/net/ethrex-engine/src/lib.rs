//! In-process ethrex execution engine.
//!
//! Wraps an ethrex [`Blockchain`] + [`Store`] and exposes what the Lean
//! consensus slot loop needs — build a payload, execute one, move the head —
//! plus transaction submission, driven entirely in-process by direct library
//! calls.
//!
//! The interface is deliberately *not* Engine-API shaped. Running in-process
//! removes the reasons that protocol is a two-step, stateless exchange: there is
//! no latency to hide, so a payload is built and returned in one call, with no
//! payload id and no server-side cache to hold it in the meantime.
//!
//! Consensus types cross the boundary ([`ExecutionPayloadV3`], [`LeanH256`]);
//! ethrex's own types stay behind it.

mod conversion;
mod p2p;

pub use p2p::{DEFAULT_TARGET_PEERS, P2PConfig, derive_el_node_key};

use std::sync::{Arc, OnceLock};

use ethlambda_types::execution_payload::ExecutionPayloadV3;
use ethlambda_types::primitives::H256 as LeanH256;
use ethrex_blockchain::{
    Blockchain,
    error::{ChainError, InvalidForkChoice, MempoolError},
    fork_choice::apply_fork_choice,
    payload::{BuildPayloadArgs, BuildPayloadArgsError, create_payload},
};
use ethrex_common::{
    Address, Bytes, H256,
    types::{
        DEFAULT_BUILDER_GAS_CEIL, ELASTICITY_MULTIPLIER, Genesis, Transaction, Withdrawal,
        WrappedEIP4844Transaction,
    },
};
use ethrex_rlp::decode::RLPDecode;
use ethrex_storage::{EngineType, Store, error::StoreError};
use tracing::warn;

use crate::conversion::{block_to_payload, payload_to_block};

/// Version byte tag used when deriving payload ids inside ethrex, matching the
/// Cancun/Prague V3 attributes shape ethlambda produces. It only feeds ethrex's
/// internal id derivation — block validity comes from the store's chain config.
const PAYLOAD_VERSION: u8 = 3;

/// EIP-4844 transaction type byte. Submissions carrying it need the wrapped
/// encoding, which is a different shape from every other type.
const EIP4844_TX_TYPE: u8 = 0x03;

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
    #[error("payload build task failed: {0}")]
    BuildTask(String),
    #[error("transaction rejected by the mempool: {0}")]
    Mempool(#[from] MempoolError),
    #[error("execution-layer p2p is already running")]
    P2PAlreadyStarted,
    #[error("execution-layer p2p configuration error: {0}")]
    P2PConfig(String),
    #[error("failed to start execution-layer p2p: {0}")]
    P2PStart(String),
    #[error("payload claims block hash {claimed:#x} but its contents hash to {computed:#x}")]
    BlockHashMismatch { claimed: H256, computed: H256 },
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
    /// Set by [`Self::start_p2p`] so it can only run once — the actors it spawns
    /// have no shutdown handle.
    p2p_started: OnceLock<()>,
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
        // Load the KZG trusted setup on a background thread. It is compiled in,
        // so there is no file to find, but the first blob verification would
        // otherwise pay a multi-second initialisation — and the call that
        // triggers it could be a payload build at interval 4.
        ethrex_crypto::kzg::warm_up_trusted_setup();

        let mut store = Store::new("", EngineType::InMemory)?;
        store.add_initial_state(genesis).await?;
        let blockchain = Arc::new(Blockchain::default_with_store(store.clone()));
        Ok(Self {
            blockchain,
            store,
            extra_data: Bytes::new(),
            gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
            p2p_started: OnceLock::new(),
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

    /// Build the execution payload for a block being proposed on top of
    /// `parent_el_hash`.
    ///
    /// One call: ethrex creates the payload skeleton and fills it synchronously,
    /// so unlike the Engine API there is no id to hold onto and no second fetch.
    ///
    /// `parent_el_hash` **must** be the EL block hash the consensus chain expects
    /// to be extended — the `execution_payload.block_hash` of the Lean block
    /// being built on. It is passed in rather than read from this engine's own
    /// canonical head because the two can differ: every node runs its own
    /// execution layer, and an EL head that has drifted from the consensus chain
    /// would produce a payload whose `parent_hash` fails the state transition's
    /// check against `state.latest_execution_payload_header.block_hash` — which
    /// makes every peer reject the block.
    ///
    /// `beacon_root` follows the lean-parent-root convention — it is the
    /// proposed block's `parent_root`, and must be the same value later passed
    /// to [`Self::execute_payload`], or the EL's block-hash check fails.
    pub async fn build_payload(
        &self,
        parent_el_hash: LeanH256,
        timestamp: u64,
        prev_randao: LeanH256,
        beacon_root: LeanH256,
        fee_recipient: [u8; 20],
    ) -> Result<ExecutionPayloadV3, EngineError> {
        let parent = H256(parent_el_hash.0);
        // Make the EL treat that block as its head before building on it, so the
        // payload is produced against the state the consensus chain expects.
        // safe/finalized are left unset (ethrex reads zero as "not provided"):
        // pinning them here would forbid a later build on an earlier block.
        apply_fork_choice(&self.store, parent, H256::zero(), H256::zero())
            .await
            .map_err(|err| {
                EngineError::Conversion(format!("cannot build on parent {parent:#x}: {err}"))
            })?;
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

        // Filling the payload is a synchronous full EVM execution plus state
        // merkleization, and the caller is the consensus actor's task: left
        // inline it would block both that actor and a tokio worker for the whole
        // build, delaying the proposal's publication alignment and the following
        // tick. Free with today's empty blocks, not once transactions flow.
        // ethrex wraps its own callers the same way.
        let blockchain = Arc::clone(&self.blockchain);
        let built = tokio::task::spawn_blocking(move || blockchain.build_payload(skeleton))
            .await
            .map_err(|err| EngineError::BuildTask(err.to_string()))??
            .payload;

        Ok(block_to_payload(built))
    }

    /// Execute a payload and import the resulting block.
    ///
    /// `Ok(())` means the execution layer accepted it. An `Err` means the
    /// payload is unexecutable on this chain — the caller decides what that
    /// implies for consensus (today: drop the block, but never stall).
    ///
    /// Blob transactions execute here **without their sidecar**: validation
    /// derives blob gas and count from `blob_versioned_hashes` alone, and KZG
    /// verification happens only on mempool insertion, never on import. That is
    /// why a peer can execute a block containing one. It also means the blob
    /// data is not available: `ExecutionPayloadV3` has no sidecar field, so it
    /// never crosses the Lean network, and the mempool eviction below discards
    /// the only copies that existed. See `docs/ethrex-inprocess-integration.md`.
    pub fn execute_payload(
        &self,
        payload: &ExecutionPayloadV3,
        parent_beacon_block_root: LeanH256,
    ) -> Result<(), EngineError> {
        let block = payload_to_block(payload, parent_beacon_block_root)?;

        // `block_hash` is the proposer's *claim*; every other header field was
        // rebuilt from the payload's own contents, so recomputing the hash is
        // what ties the two together. Without this check a payload whose bytes
        // do not match its stated hash still imports, and each node's EL then
        // stores a different block under a hash the consensus chain has already
        // committed to — after which no node can build on it and the execution
        // layer wedges network-wide. Deterministic across nodes (the proposer
        // runs this same path on its own block), so every node rejects alike.
        let claimed = H256(payload.block_hash.0);
        let computed = block.hash();
        if computed != claimed {
            return Err(EngineError::BlockHashMismatch { claimed, computed });
        }

        // Held before `add_block` takes ownership; only used on success.
        let included: Vec<H256> = block.body.transactions.iter().map(|tx| tx.hash()).collect();

        self.blockchain.add_block(block)?;

        // Drop the now-included transactions from the mempool. ethrex does this
        // from its Engine-API fork-choice handler, which we bypass, so nothing
        // else would. Skipping it is not merely a leak: the payload builder
        // fetches pooled transactions without a nonce filter, and when the
        // stale copy fails to re-execute it discards *every* transaction from
        // that sender, so each account could only ever land one transaction.
        //
        // Best-effort: the block is already imported, so a mempool bookkeeping
        // failure must not turn into a rejection.
        for tx_hash in included {
            self.blockchain
                .mempool
                .remove_transaction(&tx_hash)
                .inspect_err(|err| {
                    warn!(%err, %tx_hash, "failed to evict included transaction");
                })
                .ok();
        }

        Ok(())
    }

    /// Submit an RLP-encoded transaction to the execution layer's mempool.
    ///
    /// Returns the transaction hash on acceptance. ethrex validates internally —
    /// encoded size, duplicate hash, signature recovery, nonce/balance/chain-id,
    /// and replacement rules — so there is nothing to pre-check here; a rejection
    /// comes back as [`EngineError::Mempool`].
    ///
    /// An accepted transaction is a *candidate*: it is included when some
    /// proposer's [`Self::build_payload`] next fills a block. With
    /// execution-layer gossip running that can be any node; without it, only
    /// this one.
    ///
    /// Blob transactions (type `0x03`) must be submitted in the **wrapped**
    /// form — `0x03 || rlp([tx, wrapper_version, blobs, commitments, proofs])`,
    /// the same shape `eth_sendRawTransaction` takes — because the mempool needs
    /// the sidecar to verify the KZG proofs and to build with later. The bare
    /// form carried inside blocks has no sidecar and is rejected.
    ///
    /// Note what happens to that sidecar afterwards: see [`Self::execute_payload`].
    pub async fn submit_raw_transaction(&self, raw: &[u8]) -> Result<LeanH256, EngineError> {
        if raw.first() == Some(&EIP4844_TX_TYPE) {
            return self.submit_blob_transaction(&raw[1..]).await;
        }
        let transaction = Transaction::decode_canonical(raw)
            .map_err(|err| EngineError::Conversion(format!("decode transaction: {err}")))?;
        let hash = self.blockchain.add_transaction_to_pool(transaction).await?;
        Ok(LeanH256(hash.0))
    }

    /// Decode a wrapped blob transaction and hand it, with its sidecar, to the
    /// mempool. `rlp` is the payload after the `0x03` type byte.
    async fn submit_blob_transaction(&self, rlp: &[u8]) -> Result<LeanH256, EngineError> {
        let wrapped = WrappedEIP4844Transaction::decode(rlp)
            .map_err(|err| EngineError::Conversion(format!("decode blob transaction: {err}")))?;

        // A bare `0x03` transaction still decodes here — the decoder falls back
        // to the blobless form and hands back an empty bundle. Say so plainly
        // rather than letting it surface as an opaque bundle-validation error.
        if wrapped.blobs_bundle.blobs.is_empty() {
            return Err(EngineError::Conversion(
                "blob transaction carries no sidecar: submit the wrapped form \
                 (0x03 || rlp([tx, wrapper_version, blobs, commitments, proofs]))"
                    .into(),
            ));
        }

        let hash = self
            .blockchain
            .add_blob_transaction_to_pool(wrapped.tx, wrapped.blobs_bundle)
            .await?;
        Ok(LeanH256(hash.0))
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
