//! Data columns from this node's own execution client (`engine_getBlobsV2`).
//!
//! A fulu block held for its custody columns (see
//! `BlockChainServer::hold_block_for_columns`) is usually answered by gossip
//! within a fraction of a second. When it is not, the execution client may
//! already hold every blob the block commits to, since the transactions that
//! carry them went through its pool first. This module asks it once and turns
//! the answer into the custody columns still missing.
//!
//! # Flow
//!
//! ```text
//! hold (first time, recent block) -> spawn_fetch
//!   task:          engine_getBlobsV2(versioned hashes)      1 s ceiling
//!     null / error -> count, give up (gossip and peer asks carry on)
//!     every blob   -> spawn_blocking:
//!                       block imported meanwhile?  -> stop
//!                       custody columns still missing, none? -> stop
//!                       cells + sidecars
//!                       the chain checks, KZG included (check_built)
//!                     check_data_column_sidecars(.., ExecutionLayer)
//!   p2p: records the columns as seen, publishes the new ones on their
//!        subnets, forwards them to the chain actor, which stores them and
//!        releases the held block
//! ```
//!
//! # Why it is shaped this way
//!
//! - **Spec basis.** Fulu `p2p-interface.md`, "Distributed blob publishing
//!   using blobs retrieved from local execution-layer client": honest nodes
//!   SHOULD query `engine_getBlobsV2` as soon as they receive a valid
//!   `beacon_block` or `data_column_sidecar` from gossip, convert a complete
//!   answer to data columns and import them as if received on gossip. This
//!   node asks on the first data-availability hold of a block at most
//!   [`MAX_ASK_AGE_SLOTS`] behind the clock, whether the block came from
//!   gossip or a by-root answer, once its proposer signature verifies against
//!   its parent's state (see [`signed_by_its_proposer`]); it does not yet ask
//!   when a sidecar arrives. Hence the hand-over to p2p rather than a direct
//!   store write: publishing on subscribed subnets and updating the
//!   anti-equivocation cache are MUSTs, and p2p owns both.
//! - **Recent blocks only.** The specification's trigger is gossip, so the
//!   tip. Range sync holds older blocks by the batch, and asking for each
//!   would be an unbounded fan-out of prechecks on the chain actor, engine
//!   calls and cell computations, for blocks whose columns peers are already
//!   being asked for (see [`MAX_ASK_AGE_SLOTS`]).
//! - **One attempt.** The call races gossip delivery of the same columns, the
//!   specification's own timeout for the method is 1 s, and a retry after the
//!   engine ladder's backoff would land after that race is decided. A miss
//!   leaves the block to gossip and the per-slot peer asks, which is where it
//!   was anyway. (The execution client can learn a blob a moment later, since
//!   blob transactions keep arriving in its pool; a later ask is not useless,
//!   just not worth the delay.)
//! - **V2, not V3.** V3 answers partially, but a column needs one cell from
//!   every blob, so a partial blob set builds no complete column and this node
//!   has no partial-column assembly.
//! - **Checked like a fetched column.** The specification lets a node skip
//!   verifying blobs from its own execution client, but this node does not:
//!   the built sidecars go through the same chain checks a fetched column does
//!   ([`check_built`]), KZG proofs included, before anything is published or
//!   stored. Two things depend on it. The proposer precheck below cannot name
//!   the expected proposer for a slot past its parent's lookahead, while the
//!   chain checks advance the parent's state to find out. And every row in
//!   `DataColumns` is one this node verified: a column stored here keeps every
//!   other copy of it out (`AlreadyStored`), and block import trusts the stored
//!   columns, so a wrong blob or proof taken on trust would either stop the
//!   block for good or import it on data nobody checked. The cost is one KZG
//!   batch over the custody columns, on the blocking pool. See
//!   `docs/spec_deviations.md`.
//! - **Not gloas.** From gloas on, data availability moves from the block to
//!   the payload envelope, so a held gloas block has no columns to fill this
//!   way.
//!
//! The cell computation is CPU-heavy, so it runs on tokio's blocking pool: off
//! the async runtime and off the chain actor, which only ever sees the
//! finished columns, through p2p.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ethlambda_engine::EngineClient;
use ethlambda_network_api::{BlockChainToP2PRef, SidecarOrigin};
use ethlambda_state_transition::beacon::data_columns;
use ethlambda_state_transition::beacon::gossip::column::{self, ChainPrechecks, ChainVerdict};
use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_state_transition::beacon::precheck::{Reference, precheck_block};
use ethlambda_state_transition::beacon::stf::deneb::kzg_commitment_to_versioned_hash;
use ethlambda_storage::Store;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{DataColumnSidecar, SignedBeaconBlock, deneb, electra};
use ethlambda_types::beacon::preset::CELLS_PER_EXT_BLOB;
use ethlambda_types::beacon::primitives::KzgProof;
use ethlambda_types::primitives::H256;
use ethlambda_types::time::unix_now_ms;
use tracing::{debug, error, info, warn};

use crate::metrics;

/// How many slots behind the store's clock a held block may be and still have
/// the execution client asked for its blobs.
///
/// Wide enough for what the specification's trigger covers (a block gossip
/// delivered in its own slot or late) and for a by-root answer filling in a
/// parent missed a slot or two back. Range sync is what it cuts off: every
/// block that delivers is older than the slot it arrives in, a catch-up holds
/// them by the batch, and asking for each would cost a parent-state read and
/// a BLS verification on the chain actor ([`signed_by_its_proposer`]), an
/// engine round trip, and on a hit a cell computation, all unbounded. Such a
/// block's columns are asked of peers at once (`hold_block_for_columns`), so
/// it does not wait for a redrive either way. How often the execution client
/// would still hold an older block's blobs is not measured.
pub(crate) const MAX_ASK_AGE_SLOTS: u64 = 4;

/// Whether a held block at `slot` is recent enough, at `current_slot`, to ask
/// the execution client about (see [`MAX_ASK_AGE_SLOTS`]).
pub(crate) fn recent_enough_to_ask(slot: u64, current_slot: u64) -> bool {
    slot.saturating_add(MAX_ASK_AGE_SLOTS) >= current_slot
}

/// How many held blocks of one slot may be considered for an execution-client
/// ask, counting every block whose precheck runs, not only those that pass it.
///
/// [`MAX_ASK_AGE_SLOTS`] bounds which slots qualify, not how many blocks: a
/// peer answering by root can hand the actor any number of distinct roots for
/// a recent slot, each costing a BLS verification on the chain actor
/// ([`signed_by_its_proposer`]) and, past the parent's lookahead (where any
/// registered validator's signature passes the precheck), an engine call, a
/// cell computation and a parent-state advance in [`check_built`]. An honest
/// slot has one block, two when its proposer equivocates; the rest is room for
/// a forged copy arriving first. Once a slot's budget is spent its blocks are
/// left to gossip and the peer asks, which is where a miss leaves them anyway.
pub(crate) const MAX_ASKS_PER_SLOT: u8 = 4;

/// How many execution-client asks may be in flight at once, from the engine
/// call through the cell computation and the chain checks on the blocking
/// pool. A hold finding them all taken does not ask.
pub(crate) const MAX_ASKS_IN_FLIGHT: usize = 4;

/// The admission limits on execution-client asks ([`MAX_ASKS_PER_SLOT`],
/// [`MAX_ASKS_IN_FLIGHT`]), owned by the chain actor.
#[derive(Debug, Default)]
pub(crate) struct AskBudget {
    /// Asks admitted per block slot, for slots still inside
    /// [`MAX_ASK_AGE_SLOTS`].
    per_slot: BTreeMap<u64, u8>,
    in_flight: Arc<AtomicUsize>,
}

impl AskBudget {
    /// Admit one ask for a held block at `slot`, spending one of that slot's
    /// [`MAX_ASKS_PER_SLOT`] and taking an in-flight slot that is released
    /// when the returned permit drops. `None` when either is exhausted.
    ///
    /// Called before the precheck, so a block that fails it still spends its
    /// slot's budget: that is what bounds the BLS verifications.
    pub(crate) fn admit(&mut self, slot: u64, current_slot: u64) -> Option<AskPermit> {
        let oldest = current_slot.saturating_sub(MAX_ASK_AGE_SLOTS);
        self.per_slot = self.per_slot.split_off(&oldest);
        let asked = self.per_slot.entry(slot).or_default();
        if *asked >= MAX_ASKS_PER_SLOT {
            metrics::inc_engine_get_blobs_skipped("slot_budget");
            return None;
        }
        let taken = self
            .in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_ASKS_IN_FLIGHT).then_some(n + 1)
            });
        if taken.is_err() {
            metrics::inc_engine_get_blobs_skipped("in_flight");
            return None;
        }
        *asked += 1;
        Some(AskPermit(Arc::clone(&self.in_flight)))
    }
}

/// One in-flight execution-client ask; releases its slot on drop.
#[derive(Debug)]
pub(crate) struct AskPermit(Arc<AtomicUsize>);

impl Drop for AskPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Whether a held block may have its columns built from the execution
/// client's blobs: its proposer signature, and the rest of
/// [`precheck_block`]'s rules, hold against its parent's post-state.
///
/// A filter, not the guard: [`check_built`] runs every chain check on the
/// built columns before they leave this module, and is what keeps a forged
/// header out of p2p's seen cache and off the wire. This only saves asking the
/// execution client, and computing cells, for a block whose signature already
/// fails here. A block can reach its hold unverified, since range sync and
/// by-root answers never pass gossip validation and the import checks the
/// signature only after data availability.
///
/// It cannot catch everything [`check_built`] does: past the parent state's
/// proposer lookahead, [`precheck_block`] checks the signature against the
/// key of whichever validator the block names, not that this validator is the
/// slot's proposer.
///
/// The parent has a post-state whenever the import reaches a hold; a hold
/// without one is not asked about.
pub(crate) fn signed_by_its_proposer(
    store: &Store,
    block: &SignedBeaconBlock,
    block_root: H256,
) -> bool {
    let slot = block.slot();
    let Some(parent_state) = store
        .get_state(&block.parent_root())
        .expect("DB read should succeed")
    else {
        debug!(
            %slot,
            block_root = %ShortRoot(&block_root.0),
            "Not asking the execution client for blobs: the block's parent has no post-state"
        );
        return false;
    };
    let config = store.config();
    precheck_block(block, block_root, Reference::Parent(&parent_state), &config)
        .inspect_err(|err| {
            let proposer = block.proposer_index();
            warn!(
                %slot,
                proposer,
                block_root = %ShortRoot(&block_root.0),
                %err,
                "Not asking the execution client for blobs: the block fails its precheck"
            )
        })
        .is_ok()
}

/// Ask the execution client for a held fulu block's blobs on a task of its
/// own, and hand the custody columns built from them to the p2p layer.
pub(crate) fn spawn_fetch(
    engine: EngineClient,
    p2p: BlockChainToP2PRef,
    store: Store,
    block: electra::SignedBeaconBlock,
    block_root: H256,
    custody_columns: Vec<u64>,
    permit: AskPermit,
) {
    tokio::spawn(fetch_and_publish(
        engine,
        p2p,
        store,
        block,
        block_root,
        custody_columns,
        permit,
    ));
}

/// `permit` is held until the blocking work ends, so it bounds the cell
/// computation and the chain checks too, not only the engine call.
async fn fetch_and_publish(
    engine: EngineClient,
    p2p: BlockChainToP2PRef,
    store: Store,
    block: electra::SignedBeaconBlock,
    block_root: H256,
    custody_columns: Vec<u64>,
    permit: AskPermit,
) {
    let slot = block.message.slot;
    let versioned_hashes: Vec<H256> = block
        .message
        .body
        .blob_kzg_commitments
        .iter()
        .map(kzg_commitment_to_versioned_hash)
        .collect();

    let started = Instant::now();
    let answer = engine.get_blobs_v2(&versioned_hashes).await;
    metrics::observe_engine_get_blobs_duration(started.elapsed());

    let entries = match answer {
        Err(err) => {
            debug!(%slot, block_root = %ShortRoot(&block_root.0), %err, "engine_getBlobsV2 failed");
            metrics::inc_engine_get_blobs("error");
            return;
        }
        Ok(None) => {
            debug!(%slot, block_root = %ShortRoot(&block_root.0), "Execution client is missing blobs for the block");
            metrics::inc_engine_get_blobs("miss");
            return;
        }
        Ok(Some(entries)) => {
            metrics::inc_engine_get_blobs("hit");
            entries
        }
    };

    let blob_count = entries.len();
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // The block was imported while the execution client answered (gossip
        // completed it first): nothing left to supply.
        match store.has_state(&block_root) {
            Ok(false) => {}
            Ok(true) => return None,
            Err(err) => {
                error!(%slot, block_root = %ShortRoot(&block_root.0), %err, "Failed to check whether a held block was imported");
                return None;
            }
        }
        let present = match store.data_column_indices_for(slot, &block_root) {
            Ok(present) => present,
            Err(err) => {
                error!(%slot, block_root = %ShortRoot(&block_root.0), %err, "Failed to read a held block's stored data columns");
                return None;
            }
        };
        let missing: Vec<u64> = custody_columns
            .iter()
            .copied()
            .filter(|index| !present.contains(index))
            .collect();
        if missing.is_empty() {
            return None;
        }

        let converted = Instant::now();
        let mut blobs = Vec::with_capacity(entries.len());
        let mut proofs: Vec<KzgProof> = Vec::with_capacity(entries.len() * CELLS_PER_EXT_BLOB);
        for entry in entries {
            match deneb::Blob::try_from(entry.blob) {
                Ok(blob) => blobs.push(blob),
                Err(_) => {
                    warn!(%slot, block_root = %ShortRoot(&block_root.0), "Execution client's blob has the wrong size");
                    return None;
                }
            }
            proofs.extend(entry.proofs);
        }
        let sidecars = match data_columns::unverified_sidecars(&block, &blobs, &proofs, &missing) {
            Ok(sidecars) => sidecars,
            Err(err) => {
                warn!(%slot, block_root = %ShortRoot(&block_root.0), %err, "Execution client's blobs do not fit the block");
                return None;
            }
        };
        metrics::observe_engine_blobs_to_columns(converted.elapsed());
        let sidecars = sidecars.into_iter().map(DataColumnSidecar::Fulu).collect();
        Some(check_built(&store, slot, block_root, sidecars))
    })
    .await;

    let sidecars = match work {
        Ok(Some(sidecars)) if !sidecars.is_empty() => sidecars,
        Ok(_) => return,
        Err(err) => {
            error!(%slot, block_root = %ShortRoot(&block_root.0), %err, "Blob-to-column task failed");
            return;
        }
    };

    let columns = sidecars.len();
    if let Err(err) = p2p.check_data_column_sidecars(sidecars, SidecarOrigin::ExecutionLayer) {
        error!(%slot, %err, "Failed to hand execution-client columns to P2P");
        return;
    }

    info!(
        %slot,
        block_root = %ShortRoot(&block_root.0),
        blobs = blob_count,
        columns,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "Built data columns from the execution client's blobs"
    );
}

/// The built `sidecars` that pass every chain check a fetched column gets
/// ([`column::chain_checks`]'s rules, in the two stages p2p runs them for one
/// block: [`ChainPrechecks`], then one KZG batch).
///
/// That is the structure, the clock and finality, `AlreadyStored`, the signed
/// header (parent state, slot order, signature, the expected proposer, past
/// the lookahead by advancing the parent's state), finalized ancestry, the
/// inclusion proof, and the cells against the block's commitments. The
/// sidecars all carry one signed header, so the header is judged once.
///
/// A refusal drops the column and is counted by reason
/// (`lean_engine_blob_columns_refused_total`). `AlreadyStored` is not a
/// refusal: gossip or a peer answer stored that column while the execution
/// client answered, which is the race this call loses at times. Anything else
/// is a block whose header does not hold (a forged or wrong-proposer block that
/// got past the precheck) or an execution client whose blobs or proofs do not
/// match the block, and none of it may reach p2p's seen cache, the wire or
/// `DataColumns`.
fn check_built(
    store: &Store,
    slot: u64,
    block_root: H256,
    sidecars: Vec<DataColumnSidecar>,
) -> Vec<DataColumnSidecar> {
    let mut prechecks = ChainPrechecks::new(store, unix_now_ms());
    let mut refused: Vec<ChainVerdict> = Vec::new();
    let mut pending = Vec::with_capacity(sidecars.len());
    for sidecar in sidecars {
        match prechecks.check(&sidecar) {
            Ok(kzg) => pending.push((sidecar, kzg)),
            Err(verdict) => refused.push(verdict),
        }
    }

    let verdicts = {
        let items: Vec<_> = pending
            .iter()
            .map(|(sidecar, kzg)| (sidecar, kzg))
            .collect();
        column::kzg_verdicts(&items)
    };
    let mut kept = Vec::with_capacity(pending.len());
    for ((sidecar, _), verdict) in pending.into_iter().zip(verdicts) {
        match verdict {
            ChainVerdict::Keep => kept.push(sidecar),
            verdict => refused.push(verdict),
        }
    }

    let stored_meanwhile = ChainVerdict::Drop(Outcome::Ignore(IgnoreReason::AlreadyStored));
    for verdict in refused
        .iter()
        .filter(|&&verdict| verdict != stored_meanwhile)
    {
        let reason = match verdict {
            ChainVerdict::Drop(outcome) => outcome.labels().1,
            // The parent has a post-state whenever a block is held, so this
            // is not expected; counted rather than asserted.
            ChainVerdict::AwaitParent | ChainVerdict::Keep => "await_parent",
        };
        metrics::inc_engine_blob_columns_refused(reason);
    }
    if let Some(verdict) = refused.iter().find(|&&verdict| verdict != stored_meanwhile) {
        warn!(
            %slot,
            block_root = %ShortRoot(&block_root.0),
            ?verdict,
            refused = refused.len(),
            kept = kept.len(),
            "The chain checks refused columns built from the execution client's blobs; not publishing them"
        );
    }
    kept
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ethlambda_engine::{EngineClient, JwtSecret};
    use ethlambda_state_transition::beacon::kzg;
    use ethlambda_types::beacon::containers::SignedBeaconBlock;
    use ethlambda_types::beacon::primitives::KzgCommitment;
    use ethlambda_types::primitives::HashTreeRoot as _;
    use libssz_types::SszList;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;
    use crate::import_timing::ImportTimings;
    use crate::tests::{bare_block, bare_state, beacon_server_recording, beacon_store, fulu_block};
    use ethlambda_state_transition::beacon::helpers::test_state;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::constants::DOMAIN_BEACON_PROPOSER;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset::{self, BYTES_PER_BLOB};
    use ethlambda_types::beacon::signing::{
        compute_domain, compute_epoch_at_slot, compute_signing_root,
    };

    /// `beacon_store(0, 0)` whose anchor, the parent of every block here, has
    /// a post-state registering validator 0 under the key [`sign`] uses, so a
    /// signed block passes the precheck a hold runs before it asks the
    /// execution client.
    fn store_with_keyed_parent() -> Store {
        store_with_keyed_parent_of(1)
    }

    /// [`store_with_keyed_parent`] with `count` validators, each registered
    /// under the key [`sign`] uses for its index.
    fn store_with_keyed_parent_of(count: usize) -> Store {
        let mut store = beacon_store(0, 0);
        store
            .insert_signed_block(H256::ZERO, bare_block(0, H256::repeat_byte(0xcc)))
            .expect("insert");
        store
            .insert_state(H256::ZERO, keyed_parent_state(count))
            .expect("insert");
        store
    }

    /// `bare_state` with `count` validators keyed as [`sign`] signs.
    fn keyed_parent_state(count: usize) -> ethlambda_types::beacon::containers::BeaconState {
        let keyed = test_state::with_signing_validators_at(ForkName::Phase0, count);
        let mut state = bare_state();
        for index in 0..count {
            let validator = keyed.validator(index as u64).expect("keyed").clone();
            state
                .push_validator(validator, preset::MAX_EFFECTIVE_BALANCE)
                .expect("the validators fit the registry");
        }
        state.apply_pending_mutations();
        state
    }

    /// `block` signed by validator 0, its proposer, under the mainnet fork
    /// schedule `beacon_store` runs on.
    fn sign(mut block: SignedBeaconBlock) -> SignedBeaconBlock {
        let config = Config::mainnet();
        let fork_version =
            config.fork_version(config.fork_at_epoch(compute_epoch_at_slot(block.slot())));
        // `bare_state`'s genesis validators root.
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, H256::ZERO);
        let signing_root = compute_signing_root(block.message_hash_tree_root(), domain);
        let SignedBeaconBlock::Fulu(inner) = &mut block else {
            unreachable!("these tests build fulu blocks");
        };
        inner.signature = test_state::sign_for(inner.message.proposer_index as usize, signing_root);
        block
    }

    /// A blob whose every field element is below the BLS modulus.
    fn blob_bytes(seed: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; BYTES_PER_BLOB];
        for (i, element) in bytes.chunks_mut(32).enumerate() {
            element[1] = seed;
            element[2] = i as u8;
            element[3] = (i >> 8) as u8;
        }
        bytes
    }

    /// The `result` of an `engine_getBlobsV2` answer for `blobs`, with real
    /// cell proofs.
    fn answer_for(blobs: &[Vec<u8>]) -> String {
        answer_with_proofs_of(blobs, blobs)
    }

    /// An answer carrying `blobs`, each with the cell proofs of the blob at the
    /// same position in `proofs_from`: [`answer_for`] when the two are equal,
    /// a well-shaped answer with wrong proofs otherwise.
    fn answer_with_proofs_of(blobs: &[Vec<u8>], proofs_from: &[Vec<u8>]) -> String {
        let entries: Vec<String> = blobs
            .iter()
            .zip(proofs_from)
            .map(|(blob, proof_blob)| {
                let (_, proofs) = kzg::compute_cells_and_kzg_proofs(proof_blob).unwrap();
                let proofs: Vec<String> = proofs
                    .iter()
                    .map(|proof| format!("\"0x{}\"", hex::encode(proof.0)))
                    .collect();
                format!(
                    r#"{{"blob":"0x{}","proofs":[{}]}}"#,
                    hex::encode(blob),
                    proofs.join(",")
                )
            })
            .collect();
        format!("[{}]", entries.join(","))
    }

    /// A loopback JSON-RPC server answering every request with `result`, and
    /// counting them.
    async fn mock_engine(result: String) -> (EngineClient, Arc<AtomicUsize>) {
        let requests = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("bound address");
        let counter = Arc::clone(&requests);
        let payload = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let counter = Arc::clone(&counter);
                let payload = payload.clone();
                tokio::spawn(async move {
                    let mut pending: Vec<u8> = Vec::new();
                    loop {
                        let (head_end, body_len) = loop {
                            if let Some(end) =
                                pending.windows(4).position(|window| window == b"\r\n\r\n")
                            {
                                let head = String::from_utf8_lossy(&pending[..end]).to_lowercase();
                                let len = head
                                    .lines()
                                    .find_map(|line| line.strip_prefix("content-length:"))
                                    .and_then(|value| value.trim().parse::<usize>().ok())
                                    .unwrap_or(0);
                                break (end + 4, len);
                            }
                            let mut chunk = [0u8; 16 * 1024];
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => pending.extend_from_slice(&chunk[..read]),
                            }
                        };
                        while pending.len() < head_end + body_len {
                            let mut chunk = [0u8; 16 * 1024];
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => pending.extend_from_slice(&chunk[..read]),
                            }
                        }
                        pending.drain(..head_end + body_len);
                        counter.fetch_add(1, Ordering::SeqCst);

                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
                            payload.len()
                        );
                        if socket.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let client = EngineClient::new(format!("http://{addr}"), JwtSecret::new([0x0f; 32]))
            .expect("a client");
        (client, requests)
    }

    /// A fulu block at slot 1 committing to each of `blobs`, signed by its
    /// proposer.
    fn block_committing_to(blobs: &[Vec<u8>]) -> SignedBeaconBlock {
        block_by(0, blobs)
    }

    /// [`block_committing_to`], naming `proposer` and signed by its key.
    fn block_by(proposer: u64, blobs: &[Vec<u8>]) -> SignedBeaconBlock {
        let mut block = fulu_block(H256::ZERO, 1, 0);
        let commitments: Vec<KzgCommitment> = blobs
            .iter()
            .map(|blob| kzg::blob_to_kzg_commitment(blob).unwrap())
            .collect();
        let SignedBeaconBlock::Fulu(inner) = &mut block else {
            unreachable!("fulu_block builds a fulu block");
        };
        inner.message.proposer_index = proposer;
        inner.message.body.blob_kzg_commitments = SszList::try_from(commitments).unwrap();
        sign(block)
    }

    const CUSTODY: [u64; 3] = [0, 5, 77];

    /// Polls until `RecordingP2P` has a hand-over, or a few seconds pass.
    async fn wait_for_hand_over(p2p: &crate::tests::RecordingP2P) {
        for _ in 0..100 {
            if !p2p.checks.lock().unwrap().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn a_full_answer_hands_over_exactly_the_custody_columns() {
        let blobs = vec![blob_bytes(1), blob_bytes(2)];
        let block = block_committing_to(&blobs);
        let root = block.message_hash_tree_root();
        let (engine, requests) = mock_engine(answer_for(&blobs)).await;
        let (mut server, p2p) = beacon_server_recording(store_with_keyed_parent());
        server.engine = Some(engine);
        server.custody_columns = CUSTODY.to_vec();

        server.hold_block_for_columns(block.clone(), 1, ImportTimings::default());
        wait_for_hand_over(&p2p).await;

        let checks = p2p.checks.lock().unwrap();
        assert_eq!(checks.len(), 1, "one hand-over");
        assert_eq!(
            *p2p.check_origins.lock().unwrap(),
            vec![ethlambda_network_api::SidecarOrigin::ExecutionLayer]
        );
        let indices: Vec<u64> = checks[0]
            .iter()
            .map(|sidecar| match sidecar {
                DataColumnSidecar::Fulu(sidecar) => sidecar.index,
                DataColumnSidecar::Gloas(_) => panic!("a fulu block yields fulu sidecars"),
            })
            .collect();
        assert_eq!(indices, CUSTODY.to_vec());
        for sidecar in checks[0].iter() {
            let DataColumnSidecar::Fulu(sidecar) = sidecar else {
                unreachable!()
            };
            let header = &sidecar.signed_block_header.message;
            assert_eq!(header.slot, block.slot());
            assert_eq!(header.parent_root, block.parent_root());
            assert_eq!(header.hash_tree_root(), root);
            assert_eq!(sidecar.column.len(), blobs.len());
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_stored_custody_column_is_not_handed_over_again() {
        let blobs = vec![blob_bytes(3)];
        let block = block_committing_to(&blobs);
        let root = block.message_hash_tree_root();
        let (engine, _requests) = mock_engine(answer_for(&blobs)).await;
        let (mut server, p2p) = beacon_server_recording(store_with_keyed_parent());
        server.engine = Some(engine);
        server.custody_columns = CUSTODY.to_vec();
        server
            .store
            .put_data_column_sidecar(block.slot(), &root, 0, vec![1])
            .unwrap();

        server.hold_block_for_columns(block, 1, ImportTimings::default());
        wait_for_hand_over(&p2p).await;

        let checks = p2p.checks.lock().unwrap();
        assert_eq!(checks.len(), 1);
        let indices: Vec<u64> = checks[0]
            .iter()
            .map(|sidecar| match sidecar {
                DataColumnSidecar::Fulu(sidecar) => sidecar.index,
                DataColumnSidecar::Gloas(_) => panic!("a fulu block yields fulu sidecars"),
            })
            .collect();
        assert_eq!(indices, vec![5, 77]);
    }

    #[tokio::test]
    async fn a_null_answer_hands_nothing_over() {
        let blobs = vec![blob_bytes(4)];
        let block = block_committing_to(&blobs);
        let (engine, requests) = mock_engine("null".to_string()).await;
        let (mut server, p2p) = beacon_server_recording(store_with_keyed_parent());
        server.engine = Some(engine);
        server.custody_columns = CUSTODY.to_vec();

        server.hold_block_for_columns(block, 1, ImportTimings::default());
        for _ in 0..40 {
            if requests.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(requests.load(Ordering::SeqCst), 1, "the engine was asked");
        assert!(p2p.checks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn without_an_engine_nothing_is_asked_or_handed_over() {
        let blobs = vec![blob_bytes(5)];
        let block = block_committing_to(&blobs);
        let (mut server, p2p) = beacon_server_recording(store_with_keyed_parent());
        server.custody_columns = CUSTODY.to_vec();

        server.hold_block_for_columns(block, 1, ImportTimings::default());
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(p2p.checks.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_second_hold_of_the_same_root_does_not_ask_again() {
        let blobs = vec![blob_bytes(6)];
        let block = block_committing_to(&blobs);
        let (engine, requests) = mock_engine("null".to_string()).await;
        let (mut server, _p2p) = beacon_server_recording(store_with_keyed_parent());
        server.engine = Some(engine);
        server.custody_columns = CUSTODY.to_vec();

        server.hold_block_for_columns(block.clone(), 1, ImportTimings::default());
        for _ in 0..40 {
            if requests.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        server.hold_block_for_columns(block, 1, ImportTimings::default());
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    /// A block imported while the execution client answered (gossip
    /// completed it first): the answer is a hit, but the re-check before the
    /// build finds the block's state and nothing is built or handed over.
    #[tokio::test]
    async fn a_hit_for_a_block_imported_meanwhile_hands_nothing_over() {
        let blobs = vec![blob_bytes(8)];
        let block = block_committing_to(&blobs);
        let root = block.message_hash_tree_root();
        let mut store = beacon_store(0, 0);
        store
            .insert_signed_block(root, block.clone())
            .expect("insert");
        store.insert_state(root, bare_state()).expect("insert");
        let SignedBeaconBlock::Fulu(inner) = block else {
            unreachable!("fulu_block builds a fulu block");
        };
        let (engine, requests) = mock_engine(answer_for(&blobs)).await;
        let p2p = Arc::new(crate::tests::RecordingP2P::default());

        let permit = AskBudget::default()
            .admit(1, 1)
            .expect("an empty budget admits");
        fetch_and_publish(
            engine,
            p2p.clone(),
            store,
            inner,
            root,
            CUSTODY.to_vec(),
            permit,
        )
        .await;

        assert_eq!(requests.load(Ordering::SeqCst), 1, "the engine was asked");
        assert!(p2p.checks.lock().unwrap().is_empty());
    }

    /// A block more than `MAX_ASK_AGE_SLOTS` behind the clock (range sync's)
    /// is not asked about; one exactly that far behind still is.
    #[tokio::test]
    async fn only_a_recent_block_is_asked_about() {
        let at_the_edge = block_committing_to(&[blob_bytes(9)]);
        let too_old = block_committing_to(&[blob_bytes(10)]);
        let (engine, requests) = mock_engine("null".to_string()).await;
        let (mut server, _p2p) = beacon_server_recording(store_with_keyed_parent());
        server.engine = Some(engine);
        server.custody_columns = CUSTODY.to_vec();

        let edge = at_the_edge.slot() + MAX_ASK_AGE_SLOTS;
        server.hold_block_for_columns(too_old, edge + 1, ImportTimings::default());
        server.hold_block_for_columns(at_the_edge, edge, ImportTimings::default());
        for _ in 0..40 {
            if requests.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            requests.load(Ordering::SeqCst),
            1,
            "only the block at the edge of the window was asked about"
        );
    }

    /// An execution client whose proofs do not match its blobs (here, each
    /// blob answered with another blob's proofs): the answer has the right
    /// shape and the precheck passes, but the KZG batch refuses every built
    /// column, so nothing reaches p2p's seen cache, the wire or `DataColumns`.
    #[tokio::test]
    async fn columns_with_wrong_proofs_are_not_handed_over() {
        let blobs = vec![blob_bytes(11), blob_bytes(12)];
        let block = block_committing_to(&blobs);
        // Not another `blob_bytes`: two of those differ by the same constant
        // in every field element, and a cell proof does not change when a
        // constant is added to the polynomial, so their proofs coincide.
        let scrambled = |seed: u8| -> Vec<u8> {
            let mut bytes = blob_bytes(seed);
            for element in bytes.chunks_mut(32) {
                element[2] = element[2].wrapping_mul(7);
            }
            bytes
        };
        let wrong = answer_with_proofs_of(&blobs, &[scrambled(11), scrambled(12)]);
        assert_ne!(wrong, answer_for(&blobs), "the proofs differ");
        let (engine, requests) = mock_engine(wrong).await;
        let (mut server, p2p) = beacon_server_recording(store_with_keyed_parent());
        server.engine = Some(engine);
        server.custody_columns = CUSTODY.to_vec();

        server.hold_block_for_columns(block, 1, ImportTimings::default());
        for _ in 0..40 {
            if requests.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert_eq!(requests.load(Ordering::SeqCst), 1, "the engine was asked");
        assert!(p2p.checks.lock().unwrap().is_empty());
    }

    /// A block past its parent state's proposer lookahead (a phase0 parent has
    /// none), naming a validator that is not the slot's proposer and signed by
    /// that validator's own key. The precheck can only check the signature
    /// there, so it passes and the execution client is asked; the chain checks
    /// advance the parent's state, find the real proposer, and refuse every
    /// column. The slot's real proposer's block, from the same blobs, is
    /// handed over.
    #[tokio::test]
    async fn a_block_from_the_wrong_proposer_past_the_lookahead_is_not_handed_over() {
        let config = Config::mainnet();
        let mut advanced = keyed_parent_state(2);
        ethlambda_state_transition::beacon::stf::process_slots(&mut advanced, 1, &config)
            .expect("advance to slot 1");
        let proposer =
            ethlambda_state_transition::beacon::helpers::accessors::get_beacon_proposer_index(
                &advanced,
            )
            .expect("a proposer for slot 1");
        let impostor = 1 - proposer;

        for (named, handed_over) in [(impostor, false), (proposer, true)] {
            let blobs = vec![blob_bytes(15)];
            let block = block_by(named, &blobs);
            let (engine, requests) = mock_engine(answer_for(&blobs)).await;
            let (mut server, p2p) = beacon_server_recording(store_with_keyed_parent_of(2));
            server.engine = Some(engine);
            server.custody_columns = CUSTODY.to_vec();

            server.hold_block_for_columns(block, 1, ImportTimings::default());
            if handed_over {
                wait_for_hand_over(&p2p).await;
            } else {
                for _ in 0..40 {
                    if requests.load(Ordering::SeqCst) > 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }

            assert_eq!(
                requests.load(Ordering::SeqCst),
                1,
                "the precheck let validator {named}'s block through to the engine"
            );
            assert_eq!(
                !p2p.checks.lock().unwrap().is_empty(),
                handed_over,
                "validator {named}'s columns handed over"
            );
        }
    }

    /// A slot's budget is spent by every admitted ask, whatever its precheck
    /// says, and frees up only as the slot leaves the age window; the
    /// in-flight cap frees up as permits drop.
    #[test]
    fn the_ask_budget_bounds_asks_per_slot_and_in_flight() {
        let mut budget = AskBudget::default();
        let held: Vec<AskPermit> = (0..MAX_ASKS_IN_FLIGHT)
            .map(|i| budget.admit(10 + i as u64, 10).expect("room in flight"))
            .collect();
        assert!(budget.admit(20, 20).is_none(), "every in-flight slot taken");
        drop(held);

        for _ in 0..MAX_ASKS_PER_SLOT {
            let _ = budget.admit(30, 30).expect("room in the slot");
        }
        assert!(budget.admit(30, 30).is_none(), "slot 30's budget spent");
        assert!(budget.admit(31, 31).is_some(), "another slot has its own");
        assert!(
            budget.admit(30, 30 + MAX_ASK_AGE_SLOTS).is_none(),
            "still inside the window"
        );
        assert!(
            budget.admit(31, 31 + MAX_ASK_AGE_SLOTS + 1).is_some(),
            "a pruned slot starts over"
        );
    }

    /// Distinct roots for one recent slot, each with a bad signature: only the
    /// slot's budget of them reaches the precheck, and none the engine.
    #[tokio::test]
    async fn a_flood_of_forged_roots_for_one_slot_spends_only_its_budget() {
        let (engine, requests) = mock_engine("null".to_string()).await;
        let (mut server, _p2p) = beacon_server_recording(store_with_keyed_parent());
        server.engine = Some(engine);
        server.custody_columns = CUSTODY.to_vec();

        for seed in 0..(MAX_ASKS_PER_SLOT + 3) {
            let mut block = block_committing_to(&[blob_bytes(20)]);
            let SignedBeaconBlock::Fulu(inner) = &mut block else {
                unreachable!("fulu_block builds a fulu block");
            };
            inner.message.body.graffiti = H256::repeat_byte(seed + 1);
            server.hold_block_for_columns(block, 1, ImportTimings::default());
        }
        let genuine = block_committing_to(&[blob_bytes(20)]);
        server.hold_block_for_columns(genuine, 1, ImportTimings::default());
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "the budget was spent by the forged roots before the genuine one"
        );
        assert_eq!(
            server.blob_asks.per_slot.get(&1).copied(),
            Some(MAX_ASKS_PER_SLOT)
        );
    }

    /// An altered copy of a block (its body changed after signing, the
    /// signature kept) whose commitments name blobs the execution client
    /// holds: the columns would carry a header nobody signed, so the client is
    /// not asked and nothing reaches p2p's seen cache or the wire.
    #[tokio::test]
    async fn a_block_whose_signature_does_not_verify_is_not_asked_about() {
        let blobs = vec![blob_bytes(7)];
        let mut block = block_committing_to(&blobs);
        let SignedBeaconBlock::Fulu(inner) = &mut block else {
            unreachable!("fulu_block builds a fulu block");
        };
        inner.message.body.graffiti = H256::repeat_byte(0x01);
        let (engine, requests) = mock_engine(answer_for(&blobs)).await;
        let (mut server, p2p) = beacon_server_recording(store_with_keyed_parent());
        server.engine = Some(engine);
        server.custody_columns = CUSTODY.to_vec();

        server.hold_block_for_columns(block, 1, ImportTimings::default());
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "the engine was not asked"
        );
        assert!(p2p.checks.lock().unwrap().is_empty());
    }
}
