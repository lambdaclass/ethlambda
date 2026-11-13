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
//! hold (first time) -> spawn_fetch
//!   task:          engine_getBlobsV2(versioned hashes)      1 s ceiling
//!     null / error -> count, give up (gossip and peer asks carry on)
//!     every blob   -> spawn_blocking:
//!                       block imported meanwhile?  -> stop
//!                       custody columns still missing, none? -> stop
//!                       cells + sidecars (no KZG verification)
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
//!   node asks on the first data-availability hold of a block, whether the
//!   block came from gossip or from sync, once its proposer signature verifies
//!   against its parent's state (see [`signed_by_its_proposer`]); it does not
//!   yet ask when a sidecar arrives. Hence the hand-over to p2p rather than a
//!   direct store write: publishing on subscribed subnets and updating the
//!   anti-equivocation cache are MUSTs, and p2p owns both.
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
//! - **No KZG verification.** The specification lets a node skip verifying
//!   blobs from its own execution client, so the proofs are trusted as given
//!   and the build is [`data_columns::unverified_sidecars`]. A mismatch with
//!   the block still fails the shape checks there.
//! - **Not gloas.** From gloas on, data availability moves from the block to
//!   the payload envelope, so a held gloas block has no columns to fill this
//!   way.
//!
//! The cell computation is CPU-heavy, so it runs on tokio's blocking pool: off
//! the async runtime and off the chain actor, which only ever sees the
//! finished columns, through p2p.

use std::time::Instant;

use ethlambda_engine::EngineClient;
use ethlambda_network_api::{BlockChainToP2PRef, SidecarOrigin};
use ethlambda_state_transition::beacon::data_columns;
use ethlambda_state_transition::beacon::precheck::{Reference, precheck_block};
use ethlambda_state_transition::beacon::stf::deneb::kzg_commitment_to_versioned_hash;
use ethlambda_storage::Store;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{DataColumnSidecar, SignedBeaconBlock, deneb, electra};
use ethlambda_types::beacon::primitives::KzgProof;
use ethlambda_types::primitives::H256;
use tracing::{debug, error, info, warn};

use crate::metrics;

/// Whether a held block may have its columns built from the execution
/// client's blobs: its proposer signature, and the rest of
/// [`precheck_block`]'s rules, hold against its parent's post-state.
///
/// The columns built here carry the block's own signed header and skip every
/// check on their way out (see `SidecarOrigin::ExecutionLayer`): p2p records
/// them in the seen cache under `(slot, proposer, index)` and publishes them.
/// A block can reach its hold unverified, since range sync and by-root
/// answers never pass gossip validation and the import checks the signature
/// only after data availability. Without this, a peer serving a forged copy
/// whose commitments name blobs in the local pool would have this node publish
/// columns its peers reject, and take the seen-cache key of the real block's
/// columns from the same proposer and slot.
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
) {
    tokio::spawn(fetch_and_publish(
        engine,
        p2p,
        store,
        block,
        block_root,
        custody_columns,
    ));
}

async fn fetch_and_publish(
    engine: EngineClient,
    p2p: BlockChainToP2PRef,
    store: Store,
    block: electra::SignedBeaconBlock,
    block_root: H256,
    custody_columns: Vec<u64>,
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
        let mut proofs: Vec<KzgProof> = Vec::new();
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
        Some(sidecars)
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
    let sidecars: Vec<DataColumnSidecar> =
        sidecars.into_iter().map(DataColumnSidecar::Fulu).collect();
    let _ = p2p
        .check_data_column_sidecars(sidecars, SidecarOrigin::ExecutionLayer)
        .inspect_err(|err| error!(%slot, %err, "Failed to hand execution-client columns to P2P"));

    info!(
        %slot,
        block_root = %ShortRoot(&block_root.0),
        blobs = blob_count,
        columns,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "Built data columns from the execution client's blobs"
    );
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
        let keyed = test_state::with_signing_validators_at(ForkName::Phase0, 1);
        let validator = keyed.validator(0).expect("one validator").clone();
        let mut state = bare_state();
        state
            .push_validator(validator, preset::MAX_EFFECTIVE_BALANCE)
            .expect("one validator fits the registry");
        state.apply_pending_mutations();

        let mut store = beacon_store(0, 0);
        store
            .insert_signed_block(H256::ZERO, bare_block(0, H256::repeat_byte(0xcc)))
            .expect("insert");
        store.insert_state(H256::ZERO, state).expect("insert");
        store
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
        let entries: Vec<String> = blobs
            .iter()
            .map(|blob| {
                let (_, proofs) = kzg::compute_cells_and_kzg_proofs(blob).unwrap();
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
        let mut block = fulu_block(H256::ZERO, 1, 0);
        let commitments: Vec<KzgCommitment> = blobs
            .iter()
            .map(|blob| kzg::blob_to_kzg_commitment(blob).unwrap())
            .collect();
        let SignedBeaconBlock::Fulu(inner) = &mut block else {
            unreachable!("fulu_block builds a fulu block");
        };
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
