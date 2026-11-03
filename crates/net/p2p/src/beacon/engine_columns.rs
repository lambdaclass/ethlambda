//! Data column sidecars this node built from its own execution client's blob
//! pool (`engine_getBlobsV2`), handed over by the chain actor with
//! `SidecarOrigin::ExecutionLayer`.
//!
//! The fulu p2p spec says a client that takes blobs from its local execution
//! layer SHOULD skip verifying them, and MUST then behave as if the sidecar had
//! arrived by gossip. In particular it MUST publish the sidecar on its
//! `data_column_sidecar_{subnet_id}` topic if and only if it is subscribed to
//! that topic, and MUST update the gossip rule data structures (the
//! anti-equivocation cache, here [`P2PServer::seen_columns`]).
//!
//! That is all this module does, which is why no checks run: the sidecars are
//! built from the block the chain actor already holds, with proofs the
//! execution client vouched for, so the chain checks `beacon::column_checks`
//! runs (header signature, inclusion proof, KZG) have nothing to add. Debug
//! builds still re-run them in the chain actor.
//!
//! Recording comes before publishing on purpose. A copy of the same column that
//! gossip delivers afterwards then finds its key taken and is ignored rather
//! than re-forwarded, and a column gossip already accepted is not published a
//! second time.

use ethlambda_state_transition::beacon::das;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::primitives::HashTreeRoot as _;
use libp2p::gossipsub::IdentTopic;
use tracing::{debug, error, info, warn};

use crate::beacon::topics as beacon_topics;
use crate::gossipsub::compress_message;
use crate::{P2PServer, metrics};

/// Record each sidecar in the seen cache, publish the newly recorded ones on
/// their subnets, and hand them to the chain actor.
pub(crate) fn publish_and_forward(server: &mut P2PServer, sidecars: Vec<DataColumnSidecar>) {
    let Some(beacon) = server.wire.beacon() else {
        error!(
            columns = sidecars.len(),
            "Execution-layer columns reached a lean node; dropping them"
        );
        return;
    };
    // Subnets are derived from the custody set (see `build_swarm`), so a column
    // is subscribed to exactly when it is custodied.
    let custody_columns = beacon.custody_columns.clone();

    let mut fresh: Vec<(DataColumnSidecar, Option<IdentTopic>)> = Vec::new();
    let mut already_seen = 0u64;
    let mut not_custody = 0u64;
    let mut missing_digest = false;
    let mut batch_header = None;
    for sidecar in sidecars {
        let DataColumnSidecar::Fulu(fulu) = &sidecar else {
            debug!("Skipping a gloas sidecar from the execution layer");
            continue;
        };
        let index = fulu.index;
        if !custody_columns.contains(&index) {
            not_custody += 1;
            continue;
        }
        let header = &fulu.signed_block_header.message;
        if !server
            .seen_columns
            .record(header.slot, header.proposer_index, index)
        {
            already_seen += 1;
            continue;
        }
        batch_header.get_or_insert_with(|| (header.slot, header.hash_tree_root()));
        let topic = server
            .wire
            .beacon()
            .and_then(|beacon| beacon.publish_digest(header.slot))
            .map(|digest| {
                let subnet = das::compute_subnet_for_data_column_sidecar(index);
                IdentTopic::new(beacon_topics::data_column_topic_name(digest, subnet))
            });
        missing_digest |= topic.is_none();
        fresh.push((sidecar, topic));
    }

    let mut published = 0u64;
    let mut forwarded = Vec::with_capacity(fresh.len());
    for (sidecar, topic) in fresh {
        if let Some(topic) = topic {
            server
                .swarm_handle
                .publish(topic, compress_message(&sidecar.to_ssz()));
            published += 1;
        }
        forwarded.push(sidecar);
    }
    let unpublished = forwarded.len() as u64 - published;

    if let Some((slot, block_root)) = batch_header {
        if missing_digest {
            warn!(
                slot,
                "No held fork digest covers these columns' slot; not publishing them"
            );
        }
        info!(
            slot,
            block_root = %ShortRoot(&block_root.0),
            published,
            no_digest = unpublished,
            already_seen,
            not_custody,
            "Execution-layer data columns"
        );
    }
    metrics::inc_data_columns_from_execution_layer("published", published);
    metrics::inc_data_columns_from_execution_layer("no_digest", unpublished);
    metrics::inc_data_columns_from_execution_layer("already_seen", already_seen);
    metrics::inc_data_columns_from_execution_layer("not_custody", not_custody);

    if forwarded.is_empty() {
        return;
    }
    if let Some(blockchain) = &server.blockchain {
        let _ = blockchain.new_data_column_sidecars(forwarded).inspect_err(
            |err| error!(%err, "Failed to hand the execution-layer columns to the chain"),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_types::beacon::config::Config;

    use super::*;
    use crate::test_support::{RecordingChain, unconnected_beacon_server, valid_shaped_sidecar};

    const SLOT: u64 = 5;
    const PROPOSER: u64 = 7;

    /// A server whose node custodies `custody`, wired to a recording chain.
    async fn server_custodying(custody: &[u64]) -> (P2PServer, Arc<RecordingChain>) {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let crate::Wire::Beacon(beacon) = &mut server.wire else {
            unreachable!("unconnected_beacon_server builds a beacon wire");
        };
        beacon.custody_columns = custody.to_vec();
        // The test server's digest is a placeholder; a held digest is what
        // lets the columns be published.
        beacon.topics.fork_digest = beacon.digest_for_slot(SLOT);
        let chain = Arc::new(RecordingChain::default());
        server.blockchain = Some(chain.clone());
        (server, chain)
    }

    fn sidecar(index: u64) -> DataColumnSidecar {
        DataColumnSidecar::Fulu(valid_shaped_sidecar(SLOT, index))
    }

    fn forwarded_indices(chain: &RecordingChain) -> Vec<Vec<u64>> {
        chain
            .sidecar_batches
            .lock()
            .unwrap()
            .iter()
            .map(|batch| batch.iter().map(DataColumnSidecar::index).collect())
            .collect()
    }

    #[tokio::test]
    async fn newly_seen_custody_columns_are_forwarded_in_one_batch_and_recorded() {
        let (mut server, chain) = server_custodying(&[1, 2]).await;

        publish_and_forward(&mut server, vec![sidecar(1), sidecar(2)]);

        assert_eq!(forwarded_indices(&chain), [vec![1, 2]]);
        assert!(server.seen_columns.contains(SLOT, PROPOSER, 1));
        assert!(server.seen_columns.contains(SLOT, PROPOSER, 2));
    }

    #[tokio::test]
    async fn a_column_gossip_already_accepted_is_not_forwarded() {
        let (mut server, chain) = server_custodying(&[1, 2]).await;
        assert!(server.seen_columns.record(SLOT, PROPOSER, 1));

        publish_and_forward(&mut server, vec![sidecar(1), sidecar(2)]);

        assert_eq!(forwarded_indices(&chain), [vec![2]]);
    }

    #[tokio::test]
    async fn a_column_outside_the_custody_set_is_dropped_and_not_recorded() {
        let (mut server, chain) = server_custodying(&[1]).await;

        publish_and_forward(&mut server, vec![sidecar(1), sidecar(9)]);

        assert_eq!(forwarded_indices(&chain), [vec![1]]);
        assert!(!server.seen_columns.contains(SLOT, PROPOSER, 9));
    }

    #[tokio::test]
    async fn a_batch_with_nothing_new_sends_the_chain_nothing() {
        let (mut server, chain) = server_custodying(&[1]).await;

        publish_and_forward(&mut server, vec![sidecar(9)]);

        assert!(forwarded_indices(&chain).is_empty());
    }
}
