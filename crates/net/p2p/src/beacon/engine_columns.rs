//! Data column sidecars this node built from its own execution client's blob
//! pool (`engine_getBlobsV2`), handed over by the chain actor with
//! `SidecarOrigin::ExecutionLayer`.
//!
//! The fulu p2p spec says a client that takes blobs from its local execution
//! layer MUST behave as if the sidecar had arrived by gossip. In particular it
//! MUST publish the sidecar on its `data_column_sidecar_{subnet_id}` topic if
//! and only if it is subscribed to that topic, and MUST update the gossip rule
//! data structures (the anti-equivocation cache, here
//! [`P2PServer::seen_columns`]).
//!
//! That is all this module does, and why no checks run here: the chain actor
//! already ran every chain check on these sidecars, KZG proofs included,
//! before handing them over (`ethlambda_blockchain`'s `beacon_blobs`, the same
//! rules `beacon::column_checks` runs on a fetched column). Debug builds re-run
//! them in the chain actor.
//!
//! Recording comes before publishing on purpose. A copy of the same column that
//! gossip delivers afterwards then finds its key taken and is ignored rather
//! than re-forwarded, and a column gossip already accepted is not published a
//! second time. A column whose key is taken is still handed to the chain actor:
//! the key carries no block root, so it may be another block's of the same
//! slot and proposer, and the seen cache only gates publication, not storage.
//!
//! One copy is the exception: the identical column gossip delivered just
//! before, still in validation. Gossip records a column only once its verdict
//! is `Accept` (`verdict::Validated::record_seen`), so that copy's verdict
//! finds the key taken. Its bytes, and so its message id, are the ones
//! published here, and gossipsub put that id in its duplicate cache on
//! arrival, before validation, so the publish was refused as
//! `PublishError::Duplicate` and sent nothing. Downgrading the verdict to
//! `Ignore(AlreadySeen)` would then relay neither copy. [`PublishedColumns`]
//! remembers the ids published here so the verdict keeps its `Accept` and
//! gossipsub relays the copy it holds.

use std::num::NonZeroUsize;

use ethlambda_state_transition::beacon::das;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::DataColumnSidecar;
use ethlambda_types::primitives::HashTreeRoot as _;
use libp2p::gossipsub::{IdentTopic, MessageId};
use lru::LruCache;
use tracing::{debug, error, info, warn};

use crate::beacon::topics as beacon_topics;
use crate::gossipsub::compress_message;
use crate::{P2PServer, metrics, published_message_id};

/// Gossipsub message ids of the columns [`publish_and_forward`] published.
///
/// A gossip copy that reaches its verdict with one of these ids was in
/// validation when the column was published here: had it arrived after,
/// gossipsub would have dropped it as a duplicate of our own publish before
/// it reached this actor. So that publish sent nothing (see the module doc),
/// and the copy's `Accept` stands although its seen-cache key is taken, by
/// this very column. Bounded by capacity, like the seen caches: an id whose
/// gossip copy never comes is only evicted.
pub(crate) struct PublishedColumns(LruCache<MessageId, ()>);

impl PublishedColumns {
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    fn insert(&mut self, id: MessageId) {
        self.0.put(id, ());
    }

    /// Whether `id` is one this node published from the execution layer,
    /// forgetting it: gossipsub delivers one id at most once while it is in
    /// its duplicate cache, which outlives any validation.
    pub(crate) fn take(&mut self, id: &MessageId) -> bool {
        self.0.pop(id).is_some()
    }
}

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
        batch_header.get_or_insert_with(|| (header.slot, header.hash_tree_root()));
        // The key is taken: not published, but still forwarded. The key is
        // (slot, proposer, index) with no root, so it may belong to another
        // block of the same slot (an equivocating proposer's), whose stored
        // columns do nothing for this one; these passed every chain check, and
        // dropping them would leave this block held on data this node has.
        // When it is this block's own copy, the chain finds it stored.
        if !server
            .seen_columns
            .record(header.slot, header.proposer_index, index)
        {
            already_seen += 1;
            fresh.push((sidecar, None));
            continue;
        }
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
            let ssz = sidecar.to_ssz();
            let message_id = published_message_id(&topic.hash(), &ssz);
            server.engine_published_columns.insert(message_id);
            server.swarm_handle.publish(topic, compress_message(&ssz));
            published += 1;
        }
        forwarded.push(sidecar);
    }
    let unpublished = forwarded.len() as u64 - published - already_seen;

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

    use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::fork::ForkName;

    use super::*;
    use crate::beacon::decode::decode_data_column_sidecar;
    use crate::beacon::verdict::{Validated, settle_message};
    use crate::gossipsub::decompress_message;
    use crate::swarm_adapter::{SwarmCommand, SwarmHandle};
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

    /// What goes on the wire is what gossip validation decodes: the fulu
    /// container, snappy-compressed, on the column's own subnet topic under
    /// the digest held for its slot. Only a newly recorded custody column
    /// goes out.
    #[tokio::test]
    async fn a_new_custody_column_is_published_as_gossip_decodes_it() {
        let (mut server, _chain) = server_custodying(&[1, 2]).await;
        let (swarm_handle, mut commands) = SwarmHandle::capturing();
        server.swarm_handle = swarm_handle;
        assert!(server.seen_columns.record(SLOT, PROPOSER, 2));
        let crate::Wire::Beacon(beacon) = &server.wire else {
            unreachable!("unconnected_beacon_server builds a beacon wire");
        };
        let digest = beacon.digest_for_slot(SLOT);

        publish_and_forward(&mut server, vec![sidecar(1), sidecar(2), sidecar(9)]);

        let mut published = Vec::new();
        while let Ok(command) = commands.try_recv() {
            if let SwarmCommand::Publish { topic, data } = command {
                published.push((topic, data));
            }
        }
        assert_eq!(published.len(), 1, "only column 1 is new and custodied");
        let (topic, data) = &published[0];
        let subnet = das::compute_subnet_for_data_column_sidecar(1);
        let expected = IdentTopic::new(beacon_topics::data_column_topic_name(digest, subnet));
        assert_eq!(topic.hash(), expected.hash());
        let bytes = decompress_message(data).expect("snappy-compressed");
        let decoded = decode_data_column_sidecar(ForkName::Fulu, &bytes)
            .expect("the fulu container gossip decodes");
        assert_eq!(decoded, sidecar(1));
    }

    /// A taken seen-cache key stops publication, not the hand-over: the key
    /// has no block root, so it may be another block's of the same slot and
    /// proposer (an equivocation), whose columns do not complete this one.
    #[tokio::test]
    async fn a_column_whose_key_is_taken_is_forwarded_but_not_published() {
        let (mut server, chain) = server_custodying(&[1, 2]).await;
        let (swarm_handle, mut commands) = SwarmHandle::capturing();
        server.swarm_handle = swarm_handle;
        assert!(server.seen_columns.record(SLOT, PROPOSER, 1));

        publish_and_forward(&mut server, vec![sidecar(1), sidecar(2)]);

        assert_eq!(forwarded_indices(&chain), [vec![1, 2]]);
        let mut published = 0;
        while let Ok(command) = commands.try_recv() {
            if let SwarmCommand::Publish { .. } = command {
                published += 1;
            }
        }
        assert_eq!(published, 1, "only column 2's key was free");
    }

    /// The published column's own copy, delivered by gossip just before and
    /// still in validation, keeps its `Accept`: gossipsub refused our publish
    /// as a duplicate of it, so it is the only copy left to relay. Another
    /// copy for the same key (an equivocating block's column) is still a
    /// second valid one, and so is the same copy delivered again.
    #[tokio::test]
    async fn a_gossip_copy_of_a_published_column_keeps_its_accept() {
        let (mut server, _chain) = server_custodying(&[1]).await;
        let (swarm_handle, mut commands) = SwarmHandle::capturing();
        server.swarm_handle = swarm_handle;

        publish_and_forward(&mut server, vec![sidecar(1)]);

        let Ok(SwarmCommand::Publish { topic, data }) = commands.try_recv() else {
            panic!("column 1 is new and custodied, so it is published");
        };
        // The id gossipsub computes for a received copy of those bytes.
        let received = libp2p::gossipsub::Message {
            source: None,
            data,
            sequence_number: None,
            topic: topic.hash(),
        };
        let gossip_id = crate::compute_message_id(&received);
        let object = Validated::Column(Box::new(sidecar(1)));
        let other_id = MessageId(vec![0; 20]);

        assert_eq!(
            settle_message(&mut server, &other_id, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen),
            "a different message for the taken key is a second valid copy"
        );
        assert_eq!(
            settle_message(&mut server, &gossip_id, Outcome::Accept, &object),
            Outcome::Accept
        );
        assert_eq!(
            settle_message(&mut server, &gossip_id, Outcome::Accept, &object),
            Outcome::Ignore(IgnoreReason::AlreadySeen),
            "the id is taken once"
        );
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
