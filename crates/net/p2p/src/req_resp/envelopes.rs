//! The gloas execution payload envelope protocols
//! (`execution_payload_envelopes_by_range/1` and `_by_root/1`): the server side,
//! answering peers out of `Table::ExecutionPayloadEnvelopes`.

use ethlambda_storage::Store;
use ethlambda_types::beacon::containers::gloas;
use ethlambda_types::primitives::H256;
use libp2p::PeerId;
use libp2p::request_response::ResponseChannel;
use tracing::{debug, error, trace, warn};

use super::handlers::{beacon_block_store_or_refuse, refuse, respond};
use super::messages::ResponseCode;
use super::{Response, ResponsePayload};
use crate::P2PServer;
use crate::beacon::messages::ExecutionPayloadEnvelopesByRangeRequest;
use crate::beacon::protocols::MAX_REQUEST_PAYLOADS;

/// Answer `execution_payload_envelopes_by_range/1` off the canonical chain.
///
/// The spec makes it equivalent to `BeaconBlocksByRange` v2 with another
/// response type. An empty window is `INVALID_REQUEST` and a `start_slot`
/// below the anchor is `RESOURCE_UNAVAILABLE`, as for blocks. A `count` above
/// `MAX_REQUEST_PAYLOADS` is truncated to it rather than refused, which the
/// specification's "Clients MAY limit the number of payload envelopes in the
/// response" allows; the block handler refuses a `count` past its phase0
/// ceiling instead, because a request that wide is a protocol violation there.
/// A window before gloas simply holds no envelopes, so it is an empty answer. Which envelopes count as
/// canonical is [`Store::canonical_execution_payload_envelopes`]'s business.
pub(super) async fn handle_execution_payload_envelopes_by_range_request(
    server: &mut P2PServer,
    peer: PeerId,
    request: ExecutionPayloadEnvelopesByRangeRequest,
    channel: ResponseChannel<Response>,
) {
    let Some(channel) = beacon_block_store_or_refuse(server, peer, channel) else {
        return;
    };

    if request.count == 0 {
        refuse(
            server,
            channel,
            ResponseCode::INVALID_REQUEST,
            "invalid ExecutionPayloadEnvelopesByRange request",
        );
        return;
    }
    let envelopes = match envelopes_by_range(&server.store, request.start_slot, request.count) {
        Ok(envelopes) => envelopes,
        Err(reason) => {
            debug!(
                %peer,
                start_slot = request.start_slot,
                "ExecutionPayloadEnvelopesByRange request starts before this node's chain"
            );
            refuse(server, channel, ResponseCode::RESOURCE_UNAVAILABLE, reason);
            return;
        }
    };

    trace!(
        %peer,
        start_slot = request.start_slot,
        count = request.count,
        found = envelopes.len(),
        "Responding to ExecutionPayloadEnvelopesByRange request"
    );

    respond(
        server,
        channel,
        ResponsePayload::ExecutionPayloadEnvelopes(envelopes),
    );
}

/// The envelopes `ExecutionPayloadEnvelopesByRange` answers a non-empty window
/// with: the canonical ones in `[start_slot, start_slot + count)`, truncated
/// to `MAX_REQUEST_PAYLOADS` slots.
///
/// `Err` carries the `RESOURCE_UNAVAILABLE` reason for a `start_slot` below
/// the store's anchor, which this chain does not reach back to.
fn envelopes_by_range(
    store: &Store,
    start_slot: u64,
    count: u64,
) -> Result<Vec<gloas::SignedExecutionPayloadEnvelope>, &'static str> {
    if start_slot < store.anchor_slot() {
        return Err("requested range starts before this node's earliest available slot");
    }
    let count = count.min(MAX_REQUEST_PAYLOADS);
    // An overflowing window is attacker-supplied and answered empty, as is a
    // zero `count`, which has no last offset to add.
    let Some(end_slot) = count
        .checked_sub(1)
        .and_then(|last_offset| start_slot.checked_add(last_offset))
    else {
        return Ok(Vec::new());
    };
    Ok(store
        .canonical_execution_payload_envelopes(start_slot, end_slot)
        .inspect_err(|err| {
            warn!(
                start_slot,
                end_slot,
                ?err,
                "Failed to get execution payload envelopes by slot range"
            )
        })
        .unwrap_or_default())
}

/// Answer `execution_payload_envelopes_by_root/1` with whichever of the named
/// envelopes this node holds.
///
/// The counterpart of [`handle_beacon_blocks_by_root_request`]: a root with no
/// stored envelope is left out rather than answered with an error, and the
/// answer follows the order asked in. Roots past `MAX_REQUEST_PAYLOADS` are
/// ignored (the wire list type already bounds a decoded request to it).
pub(super) async fn handle_execution_payload_envelopes_by_root_request(
    server: &mut P2PServer,
    peer: PeerId,
    roots: Vec<H256>,
    channel: ResponseChannel<Response>,
) {
    let Some(channel) = beacon_block_store_or_refuse(server, peer, channel) else {
        return;
    };

    let requested = roots.len();
    let envelopes = envelopes_by_root(&server.store, &roots);

    trace!(
        %peer,
        requested,
        found = envelopes.len(),
        "Responding to ExecutionPayloadEnvelopesByRoot request"
    );

    respond(
        server,
        channel,
        ResponsePayload::ExecutionPayloadEnvelopes(envelopes),
    );
}

/// The held envelopes among `roots`, in the order asked, looking at no more
/// than `MAX_REQUEST_PAYLOADS` of them.
fn envelopes_by_root(store: &Store, roots: &[H256]) -> Vec<gloas::SignedExecutionPayloadEnvelope> {
    roots
        .iter()
        .take(MAX_REQUEST_PAYLOADS as usize)
        .filter_map(|root| {
            store
                .get_execution_payload_envelope(root)
                .inspect_err(|err| {
                    error!(
                        root = %ethlambda_types::ShortRoot(&root.0),
                        %err,
                        "Stored execution payload envelope failed to read"
                    )
                })
                .ok()
                .flatten()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::encoding::test_support;
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::SignedBeaconBlock;
    use ethlambda_types::beacon::fork_choice::PayloadStatus;
    use ethlambda_types::checkpoint::Checkpoint;
    use std::sync::Arc;

    /// A gloas block whose bid builds on the payload `parent_block_hash`.
    fn gloas_block(slot: u64, parent_root: H256, parent_block_hash: H256) -> SignedBeaconBlock {
        let mut block = gloas::SignedBeaconBlock {
            message: gloas::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: Default::default(),
            },
            signature: Default::default(),
        };
        block
            .message
            .body
            .signed_execution_payload_bid
            .message
            .parent_block_hash = parent_block_hash;
        SignedBeaconBlock::Gloas(block)
    }

    fn beacon_store() -> Store {
        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            0,
            Config::mainnet(),
            H256::ZERO,
            Checkpoint::default(),
            0,
        );
        store
            .insert_signed_block(H256::ZERO, gloas_block(0, H256::ZERO, H256::ZERO))
            .expect("insert anchor");
        store
    }

    /// Inserts `block` and moves the head to it; returns its root.
    fn extend_chain(store: &mut Store, block: SignedBeaconBlock) -> H256 {
        let root = block.message_hash_tree_root();
        store.insert_signed_block(root, block).expect("insert");
        store.set_head_payload_status(PayloadStatus::Full);
        store
            .update_checkpoints(ForkCheckpoints::head_only(root))
            .expect("advance head");
        root
    }

    fn reveal(
        store: &mut Store,
        slot: u64,
        root: H256,
        hash: H256,
    ) -> gloas::SignedExecutionPayloadEnvelope {
        let envelope = test_support::envelope(root, slot, hash);
        store.insert_verified_payload(slot, &envelope);
        envelope
    }

    fn hash(byte: u8) -> H256 {
        H256::repeat_byte(byte)
    }

    /// Canonical slots 1 to 3, every payload revealed and built on, plus a
    /// sibling of slot 2 with its own envelope. Returns the three canonical
    /// envelopes.
    fn chain_with_every_payload_built_on() -> (Store, Vec<gloas::SignedExecutionPayloadEnvelope>) {
        let mut store = beacon_store();
        let root_1 = extend_chain(&mut store, gloas_block(1, H256::ZERO, hash(0)));
        let root_2 = extend_chain(&mut store, gloas_block(2, root_1, hash(1)));
        let root_3 = extend_chain(&mut store, gloas_block(3, root_2, hash(2)));
        // A fork at slot 2 that the head does not descend from.
        let sibling = gloas_block(2, root_1, hash(9));
        let sibling_root = sibling.message_hash_tree_root();
        store
            .insert_signed_block(sibling_root, sibling)
            .expect("insert");
        reveal(&mut store, 2, sibling_root, hash(0x99));
        let envelopes = vec![
            reveal(&mut store, 1, root_1, hash(1)),
            reveal(&mut store, 2, root_2, hash(2)),
            reveal(&mut store, 3, root_3, hash(3)),
        ];
        (store, envelopes)
    }

    #[test]
    fn by_range_serves_only_canonical_envelopes_in_slot_order() {
        let (store, envelopes) = chain_with_every_payload_built_on();

        let served = envelopes_by_range(&store, 1, 3).expect("in window");

        assert_eq!(served, envelopes);
        assert_eq!(
            envelopes_by_range(&store, 2, 1).expect("in window"),
            envelopes[1..2]
        );
    }

    #[test]
    fn by_range_omits_a_payload_the_next_block_does_not_build_on() {
        let mut store = beacon_store();
        let root_1 = extend_chain(&mut store, gloas_block(1, H256::ZERO, hash(0)));
        // Slot 2 builds on slot 1's empty branch, not on the payload revealed.
        let root_2 = extend_chain(&mut store, gloas_block(2, root_1, hash(0)));
        reveal(&mut store, 1, root_1, hash(1));
        let head_envelope = reveal(&mut store, 2, root_2, hash(2));

        let served = envelopes_by_range(&store, 1, 2).expect("in window");

        assert_eq!(served, vec![head_envelope]);
    }

    #[test]
    fn by_range_judges_the_last_block_of_a_window_by_its_successor_past_the_window() {
        let mut store = beacon_store();
        let root_1 = extend_chain(&mut store, gloas_block(1, H256::ZERO, hash(0)));
        // Slot 3 follows an empty slot 2 and builds on slot 1's payload.
        extend_chain(&mut store, gloas_block(3, root_1, hash(1)));
        let envelope = reveal(&mut store, 1, root_1, hash(1));

        assert_eq!(
            envelopes_by_range(&store, 1, 1).expect("in window"),
            vec![envelope]
        );
    }

    /// A phase0 block, standing in for any block before gloas.
    fn pre_gloas_block(slot: u64, parent_root: H256) -> SignedBeaconBlock {
        use ethlambda_types::beacon::containers::phase0;

        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: H256::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        })
    }

    #[test]
    fn by_range_caps_the_window_at_max_request_payloads() {
        let mut store = beacon_store();
        let total = MAX_REQUEST_PAYLOADS + 2;
        let payload_hash = |slot: u64| H256::repeat_byte(slot as u8);
        let mut parent = H256::ZERO;
        for slot in 1..=total {
            // Each block builds on the previous slot's payload, so every
            // envelope is on the chain and only the cap can cut the answer.
            let block = gloas_block(slot, parent, payload_hash(slot - 1));
            parent = extend_chain(&mut store, block);
            reveal(&mut store, slot, parent, payload_hash(slot));
        }

        let served = envelopes_by_range(&store, 1, total).expect("in window");

        assert_eq!(served.len() as u64, MAX_REQUEST_PAYLOADS);
        let last_slot = served
            .last()
            .expect("non-empty")
            .message
            .payload
            .slot_number;
        assert_eq!(last_slot, MAX_REQUEST_PAYLOADS);
        // A count past the cap is cut to it, not refused.
        let wide = envelopes_by_range(&store, 1, u64::MAX).expect("in window");
        assert_eq!(wide, served);
    }

    #[test]
    fn by_range_answers_empty_for_a_pre_gloas_window_that_has_blocks() {
        let mut store = beacon_store();
        let root_1 = extend_chain(&mut store, pre_gloas_block(1, H256::ZERO));
        let root_2 = extend_chain(&mut store, pre_gloas_block(2, root_1));
        let root_3 = extend_chain(&mut store, gloas_block(3, root_2, hash(0)));
        let envelope = reveal(&mut store, 3, root_3, hash(3));

        assert!(
            envelopes_by_range(&store, 1, 2)
                .expect("in window")
                .is_empty()
        );
        assert_eq!(
            envelopes_by_range(&store, 1, 3).expect("in window"),
            vec![envelope]
        );
    }

    #[test]
    fn by_range_answers_empty_for_an_overflowing_window() {
        let (store, _) = chain_with_every_payload_built_on();

        assert!(
            envelopes_by_range(&store, u64::MAX, 5)
                .expect("in window")
                .is_empty()
        );
    }

    #[test]
    fn by_range_refuses_a_start_below_the_anchor() {
        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            0,
            Config::mainnet(),
            H256::ZERO,
            Checkpoint::default(),
            10,
        );
        store
            .insert_signed_block(H256::ZERO, gloas_block(10, H256::ZERO, H256::ZERO))
            .expect("insert anchor");

        assert!(envelopes_by_range(&store, 9, 1).is_err());
        assert!(envelopes_by_range(&store, 10, 1).is_ok());
    }

    #[test]
    fn by_root_serves_known_envelopes_in_request_order_and_skips_unknown_roots() {
        let (store, envelopes) = chain_with_every_payload_built_on();
        let roots: Vec<H256> = envelopes
            .iter()
            .map(|e| e.message.beacon_block_root)
            .collect();
        let asked = vec![roots[2], H256::repeat_byte(0xee), roots[0]];

        let served = envelopes_by_root(&store, &asked);

        assert_eq!(served, vec![envelopes[2].clone(), envelopes[0].clone()]);
    }

    #[test]
    fn by_root_looks_at_no_more_than_the_limit() {
        let (store, envelopes) = chain_with_every_payload_built_on();
        let known = envelopes[0].message.beacon_block_root;
        let mut asked = vec![H256::repeat_byte(0xee); MAX_REQUEST_PAYLOADS as usize];
        asked.push(known);

        assert!(envelopes_by_root(&store, &asked).is_empty());
    }
}
