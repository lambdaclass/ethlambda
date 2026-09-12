//! The beacon-specific halves of what `P2PServer` does.
//!
//! One thing now: it builds this node's own `Status` and `MetaData` bodies and
//! opens the handshake with them. Neither answering a request nor decoding
//! gossip is here; those are `crate::req_resp::handlers` and
//! `crate::gossipsub::handler`, one dispatch each for both chains, which call
//! [`build_status`] and [`build_metadata`] for the bodies they cannot construct
//! themselves.

use ethlambda_storage::Store;
use ethlambda_types::beacon::primitives::Root;
use libp2p::PeerId;
use tracing::debug;

use super::messages::{
    AttnetsBits, BeaconMetaData, BeaconStatus, MetaDataV1, MetaDataV2, MetaDataV3, StatusV1,
    StatusV2, SyncnetsBits,
};
use super::{BeaconWire, constants, protocols};
use crate::P2PServer;
use crate::req_resp::Request;

/// The `Status` this node advertises, in the version the stream asked for.
///
/// Derived from `store`: `head_root`/`head_slot` come from
/// [`Store::beacon_head`], `finalized_root`/`finalized_epoch` from
/// [`Store::beacon_finalized_checkpoint`], and (on v2) `earliest_available_slot`
/// from [`Store::latest_finalized`]'s own slot rather than
/// `finalized_epoch * SLOTS_PER_EPOCH`: this node anchors at a checkpoint and
/// keeps only the unfinalized window above it, so the epoch's first slot is
/// not necessarily a slot it holds, while the anchor checkpoint written by
/// [`Store::init_beacon`] and only ever advanced forward by finality is
/// exactly the oldest block this directory can still produce. Naming that
/// slot is what tells a peer not to ask this node for anything older; naming
/// zero would claim genesis is in reach.
///
/// [`Store::beacon_head`] answers `None` in one window: between
/// [`Store::init_beacon`] seeding `KEY_HEAD` with the anchor root and the
/// beacon fork choice's own `get_forkchoice_store` inserting the block that
/// root names. There is no chain to derive anything from yet in that window,
/// so every field but the fork digest falls back to zero, which stays honest
/// for it: lighthouse's relevance check explicitly exempts a zero
/// `finalized_root` from its finalized-root comparison, reading it as "this
/// peer is syncing" rather than as a conflicting chain, so a zero Status keeps
/// the connection instead of earning an `IrrelevantPeer` disconnect.
///
/// `version` is the stream's, not ours to choose: a v1 body written on a v2
/// stream is eight bytes short and the codec refuses it, which killed the
/// connection outright. Answering a request means answering in its own version.
pub fn build_status(store: &Store, wire: &BeaconWire, version: StatusVersion) -> BeaconStatus {
    let (finalized_root, finalized_epoch, head_root, head_slot, earliest_available_slot) =
        match store.beacon_head() {
            Some((head_slot, head_root)) => {
                let finalized = store.beacon_finalized_checkpoint();
                let earliest_available_slot = store
                    .latest_finalized()
                    .expect("finalized checkpoint exists")
                    .slot;
                (
                    finalized.root,
                    finalized.epoch,
                    head_root,
                    head_slot,
                    earliest_available_slot,
                )
            }
            None => (Root::ZERO, 0, Root::ZERO, 0, 0),
        };

    let v1 = StatusV1 {
        fork_digest: wire.fork_digest,
        finalized_root,
        finalized_epoch,
        head_root,
        head_slot,
    };
    match version {
        StatusVersion::V1 => BeaconStatus::V1(v1),
        StatusVersion::V2 => BeaconStatus::V2(StatusV2 {
            fork_digest: v1.fork_digest,
            finalized_root: v1.finalized_root,
            finalized_epoch: v1.finalized_epoch,
            head_root: v1.head_root,
            head_slot: v1.head_slot,
            earliest_available_slot,
        }),
    }
}

/// Which `Status` version a stream negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusVersion {
    V1,
    V2,
}

impl StatusVersion {
    /// The version to answer a request in: the one it arrived in.
    pub fn of(status: &BeaconStatus) -> Self {
        match status {
            BeaconStatus::V1(_) => Self::V1,
            BeaconStatus::V2(_) => Self::V2,
        }
    }
}

/// The `MetaData` this node advertises, in the version the protocol asked for.
///
/// `attnets` and `syncnets` are all-zero because this node subscribes to no
/// subnet, which is exactly what it serves. `custody_group_count` is
/// `CUSTODY_REQUIREMENT` rather than zero because peers may reject a lower
/// value outright; it is the widest gap between what this node advertises and
/// what it serves, and startup logs it.
pub fn build_metadata(wire: &BeaconWire, protocol: &str) -> Option<BeaconMetaData> {
    let seq_number = wire.metadata_seq_number;
    match protocol {
        protocols::METADATA_V1 => Some(BeaconMetaData::V1(MetaDataV1 {
            seq_number,
            attnets: AttnetsBits::default(),
        })),
        protocols::METADATA_V2 => Some(BeaconMetaData::V2(MetaDataV2 {
            seq_number,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
        })),
        protocols::METADATA_V3 => Some(BeaconMetaData::V3(MetaDataV3 {
            seq_number,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
            custody_group_count: constants::CUSTODY_REQUIREMENT,
        })),
        _ => None,
    }
}

/// Open the handshake on a newly established connection.
///
/// `status/1` rather than `status/2`: every mainnet client still answers v1,
/// and the throwaway probe that proved this path completed its handshake on v1.
/// A peer that has dropped v1 refuses the stream with "the remote supports none
/// of the requested protocols", which is what [`retry_status_on_other_version`]
/// answers.
pub async fn send_status(server: &P2PServer, peer_id: PeerId, wire_status: BeaconStatus) {
    let protocol = match StatusVersion::of(&wire_status) {
        StatusVersion::V1 => protocols::STATUS_V1,
        StatusVersion::V2 => protocols::STATUS_V2,
    };
    server
        .swarm_handle
        .send_request(
            peer_id,
            Request::Status(wire_status),
            libp2p::StreamProtocol::new(protocol),
        )
        .await;
}

/// Re-open a refused handshake on the other `Status` version.
///
/// A peer that supports neither version was never going to talk to us, and one
/// retry cannot loop: the retry is sent in the version the first attempt was
/// not.
pub async fn retry_status_on_other_version(server: &P2PServer, peer_id: PeerId) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    let status = build_status(&server.store, wire, StatusVersion::V2);
    debug!(%peer_id, "Retrying the beacon handshake on status/2");
    send_status(server, peer_id, status).await;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::beacon::topics;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{SignedBeaconBlock, phase0};
    use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
    use ethlambda_types::checkpoint::Checkpoint;

    fn wire() -> BeaconWire {
        BeaconWire {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            topics: topics::BeaconTopics::new([0x8c, 0x9f, 0x62, 0xfe]),
            config: Config::mainnet(),
            genesis_time: 1_606_824_023,
            genesis_validators_root: Root::ZERO,
            metadata_seq_number: 0,
        }
    }

    /// A beacon store past `Store::init_beacon` but before the beacon fork
    /// choice's `get_forkchoice_store` has inserted the anchor block: `KEY_HEAD`
    /// names a root no block row exists for, so `Store::beacon_head` answers
    /// `None`.
    fn store_with_no_head() -> Store {
        Store::init_beacon(
            Arc::new(InMemoryBackend::default()),
            1_606_824_023,
            Config::mainnet(),
            Root::ZERO,
            Checkpoint::default(),
        )
    }

    /// A beacon store anchored at a real, inserted block, so both
    /// `Store::beacon_head` and `Store::beacon_finalized_checkpoint` answer
    /// from it. Returns the store alongside the anchor's slot and root, which
    /// `init_beacon` also seeds as the finalized (and justified) checkpoint.
    fn anchored_store() -> (Store, u64, Root) {
        let anchor_slot = 2 * SLOTS_PER_EPOCH;
        let block = SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot: anchor_slot,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: Root::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        });
        let anchor_root = block.message_hash_tree_root();

        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::default()),
            1_606_824_023,
            Config::mainnet(),
            anchor_root,
            Checkpoint {
                root: anchor_root,
                slot: anchor_slot,
            },
        );
        store
            .insert_signed_block(anchor_root, block)
            .expect("insert anchor block");

        (store, anchor_slot, anchor_root)
    }

    #[test]
    fn a_store_with_no_head_advertises_the_digest_and_nothing_else() {
        // Zero roots are the honest answer for the window before this store has
        // a head row to read, and lighthouse exempts a zero finalized_root from
        // its relevance check, so this keeps the connection rather than earning
        // a disconnect.
        let store = store_with_no_head();
        let BeaconStatus::V1(status) = build_status(&store, &wire(), StatusVersion::V1) else {
            panic!("v1 was asked for");
        };
        assert_eq!(status.fork_digest, [0x8c, 0x9f, 0x62, 0xfe]);
        assert_eq!(status.finalized_root, Root::ZERO);
        assert_eq!(status.head_root, Root::ZERO);
        assert_eq!(status.finalized_epoch, 0);
        assert_eq!(status.head_slot, 0);
    }

    #[test]
    fn an_anchored_store_advertises_its_own_head_and_finalized_checkpoint() {
        let (store, anchor_slot, anchor_root) = anchored_store();

        let BeaconStatus::V2(status) = build_status(&store, &wire(), StatusVersion::V2) else {
            panic!("v2 was asked for");
        };
        assert_eq!(status.head_root, anchor_root);
        assert_eq!(status.head_slot, anchor_slot);
        // `init_beacon` seeds the finalized checkpoint with the anchor itself,
        // and nothing in this test advances finality past it.
        assert_eq!(status.finalized_root, anchor_root);
        assert_eq!(status.finalized_epoch, anchor_slot / SLOTS_PER_EPOCH);
        // The anchor's own slot: the oldest block this directory can serve,
        // not genesis.
        assert_eq!(status.earliest_available_slot, anchor_slot);
    }

    /// A v1 body on a v2 stream is eight bytes short, and the codec refuses to
    /// write it: answering every `Status` in v1 dropped the connection of every
    /// peer that opened the handshake on `status/2`.
    #[test]
    fn the_status_version_answered_is_the_one_that_was_asked_for() {
        let wire = wire();
        let store = store_with_no_head();

        assert!(matches!(
            build_status(&store, &wire, StatusVersion::V1),
            BeaconStatus::V1(_)
        ));
        assert!(matches!(
            build_status(&store, &wire, StatusVersion::V2),
            BeaconStatus::V2(_)
        ));

        let peer_asked_in = BeaconStatus::V2(StatusV2 {
            fork_digest: wire.fork_digest,
            finalized_root: Default::default(),
            finalized_epoch: 0,
            head_root: Default::default(),
            head_slot: 0,
            earliest_available_slot: 0,
        });
        assert_eq!(StatusVersion::of(&peer_asked_in), StatusVersion::V2);
    }

    #[test]
    fn metadata_matches_the_protocol_version_asked_for() {
        let wire = wire();
        assert!(matches!(
            build_metadata(&wire, protocols::METADATA_V1),
            Some(BeaconMetaData::V1(_))
        ));
        assert!(matches!(
            build_metadata(&wire, protocols::METADATA_V2),
            Some(BeaconMetaData::V2(_))
        ));
        let Some(BeaconMetaData::V3(v3)) = build_metadata(&wire, protocols::METADATA_V3) else {
            panic!("v3 requested");
        };
        assert_eq!(v3.custody_group_count, constants::CUSTODY_REQUIREMENT);
        assert!(build_metadata(&wire, protocols::PING_V1).is_none());
    }

    #[test]
    fn the_advertised_subnets_are_empty() {
        // What a node subscribing to no subnet actually serves. Claiming
        // otherwise would earn peer-score penalties for silence on subnets we
        // advertised.
        let Some(BeaconMetaData::V3(v3)) = build_metadata(&wire(), protocols::METADATA_V3) else {
            panic!("v3 requested");
        };
        assert_eq!(v3.attnets, AttnetsBits::default());
        assert_eq!(v3.syncnets, SyncnetsBits::default());
    }
}
