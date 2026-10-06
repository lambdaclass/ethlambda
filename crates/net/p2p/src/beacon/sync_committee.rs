//! Sync committee subnets and publishing for the beacon wire.
//!
//! Sync subnets are joined on demand only, from a validator client's
//! `sync_committee_subscriptions` request, and advertised in MetaData's
//! `syncnets` (never the ENR). Nothing here subscribes without a request.
//!
//! These are the entry points the `RpcToP2P` handlers call. The bodies are
//! filled in by the p2p stage of the sync committee work; until then they do
//! nothing, so the workspace builds with the handlers wired.

use ethlambda_types::beacon::containers::altair::{
    SignedContributionAndProof, SyncCommitteeMessage,
};
use ethlambda_types::beacon::primitives::Epoch;

use crate::P2PServer;

/// Gossip `message` on `sync_committee_{id}` for each of `subnet_ids`, and
/// mark each `(slot, validator, subnet)` seen so a peer's echo is ignored.
pub(crate) fn publish_sync_committee_message(
    _server: &mut P2PServer,
    _subnet_ids: Vec<u64>,
    _message: SyncCommitteeMessage,
) {
}

/// Gossip `signed` on `sync_committee_contribution_and_proof`, and mark it
/// seen.
pub(crate) fn publish_sync_committee_contribution(
    _server: &mut P2PServer,
    _signed: SignedContributionAndProof,
) {
}

/// Join each `(subnet_id, until_epoch)` (exclusive), extending an existing
/// join.
pub(crate) fn join_sync_committee_subnets(_server: &mut P2PServer, _subnets: Vec<(u64, Epoch)>) {}

/// Leave every subnet whose `until_epoch` has been reached.
#[allow(dead_code)]
pub(crate) fn leave_expired_sync_committee_subnets(_server: &mut P2PServer) {}

/// Drop pooled messages older than the retained window.
#[allow(dead_code)]
pub(crate) fn prune_sync_committee_pool(_server: &P2PServer) {}
