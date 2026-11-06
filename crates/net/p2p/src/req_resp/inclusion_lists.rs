//! Heze's inclusion list protocol (`inclusion_lists_by_indices/1`): the server
//! side, answering peers out of the inclusion list store, and the store
//! handling of a list that arrives in a response.

use ethlambda_state_transition::beacon::inclusion_list::{
    committee_state, get_inclusion_list_committee, on_inclusion_list,
};
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::heze::SignedInclusionList;
use ethlambda_types::time::unix_now_ms;
use libp2p::PeerId;
use libp2p::request_response::ResponseChannel;
use tracing::{debug, trace};

use super::handlers::{beacon_block_store_or_refuse, respond};
use super::{Response, ResponsePayload};
use crate::P2PServer;
use crate::beacon::messages::InclusionListsByIndicesRequest;

/// Answer `inclusion_lists_by_indices/1` with the stored lists of the
/// committee members `indices` names.
///
/// `indices` is read against `get_inclusion_list_committee(state, slot)` under
/// the request's `dependent_root`. Equivocators' lists are left out, as the
/// specification asks, and so is every member this node holds no list for:
/// the answer may be shorter than the request. A committee this node cannot
/// compute (a dependent root it does not hold, or a state no longer cached)
/// is an empty answer rather than an error; the specification lets a node
/// omit what it does not have, and the store only keeps a short window of
/// slots anyway.
pub(super) async fn handle_inclusion_lists_by_indices_request(
    server: &mut P2PServer,
    peer: PeerId,
    request: InclusionListsByIndicesRequest,
    channel: ResponseChannel<Response>,
) {
    let Some(channel) = beacon_block_store_or_refuse(server, peer, channel) else {
        return;
    };

    let lists = lists_for_request(server, &request);
    trace!(
        %peer,
        slot = request.slot,
        dependent_root = %ShortRoot(&request.dependent_root.0),
        found = lists.len(),
        "Responding to InclusionListsByIndices request"
    );
    respond(server, channel, ResponsePayload::InclusionLists(lists));
}

/// The stored lists `request` asks for, or none when its committee cannot be
/// computed.
fn lists_for_request(
    server: &P2PServer,
    request: &InclusionListsByIndicesRequest,
) -> Vec<SignedInclusionList> {
    let store = &server.store;
    let Some(state) = committee_state(store, request.slot, request.dependent_root) else {
        return Vec::new();
    };
    let Ok(committee) =
        get_inclusion_list_committee(&state, request.slot, &*store.committee_cache())
    else {
        return Vec::new();
    };
    store.inclusion_list_store().lists_for(
        &committee,
        request.slot,
        request.dependent_root,
        &request.indices,
    )
}

/// Store the lists a peer answered with, each through `on_inclusion_list`,
/// which checks everything gossip would and judges timeliness by when it
/// arrived here. A list that fails is dropped, never penalized: this node
/// sends no such request, so an answer is one it did not ask for.
pub(super) fn handle_inclusion_lists_response(
    server: &P2PServer,
    peer: PeerId,
    lists: Vec<SignedInclusionList>,
) {
    let now_ms = unix_now_ms();
    for list in lists {
        let slot = list.message.slot;
        let validator = list.message.validator_index;
        let _ = on_inclusion_list(&server.store, &list, now_ms).inspect_err(|err| {
            debug!(
                %peer,
                slot,
                validator,
                %err,
                "Dropping an inclusion list from a req/resp answer"
            )
        });
    }
}
