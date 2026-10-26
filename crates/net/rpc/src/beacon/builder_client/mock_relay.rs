//! A builder API server for tests.
//!
//! It serves one bid, records what it is asked and sent, and has knobs for
//! the ways real builders differ: refusing SSZ, ignoring `Accept`, answering
//! slowly, and leaving out `Eth-Consensus-Version`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ethlambda_state_transition::beacon::helpers::test_state::{secret_key_for, sign_for};
use ethlambda_types::beacon::builder::{BuilderBid, SignedBuilderBid};
use ethlambda_types::beacon::primitives::{BlsPubkey, HashTreeRoot as _, Version};
use ethlambda_types::beacon::signing::{compute_builder_domain, compute_signing_root};
use libssz::SszEncode as _;

use super::VersionedBid;

/// The relay's own key: an index far from any test validator's.
const RELAY_KEY: usize = 1_000_000;

type Shared = Arc<Mutex<RelayState>>;

#[derive(Default)]
struct RelayState {
    genesis_fork_version: Version,
    refuses_ssz: bool,
    ignores_accept: bool,
    omits_consensus_version: bool,
    delay: Duration,
    bid: Option<VersionedBid>,
    header_requests: Vec<HeaderRequest>,
}

/// One `getHeader` the relay received.
#[derive(Debug, Clone)]
pub(crate) struct HeaderRequest {
    pub(crate) slot: String,
    pub(crate) parent_hash: String,
    pub(crate) pubkey: String,
    pub(crate) headers: HeaderMap,
}

pub(crate) struct MockRelay {
    pub(crate) url: String,
    state: Shared,
}

impl MockRelay {
    /// A relay on a free local port, for the chain whose genesis fork
    /// version is `genesis_fork_version`. It takes SSZ, answers at once and
    /// has no bid.
    pub(crate) async fn start(genesis_fork_version: Version) -> Self {
        let state = Arc::new(Mutex::new(RelayState {
            genesis_fork_version,
            ..RelayState::default()
        }));
        let app = Router::new()
            .route(
                "/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}",
                get(header),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, state }
    }

    /// Refuse SSZ outright: 406 to an `Accept` that starts with SSZ, as a
    /// builder that reads only the first media type does.
    pub(crate) fn refuse_ssz(&self) {
        self.state.lock().unwrap().refuses_ssz = true;
    }

    /// Answer JSON whatever the `Accept`, without refusing.
    pub(crate) fn ignore_accept(&self) {
        self.state.lock().unwrap().ignores_accept = true;
    }

    /// Leave `Eth-Consensus-Version` off every answer.
    pub(crate) fn omit_consensus_version(&self) {
        self.state.lock().unwrap().omits_consensus_version = true;
    }

    /// Hold every `getHeader` answer for `delay`.
    pub(crate) fn delay(&self, delay: Duration) {
        self.state.lock().unwrap().delay = delay;
    }

    /// Serve `bid` to every `getHeader`.
    pub(crate) fn offer(&self, bid: VersionedBid) {
        self.state.lock().unwrap().bid = Some(bid);
    }

    pub(crate) fn header_requests(&self) -> Vec<HeaderRequest> {
        self.state.lock().unwrap().header_requests.clone()
    }

    /// The key this relay signs its bids with.
    pub(crate) fn pubkey(&self) -> BlsPubkey {
        BlsPubkey(secret_key_for(RELAY_KEY).sk_to_pk().to_bytes())
    }

    /// `message` as this relay sends it: naming the relay's key and signed
    /// with it under the builder domain.
    pub(crate) fn sign_bid(&self, mut message: BuilderBid) -> SignedBuilderBid {
        message.pubkey = self.pubkey();
        let genesis_fork_version = self.state.lock().unwrap().genesis_fork_version;
        let domain = compute_builder_domain(genesis_fork_version);
        let root = compute_signing_root(message.hash_tree_root(), domain);
        SignedBuilderBid {
            message,
            signature: sign_for(RELAY_KEY, root),
        }
    }
}

async fn header(
    State(state): State<Shared>,
    Path((slot, parent_hash, pubkey)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let delay = state.lock().unwrap().delay;
    tokio::time::sleep(delay).await;

    let mut state = state.lock().unwrap();
    state.header_requests.push(HeaderRequest {
        slot,
        parent_hash,
        pubkey,
        headers: headers.clone(),
    });
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let wants_ssz = accept.starts_with(crate::SSZ_CONTENT_TYPE);
    if wants_ssz && state.refuses_ssz {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }
    let Some(VersionedBid { fork, bid }) = state.bid.clone() else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let mut response = if wants_ssz && !state.ignores_accept {
        (
            [(header::CONTENT_TYPE, crate::SSZ_CONTENT_TYPE)],
            bid.to_ssz(),
        )
            .into_response()
    } else {
        let body = serde_json::json!({ "version": fork.as_str(), "data": bid }).to_string();
        ([(header::CONTENT_TYPE, "application/json")], body).into_response()
    };
    if !state.omits_consensus_version {
        response.headers_mut().insert(
            "eth-consensus-version",
            HeaderValue::from_static(fork.as_str()),
        );
    }
    response
}
