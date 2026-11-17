//! A builder API server for tests.
//!
//! It serves one bid, records what it is asked and sent, and has knobs for
//! the ways real builders differ: refusing SSZ, ignoring `Accept`, answering
//! slowly, and leaving out `Eth-Consensus-Version`. It also verifies
//! registration signatures and refuses SSZ registrations, records blinded
//! block submissions, and has `answer_headers_with` and
//! `answer_submissions_with` to answer a call with exactly what a test needs.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ethlambda_state_transition::beacon::bls;
use ethlambda_state_transition::beacon::helpers::test_state::{secret_key_for, sign_for};
use ethlambda_types::beacon::builder::{
    BuilderBid, SignedBlindedBeaconBlock, SignedBuilderBid, SignedValidatorRegistrationV1,
    ValidatorRegistrationV1,
};
use ethlambda_types::beacon::primitives::{
    BlsPubkey, ExecutionAddress, HashTreeRoot as _, Version,
};
use ethlambda_types::beacon::signing::{compute_builder_domain, compute_signing_root};
use libssz::{SszDecode as _, SszEncode as _};

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
    raw_answer: Option<RawAnswer>,
    registrations: Vec<SignedValidatorRegistrationV1>,
    blinded_blocks: Vec<SignedBlindedBeaconBlock>,
    /// What `submitBlindedBlockV2` answers; `None` is 202.
    submit_status: Option<StatusCode>,
    /// Submissions that arrived SSZ-encoded, refused or not.
    ssz_submissions: usize,
}

/// A fixed answer to every `getHeader`.
#[derive(Clone)]
struct RawAnswer {
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    consensus_version: Option<&'static str>,
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
            .route("/eth/v1/builder/validators", post(register))
            .route("/eth/v2/builder/blinded_blocks", post(submit))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, state }
    }

    /// Refuse SSZ outright: 406 to an `Accept` that starts with SSZ, as a
    /// builder that reads only the first media type does.
    /// An SSZ `submitBlindedBlockV2` is refused too, with 415.
    pub(crate) fn refuse_ssz(&self) {
        self.state.lock().unwrap().refuses_ssz = true;
    }

    /// Answer JSON whatever the `Accept`, without refusing.
    pub(crate) fn ignore_accept(&self) {
        self.state.lock().unwrap().ignores_accept = true;
    }

    /// Leave `Eth-Consensus-Version` off SSZ answers. JSON answers never carry
    /// it, as MEV-Boost's do not.
    pub(crate) fn omit_consensus_version(&self) {
        self.state.lock().unwrap().omits_consensus_version = true;
    }

    /// Answer every `getHeader` with exactly this, whatever the request.
    pub(crate) fn answer_headers_with(
        &self,
        status: StatusCode,
        content_type: &'static str,
        body: Vec<u8>,
        consensus_version: Option<&'static str>,
    ) {
        self.state.lock().unwrap().raw_answer = Some(RawAnswer {
            status,
            content_type,
            body,
            consensus_version,
        });
    }

    /// Hold every `getHeader` answer for `delay`.
    pub(crate) fn delay(&self, delay: Duration) {
        self.state.lock().unwrap().delay = delay;
    }

    /// Serve `bid` to every `getHeader`.
    pub(crate) fn offer(&self, bid: VersionedBid) {
        self.state.lock().unwrap().bid = Some(bid);
    }

    /// Answer every `submitBlindedBlockV2` with `status` instead of 202.
    pub(crate) fn answer_submissions_with(&self, status: StatusCode) {
        self.state.lock().unwrap().submit_status = Some(status);
    }

    pub(crate) fn blinded_blocks(&self) -> Vec<SignedBlindedBeaconBlock> {
        self.state.lock().unwrap().blinded_blocks.clone()
    }

    pub(crate) fn ssz_submissions(&self) -> usize {
        self.state.lock().unwrap().ssz_submissions
    }

    pub(crate) fn registrations(&self) -> Vec<SignedValidatorRegistrationV1> {
        self.state.lock().unwrap().registrations.clone()
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
    if let Some(raw) = state.raw_answer.clone() {
        let mut response = (
            raw.status,
            [(header::CONTENT_TYPE, raw.content_type)],
            raw.body,
        )
            .into_response();
        if let Some(version) = raw.consensus_version {
            response
                .headers_mut()
                .insert("eth-consensus-version", HeaderValue::from_static(version));
        }
        return response;
    }
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
    if wants_ssz && !state.ignores_accept {
        let mut response = (
            [(header::CONTENT_TYPE, crate::SSZ_CONTENT_TYPE)],
            bid.to_ssz(),
        )
            .into_response();
        if !state.omits_consensus_version {
            response.headers_mut().insert(
                "eth-consensus-version",
                HeaderValue::from_static(fork.as_str()),
            );
        }
        response
    } else {
        let body = serde_json::json!({ "version": fork.as_str(), "data": bid }).to_string();
        ([(header::CONTENT_TYPE, "application/json")], body).into_response()
    }
}

async fn register(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let mut state = state.lock().unwrap();
    // The client always registers in JSON (see `register_validators`); an
    // SSZ registration here is a regression.
    if is_ssz_request(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let Ok(registrations) = serde_json::from_slice::<Vec<SignedValidatorRegistrationV1>>(&body)
    else {
        return bad_request("invalid JSON");
    };
    let domain = compute_builder_domain(state.genesis_fork_version);
    for registration in &registrations {
        let root = compute_signing_root(registration.message.hash_tree_root(), domain);
        if !bls::verify(&registration.message.pubkey, root, &registration.signature) {
            return bad_request("invalid signature");
        }
    }
    state.registrations.extend(registrations);
    StatusCode::OK.into_response()
}

async fn submit(State(state): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let mut state = state.lock().unwrap();
    let ssz = is_ssz_request(&headers);
    if ssz {
        state.ssz_submissions += 1;
        if state.refuses_ssz {
            return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
        }
        // builder-specs requires the header on an SSZ submission.
        if !headers.contains_key("eth-consensus-version") {
            return bad_request("missing Eth-Consensus-Version");
        }
    }
    let block = if ssz {
        SignedBlindedBeaconBlock::from_ssz_bytes(&body).ok()
    } else {
        serde_json::from_slice(&body).ok()
    };
    let Some(block) = block else {
        return bad_request("invalid block encoding");
    };
    state.blinded_blocks.push(block);
    match state.submit_status {
        None => StatusCode::ACCEPTED.into_response(),
        Some(StatusCode::BAD_REQUEST) => bad_request("block refused"),
        Some(status) => status.into_response(),
    }
}

/// Test validator `index`'s registration, signed with its key for the chain
/// whose genesis fork version is `genesis_fork_version`.
pub(crate) fn signed_registration(
    index: usize,
    genesis_fork_version: Version,
) -> SignedValidatorRegistrationV1 {
    let message = ValidatorRegistrationV1 {
        fee_recipient: ExecutionAddress::repeat_byte(0x11),
        gas_limit: 60_000_000,
        timestamp: 1_700_000_000,
        pubkey: BlsPubkey(secret_key_for(index).sk_to_pk().to_bytes()),
    };
    let domain = compute_builder_domain(genesis_fork_version);
    let root = compute_signing_root(message.hash_tree_root(), domain);
    SignedValidatorRegistrationV1 {
        message,
        signature: sign_for(index, root),
    }
}

fn is_ssz_request(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(crate::SSZ_CONTENT_TYPE))
}

/// builder-specs' `ErrorMessage` body for a 400.
fn bad_request(message: &str) -> Response {
    let body = serde_json::json!({ "code": 400, "message": message }).to_string();
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}
