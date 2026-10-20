//! `/eth/v1/beacon/execution_proofs` (EIP-8440).
//!
//! The way out for the execution chain proofs this node verified: a node that
//! cannot execute (a partial stateful node, say) reads a block's proofs here
//! and verifies them itself, and a prover submits its proofs here for the
//! node to gossip. The route shapes follow the Lighthouse branch that serves
//! EIP-8025 proofs, with EIP-8440's containers.

use std::sync::Arc;

use axum::{
    Extension, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::execution_proofs::ExecutionProofEngine;
use ethlambda_state_transition::beacon::gossip::{
    Outcome, SeenExecutionProofs,
    execution_proof::{cheap_checks, stateful_checks},
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::containers::execution_proof::SignedExecutionProof;
use libssz::SszEncode;
use serde::Serialize;
use tracing::{debug, warn};

use crate::{
    beacon::{ApiError, blocks::is_finalized, decode_list},
    shared::{
        block_id::{BlockId, IdError},
        content::{Encoding, ssz_response},
        optimistic::block_is_optimistic,
    },
};

/// The proof engine the POST route verifies submitted proofs with. `None` on
/// a node that takes no execution proofs, where the route answers 503; the
/// GET route serves whatever the store holds either way.
#[derive(Clone, Default)]
pub struct ProofEngineHandle(pub Option<Arc<dyn ExecutionProofEngine>>);

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v1/beacon/execution_proofs/{block_id}",
            get(get_execution_proofs),
        )
        .route(
            "/eth/v1/beacon/execution_proofs",
            post(post_execution_proofs).layer(DefaultBodyLimit::max(super::MAX_PUBLISH_BODY_BYTES)),
        )
}

/// The JSON body of a GET: the proofs, with the flags every block-keyed
/// response carries. No `version`: the container is the same at every fork.
#[derive(Debug, Serialize)]
struct ProofsResponse {
    execution_optimistic: bool,
    finalized: bool,
    data: Vec<SignedExecutionProof>,
}

/// `GET /eth/v1/beacon/execution_proofs/{block_id}`: the verified proofs held
/// for that block, in proof type order, as JSON or as an SSZ list on
/// `Accept: application/octet-stream`. An empty list for a known block with
/// no proof yet; 404 for a block this node does not hold.
async fn get_execution_proofs(
    Path(block_id): Path<String>,
    State(store): State<Store>,
    headers: HeaderMap,
) -> Response {
    let root = match BlockId::parse(&block_id).and_then(|id| id.resolve_beacon(&store)) {
        Ok(root) => root,
        Err(IdError::Malformed) => return ApiError::BadRequest("invalid block id").into_response(),
        Err(IdError::NotFound) => return ApiError::NotFound("block not found").into_response(),
    };
    let Some((slot, _)) = store.block_slot_and_state_root(&root) else {
        return ApiError::NotFound("block not found").into_response();
    };
    let proofs = store.execution_proofs(&root);
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    match Encoding::from_accept(accept) {
        Encoding::Ssz => ssz_response(proofs.to_ssz()),
        Encoding::Json => crate::json_response(ProofsResponse {
            execution_optimistic: block_is_optimistic(&store, root),
            finalized: is_finalized(&store, slot),
            data: proofs,
        }),
    }
}

/// One refused proof, in the Beacon API's `IndexedErrorMessage` shape.
#[derive(Debug, Serialize)]
struct Failure {
    index: usize,
    message: String,
}

/// `POST /eth/v1/beacon/execution_proofs`: a JSON array or SSZ list of
/// `SignedExecutionProof`s a prover submits. Each goes through the checks
/// gossip applies to a peer's (the head block is held with its state, the
/// prover is an active validator who signed it, the proof engine takes the
/// proof), on a blocking thread since the signature and the proof
/// verification are CPU-bound. A proof that passes is gossiped and handed to
/// the chain actor by the publish path; the others are reported by position
/// and the rest still go out. 503 when this node runs no proof engine.
async fn post_execution_proofs(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(engine): Extension<ProofEngineHandle>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(engine) = engine.0 else {
        return ApiError::ServiceUnavailable("execution proofs are not enabled on this node")
            .into_response();
    };
    let proofs = match decode_list::<SignedExecutionProof>(&headers, &body) {
        Ok(proofs) => proofs,
        Err(err) => return err.into_response(),
    };
    let mut failures = Vec::new();
    for (index, proof) in proofs.into_iter().enumerate() {
        let proof_type = proof.message.proof_type;
        let validator = proof.validator_index;
        let (verdict, proof) = {
            let store = store.clone();
            let engine = Arc::clone(&engine);
            tokio::task::spawn_blocking(move || {
                // Not P2P's seen cache: that holds what peers sent, and says
                // nothing about what this node's own prover submits. The
                // store's own one-per-type rule covers a repeat.
                let seen = SeenExecutionProofs::new(std::num::NonZeroUsize::MIN);
                let verdict = match cheap_checks(&seen, &store, &proof) {
                    Ok(()) => stateful_checks(&store, &proof, Some(engine.as_ref())),
                    Err(outcome) => outcome,
                };
                (verdict, proof)
            })
            .await
            .unwrap_or_else(|_| {
                (
                    Outcome::Ignore(
                        ethlambda_state_transition::beacon::gossip::IgnoreReason::Internal,
                    ),
                    SignedExecutionProof {
                        message:
                            ethlambda_types::beacon::containers::execution_proof::ExecutionProof {
                                proof_data: Default::default(),
                                proof_type,
                                origin_block_root: Default::default(),
                                head_block_root: Default::default(),
                            },
                        validator_index: validator,
                        signature: Default::default(),
                    },
                )
            })
        };
        if verdict != Outcome::Accept {
            let (outcome, reason) = verdict.labels();
            warn!(
                proof_type,
                validator, outcome, reason, "Refused a submitted execution proof"
            );
            failures.push(Failure {
                index,
                message: format!("{outcome}: {reason}"),
            });
            continue;
        }
        match p2p.publish_execution_proof(Box::new(proof)) {
            Ok(()) => debug!(proof_type, validator, "Accepted execution proof for gossip"),
            Err(_) => failures.push(Failure {
                index,
                message: "the network actor is not running".to_string(),
            }),
        }
    }

    if failures.is_empty() {
        return StatusCode::OK.into_response();
    }
    let body = serde_json::json!({
        "code": 400,
        "message": "some execution proofs failed validation and were not published",
        "failures": failures,
    });
    let mut response = crate::json_response(body);
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{RecordingNetwork, gloas_fixture};
    use axum::{body::Body, http::Request};
    use ethlambda_state_transition::beacon::constants::DOMAIN_EXECUTION_PROOF;
    use ethlambda_state_transition::beacon::execution_proofs::{
        ExecutionProof, MockExecutionProofEngine,
    };
    use ethlambda_state_transition::beacon::fork::ForkName;
    use ethlambda_state_transition::beacon::helpers::accessors::get_domain;
    use ethlambda_state_transition::beacon::helpers::misc::compute_signing_root;
    use ethlambda_state_transition::beacon::helpers::test_state::{
        sign_for, with_signing_validators_at,
    };
    use ethlambda_types::beacon::containers::BeaconState;
    use ethlambda_types::beacon::primitives::HashTreeRoot as _;
    use ethlambda_types::primitives::H256;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    struct Reply {
        status: StatusCode,
        body: Bytes,
    }

    async fn send(
        store: Store,
        network: Arc<RecordingNetwork>,
        engine: ProofEngineHandle,
        request: Request<Body>,
    ) -> Reply {
        let p2p: RpcToP2PRef = network;
        let response = routes()
            .with_state(store)
            .layer(Extension(p2p))
            .layer(Extension(engine))
            .oneshot(request)
            .await
            .unwrap();
        Reply {
            status: response.status(),
            body: response.into_body().collect().await.unwrap().to_bytes(),
        }
    }

    fn json(reply: &Reply) -> serde_json::Value {
        serde_json::from_slice(&reply.body).unwrap()
    }

    fn get(uri: &str, accept: Option<&str>) -> Request<Body> {
        let mut request = Request::builder().uri(uri);
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        request.body(Body::empty()).unwrap()
    }

    fn post_json(proofs: &[SignedExecutionProof]) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/eth/v1/beacon/execution_proofs")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(proofs).unwrap()))
            .unwrap()
    }

    /// The gloas fixture with a signing registry as `g1`'s post-state, which
    /// the gossip checks read.
    fn fixture() -> (Store, H256, u64, BeaconState) {
        let fixture = gloas_fixture();
        let (root, slot) = fixture.g1;
        let mut store = fixture.store;
        let state = with_signing_validators_at(ForkName::Gloas, 4);
        store.insert_state(root, state.clone()).unwrap();
        (store, root, slot, state)
    }

    fn proof(
        state: &BeaconState,
        head: H256,
        proof_type: u8,
        validator: u64,
    ) -> SignedExecutionProof {
        let chain_id = ethlambda_types::beacon::config::Config::mainnet().deposit_chain_id;
        let mut message = ExecutionProof {
            proof_data: Default::default(),
            proof_type,
            origin_block_root: H256::from([1; 32]),
            head_block_root: head,
        };
        message.proof_data =
            MockExecutionProofEngine::proof_claiming(&message.public_input(chain_id))
                .try_into()
                .unwrap();
        let domain = get_domain(state, DOMAIN_EXECUTION_PROOF, None);
        let signing_root = compute_signing_root(message.hash_tree_root(), domain);
        SignedExecutionProof {
            message,
            validator_index: validator,
            signature: sign_for(validator as usize, signing_root),
        }
    }

    fn mock_engine() -> ProofEngineHandle {
        ProofEngineHandle(Some(Arc::new(MockExecutionProofEngine)))
    }

    #[tokio::test]
    async fn proofs_are_served_per_block_as_json_or_ssz() {
        let (mut store, root, slot, state) = fixture();
        let url = format!("/eth/v1/beacon/execution_proofs/0x{root:x}");

        let reply = send(
            store.clone(),
            Default::default(),
            mock_engine(),
            get(&url, None),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(json(&reply)["data"], serde_json::json!([]));

        let kept = proof(&state, root, 2, 1);
        assert!(store.insert_execution_proof(root, slot, kept.clone()));
        let reply = send(
            store.clone(),
            Default::default(),
            mock_engine(),
            get(&url, None),
        )
        .await;
        let body = json(&reply);
        assert_eq!(body["data"][0]["message"]["proof_type"], "2");
        assert_eq!(body["data"][0]["validator_index"], "1");
        assert_eq!(
            body["data"][0]["message"]["head_block_root"],
            format!("0x{root:x}")
        );
        assert_eq!(body["finalized"], false);

        let reply = send(
            store.clone(),
            Default::default(),
            mock_engine(),
            get(&url, Some("application/octet-stream")),
        )
        .await;
        assert_eq!(reply.body.as_ref(), vec![kept].to_ssz());

        let reply = send(
            store.clone(),
            Default::default(),
            mock_engine(),
            get("/eth/v1/beacon/execution_proofs/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", None),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        let reply = send(
            store,
            Default::default(),
            mock_engine(),
            get("/eth/v1/beacon/execution_proofs/nope", None),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_submitted_proof_is_checked_like_gossip_and_published() {
        let (store, root, _slot, state) = fixture();
        let network = Arc::new(RecordingNetwork::default());
        let good = proof(&state, root, 1, 2);
        let mut tampered = proof(&state, root, 3, 3);
        tampered.message.origin_block_root = H256::from([9; 32]);

        let reply = send(
            store.clone(),
            network.clone(),
            mock_engine(),
            post_json(&[good.clone(), tampered]),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let body = json(&reply);
        assert_eq!(body["failures"][0]["index"], 1);
        assert_eq!(body["failures"][0]["message"], "reject: bad_signature");
        assert_eq!(
            *network.execution_proofs.lock().unwrap(),
            vec![good.clone()]
        );

        // Without an engine the node takes no proofs at all.
        let reply = send(
            store,
            network,
            ProofEngineHandle::default(),
            post_json(&[good]),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    }
}
