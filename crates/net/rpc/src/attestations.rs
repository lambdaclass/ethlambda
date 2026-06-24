use axum::{
    Router,
    extract::rejection::QueryRejection,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use ethlambda_storage::Store;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::json_response;

#[derive(Deserialize)]
struct AttQuery {
    slot: Option<u64>,
    validator_index: Option<u64>,
}

#[derive(Serialize)]
struct AttestationEntry {
    validator_index: u64,
    slot: u64,
    source_slot: u64,
    target_slot: u64,
}

/// `GET /lean/v0/attestations` — returns per-validator latest attestations.
///
/// # Query parameters
/// - `slot`: filter to entries whose `slot` matches. Note: the underlying store
///   holds one **latest** attestation per validator (the highest-slot one seen),
///   so `?slot=N` filters *over that latest-only set* — it does NOT return all
///   historical attestations ever cast at slot N.
/// - `validator_index`: filter to a single validator's entry.
///
/// Both filters may be combined. Results are sorted by `validator_index`.
async fn get_attestations(
    query: Result<Query<AttQuery>, QueryRejection>,
    State(store): State<Store>,
) -> impl IntoResponse {
    let Query(q) = match query {
        Ok(q) => q,
        Err(_) => {
            let mut response = json_response(json!({ "error": "invalid query parameter" }));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return response;
        }
    };

    let known = store.extract_latest_known_attestations();
    let mut out: Vec<AttestationEntry> = known
        .into_iter()
        .filter(|(vid, data)| {
            q.slot.is_none_or(|s| data.slot == s) && q.validator_index.is_none_or(|v| *vid == v)
        })
        .map(|(validator_index, data)| AttestationEntry {
            validator_index,
            slot: data.slot,
            source_slot: data.source.slot,
            target_slot: data.target.slot,
        })
        .collect();
    out.sort_by_key(|e| e.validator_index);
    json_response(out)
}

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/lean/v0/attestations", get(get_attestations))
}

#[cfg(test)]
mod tests {
    use crate::test_utils::create_test_state;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use ethlambda_types::{
        attestation::AggregationBits,
        attestation::{AttestationData, HashedAttestationData},
        block::TypeOneMultiSignature,
        checkpoint::Checkpoint,
    };
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn make_att_data(slot: u64, source_slot: u64, target_slot: u64) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            source: Checkpoint {
                slot: source_slot,
                root: Default::default(),
            },
            target: Checkpoint {
                slot: target_slot,
                root: Default::default(),
            },
        }
    }

    fn proof_for_validator(vid: usize) -> TypeOneMultiSignature {
        let mut bits = AggregationBits::with_length(vid + 1).unwrap();
        bits.set(vid, true).unwrap();
        TypeOneMultiSignature::empty(bits)
    }

    fn seed_known_attestation(store: &mut Store, validator_index: usize, data: AttestationData) {
        store.insert_known_aggregated_payload(
            HashedAttestationData::new(data),
            proof_for_validator(validator_index),
        );
    }

    #[tokio::test]
    async fn attestations_empty_store_returns_empty_array() {
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::build_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn attestations_returns_seeded_entries_with_correct_fields() {
        let mut store =
            Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());

        seed_known_attestation(&mut store, 0, make_att_data(5, 1, 4));
        seed_known_attestation(&mut store, 2, make_att_data(7, 3, 6));

        let app = crate::build_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

        // Sorted by validator_index: 0 first, then 2.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["validator_index"], 0);
        assert_eq!(entries[0]["slot"], 5);
        assert_eq!(entries[0]["source_slot"], 1);
        assert_eq!(entries[0]["target_slot"], 4);
        assert_eq!(entries[1]["validator_index"], 2);
        assert_eq!(entries[1]["slot"], 7);
    }

    #[tokio::test]
    async fn attestations_slot_filter() {
        let mut store =
            Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());

        seed_known_attestation(&mut store, 0, make_att_data(5, 1, 4));
        seed_known_attestation(&mut store, 1, make_att_data(7, 3, 6));
        seed_known_attestation(&mut store, 2, make_att_data(5, 1, 4));

        let app = crate::build_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/attestations?slot=5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

        // Only validators 0 and 2 attested at slot 5.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["validator_index"], 0);
        assert_eq!(entries[1]["validator_index"], 2);
    }

    #[tokio::test]
    async fn attestations_validator_index_filter() {
        let mut store =
            Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());

        seed_known_attestation(&mut store, 0, make_att_data(5, 1, 4));
        seed_known_attestation(&mut store, 1, make_att_data(7, 3, 6));
        seed_known_attestation(&mut store, 2, make_att_data(5, 1, 4));

        let app = crate::build_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/attestations?validator_index=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["validator_index"], 1);
        assert_eq!(entries[0]["slot"], 7);
    }

    #[tokio::test]
    async fn attestations_combined_slot_and_validator_filter() {
        let mut store =
            Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());

        seed_known_attestation(&mut store, 0, make_att_data(5, 1, 4));
        seed_known_attestation(&mut store, 1, make_att_data(5, 1, 4));

        let app = crate::build_api_router(store);
        // validator 0 at slot 5 → match
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/attestations?slot=5&validator_index=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["validator_index"], 0);

        // validator 0 at slot 9 → no match
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/attestations?slot=9&validator_index=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[tokio::test]
    async fn attestations_bad_query_param_returns_json_400() {
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::build_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/attestations?slot=abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_some(), "expected JSON error field");
    }
}
