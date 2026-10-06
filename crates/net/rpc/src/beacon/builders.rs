//! `POST /eth/v1/beacon/states/{state_id}/builders`: the builder registry of a
//! gloas state, filtered by id and status.
//!
//! The Beacon API defines only the POST form, so a builder list is a request
//! with a body rather than a query string.

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::post,
};
use ethlambda_state_transition::beacon::helpers::gloas::is_active_builder;
use ethlambda_storage::Store;
use ethlambda_types::beacon::{
    constants::FAR_FUTURE_EPOCH,
    containers::{BeaconState, gloas::Builder},
    primitives::{BlsPubkey, ValidatorIndex},
};
use serde::{Deserialize, Serialize};

use crate::beacon::{ApiError, blocks::is_finalized, states::load};

pub(crate) fn routes() -> Router<Store> {
    Router::new().route(
        "/eth/v1/beacon/states/{state_id}/builders",
        post(post_builders),
    )
}

/// `api.yaml#BuilderStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuilderStatus {
    Pending,
    Active,
    Exited,
}

impl BuilderStatus {
    fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Exited => "exited",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "exited" => Some(Self::Exited),
            _ => None,
        }
    }
}

/// A builder id: a registry index or a 48-byte public key.
enum BuilderId {
    Index(u64),
    Pubkey(BlsPubkey),
}

impl BuilderId {
    fn parse(text: &str) -> Result<Self, ApiError> {
        let invalid = || ApiError::BadRequest("invalid builder id");
        if let Some(digits) = text.strip_prefix("0x") {
            let bytes: [u8; 48] = hex::decode(digits)
                .map_err(|_| invalid())?
                .try_into()
                .map_err(|_| invalid())?;
            return Ok(Self::Pubkey(BlsPubkey(bytes)));
        }
        text.parse().map(Self::Index).map_err(|_| invalid())
    }

    fn selects(&self, index: u64, builder: &Builder) -> bool {
        match self {
            Self::Index(wanted) => *wanted == index,
            Self::Pubkey(wanted) => *wanted == builder.pubkey,
        }
    }
}

/// The optional request body. Empty or absent filters select everything.
#[derive(Debug, Default, Deserialize)]
struct BuildersRequest {
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    statuses: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BuilderEntry<'a> {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    index: ValidatorIndex,
    status: &'static str,
    builder: &'a Builder,
}

/// `POST /eth/v1/beacon/states/{state_id}/builders`.
///
/// An id naming no builder is omitted rather than failing the request. The
/// answer is in registry order, which the specification leaves unspecified.
async fn post_builders(
    Path(state_id): Path<String>,
    State(store): State<Store>,
    body: Bytes,
) -> Response {
    let request = if body.is_empty() {
        BuildersRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => return ApiError::BadRequest("invalid request body").into_response(),
        }
    };
    let ids = match request
        .ids
        .iter()
        .map(|id| BuilderId::parse(id))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(err) => return err.into_response(),
    };
    let statuses = match request
        .statuses
        .iter()
        .map(|status| BuilderStatus::parse(status).ok_or(ApiError::BadRequest("invalid status")))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(statuses) => statuses,
        Err(err) => return err.into_response(),
    };
    let (root, state) = match load(&store, &state_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };
    let BeaconState::Gloas(inner) = state.as_ref() else {
        return ApiError::BadRequest("the requested state is prior to Gloas").into_response();
    };

    let mut entries = Vec::new();
    for (index, builder) in inner.builders.iter().enumerate() {
        let index = index as u64;
        if !(ids.is_empty() || ids.iter().any(|id| id.selects(index, builder))) {
            continue;
        }
        let status = if builder.withdrawable_epoch != FAR_FUTURE_EPOCH {
            BuilderStatus::Exited
        } else if is_active_builder(inner, index).unwrap_or(false) {
            BuilderStatus::Active
        } else {
            BuilderStatus::Pending
        };
        if !(statuses.is_empty() || statuses.contains(&status)) {
            continue;
        }
        entries.push(BuilderEntry {
            index,
            status: status.name(),
            builder,
        });
    }

    crate::json_response(serde_json::json!({
        "execution_optimistic": crate::shared::optimistic::block_is_optimistic(&store, root),
        "finalized": is_finalized(&store, state.slot()),
        "data": entries,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::beacon_store_with_config;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_state_transition::beacon::helpers::test_state::with_signing_validators_at;
    use ethlambda_types::beacon::{config::Config, fork::ForkName};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    fn builder(seed: u8, deposit_epoch: u64, withdrawable_epoch: u64) -> Builder {
        Builder {
            pubkey: BlsPubkey([seed; 48]),
            version: 3,
            execution_address: Default::default(),
            balance: 32_000_000_000 + u64::from(seed),
            deposit_epoch,
            withdrawable_epoch,
        }
    }

    /// A gloas head state whose registry holds an active builder (0), a
    /// pending one (1, deposited at the finalized epoch) and an exited one (2).
    fn gloas_state_with_builders() -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Gloas, 64);
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        inner.finalized_checkpoint.epoch = 10;
        for builder in [
            builder(1, 3, FAR_FUTURE_EPOCH),
            builder(2, 10, FAR_FUTURE_EPOCH),
            builder(3, 3, 20),
        ] {
            inner.builders.push(builder);
        }
        state
    }

    async fn post_to(store: Store, state_id: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::post(format!("/eth/v1/beacon/states/{state_id}/builders"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    fn gloas_store() -> Store {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        beacon_store_with_config(gloas_state_with_builders(), config).0
    }

    fn indices(json: &serde_json::Value) -> Vec<String> {
        json["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["index"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn every_builder_is_listed_in_registry_order_with_its_status() {
        for body in ["", "{}", r#"{"ids":[],"statuses":[]}"#] {
            let (status, json) = post_to(gloas_store(), "head", body).await;
            assert_eq!(status, StatusCode::OK, "{body:?}");
            assert_eq!(indices(&json), ["0", "1", "2"]);
            let statuses: Vec<_> = json["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["status"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(statuses, ["active", "pending", "exited"]);
            assert_eq!(json["execution_optimistic"], false);
            assert!(json["finalized"].is_boolean());
        }
    }

    #[tokio::test]
    async fn numbers_are_quoted() {
        let (_, json) = post_to(gloas_store(), "head", "").await;
        let first = &json["data"][0];
        assert_eq!(first["index"], "0");
        assert_eq!(first["builder"]["version"], "3");
        assert_eq!(first["builder"]["balance"], "32000000001");
        assert_eq!(first["builder"]["deposit_epoch"], "3");
        assert_eq!(
            first["builder"]["withdrawable_epoch"],
            FAR_FUTURE_EPOCH.to_string()
        );
        assert!(
            first["builder"]["pubkey"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
    }

    #[tokio::test]
    async fn builders_are_selected_by_index_or_public_key_and_unknown_ids_are_omitted() {
        let pubkey = format!("0x{}", "03".repeat(48));
        let body = format!(r#"{{"ids":["1","{pubkey}","99","0x{}"]}}"#, "ff".repeat(48));
        let (status, json) = post_to(gloas_store(), "head", &body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(indices(&json), ["1", "2"]);
    }

    #[tokio::test]
    async fn the_status_filter_narrows_the_list() {
        let (_, json) = post_to(gloas_store(), "head", r#"{"statuses":["active"]}"#).await;
        assert_eq!(indices(&json), ["0"]);
        let (_, json) = post_to(
            gloas_store(),
            "head",
            r#"{"statuses":["pending","exited"]}"#,
        )
        .await;
        assert_eq!(indices(&json), ["1", "2"]);
        let (_, json) = post_to(
            gloas_store(),
            "head",
            r#"{"ids":["0","1"],"statuses":["exited"]}"#,
        )
        .await;
        assert!(indices(&json).is_empty());
    }

    #[tokio::test]
    async fn a_bad_body_id_or_status_is_a_400() {
        for body in [
            "not json",
            r#"{"ids":["zero"]}"#,
            r#"{"ids":["0x1234"]}"#,
            r#"{"statuses":["retired"]}"#,
            r#"{"ids":"0"}"#,
        ] {
            let (status, _) = post_to(gloas_store(), "head", body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        }
    }

    #[tokio::test]
    async fn a_pre_gloas_state_is_a_400_and_an_unknown_one_a_404() {
        let state = with_signing_validators_at(ForkName::Fulu, 64);
        let (store, _) = beacon_store_with_config(state, Config::mainnet());
        let (status, json) = post_to(store, "head", "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["message"], "the requested state is prior to Gloas");

        let (status, _) = post_to(gloas_store(), "999999", "").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = post_to(gloas_store(), "nonsense", "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
