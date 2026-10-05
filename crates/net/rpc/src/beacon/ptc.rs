//! The payload timeliness committee's validator-facing endpoints.
//!
//! STUB: owned by the PTC task (see the contract), which fills in
//! `POST /eth/v1/validator/duties/ptc/{epoch}`,
//! `GET /eth/v1/validator/payload_attestation_data` and
//! `GET`/`POST /eth/v1/beacon/pool/payload_attestations`.

use axum::Router;
use ethlambda_storage::Store;

pub(crate) fn routes() -> Router<Store> {
    Router::new()
}
