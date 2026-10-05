//! Gloas block production and payload envelope publication.
//!
//! STUB: owned by the block-production task (see the contract), which fills
//! in `POST /eth/v4/validator/blocks/{slot}`,
//! `GET /eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}`
//! and `POST /eth/v1/beacon/execution_payload_envelopes`.

use axum::Router;
use ethlambda_storage::Store;

pub(crate) fn routes() -> Router<Store> {
    Router::new()
}
