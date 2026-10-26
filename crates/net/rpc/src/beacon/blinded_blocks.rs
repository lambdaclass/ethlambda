//! `POST /eth/v2/beacon/blinded_blocks` (fulu), and the guard both publish
//! endpoints share against signing two blocks for one slot.
//!
//! A blinded block goes to the builder, which publishes the full block and
//! its data columns itself (`submitBlindedBlockV2`). The block then comes
//! back over gossip and imports like any other. Nothing is gossiped or
//! imported here.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use ethlambda_state_transition::beacon::block_production::advance_to_slot;
use ethlambda_state_transition::beacon::helpers::accessors::get_beacon_proposer_index;
use ethlambda_state_transition::beacon::stf::verify_proposer_signature;
use ethlambda_storage::Store;
use ethlambda_types::beacon::builder::SignedBlindedBeaconBlock;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{HashTreeRoot as _, Root, Slot};
use ethlambda_types::beacon::signing::compute_start_slot_at_epoch;
use tracing::{error, info, warn};

use super::builder_client::BuilderError;
use super::builder_flow::Builder;
use super::proposal::require_fulu_slot;
use super::{ApiError, BodyEncoding};

/// The block root this node published or handed to the builder for each
/// slot, so a second, different block for a slot is refused instead of
/// broadcast. Pruned below the finalized slot.
#[derive(Debug, Clone, Default)]
pub(crate) struct PublishedProposals(Arc<Mutex<BTreeMap<Slot, Root>>>);

impl PublishedProposals {
    /// Claims `slot` for `root`, or refuses with the root already claimed.
    /// The same root again is a retry, not an equivocation.
    pub(crate) fn claim(&self, slot: Slot, root: Root, finalized_slot: Slot) -> Result<(), Root> {
        let mut published = self.0.lock().expect("published proposals lock poisoned");
        *published = published.split_off(&finalized_slot);
        match published.get(&slot) {
            Some(&claimed) if claimed != root => Err(claimed),
            Some(_) => Ok(()),
            None => {
                published.insert(slot, root);
                Ok(())
            }
        }
    }
}

/// The finalized checkpoint's start slot, below which no claim matters.
pub(crate) fn finalized_slot(store: &Store) -> Slot {
    compute_start_slot_at_epoch(store.beacon_finalized_checkpoint().epoch)
}

/// Checked like `post_block`'s fulu path, before anything leaves this node:
/// the parent is held, the block is after it, its proposer is the one the
/// parent's state names for the slot, and the proposer's signature verifies.
/// Then the slot is claimed, and the block goes to the builder.
///
/// The submission runs on its own task. Once the proposer has signed it is
/// committed, so a validator client that hangs up must not cancel the
/// reveal. The answer is the builder's: 202 becomes 200 and a 400 is passed
/// through. Anything else is a 500, with no local fallback, since a second
/// block would be an equivocation.
pub(crate) async fn post_blinded_block(
    State(store): State<Store>,
    builder: Option<Extension<Arc<Builder>>>,
    Extension(published): Extension<PublishedProposals>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(Extension(builder)) = builder else {
        return ApiError::Internal("no builder is configured (--builder)").into_response();
    };
    let fork = headers
        .get("eth-consensus-version")
        .and_then(|value| value.to_str().ok())
        .and_then(ForkName::parse);
    if fork != Some(ForkName::Fulu) {
        return ApiError::BadRequest("Eth-Consensus-Version must be fulu").into_response();
    }
    let encoding = match BodyEncoding::from_headers(&headers) {
        Ok(encoding) => encoding,
        Err(err) => return err.into_response(),
    };
    let Some(signed) = encoding.decode::<SignedBlindedBeaconBlock>(&body) else {
        return ApiError::BadRequest("the body is not a fulu SignedBlindedBeaconBlock")
            .into_response();
    };
    let slot = signed.message.slot;
    if let Err(err) = require_fulu_slot(
        &store.config(),
        slot,
        "blinded blocks are accepted for fulu slots only",
    ) {
        return err.into_response();
    }
    let Some(parent_state) = store.get_state(&signed.message.parent_root).ok().flatten() else {
        return ApiError::BadRequest("the block's parent is not known to this node")
            .into_response();
    };
    let config = store.config();
    let checked = tokio::task::spawn_blocking(move || {
        if slot <= parent_state.slot() {
            return Err("the block is not after its parent");
        }
        let state = advance_to_slot(&parent_state, slot, &config)
            .map_err(|_| "advancing the parent state failed")?;
        let proposer = get_beacon_proposer_index(&state).map_err(|_| "no proposer for the slot")?;
        if signed.message.proposer_index != proposer {
            return Err("wrong proposer for the slot");
        }
        let root = signed.message.hash_tree_root();
        if !verify_proposer_signature(&state, proposer, root, &signed.signature) {
            return Err("invalid block signature");
        }
        Ok((signed, root))
    })
    .await;
    let (signed, root) = match checked {
        Ok(Ok(checked)) => checked,
        Ok(Err(message)) => return ApiError::BadRequest(message).into_response(),
        Err(err) => {
            error!(%err, "Checking a published blinded block failed");
            return ApiError::Internal("checking the blinded block failed").into_response();
        }
    };
    if published.claim(slot, root, finalized_slot(&store)).is_err() {
        warn!(slot, "Refusing a second, different block for the slot");
        return ApiError::BadRequest("this node already published a different block for the slot")
            .into_response();
    }

    let client = builder.client.clone();
    let submitted =
        tokio::spawn(async move { client.submit_blinded_block(&signed, ForkName::Fulu).await })
            .await;
    match submitted {
        Ok(Ok(())) => {
            info!(slot, "The builder took the blinded block");
            StatusCode::OK.into_response()
        }
        Ok(Err(BuilderError::BadRequest(message))) => {
            warn!(slot, %message, "The builder refused the blinded block");
            ApiError::BadRequestDetail(message).into_response()
        }
        Ok(Err(err)) => {
            warn!(slot, %err, "The builder did not take the blinded block");
            ApiError::Internal("the builder did not take the block").into_response()
        }
        Err(err) => {
            error!(%err, "Submitting the blinded block failed");
            ApiError::Internal("submitting the block failed").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_is_claimed_once_and_a_retry_of_the_same_root_passes() {
        let published = PublishedProposals::default();
        let first = Root::repeat_byte(1);
        assert_eq!(published.claim(10, first, 0), Ok(()));
        assert_eq!(published.claim(10, first, 0), Ok(()));
        assert_eq!(published.claim(10, Root::repeat_byte(2), 0), Err(first));
    }

    #[test]
    fn claims_below_the_finalized_slot_are_forgotten() {
        let published = PublishedProposals::default();
        published.claim(10, Root::repeat_byte(1), 0).unwrap();
        assert_eq!(published.claim(10, Root::repeat_byte(2), 11), Ok(()));
    }
}
