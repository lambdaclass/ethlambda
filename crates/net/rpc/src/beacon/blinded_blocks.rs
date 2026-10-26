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

/// Why a slot could not be claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaimError {
    /// The slot is below the finalized one, where claims are forgotten, so a
    /// second block could not be told from the first.
    Finalized,
    /// This node already published another block for the slot.
    Taken(Root),
}

impl ClaimError {
    /// The 400 a publish endpoint answers with.
    pub(crate) fn into_api_error(self) -> ApiError {
        match self {
            Self::Finalized => ApiError::BadRequest("the slot is already finalized"),
            Self::Taken(_) => {
                ApiError::BadRequest("this node already published a different block for the slot")
            }
        }
    }
}

impl PublishedProposals {
    /// Claims `slot` for `root`, or refuses: below `finalized_slot` (a slot
    /// equal to it is still held, as `split_off` keeps it), or with the root
    /// already claimed. The same root again is a retry, not an equivocation.
    pub(crate) fn claim(
        &self,
        slot: Slot,
        root: Root,
        finalized_slot: Slot,
    ) -> Result<(), ClaimError> {
        if slot < finalized_slot {
            return Err(ClaimError::Finalized);
        }
        let mut published = self.0.lock().expect("published proposals lock poisoned");
        *published = published.split_off(&finalized_slot);
        match published.get(&slot) {
            Some(&claimed) if claimed != root => Err(ClaimError::Taken(claimed)),
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
    if let Err(err) = published.claim(slot, root, finalized_slot(&store)) {
        warn!(slot, ?err, "Refusing a block for the slot");
        return err.into_api_error().into_response();
    }

    // The outcome is logged inside the task: once the proposer has signed, a
    // validator client that hangs up drops this handler, and the reveal's
    // result would otherwise go unrecorded. A block the builder does not take
    // is a missed slot, so those are errors.
    let client = builder.client.clone();
    let submitted = tokio::spawn(async move {
        let result = client.submit_blinded_block(&signed, ForkName::Fulu).await;
        match &result {
            Ok(()) => info!(slot, "The builder took the blinded block"),
            Err(BuilderError::BadRequest(message)) => {
                error!(slot, %message, "The builder refused the signed blinded block")
            }
            Err(err) => error!(slot, %err, "The builder did not take the signed blinded block"),
        }
        result
    })
    .await;
    match submitted {
        Ok(Ok(())) => StatusCode::OK.into_response(),
        Ok(Err(BuilderError::BadRequest(message))) => {
            ApiError::BadRequestDetail(message).into_response()
        }
        Ok(Err(_)) => ApiError::Internal("the builder did not take the block").into_response(),
        Err(err) => {
            error!(slot, %err, "Submitting the blinded block failed");
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
        assert_eq!(
            published.claim(10, Root::repeat_byte(2), 0),
            Err(ClaimError::Taken(first))
        );
    }

    #[test]
    fn a_claim_below_the_finalized_slot_is_refused() {
        let published = PublishedProposals::default();
        published.claim(10, Root::repeat_byte(1), 0).unwrap();
        assert_eq!(
            published.claim(10, Root::repeat_byte(2), 11),
            Err(ClaimError::Finalized)
        );
        assert_eq!(
            published.claim(10, Root::repeat_byte(1), 11),
            Err(ClaimError::Finalized)
        );
    }

    #[test]
    fn the_finalized_slot_itself_can_still_be_claimed() {
        let published = PublishedProposals::default();
        assert_eq!(published.claim(11, Root::repeat_byte(1), 11), Ok(()));
        assert_eq!(
            published.claim(11, Root::repeat_byte(2), 11),
            Err(ClaimError::Taken(Root::repeat_byte(1)))
        );
    }
}
