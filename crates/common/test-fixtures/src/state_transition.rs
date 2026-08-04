//! State-transition test fixture types.
//!
//! Used by the Hive `/lean/v0/test_driver/state_transition/run` endpoint,
//! which receives the entire fixture case as the JSON body from the lean
//! spec-assets simulator. Extra fields (such as `_info` or `post`) are
//! ignored by serde, so we only deserialize the parts the driver needs.

use crate::{Block, TestState};
use serde::Deserialize;

/// Request body for `POST /lean/v0/test_driver/state_transition/run`.
///
/// The simulator sends the full fixture case verbatim; we only need `pre` and
/// `blocks` to drive the STF. `rejection_reason` is captured because Ream's
/// driver uses its presence to force a deterministic error when `blocks` is
/// empty (otherwise the suite would expect a failure with no STF call to
/// produce one).
///
/// Deliberately a `String` and not a [`crate::RejectionReason`]: the driver reads
/// presence only, never the value, so typing it would buy nothing here. The
/// offline runners, which do assert the reason, parse the same field into
/// [`crate::RejectionReason`].
#[derive(Debug, Clone, Deserialize)]
pub struct StateTransitionRunRequest {
    pub pre: TestState,
    pub blocks: Vec<Block>,
    #[serde(default, rename = "rejectionReason")]
    pub rejection_reason: Option<String>,
}
