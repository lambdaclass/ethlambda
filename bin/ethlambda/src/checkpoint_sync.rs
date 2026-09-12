//! Checkpoint sync for `ethlambda node`, against a lean peer's `/lean/v0/…`
//! API.
//!
//! The URL cleaning, the base-URL trim and the "try each URL, first success
//! wins" fan-out below were a `checkpoint_common` module while `crate::beacon`
//! read mainnet's genesis metadata as JSON off the same `--checkpoint-sync-url`
//! list. It reads that from the genesis state built into the binary now, so
//! this is the only caller left and they have folded back in here.
//!
//! The HTTP client is built here for a reason that outlived that split: a
//! finalized `State` is large enough to need a connect timeout plus an
//! inactivity read timeout, where a plain total timeout would kill a healthy
//! slow transfer.
//!
//! This path fetches the state and then the block, from endpoints that each
//! mean "whatever is finalized right now", so the peer can advance
//! finalization between the two requests. That is what
//! [`fetch_finalized_anchor`]'s retry loop (via [`try_checkpoint_url`]) is
//! for. Sequential rather than concurrent so both chains run one shape: the
//! beacon path cannot issue its block request until it has read the anchor
//! block's slot off the state.

use std::future::Future;
use std::time::Duration;

use ethlambda_p2p::beacon::decode;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_types::beacon::preset;
use ethlambda_types::block::SignedBlock;
use ethlambda_types::genesis::{GenesisMismatch, verify_state_genesis};
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use ethlambda_types::state::{State, anchor_pair_is_consistent};
use libssz::{DecodeError, SszDecode};
use reqwest::Client;
use tracing::{error, info, warn};

/// Timeout for establishing the HTTP connection to the checkpoint peer.
/// Fail fast if the peer is unreachable.
const CHECKPOINT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for reading data during body download.
/// This is an inactivity timeout - it resets on each successful read.
const CHECKPOINT_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Path of the finalized-state endpoint (relative to the peer's API base URL).
const FINALIZED_STATE_PATH: &str = "/lean/v0/states/finalized";

/// Path of the finalized-block endpoint (relative to the peer's API base URL).
const FINALIZED_BLOCK_PATH: &str = "/lean/v0/blocks/finalized";

/// Path of the finalized-state endpoint on a Beacon API server.
///
/// `finalized` resolves to the state at the finalized checkpoint's epoch
/// boundary, which may be a slot with no block in it. See
/// [`fetch_beacon_anchor`].
const BEACON_FINALIZED_STATE_PATH: &str = "/eth/v2/debug/beacon/states/finalized";

/// Path of the block-by-slot endpoint on a Beacon API server.
fn beacon_block_path(slot: u64) -> String {
    format!("/eth/v2/beacon/blocks/{slot}")
}

/// Maximum attempts to refetch the anchor pair if the state and block roots don't match.
const MAX_ANCHOR_FETCH_ATTEMPTS: u32 = 3;

/// Delay between anchor fetch attempts.
const ANCHOR_FETCH_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Fixed backoff between checkpoint-sync attempts.
const CHECKPOINT_RETRY_BACKOFF: Duration = Duration::from_secs(5);

/// Maximum checkpoint-sync attempts before the process gives up, giving a
/// slow-to-boot peer time to become reachable. Attempts stay within Hive's
/// client-startup budget when each one fails fast.
const MAX_CHECKPOINT_ATTEMPTS: u32 = 5;

/// Strip one trailing slash, so `{base}{path}` never doubles one.
fn trim_trailing_slash(url: &str) -> &str {
    url.trim_end_matches('/')
}

/// Trim whitespace from each URL and drop any that become empty.
///
/// A shell expanding an unset variable into `--checkpoint-sync-url ""` is an
/// easy way to end up with an empty string in the list; treating it as a URL
/// worth dialing is never useful.
pub(crate) fn clean_urls<I>(urls: I) -> Vec<String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    urls.into_iter()
        .map(|url| url.as_ref().trim().to_string())
        .filter(|url| !url.is_empty())
        .collect()
}

/// Try each URL in turn, stopping at the first success.
///
/// `attempt` receives the URL (owned, not borrowed: a closure returning a
/// future can't hand back one that borrows its own argument, since `Fut` is a
/// single associated type rather than one per call; cloning a handful of
/// short strings is a cheap way around that) and whether another one remains
/// after it, so the caller can word a "trying next" vs. "no more URLs" log
/// without this function knowing what logging looks like on either side.
/// `on_exhausted` turns whatever `attempt` left behind into the error to
/// return: it is called with `None` only when `urls` was empty to begin with,
/// and with `Some(the last error)` once every URL has been tried and failed.
async fn try_urls_in_order<T, E, Fut>(
    urls: &[String],
    mut attempt: impl FnMut(String, bool) -> Fut,
    on_exhausted: impl FnOnce(Option<E>) -> E,
) -> Result<T, E>
where
    Fut: Future<Output = Result<T, E>>,
{
    let mut iter = urls.iter().peekable();
    let mut last_err = None;
    while let Some(url) = iter.next() {
        let has_more = iter.peek().is_some();
        match attempt(url.clone(), has_more).await {
            Ok(value) => return Ok(value),
            Err(err) => last_err = Some(err),
        }
    }
    Err(on_exhausted(last_err))
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointSyncError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("SSZ deserialization failed: {0:?}")]
    SszDecode(DecodeError),
    #[error("checkpoint state slot cannot be 0")]
    SlotIsZero,
    #[error("checkpoint state has no validators")]
    NoValidators,
    #[error("checkpoint state does not match the configured genesis: {0}")]
    Genesis(#[from] GenesisMismatch),
    /// Reading the persisted store failed. Startup aborts: the operator has
    /// to point at the right data directory or remove it.
    #[error("failed to load persisted DB state: {0}")]
    DbState(#[from] ethlambda_storage::Error),
    /// The data directory holds the other chain. Refusing to touch it is
    /// deliberate: re-initializing on top would leave the foreign blocks in
    /// place, and they are reachable through the slot-indexed reads that serve
    /// `BlocksByRange`.
    #[error(
        "data directory holds a {found:?} chain, not a {expected:?} one; \
         wipe it or switch sub-command"
    )]
    WrongChain {
        expected: ethlambda_storage::Chain,
        found: ethlambda_storage::Chain,
    },
    #[error("finalized slot cannot exceed state slot")]
    FinalizedExceedsStateSlot,
    #[error("justified slot cannot precede finalized slot")]
    JustifiedPrecedesFinalized,
    #[error("justified and finalized at same slot must have matching roots")]
    JustifiedFinalizedRootMismatch,
    #[error("block header slot exceeds state slot")]
    BlockHeaderSlotExceedsState,
    #[error("block header at finalized slot must match finalized root")]
    BlockHeaderFinalizedRootMismatch,
    #[error("block header at justified slot must match justified root")]
    BlockHeaderJustifiedRootMismatch,
    #[error("anchor block does not match anchor state")]
    AnchorPairingMismatch,
    #[error("no checkpoint urls configured")]
    NoCheckpointUrls,
    #[error("failed to insert anchor signed block into store")]
    StoreInsertSignedBlock,
    /// `get_forkchoice_store` checks the same pair of forks; reaching it here
    /// first lets the error name the peer that served the mismatched pair,
    /// and keeps a peer problem out of a function whose other errors mean the
    /// specification was violated.
    #[error("anchor state is at {state} but the anchor block is at {block}")]
    AnchorForkMismatch {
        state: ethlambda_types::beacon::fork::ForkName,
        block: ethlambda_types::beacon::fork::ForkName,
    },
    #[error("peer served no block at the anchor slot {slot}")]
    AnchorBlockMissing { slot: u64 },
    #[error("beacon checkpoint sync requires --checkpoint-sync-url: there is no genesis-sync path")]
    BeaconGenesisSync,
    /// The buffer served for the finalized beacon state is too short to hold
    /// the slot at its fixed offset, so no fork could even be resolved before
    /// decoding could be attempted. Carries `slot_from_ssz`'s own error, which
    /// is always an `InvalidByteLength` naming the offset it expected against
    /// the length it got.
    #[error("beacon state buffer too short to read its slot: {0:?}")]
    BeaconStateSlotDecode(ethlambda_types::beacon::error::Error),
    /// The beacon state did not decode as the fork its own slot named.
    /// Separate from [`CheckpointSyncError::BeaconStateSlotDecode`], whose
    /// slot read already succeeded: the fork is known by this point, and
    /// "decoded as the wrong fork" is the failure mode that actually matters
    /// here, so it is kept rather than discarded along with the rest of
    /// `ethlambda-types`' own decode error.
    #[error("beacon state did not decode as {fork}: {source:?}")]
    BeaconStateDecode {
        fork: ethlambda_types::beacon::fork::ForkName,
        source: ethlambda_types::beacon::error::Error,
    },
    /// The beacon block at `slot` did not decode. Reuses the gossip path's
    /// decoder, which resolves and discards its own fork internally and
    /// collapses every libssz failure into one `Ssz` variant alongside
    /// `Truncated`/`UnknownTopic`, so its own [`decode::DecodeError`] is the
    /// most detail available at this call site. Named `err` rather than
    /// `source`: that type does not implement `std::error::Error`, and
    /// thiserror would otherwise require it to for the automatic
    /// `Error::source()` a field literally named `source` gets.
    #[error("beacon block at slot {slot} did not decode: {err}")]
    BeaconBlockDecode { slot: u64, err: decode::DecodeError },
}

/// Build the HTTP client used for checkpoint sync fetches.
///
/// Uses two-phase timeout strategy:
/// - Connect timeout (15s): Fails quickly if peer is unreachable
/// - Read timeout (15s): Inactivity timeout that resets on each read
///
/// Note: We use a read timeout (via `.read_timeout()`) instead of a total download
/// timeout to automatically detect stalled downloads. This allows large states
/// to be downloaded successfully as long as data keeps flowing, while still
/// failing fast if the connection stalls. A plain total timeout would
/// disconnect even for valid downloads if the state is simply too large to
/// transfer within the time limit.
fn build_client() -> Result<Client, CheckpointSyncError> {
    Ok(Client::builder()
        .connect_timeout(CHECKPOINT_CONNECT_TIMEOUT)
        .read_timeout(CHECKPOINT_READ_TIMEOUT)
        .build()?)
}

/// Fetch an `application/octet-stream` body from `url` and decode it with
/// `decode`.
///
/// Takes a closure rather than returning the bytes so the body is never
/// copied: a mainnet `BeaconState` is hundreds of megabytes, and handing it
/// back as a `Vec` would double the peak.
async fn fetch_decoded<T>(
    client: &Client,
    url: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, CheckpointSyncError>,
) -> Result<T, CheckpointSyncError> {
    let bytes = client
        .get(url)
        .header("Accept", "application/octet-stream")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    decode(&bytes)
}

/// Fetch and SSZ-decode an `application/octet-stream` body from `url`, for a
/// container whose shape does not depend on a fork.
async fn fetch_ssz<T: SszDecode>(client: &Client, url: &str) -> Result<T, CheckpointSyncError> {
    fetch_decoded(client, url, |bytes| {
        T::from_ssz_bytes(bytes).map_err(CheckpointSyncError::SszDecode)
    })
    .await
}

/// Normalize a checkpoint-sync URL to a base URL.
///
/// Operators historically pass the full state URL (e.g.
/// `http://peer:5052/lean/v0/states/finalized`) via `--checkpoint-sync-url`.
/// The new contract is a base URL (`http://peer:5052`) so we can derive both
/// the state and block endpoints. To avoid breaking existing devnet scripts,
/// strip a trailing legacy path if present, on top of the trailing-slash trim
/// [`trim_trailing_slash`] applies.
// TODO: remove this and use the full URL
fn normalize_base_url(url: &str) -> &str {
    // Trim trailing slashes FIRST so that the legacy-suffix strip succeeds on
    // inputs like `…/lean/v0/states/finalized/`; otherwise we'd leave the
    // state path embedded in the "base URL" and double-prefix every request.
    let trimmed = trim_trailing_slash(url);
    trimmed
        .strip_suffix(FINALIZED_STATE_PATH)
        .unwrap_or(trimmed)
}

/// Fetch the finalized state from a checkpoint peer and verify it
/// against the local genesis configuration.
async fn fetch_finalized_state(
    client: &Client,
    base_url: &str,
    expected_genesis_time: u64,
    expected_genesis_validators_root: H256,
) -> Result<State, CheckpointSyncError> {
    let url = format!("{base_url}{FINALIZED_STATE_PATH}");
    let state: State = fetch_ssz(client, &url).await?;

    verify_checkpoint_state(&state)?;

    // Then the genesis identity, through the check the resume path and the
    // beacon path also run, so all three agree on what makes a state ours.
    // It takes a `BeaconState`, so the lean state moves into that wrapper and
    // straight back out of it; a move, not a copy.
    let state = BeaconState::Lean(state);
    let verdict = verify_state_genesis(
        &state,
        expected_genesis_time,
        expected_genesis_validators_root,
    );
    let BeaconState::Lean(state) = state else {
        unreachable!("the variant constructed one line above")
    };
    verdict?;

    Ok(state)
}

/// Fetch the finalized signed block from a checkpoint peer.
async fn fetch_finalized_block(
    client: &Client,
    base_url: &str,
) -> Result<SignedBlock, CheckpointSyncError> {
    let url = format!("{base_url}{FINALIZED_BLOCK_PATH}");
    fetch_ssz(client, &url).await
}

/// Fetch the finalized state, then the finalized block, and verify they pair.
///
/// If the peer advances finalization between the two requests the pairing will
/// not hold; the caller is expected to retry.
pub async fn fetch_finalized_anchor(
    url: &str,
    expected_genesis_time: u64,
    genesis_validators_root: H256,
) -> Result<(State, SignedBlock), CheckpointSyncError> {
    let base_url = normalize_base_url(url);
    let client = build_client()?;

    // State first, then the block, sequentially. It is the order the beacon
    // path needs, since that one addresses the block by a slot read off the
    // state, and running one shape on both chains is worth more than the
    // window the concurrent fetch saved. Both endpoints answer "whatever is
    // finalized right now", so the peer can still advance finalization
    // between them; `try_checkpoint_url` retries that.
    let mut state = fetch_finalized_state(
        &client,
        base_url,
        expected_genesis_time,
        genesis_validators_root,
    )
    .await?;
    let signed_block = fetch_finalized_block(&client, base_url).await?;

    // Strictly mirrors the invariants `Store::get_forkchoice_store` asserts —
    // header equality, state self-consistency, and `block.state_root` equal
    // to the canonical tree-hash root of the state.
    if !anchor_pair_is_consistent(&mut state, &signed_block.message) {
        return Err(CheckpointSyncError::AnchorPairingMismatch);
    }

    Ok((state, signed_block))
}

/// Verify a downloaded checkpoint state is structurally valid.
///
/// Says nothing about which network the state belongs to; that is
/// [`verify_state_genesis`]'s job, and the caller runs both.
fn verify_checkpoint_state(state: &State) -> Result<(), CheckpointSyncError> {
    // Slot sanity check. Checkpoint-specific: unlike a state loaded from our
    // own data directory, a downloaded anchor at genesis is never legitimate.
    if state.slot == 0 {
        return Err(CheckpointSyncError::SlotIsZero);
    }

    // Validators exist
    if state.validators.is_empty() {
        return Err(CheckpointSyncError::NoValidators);
    }

    // Finalized slot sanity
    if state.latest_finalized.slot > state.slot {
        return Err(CheckpointSyncError::FinalizedExceedsStateSlot);
    }

    // Justified must be at or after finalized
    if state.latest_justified.slot < state.latest_finalized.slot {
        return Err(CheckpointSyncError::JustifiedPrecedesFinalized);
    }

    // If justified and finalized are at same slot, roots must match
    if state.latest_justified.slot == state.latest_finalized.slot
        && state.latest_justified.root != state.latest_finalized.root
    {
        return Err(CheckpointSyncError::JustifiedFinalizedRootMismatch);
    }

    // Block header slot consistency
    if state.latest_block_header.slot > state.slot {
        return Err(CheckpointSyncError::BlockHeaderSlotExceedsState);
    }

    // If block header matches checkpoint slots, roots must match
    let block_root = state.latest_block_header.hash_tree_root();

    if state.latest_block_header.slot == state.latest_finalized.slot
        && block_root != state.latest_finalized.root
    {
        return Err(CheckpointSyncError::BlockHeaderFinalizedRootMismatch);
    }

    if state.latest_block_header.slot == state.latest_justified.slot
        && block_root != state.latest_justified.root
    {
        return Err(CheckpointSyncError::BlockHeaderJustifiedRootMismatch);
    }

    Ok(())
}

/// Fetch the finalized anchor from a single checkpoint URL, retrying transient
/// races where the peer advances finalization between the state and block
/// fetches.
async fn try_checkpoint_url(
    url: &str,
    genesis_time: u64,
    genesis_validators_root: H256,
) -> Result<(State, SignedBlock), CheckpointSyncError> {
    let mut attempt = 1;
    loop {
        match fetch_finalized_anchor(url, genesis_time, genesis_validators_root).await {
            Ok(pair) => return Ok(pair),
            Err(CheckpointSyncError::AnchorPairingMismatch)
                if attempt < MAX_ANCHOR_FETCH_ATTEMPTS =>
            {
                warn!(
                    %url,
                    attempt,
                    max = MAX_ANCHOR_FETCH_ATTEMPTS,
                    "Anchor state and block disagree (peer likely advanced finalization mid-fetch); retrying"
                );
                tokio::time::sleep(ANCHOR_FETCH_RETRY_DELAY).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Try each checkpoint URL in order, returning the first successful anchor
/// pair. Logs per-peer success/failure. On total failure, returns
/// the last fetch error encountered.
pub async fn fetch_anchor_block_and_state(
    checkpoint_urls: &[String],
    genesis_time: u64,
    genesis_validators_root: H256,
) -> Result<(State, SignedBlock), CheckpointSyncError> {
    try_urls_in_order(
        checkpoint_urls,
        |url, has_more| async move {
            match try_checkpoint_url(&url, genesis_time, genesis_validators_root).await {
                Ok(pair) => {
                    info!(%url, "Checkpoint sync successful with this peer");
                    Ok(pair)
                }
                Err(err) => {
                    if has_more {
                        warn!(%url, %err, "Checkpoint sync failed for this peer; trying next URL");
                    } else {
                        warn!(%url, %err, "Checkpoint sync failed for this peer; no more URLs to try");
                    }
                    Err(err)
                }
            }
        },
        |last_err| match last_err {
            Some(err) => {
                error!(%err, "All checkpoint sync attempts failed");
                err
            }
            None => CheckpointSyncError::NoCheckpointUrls,
        },
    )
    .await
}

/// Fetch the finalized anchor, retrying any failure (e.g. the peer not yet
/// reachable) for up to MAX_CHECKPOINT_ATTEMPTS attempts with a fixed backoff
/// between them before giving up.
pub async fn fetch_anchor_with_retry(
    checkpoint_urls: &[String],
    genesis_time: u64,
    genesis_validators_root: H256,
) -> Result<(State, SignedBlock), CheckpointSyncError> {
    let mut attempt: u32 = 1;
    loop {
        match fetch_anchor_block_and_state(checkpoint_urls, genesis_time, genesis_validators_root)
            .await
        {
            Ok(pair) => return Ok(pair),
            Err(err) if attempt < MAX_CHECKPOINT_ATTEMPTS => {
                warn!(attempt, %err, "Checkpoint sync attempt failed; retrying");
                tokio::time::sleep(CHECKPOINT_RETRY_BACKOFF).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

// ---------------------------------------------------------------------------
// Beacon path: checkpoint sync against a standard Beacon API server.
// ---------------------------------------------------------------------------

/// Fetch the finalized beacon state, decoding it at the fork its own slot
/// names.
///
/// The fork comes from the slot rather than the `Eth-Consensus-Version`
/// header: SSZ carries no type tag, and lighthouse's checkpoint-sync client
/// resolves it the same way. Deriving it removes any dependence on the peer
/// setting a header correctly.
async fn fetch_beacon_finalized_state(
    client: &Client,
    base_url: &str,
    config: &Config,
) -> Result<BeaconState, CheckpointSyncError> {
    let url = format!("{base_url}{BEACON_FINALIZED_STATE_PATH}");
    fetch_decoded(client, &url, |bytes| {
        let slot = BeaconState::slot_from_ssz(bytes)
            .map_err(CheckpointSyncError::BeaconStateSlotDecode)?;
        let fork = decode::fork_at_slot(config, slot);
        BeaconState::from_ssz(fork, bytes)
            .map_err(|source| CheckpointSyncError::BeaconStateDecode { fork, source })
    })
    .await
}

/// Fetch the signed beacon block at `slot`, decoding it at the fork its own
/// slot names.
///
/// Reuses the gossip path's decoder: the problem is identical, and its slot
/// peek already handles the outer container's offset.
async fn fetch_beacon_block(
    client: &Client,
    base_url: &str,
    config: &Config,
    slot: u64,
) -> Result<SignedBeaconBlock, CheckpointSyncError> {
    let url = format!("{base_url}{}", beacon_block_path(slot));
    let response = client
        .get(&url)
        .header("Accept", "application/octet-stream")
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(CheckpointSyncError::AnchorBlockMissing { slot });
    }
    let bytes = response.error_for_status()?.bytes().await?;

    decode::decode_block(config, &bytes)
        .map_err(|err| CheckpointSyncError::BeaconBlockDecode { slot, err })
}

/// Verify a downloaded beacon anchor state is structurally sound.
///
/// The beacon counterpart to [`verify_checkpoint_state`], checking the same
/// classes of fault against beacon's own fields: a genesis anchor is never a
/// legitimate checkpoint, checkpoints cannot sit in the future or out of
/// order, and the header cannot lead the state.
///
/// Says nothing about which network the state belongs to, exactly as the lean
/// one does not; [`verify_state_genesis`] answers that and the caller runs
/// both.
fn verify_beacon_checkpoint_state(state: &BeaconState) -> Result<(), CheckpointSyncError> {
    if state.slot() == 0 {
        return Err(CheckpointSyncError::SlotIsZero);
    }

    if state.validators().is_empty() {
        return Err(CheckpointSyncError::NoValidators);
    }

    let current_epoch = state.slot() / preset::SLOTS_PER_EPOCH;
    if state.finalized_checkpoint().epoch > current_epoch {
        return Err(CheckpointSyncError::FinalizedExceedsStateSlot);
    }

    if state.current_justified_checkpoint().epoch < state.finalized_checkpoint().epoch {
        return Err(CheckpointSyncError::JustifiedPrecedesFinalized);
    }

    if state.latest_block_header().slot > state.slot() {
        return Err(CheckpointSyncError::BlockHeaderSlotExceedsState);
    }

    Ok(())
}

/// Check that a beacon anchor's state and block belong together.
///
/// Two checks, in order. First, that the two agree on which fork applies: a
/// mismatch here means the peer served a container shaped for the wrong
/// fork, which `get_forkchoice_store` checks too, so catching it here lets
/// the error name the peer rather than surfacing a spec violation deeper in.
///
/// Second, that `block` is the one `state.latest_block_header` names, checked
/// on the header root rather than on `block.state_root ==
/// hash_tree_root(state)`. `states/finalized` resolves to the state at the
/// finalized epoch's boundary slot, which may have been empty; when it was,
/// the state has advanced one slot past its own `latest_block_header` (the
/// header still names the last block that actually existed, not the empty
/// boundary slot), so the state's own root no longer matches what the header
/// committed to. The header is unaffected by that advance, since
/// `latest_block_header.state_root` is left zero only for the duration of
/// the block's own slot and is filled in with the real root the moment the
/// slot moves past it (`process_slot`). So the zero is substituted with the
/// state's current root only when the header still carries the placeholder;
/// once the slot has advanced, the header already carries the real value and
/// that value is trusted as-is.
fn verify_beacon_anchor_pairing(
    state: &BeaconState,
    block: &SignedBeaconBlock,
) -> Result<(), CheckpointSyncError> {
    if block.fork_name() != state.fork_name() {
        return Err(CheckpointSyncError::AnchorForkMismatch {
            state: state.fork_name(),
            block: block.fork_name(),
        });
    }

    let mut header = state.latest_block_header().clone();
    if header.state_root == H256::ZERO {
        header.state_root = state.hash_tree_root();
    }
    if header.hash_tree_root() != block.message_hash_tree_root() {
        return Err(CheckpointSyncError::AnchorPairingMismatch);
    }

    Ok(())
}

/// Fetch a beacon anchor pair and verify it.
///
/// State first, then the block at `state.latest_block_header.slot`, which is
/// lighthouse's order and the only one available: the block cannot be
/// addressed until the state names its slot. The pairing and fork checks
/// themselves are [`verify_beacon_anchor_pairing`]'s job, kept pure so they
/// are reachable from a test without an HTTP server.
pub async fn fetch_beacon_anchor(
    url: &str,
    config: &Config,
    genesis_time: u64,
    genesis_validators_root: H256,
) -> Result<(BeaconState, SignedBeaconBlock), CheckpointSyncError> {
    let base_url = trim_trailing_slash(url);
    let client = build_client()?;

    let state = fetch_beacon_finalized_state(&client, base_url, config).await?;
    verify_beacon_checkpoint_state(&state)?;
    verify_state_genesis(&state, genesis_time, genesis_validators_root)?;

    let block_slot = state.latest_block_header().slot;
    let block = fetch_beacon_block(&client, base_url, config, block_slot).await?;

    verify_beacon_anchor_pairing(&state, &block)?;

    Ok((state, block))
}

/// Try each checkpoint URL in order, then retry the whole round, exactly as
/// the lean path does. The two loops are shared rather than duplicated:
/// `try_urls_in_order` and the fixed backoff mean the same thing on both
/// chains.
pub async fn fetch_beacon_anchor_with_retry(
    checkpoint_urls: &[String],
    config: &Config,
    genesis_time: u64,
    genesis_validators_root: H256,
) -> Result<(BeaconState, SignedBeaconBlock), CheckpointSyncError> {
    let mut attempt: u32 = 1;
    loop {
        let round = try_urls_in_order(
            checkpoint_urls,
            |url, has_more| async move {
                match fetch_beacon_anchor(&url, config, genesis_time, genesis_validators_root).await
                {
                    Ok(pair) => {
                        info!(%url, "Checkpoint sync successful with this peer");
                        Ok(pair)
                    }
                    Err(err) => {
                        if has_more {
                            warn!(%url, %err, "Checkpoint sync failed for this peer; trying next URL");
                        } else {
                            warn!(%url, %err, "Checkpoint sync failed for this peer; no more URLs to try");
                        }
                        Err(err)
                    }
                }
            },
            |last_err| match last_err {
                Some(err) => {
                    error!(%err, "All checkpoint sync attempts failed");
                    err
                }
                None => CheckpointSyncError::NoCheckpointUrls,
            },
        )
        .await;

        match round {
            Ok(pair) => return Ok(pair),
            Err(err) if attempt < MAX_CHECKPOINT_ATTEMPTS => {
                warn!(attempt, %err, "Checkpoint sync attempt failed; retrying");
                tokio::time::sleep(CHECKPOINT_RETRY_BACKOFF).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The URL helpers first, then the checkpoint-sync path that uses them.

    #[test]
    fn trim_trailing_slash_strips_exactly_one() {
        assert_eq!(trim_trailing_slash("http://peer:5052/"), "http://peer:5052");
        assert_eq!(trim_trailing_slash("http://peer:5052"), "http://peer:5052");
    }

    #[test]
    fn clean_urls_trims_and_drops_empties() {
        let urls = vec![
            " http://a ".to_string(),
            String::new(),
            "   ".to_string(),
            "http://b".to_string(),
        ];
        assert_eq!(clean_urls(urls), vec!["http://a", "http://b"]);
    }

    #[test]
    fn clean_urls_accepts_a_borrowed_slice_too() {
        // `run_node` cleans a borrowed URL list rather than consuming it;
        // this pins that the generic bound covers that.
        let urls = vec![" http://a ".to_string()];
        assert_eq!(clean_urls(&urls), vec!["http://a"]);
    }

    #[tokio::test]
    async fn try_urls_in_order_returns_the_first_success() {
        let urls = vec!["a".to_string(), "b".to_string()];
        let result: Result<&str, &str> = try_urls_in_order(
            &urls,
            |url, _has_more| async move { if url == "a" { Err("nope") } else { Ok("yes") } },
            |_last_err| "exhausted",
        )
        .await;
        assert_eq!(result, Ok("yes"));
    }

    #[tokio::test]
    async fn an_empty_list_is_distinguished_from_an_exhausted_one() {
        let empty: Vec<String> = vec![];
        let empty_result: Result<&str, &str> = try_urls_in_order(
            &empty,
            |_url, _has_more| async { Err("unreachable") },
            |last_err| {
                assert!(last_err.is_none(), "an empty list never attempts anything");
                "no urls configured"
            },
        )
        .await;
        assert_eq!(empty_result, Err("no urls configured"));

        let urls = vec!["a".to_string()];
        let exhausted_result: Result<&str, &str> = try_urls_in_order(
            &urls,
            |_url, _has_more| async { Err("boom") },
            |last_err| {
                assert_eq!(last_err, Some("boom"));
                "exhausted"
            },
        )
        .await;
        assert_eq!(exhausted_result, Err("exhausted"));
    }

    #[tokio::test]
    async fn has_more_is_false_only_on_the_last_url() {
        let urls = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut seen = Vec::new();
        let _: Result<(), &str> = try_urls_in_order(
            &urls,
            |url, has_more| {
                seen.push((url, has_more));
                async { Err("keep going") }
            },
            |_| "exhausted",
        )
        .await;
        assert_eq!(
            seen,
            vec![
                ("a".to_string(), true),
                ("b".to_string(), true),
                ("c".to_string(), false),
            ]
        );
    }
    use ethlambda_types::block::BlockHeader;
    use ethlambda_types::checkpoint::Checkpoint;
    use ethlambda_types::state::{JustificationValidators, JustifiedSlots, StateConfig, Validator};
    use libssz_types::SszList;

    // Helper to create valid test state
    fn create_test_state(slot: u64, validators: Vec<Validator>, genesis_time: u64) -> State {
        State {
            slot,
            validators: SszList::try_from(validators).unwrap(),
            latest_block_header: BlockHeader {
                slot,
                parent_root: H256::ZERO,
                state_root: H256::ZERO,
                body_root: H256::ZERO,
                proposer_index: 0,
            },
            latest_justified: Checkpoint {
                slot: slot.saturating_sub(10),
                root: H256::ZERO,
            },
            latest_finalized: Checkpoint {
                slot: slot.saturating_sub(20),
                root: H256::ZERO,
            },
            config: StateConfig { genesis_time },
            historical_block_hashes: Default::default(),
            justified_slots: JustifiedSlots::new(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        }
    }

    fn create_test_validator() -> Validator {
        Validator {
            attestation_pubkey: [1u8; 52],
            proposal_pubkey: [11u8; 52],
            index: 0,
        }
    }

    #[test]
    fn verify_accepts_valid_state() {
        let validators = vec![create_test_validator()];
        let state = create_test_state(100, validators, 1000);
        assert!(verify_checkpoint_state(&state).is_ok());
    }

    #[test]
    fn verify_rejects_slot_zero() {
        let validators = vec![create_test_validator()];
        let state = create_test_state(0, validators, 1000);
        assert!(verify_checkpoint_state(&state).is_err());
    }

    #[test]
    fn verify_rejects_empty_validators() {
        let state = create_test_state(100, vec![], 1000);
        assert!(verify_checkpoint_state(&state).is_err());
    }

    #[test]
    fn verify_rejects_finalized_after_state_slot() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        state.latest_finalized.slot = 101; // Finalized after state slot
        assert!(verify_checkpoint_state(&state).is_err());
    }

    #[test]
    fn verify_rejects_justified_before_finalized() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        state.latest_finalized.slot = 50;
        state.latest_justified.slot = 40; // Justified before finalized
        assert!(verify_checkpoint_state(&state).is_err());
    }

    #[test]
    fn verify_accepts_justified_equals_finalized_with_matching_roots() {
        use ethlambda_types::primitives::H256;
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        let common_root = H256::from([42u8; 32]);
        state.latest_finalized.slot = 50;
        state.latest_finalized.root = common_root;
        state.latest_justified.slot = 50; // Same slot
        state.latest_justified.root = common_root; // Same root
        assert!(verify_checkpoint_state(&state).is_ok());
    }

    #[test]
    fn verify_rejects_justified_equals_finalized_with_different_roots() {
        use ethlambda_types::primitives::H256;
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        state.latest_finalized.slot = 50;
        state.latest_finalized.root = H256::from([1u8; 32]);
        state.latest_justified.slot = 50; // Same slot
        state.latest_justified.root = H256::from([2u8; 32]); // Different root - conflict!
        assert!(verify_checkpoint_state(&state).is_err());
    }

    #[test]
    fn verify_rejects_block_header_slot_exceeds_state() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        state.latest_block_header.slot = 101; // Block header slot exceeds state slot
        assert!(verify_checkpoint_state(&state).is_err());
    }

    #[test]
    fn verify_accepts_block_header_matches_finalized_with_correct_root() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        state.latest_block_header.slot = 50;
        let block_root = state.latest_block_header.hash_tree_root();
        state.latest_finalized.slot = 50;
        state.latest_finalized.root = block_root;
        assert!(verify_checkpoint_state(&state).is_ok());
    }

    #[test]
    fn verify_rejects_block_header_matches_finalized_with_wrong_root() {
        use ethlambda_types::primitives::H256;
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        state.latest_block_header.slot = 50;
        state.latest_finalized.slot = 50;
        state.latest_finalized.root = H256::from([99u8; 32]); // Wrong root
        assert!(verify_checkpoint_state(&state).is_err());
    }

    #[test]
    fn verify_accepts_block_header_matches_justified_with_correct_root() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        state.latest_block_header.slot = 90;
        let block_root = state.latest_block_header.hash_tree_root();
        state.latest_justified.slot = 90;
        state.latest_justified.root = block_root;
        assert!(verify_checkpoint_state(&state).is_ok());
    }

    #[test]
    fn verify_rejects_block_header_matches_justified_with_wrong_root() {
        use ethlambda_types::primitives::H256;
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        state.latest_block_header.slot = 90;
        state.latest_justified.slot = 90;
        state.latest_justified.root = H256::from([99u8; 32]); // Wrong root
        assert!(verify_checkpoint_state(&state).is_err());
    }

    // --- normalize_base_url ---

    #[test]
    fn normalize_strips_legacy_state_path() {
        assert_eq!(
            normalize_base_url("http://peer:5052/lean/v0/states/finalized"),
            "http://peer:5052"
        );
    }

    #[test]
    fn normalize_passes_through_base_url() {
        assert_eq!(normalize_base_url("http://peer:5052"), "http://peer:5052");
    }

    #[test]
    fn normalize_strips_trailing_slash() {
        assert_eq!(normalize_base_url("http://peer:5052/"), "http://peer:5052");
    }

    #[test]
    fn normalize_strips_legacy_state_path_with_trailing_slash() {
        // Regression: a trailing slash on the legacy path used to defeat
        // strip_suffix, leaving the path embedded in the "base URL".
        assert_eq!(
            normalize_base_url("http://peer:5052/lean/v0/states/finalized/"),
            "http://peer:5052"
        );
    }

    // --- beacon anchor verification ---

    /// A recent-looking anchor built from the genesis state shipped in the
    /// binary. A real mainnet state, and the one the identity check runs
    /// against, moved off slot 0 so it is a legitimate checkpoint.
    fn beacon_anchor_state() -> BeaconState {
        let mut state =
            crate::beacon::mainnet_genesis_state().expect("the built-in archive decodes");
        *state.slot_mut() = 288;
        state
    }

    /// Slot 0 is never a legitimate checkpoint anchor, however well-formed the
    /// state is otherwise.
    #[test]
    fn a_beacon_state_at_genesis_is_rejected_as_an_anchor() {
        let state = crate::beacon::mainnet_genesis_state().unwrap();

        assert!(matches!(
            verify_beacon_checkpoint_state(&state),
            Err(CheckpointSyncError::SlotIsZero)
        ));
    }

    #[test]
    fn a_structurally_sound_beacon_anchor_passes() {
        assert!(verify_beacon_checkpoint_state(&beacon_anchor_state()).is_ok());
    }

    /// An anchor with an empty validator registry is never legitimate,
    /// however sound its checkpoints and header otherwise are.
    #[test]
    fn a_beacon_anchor_with_no_validators_is_rejected() {
        let mut state = beacon_anchor_state();
        // `SszList`'s `DerefMut` target is a slice, which cannot shrink, so
        // emptying the list means replacing it rather than mutating in place.
        *state.validators_mut() = Default::default();

        assert!(matches!(
            verify_beacon_checkpoint_state(&state),
            Err(CheckpointSyncError::NoValidators)
        ));
    }

    /// The finalized checkpoint can never name an epoch beyond the one the
    /// state's own slot has reached.
    #[test]
    fn a_beacon_anchor_with_finalized_epoch_beyond_state_is_rejected() {
        let mut state = beacon_anchor_state();
        let current_epoch = state.slot() / preset::SLOTS_PER_EPOCH;
        state.finalized_checkpoint_mut().epoch = current_epoch + 1;

        assert!(matches!(
            verify_beacon_checkpoint_state(&state),
            Err(CheckpointSyncError::FinalizedExceedsStateSlot)
        ));
    }

    /// The justified checkpoint can never sit behind the finalized one.
    /// `beacon_anchor_state`'s genesis-derived checkpoints both start at
    /// epoch 0, so moving finalized ahead is the one mutation needed to put
    /// justified behind it.
    #[test]
    fn a_beacon_anchor_with_justified_epoch_before_finalized_is_rejected() {
        let mut state = beacon_anchor_state();
        state.finalized_checkpoint_mut().epoch = 1;

        assert!(matches!(
            verify_beacon_checkpoint_state(&state),
            Err(CheckpointSyncError::JustifiedPrecedesFinalized)
        ));
    }

    /// The header's own slot can never lead the state's slot.
    #[test]
    fn a_beacon_anchor_with_block_header_slot_beyond_state_is_rejected() {
        let mut state = beacon_anchor_state();
        state.latest_block_header_mut().slot = state.slot() + 1;

        assert!(matches!(
            verify_beacon_checkpoint_state(&state),
            Err(CheckpointSyncError::BlockHeaderSlotExceedsState)
        ));
    }

    /// Structurally fine and still not ours: the identity check is what
    /// separates the two.
    #[test]
    fn a_beacon_state_from_another_network_is_rejected() {
        let genesis = crate::beacon::mainnet_genesis().unwrap();
        let state = beacon_anchor_state();

        assert!(verify_beacon_checkpoint_state(&state).is_ok());
        assert!(matches!(
            verify_state_genesis(
                &state,
                genesis.genesis_time + 1,
                genesis.genesis_validators_root
            ),
            Err(GenesisMismatch::GenesisTime { .. })
        ));
    }

    #[test]
    fn a_beacon_state_of_this_network_is_accepted() {
        let genesis = crate::beacon::mainnet_genesis().unwrap();
        let state = beacon_anchor_state();

        assert_eq!(
            verify_state_genesis(
                &state,
                genesis.genesis_time,
                genesis.genesis_validators_root
            ),
            Ok(())
        );
    }

    // --- beacon anchor pairing ---

    use ethlambda_types::beacon::containers::{BeaconBlockHeader, altair, phase0};
    use ethlambda_types::beacon::fork::ForkName;

    /// A phase0 signed block with an empty body, for tests that only care
    /// about `slot`/`parent_root`/`state_root`/`body_root`. Same shape as the
    /// `block` helper in `ethlambda_state_transition`'s own `fork_choice`
    /// test module.
    fn phase0_block(slot: u64, parent_root: H256) -> SignedBeaconBlock {
        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: H256::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        })
    }

    /// An exact anchor pair, built from the mainnet genesis fixture: `state`'s
    /// `latest_block_header` names `block` as a fixed point, the way the
    /// state transition produces one. The header's `state_root` is left
    /// zero, the way it sits inside the block's own slot; the state's root is
    /// then computed against that and written back into the block, so the
    /// header root and the block root agree once that zero is substituted.
    fn beacon_anchor_pair() -> (BeaconState, SignedBeaconBlock) {
        let mut state = beacon_anchor_state();
        let parent_root = state.latest_block_header().parent_root;
        let mut signed = phase0_block(state.slot(), parent_root);

        let SignedBeaconBlock::Phase0(inner) = &signed else {
            unreachable!("phase0_block builds a phase0 signed block");
        };
        *state.latest_block_header_mut() = BeaconBlockHeader {
            slot: inner.message.slot,
            proposer_index: inner.message.proposer_index,
            parent_root,
            state_root: H256::ZERO,
            body_root: inner.message.body.hash_tree_root(),
        };

        let state_root = state.hash_tree_root();
        let SignedBeaconBlock::Phase0(inner) = &mut signed else {
            unreachable!("phase0_block builds a phase0 signed block");
        };
        inner.message.state_root = state_root;

        (state, signed)
    }

    /// Advance a state one empty slot by hand, the way `process_slot` does:
    /// fill in the header's `state_root`, then move the slot on. The state is
    /// then past its own anchor block, which is the shape a checkpoint-synced
    /// anchor arrives in when the finalized epoch boundary was empty.
    fn advance_one_empty_slot(state: &mut BeaconState) {
        let root = state.hash_tree_root();
        state.latest_block_header_mut().state_root = root;
        *state.slot_mut() += 1;
    }

    #[test]
    fn an_exact_anchor_pair_passes_pairing() {
        let (state, block) = beacon_anchor_pair();
        assert!(verify_beacon_anchor_pairing(&state, &block).is_ok());
    }

    /// The whole point of the deviation from pairing on `block.state_root ==
    /// hash_tree_root(state)`: a `finalized` state that has advanced past its
    /// own anchor block (the epoch boundary was empty) must still pass.
    #[test]
    fn a_state_advanced_past_its_block_still_passes_pairing() {
        let (mut state, block) = beacon_anchor_pair();
        advance_one_empty_slot(&mut state);

        assert!(verify_beacon_anchor_pairing(&state, &block).is_ok());
    }

    #[test]
    fn a_block_the_state_does_not_name_is_rejected() {
        let (state, mut block) = beacon_anchor_pair();
        let SignedBeaconBlock::Phase0(inner) = &mut block else {
            unreachable!("beacon_anchor_pair builds a phase0 signed block");
        };
        // Change the block without updating the header that is supposed to
        // name it: the header still points at the original block.
        inner.message.parent_root = H256::repeat_byte(0xAA);

        assert!(matches!(
            verify_beacon_anchor_pairing(&state, &block),
            Err(CheckpointSyncError::AnchorPairingMismatch)
        ));
    }

    #[test]
    fn a_fork_mismatch_between_state_and_block_is_rejected() {
        let (state, _) = beacon_anchor_pair();
        let altair_block = SignedBeaconBlock::Altair(altair::SignedBeaconBlock {
            message: altair::BeaconBlock {
                slot: state.slot(),
                proposer_index: 0,
                parent_root: H256::ZERO,
                state_root: H256::ZERO,
                body: altair::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: H256::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                    sync_aggregate: Default::default(),
                },
            },
            signature: Default::default(),
        });

        assert!(matches!(
            verify_beacon_anchor_pairing(&state, &altair_block),
            Err(CheckpointSyncError::AnchorForkMismatch {
                state: ForkName::Phase0,
                block: ForkName::Altair,
            })
        ));
    }
}
