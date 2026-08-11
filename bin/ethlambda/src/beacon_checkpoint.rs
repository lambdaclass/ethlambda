//! Checkpoint sync for `ethlambda beacon`, against a Beacon API provider.
//!
//! Distinct from `crate::checkpoint_sync`, which speaks lean's `/lean/v0/…`
//! endpoints and lean's `State`. The two share the idea and nothing else: the
//! paths, the SSZ types, the fork-versioning problem and the ordering are all
//! different.
//!
//! The anchor pair is fetched block-first. `block.state_root` is the root of
//! that block's own post-state, so fetching the state *by that root* returns
//! exactly the state the block commits to. The store constructor's
//! `anchor_block.state_root == hash_tree_root(anchor_state)` assertion then
//! holds by construction, with no retry loop for the case where the provider
//! advances finalization mid-fetch.

use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::{Root, Slot};
use reqwest::Client;
use tracing::{info, warn};

/// Fail fast when the provider is unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Inactivity timeout, reset on every successful read, so a mainnet
/// `BeaconState` of a few hundred megabytes can download for as long as bytes
/// keep arriving. A total timeout would kill a healthy slow transfer.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

const FINALIZED_BLOCK_PATH: &str = "/eth/v2/beacon/blocks/finalized";
const STATES_PATH_PREFIX: &str = "/eth/v2/debug/beacon/states/";

/// The Beacon API's fork tag on an SSZ response. Required by the API spec for
/// v2 SSZ responses, but proxies do strip headers, hence the fallback below.
const CONSENSUS_VERSION_HEADER: &str = "eth-consensus-version";

/// Byte offset of `BeaconState.slot`.
///
/// The state's first two fields are fixed-size and identical in every fork:
/// `genesis_time` (8 bytes) then `genesis_validators_root` (32). So the slot
/// is readable without knowing the fork, which is what breaks the circular
/// dependency between "which fork is this" and "decode it".
const STATE_SLOT_OFFSET: usize = 40;

/// Byte offset of `SignedBeaconBlock.message`'s own offset word.
///
/// `SignedBeaconBlock` is `(message: BeaconBlock, signature: BlsSignature)`.
/// `message` is variable-size, so the container starts with its 4-byte offset;
/// `BeaconBlock`'s own first field is `slot`, so the slot sits at that offset.
const BLOCK_MESSAGE_OFFSET_AT: usize = 0;

#[derive(Debug, thiserror::Error)]
pub enum BeaconCheckpointError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("SSZ deserialization failed: {0}")]
    SszDecode(String),
    #[error("response is too short to read a slot from ({0} bytes)")]
    ResponseTooShort(usize),
    #[error("unknown consensus version '{0}'")]
    UnknownConsensusVersion(String),
    #[error("anchor state is at slot 0; the chain has not finalized anything yet")]
    AnchorIsGenesis,
    #[error("anchor state fork {state} does not match anchor block fork {block}")]
    ForkMismatch { state: String, block: String },
    #[error("anchor block slot {block} does not match anchor state slot {state}")]
    SlotMismatch { state: Slot, block: Slot },
    #[error("anchor block state_root does not match the fetched state's tree hash root")]
    AnchorPairMismatch,
    #[error("anchor state carries a zero genesis_validators_root")]
    ZeroGenesisValidatorsRoot,
    #[error("no checkpoint sync url configured")]
    NoCheckpointUrl,
}

/// A verified checkpoint-sync anchor: a finalized block and its own post-state.
pub struct BeaconAnchor {
    pub state: BeaconState,
    pub block: SignedBeaconBlock,
}

impl BeaconAnchor {
    /// The value the fork digest, and therefore every topic name, ENR `eth2`
    /// entry and discv5 admission decision, is derived from.
    pub fn genesis_validators_root(&self) -> Root {
        self.state.genesis_validators_root()
    }

    pub fn genesis_time(&self) -> u64 {
        self.state.genesis_time()
    }

    pub fn slot(&self) -> Slot {
        self.state.slot()
    }
}

/// Strip a trailing slash so `{base}{path}` never doubles one.
fn normalize_base_url(url: &str) -> &str {
    url.trim_end_matches('/')
}

/// The state endpoint for one state root.
///
/// The root is hex-encoded by hand rather than formatted: `ethereum_types`'
/// `Display` abbreviates a 32-byte hash to `0x1234…5678`, which would produce a
/// URL that looks plausible and 404s.
fn state_url(base: &str, state_root: Root) -> String {
    format!("{base}{STATES_PATH_PREFIX}0x{}", hex::encode(state_root.0))
}

/// The fork an SSZ response should be decoded as.
///
/// Prefers the `Eth-Consensus-Version` header, which the Beacon API requires on
/// SSZ responses. Falls back to the fork the config schedules for the slot read
/// out of the payload at `slot_offset`, so a header-stripping proxy is an
/// inconvenience rather than a failure.
fn fork_for_response(
    header: Option<&str>,
    body: &[u8],
    slot_offset: usize,
    config: &Config,
) -> Result<ForkName, BeaconCheckpointError> {
    if let Some(name) = header {
        let lowered = name.trim().to_ascii_lowercase();
        return ForkName::parse(&lowered)
            .ok_or_else(|| BeaconCheckpointError::UnknownConsensusVersion(name.to_string()));
    }
    let slot = read_u64_le(body, slot_offset)?;
    Ok(config.fork_at_epoch(slot / SLOTS_PER_EPOCH))
}

fn read_u64_le(body: &[u8], offset: usize) -> Result<u64, BeaconCheckpointError> {
    let end = offset
        .checked_add(8)
        .ok_or(BeaconCheckpointError::ResponseTooShort(body.len()))?;
    let bytes: [u8; 8] = body
        .get(offset..end)
        .ok_or(BeaconCheckpointError::ResponseTooShort(body.len()))?
        .try_into()
        .expect("the slice is exactly eight bytes long");
    Ok(u64::from_le_bytes(bytes))
}

/// Byte offset of `BeaconBlock.slot` inside a `SignedBeaconBlock`'s SSZ.
fn block_slot_offset(body: &[u8]) -> Result<usize, BeaconCheckpointError> {
    let end = BLOCK_MESSAGE_OFFSET_AT + 4;
    let bytes: [u8; 4] = body
        .get(BLOCK_MESSAGE_OFFSET_AT..end)
        .ok_or(BeaconCheckpointError::ResponseTooShort(body.len()))?
        .try_into()
        .expect("the slice is exactly four bytes long");
    Ok(u32::from_le_bytes(bytes) as usize)
}

/// Every check that must hold before this anchor is written to disk.
///
/// The `state_root` comparison merkleizes the whole state, which on mainnet is
/// a few seconds of SHA-256. The store constructor will do it again; paying it
/// twice at startup is worth having the pair rejected here, where the error
/// names the provider, rather than inside the store constructor.
pub fn verify_beacon_anchor(anchor: &BeaconAnchor) -> Result<(), BeaconCheckpointError> {
    if anchor.state.slot() == 0 {
        return Err(BeaconCheckpointError::AnchorIsGenesis);
    }
    if anchor.state.fork_name() != anchor.block.fork_name() {
        return Err(BeaconCheckpointError::ForkMismatch {
            state: anchor.state.fork_name().as_str().to_string(),
            block: anchor.block.fork_name().as_str().to_string(),
        });
    }
    if anchor.state.slot() != anchor.block.slot() {
        return Err(BeaconCheckpointError::SlotMismatch {
            state: anchor.state.slot(),
            block: anchor.block.slot(),
        });
    }
    if anchor.block.state_root() != anchor.state.hash_tree_root() {
        return Err(BeaconCheckpointError::AnchorPairMismatch);
    }
    if anchor.state.genesis_validators_root().is_zero() {
        return Err(BeaconCheckpointError::ZeroGenesisValidatorsRoot);
    }
    Ok(())
}

fn build_client() -> Result<Client, BeaconCheckpointError> {
    Ok(Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .build()?)
}

/// Fetch an SSZ body together with its `Eth-Consensus-Version` header.
async fn fetch_ssz(
    client: &Client,
    url: &str,
) -> Result<(Option<String>, Vec<u8>), BeaconCheckpointError> {
    let response = client
        .get(url)
        .header("Accept", "application/octet-stream")
        .send()
        .await?
        .error_for_status()?;
    let version = response
        .headers()
        .get(CONSENSUS_VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response.bytes().await?.to_vec();
    Ok((version, body))
}

/// Fetch and verify the anchor pair from one provider.
pub async fn fetch_beacon_anchor(
    url: &str,
    config: &Config,
) -> Result<BeaconAnchor, BeaconCheckpointError> {
    let base = normalize_base_url(url);
    let client = build_client()?;

    let block_url = format!("{base}{FINALIZED_BLOCK_PATH}");
    let (block_version, block_body) = fetch_ssz(&client, &block_url).await?;
    let block_fork = fork_for_response(
        block_version.as_deref(),
        &block_body,
        block_slot_offset(&block_body)?,
        config,
    )?;
    let block = SignedBeaconBlock::from_ssz(block_fork, &block_body)
        .map_err(|err| BeaconCheckpointError::SszDecode(format!("{err:?}")))?;

    let url = state_url(base, block.state_root());
    let (state_version, state_body) = fetch_ssz(&client, &url).await?;
    let state_fork = fork_for_response(
        state_version.as_deref(),
        &state_body,
        STATE_SLOT_OFFSET,
        config,
    )?;
    let state = BeaconState::from_ssz(state_fork, &state_body)
        .map_err(|err| BeaconCheckpointError::SszDecode(format!("{err:?}")))?;

    let anchor = BeaconAnchor { state, block };
    verify_beacon_anchor(&anchor)?;
    Ok(anchor)
}

/// Try each url in order, returning the first verified anchor.
pub async fn fetch_beacon_anchor_from_any(
    urls: &[String],
    config: &Config,
) -> Result<BeaconAnchor, BeaconCheckpointError> {
    let mut last_err: Option<BeaconCheckpointError> = None;
    for url in urls {
        match fetch_beacon_anchor(url, config).await {
            Ok(anchor) => {
                info!(
                    %url,
                    anchor_slot = anchor.slot(),
                    fork = anchor.state.fork_name().as_str(),
                    "Beacon checkpoint sync successful with this provider"
                );
                return Ok(anchor);
            }
            Err(err) => {
                warn!(%url, %err, "Beacon checkpoint sync failed for this provider");
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap_or(BeaconCheckpointError::NoCheckpointUrl))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mainnet() -> Config {
        Config::mainnet()
    }

    #[test]
    fn normalize_trims_one_trailing_slash() {
        assert_eq!(
            normalize_base_url("https://beaconstate.info/"),
            "https://beaconstate.info"
        );
        assert_eq!(
            normalize_base_url("https://beaconstate.info"),
            "https://beaconstate.info"
        );
    }

    #[test]
    fn the_state_url_carries_the_full_root() {
        // `ethereum_types`' Display abbreviates to `0x1234…5678`, which would
        // build a URL that looks right and 404s on every provider.
        let url = state_url("https://beaconstate.info", Root::repeat_byte(0xab));

        assert_eq!(
            url,
            format!(
                "https://beaconstate.info/eth/v2/debug/beacon/states/0x{}",
                "ab".repeat(32)
            )
        );
        assert!(!url.contains('…'));
    }

    #[test]
    fn the_consensus_version_header_decides_the_fork() {
        // The body is never read when the header is present, so an empty one
        // is enough to prove the header alone answers the question.
        let fork = fork_for_response(Some("fulu"), &[], STATE_SLOT_OFFSET, &mainnet()).unwrap();
        assert_eq!(fork, ForkName::Fulu);
    }

    #[test]
    fn the_consensus_version_header_is_case_insensitive() {
        // Not every provider lowercases it, and `ForkName::parse` matches the
        // spec's own lowercase names exactly.
        let fork = fork_for_response(Some("Electra"), &[], STATE_SLOT_OFFSET, &mainnet()).unwrap();
        assert_eq!(fork, ForkName::Electra);
    }

    #[test]
    fn an_unknown_consensus_version_is_an_error_not_a_guess() {
        let err = fork_for_response(Some("gloas"), &[], STATE_SLOT_OFFSET, &mainnet())
            .expect_err("a fork this crate does not implement cannot be decoded");
        assert!(matches!(
            err,
            BeaconCheckpointError::UnknownConsensusVersion(_)
        ));
    }

    #[test]
    fn a_missing_header_falls_back_to_the_slot_in_the_payload() {
        // A state body whose first 40 bytes are the two fixed-size fields, then
        // a slot inside fulu's range. Nothing past the slot is read.
        let config = mainnet();
        let fulu_slot = config.fulu_fork_epoch * SLOTS_PER_EPOCH;
        let mut body = vec![0u8; STATE_SLOT_OFFSET + 8];
        body[STATE_SLOT_OFFSET..].copy_from_slice(&fulu_slot.to_le_bytes());

        let fork = fork_for_response(None, &body, STATE_SLOT_OFFSET, &config).unwrap();
        assert_eq!(fork, ForkName::Fulu);
    }

    #[test]
    fn a_missing_header_and_a_truncated_body_is_an_error() {
        let body = vec![0u8; STATE_SLOT_OFFSET];
        let err = fork_for_response(None, &body, STATE_SLOT_OFFSET, &mainnet())
            .expect_err("there is no slot to read");
        assert!(matches!(err, BeaconCheckpointError::ResponseTooShort(_)));
    }

    #[test]
    fn the_block_slot_offset_is_read_from_the_containers_offset_word() {
        // A `SignedBeaconBlock` starts with the 4-byte offset of `message`.
        // 100 = 4 (the offset word) + 96 (the signature).
        let mut body = vec![0u8; 108];
        body[0..4].copy_from_slice(&100u32.to_le_bytes());
        assert_eq!(block_slot_offset(&body).unwrap(), 100);
    }

    #[tokio::test]
    async fn an_unreachable_provider_is_reported_not_ignored() {
        // Loopback port 1 refuses immediately, so this never touches a network.
        let urls = ["http://127.0.0.1:1".to_string()];
        let err = fetch_beacon_anchor_from_any(&urls, &mainnet())
            .await
            .err()
            .expect("an unreachable provider cannot produce an anchor");
        assert!(matches!(err, BeaconCheckpointError::Http(_)), "got {err}");
    }

    #[tokio::test]
    async fn an_empty_url_list_is_its_own_error() {
        let err = fetch_beacon_anchor_from_any(&[], &mainnet())
            .await
            .err()
            .expect("no urls means no anchor");
        assert!(matches!(err, BeaconCheckpointError::NoCheckpointUrl));
    }
}
