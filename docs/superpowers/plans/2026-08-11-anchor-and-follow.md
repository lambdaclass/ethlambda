# Anchor and Follow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take `ethlambda beacon` from a checkpoint-sync anchor to the live mainnet head and keep it there: fetch the anchor before the swarm exists, close the anchor-to-head gap with `beacon_blocks_by_range/2`, buffer gossip blocks that arrive on a parent the store does not have yet, and keep the head within a slot of wall clock afterwards.

**Architecture:** Nothing here is a new sync engine. The session state is lean's existing `RangeSyncState` in `crates/net/p2p/src/lib.rs`, given a per-network batch cap; three small pure functions in a new `beacon/range_sync.rs` turn it into a beacon session, and a new `beacon/sync.rs` is the actor wiring around them. The parent-missing case mirrors lean's `pending_blocks` cascade in `BlockChainServer`, extracted into a testable `PendingBeaconBlocks` buffer. Checkpoint sync fetches the block first and the state by that block's `state_root`, which makes the anchor pair consistent by construction rather than by retry.

**Tech Stack:** Rust 1.97.1 (edition 2024), libp2p (request-response over QUIC), `spawned-concurrency` actors, `reqwest` for the Beacon API, `libssz` / `libssz-merkle`, prometheus via `ethlambda-metrics`.

---

## Plan series

This is plan 5 of 5 for sub-projects A1 and A2 of
`docs/superpowers/specs/2026-08-10-mainnet-network-design.md`. Each plan ends
with a working, testable tree.

| # | Plan | Ends when |
|---|---|---|
| 1 | Beacon type unification | Types live in `ethlambda-types`, `BeaconState::Lean` exists, every fixture suite green |
| 2 | CLI subcommands | `ethlambda lean` and `ethlambda beacon` parse, bare flags still resolve to `lean`, devnet unchanged |
| 3 | Beacon handlers on the DB-backed `Store`, and the `BlockChainServer` variant dispatch (spec §4, §5) | `fork_choice::Store` deleted, all 150 `fork_choice` fixture cases green against `ethlambda_storage::Store` |
| 4 | Mainnet wire | Node peers with mainnet, decodes a `beacon_block` within ~30s |
| 5 | **Anchor and follow** (this plan) | Checkpoint sync, anchor-to-head range fetch, head tracks wall clock |

**Plans 2, 3 and 4 must be complete before this one starts.** This plan calls
their output directly: the `beacon` subcommand's entry point (2), the beacon
fork-choice handlers over `ethlambda_storage::Store` (3), and the beacon gossip
topics, req/resp protocol ids and fork digest (4).

---

## Assumed surface from plans 2 to 4

Task 1 verifies every row below before any code is written. These names are used
verbatim throughout this plan. **If a name differs, rename it in this plan and
carry on: every row is a naming difference, not a design difference.** If a
whole *capability* is missing rather than renamed, the task that needs it says
so in its own preamble.

| Item | Assumed path and shape | Owner |
|---|---|---|
| Beacon subcommand entry | `bin/ethlambda/src/beacon_node.rs`, `pub async fn run_beacon(options: cli::BeaconOptions, rpc_config: RpcConfig) -> eyre::Result<()>` | 2 |
| Beacon CLI options | `cli::BeaconOptions` with `checkpoint_sync_url: Vec<String>`, `data_dir`, `node_key`, `node_id`, `gossipsub_port`, `bootnodes: Option<PathBuf>`, `discovery` | 2 |
| Anchor store constructor | `ethlambda_storage::Store::get_forkchoice_store(backend, anchor_state: BeaconState, anchor_block: SignedBeaconBlock, config: &Config) -> Result<Store, _>` | 3 |
| State presence | `ethlambda_storage::Store::has_state(&self, root: &H256) -> Result<bool, Error>` (unchanged from today) | pre-existing |
| Head slot | `ethlambda_storage::Store::head_slot(&self) -> u64` (unchanged from today) | pre-existing |
| Beacon handlers | `ethlambda_beacon::fork_choice::{on_tick, on_block, on_attestation, on_attester_slashing, get_head}`, each taking `&mut ethlambda_storage::Store` | 3 |
| Beacon block handler on the actor | `BlockChainServer::on_beacon_block(&mut self, block: SignedBeaconBlock)` in `crates/blockchain/src/lib.rs` | 3 |
| Beacon block ingress message | `ethlambda_network_api::P2PToBlockChain::new_beacon_block(&self, block: SignedBeaconBlock, source: BlockSource) -> Result<(), ActorError>` | 3 |
| Fork digest | `ethlambda_p2p::beacon::fork_digest::compute_fork_digest(config: &Config, genesis_validators_root: Root, epoch: Epoch) -> [u8; 4]` | 4 |
| Beacon req/resp ids | `ethlambda_p2p::beacon::req_resp::{BEACON_STATUS_PROTOCOL_V2, BEACON_BLOCKS_BY_RANGE_PROTOCOL_V2, BEACON_BLOCKS_BY_ROOT_PROTOCOL_V2}` | 4 |
| Beacon req/resp types | `ethlambda_p2p::beacon::req_resp::{BeaconStatus { head_slot, .. }, BeaconBlocksByRangeRequest { start_slot: u64, count: u64 }, BeaconBlocksByRootRequest { roots: BeaconRequestedBlockRoots }, BeaconRequestedBlockRoots}` (an `SszList<Root, _>` with `new` and `push`, like lean's `RequestedBlockRoots`) | 4 |
| Swarm-level variants | `Request::{BeaconStatus, BeaconBlocksByRange, BeaconBlocksByRoot}` and `ResponsePayload::{BeaconStatus, BeaconBlocks(Vec<SignedBeaconBlock>)}` in `crates/net/p2p/src/req_resp/messages.rs` | 4 |
| Beacon p2p module root | `crates/net/p2p/src/beacon/mod.rs` | 4 |

`BeaconBlocksByRangeRequest` is `{ start_slot, count }` with no `step`: `step`
was in `beacon_blocks_by_range/1` and was removed in `/2`. If plan 4 kept a
deprecated `step` field, set it to `1` at the one construction site in Task 6.

### What plan 3 owns and this plan does not

Spec §9's "driving the handlers" is split across the two plans, and this plan
touches only the second half:

| Piece of §9 | Owner |
|---|---|
| `on_tick`, `on_attestation`, `on_attester_slashing` bodies and their dispatch | 3 |
| Block-borne `on_attestation(.., is_from_block = true)` per attestation | 3 |
| `ExecutionEngine::valid()` and `DataAvailability::NotRequired`, and logging both stubs at startup | 3 |
| The slot clock that fires the beacon tick | 3 |
| The **order** blocks reach `on_block` in, and what happens when the parent is missing | **5** |
| `get_head`'s result reaching metrics and the sync status | **5** |

---

## File structure

| File | Responsibility |
|---|---|
| `crates/common/types/src/primitives.rs` | **Modify.** `From` impls between the beacon `Root` and the lean `H256`: same 32 bytes, two types, and every store lookup crosses the line |
| `crates/net/p2p/src/lib.rs` | **Modify.** `RangeSyncState` gains a per-network batch cap; `P2PServer` gains the beacon session, the peer-head table and the beacon by-root request table; `PendingRequestKind` gains two beacon variants |
| `crates/net/p2p/src/beacon/mod.rs` | **Modify.** Declare `range_sync` and `sync` |
| `crates/net/p2p/src/beacon/range_sync.rs` | **Create.** Pure: gap computation, best-peer selection, session open/merge, request construction at the range limits. Every deterministic range test lives here |
| `crates/net/p2p/src/beacon/sync.rs` | **Create.** Actor wiring: status responses open or extend a session, block responses complete a batch and request the next, failures rotate peers, a timer re-arms the session, and a still-orphaned block is fetched by root |
| `crates/net/p2p/src/req_resp/handlers.rs` | **Modify.** Route the beacon response variants to `beacon::sync` |
| `crates/net/api/src/lib.rs` | **Modify.** `BlockChainToP2P::fetch_beacon_block(root)` |
| `crates/blockchain/src/beacon_pending.rs` | **Create.** Parent-keyed buffer for gossip blocks whose parent is not in the store; deepest-missing-ancestor resolution; slot-ordered drain; the tip-only regression test |
| `crates/blockchain/src/lib.rs` | **Modify.** Declare `beacon_pending`; the beacon block handler buffers instead of dropping, and cascades on import |
| `crates/blockchain/src/metrics.rs` | **Modify.** `lean_sync_anchor_slot`, `lean_sync_pending_blocks`, `lean_sync_pending_dropped_total`, `lean_sync_range_blocks_total` |
| `crates/beacon/src/fork_choice.rs` | **Modify.** One test: `on_block` refuses a block whose parent is not in the store |
| `bin/ethlambda/src/beacon_checkpoint.rs` | **Create.** Beacon API checkpoint sync: block first, state by that block's `state_root`, fork from `Eth-Consensus-Version` with a slot-offset fallback, anchor verification |
| `bin/ethlambda/src/beacon_node.rs` | **Modify.** Startup order: anchor, then fork digest, then swarm |
| `docs/beacon_sync.md` | **Create.** Operator reference: startup order, what the metrics mean, the manual verification procedure |
| `docs/SUMMARY.md` | **Modify.** Link the new page |
| `docs/checkpoint_sync.md` | **Modify.** Point at the beacon variant |

---

## Why `RangeSyncState` is reused rather than replaced

`crates/net/p2p/src/lib.rs:82-143` already solves the problem this plan needs
solved, and solves it in a way that is not lean-specific:

| `RangeSyncState` behaviour | Needed for the beacon anchor-to-head fetch? |
|---|---|
| `current_range: Range<u64>` of slots, exclusive end | Yes, identically |
| `peer_set: HashMap<PeerId, u64>` of advertised heads | Yes: beacon `Status` carries `head_slot` too |
| `in_flight` allowing one batch at a time | Yes: the same backpressure, so a slow peer cannot be handed the whole gap |
| `next_batch` picking the highest-head peer that covers the range start | Yes, identically |
| `complete_batch` advancing the range start past what arrived | Yes, identically |
| `fail_peer` dropping a peer and clearing `in_flight` | Yes: this *is* the retry and peer-rotation path |
| `drop_stale_peers` evicting peers that fell behind the range | Yes, identically |

Exactly one thing is lean-specific: `next_batch` clamps the batch to lean's
`MAX_REQUEST_BLOCKS` (1024). `beacon_blocks_by_range/2` has been capped at
`MAX_REQUEST_BLOCKS_DENEB` (128) since deneb. That becomes a field, defaulted to
lean's value by the existing `new`, so no lean call site or lean test changes.

Two beacon-only behaviours sit *around* the state rather than inside it, so they
are free functions in `beacon/range_sync.rs` and do not fork the type:

- the request that goes on the wire is `BeaconBlocksByRangeRequest`, not lean's
  `BlocksByRangeRequest`;
- the session is re-armed from a timer, not only from a peer's first `Status`.
  Lean opens a session on a status response and never reopens it; a beacon
  follower that must *stay* at the head needs a periodic check, or a session
  whose peers all failed is the end of syncing for that process.

---

## What "done" means, and which half is automated

| Requirement (spec §6, §9) | How it is proven | Automated? |
|---|---|---|
| Gap computation from anchor to peer head | `forward_sync_range` tests, Task 5 | Yes, `make test` |
| Batch construction at the range limits | `next_request` tests, Task 6 | Yes, `make test` |
| Retry and peer rotation | `fail_peer` rotation tests, Task 6 | Yes, `make test` |
| A block whose parent is missing is not imported | `on_block` test, Task 9 | Yes, `make test-beacon` |
| A tip-tracking follower that never backfills fails | `tip_blocks_are_not_importable_until_the_gap_is_filled`, Task 8 | Yes, `make test` |
| Buffered gossip applies in slot order once the parent lands | same test, Task 8 | Yes, `make test` |
| A block still orphaned after the range fetch is fetched by root | `beacon::sync` tests, Task 11 | Yes, `make test` |
| Anchor pair is consistent; fork read from the response | `beacon_checkpoint` tests, Task 2 | Yes, `make test` |
| Checkpoint sync runs *before* the swarm | Task 3's ordering test | Yes, `make test` |
| Node peers with mainnet and closes a real ~64-slot gap | Manual procedure, Task 14 | **No** |
| Head stays within one slot of wall clock | Manual procedure, Task 14 | **No** |
| Finalization advances past the anchor | Manual procedure, Task 14 | **No** |

The last three are live-network properties. No test in this repository can
assert them, because they depend on mainnet peers being reachable and on the
chain finalizing. Task 14 makes them a written, reproducible procedure with
exact commands, exact metric names, and an explicit wait time, so "healthy" is a
check rather than a judgement.

---

## Task 1: Baseline and surface check

**Files:** none modified.

- [ ] **Step 1: Confirm the branch and that plans 1 to 4 landed**

```bash
git branch --show-current
git log --oneline -20
```

Expected: branch `feat/mainnet-network`, with commits from plans 2, 3 and 4 in
the log. If plan 4's commits are absent, stop: this plan cannot run.

- [ ] **Step 2: Record the green baseline**

```bash
make fmt && git diff --stat
make lint
make test
make test-beacon
```

Expected: `make fmt` leaves no diff; `make lint` prints no warnings; `make test`
passes; `make test-beacon` passes both presets with `mainnet 5705 fixture cases,
152 ignored` and `minimal 40009 fixture cases, 3692 ignored`. Record the numbers;
every later task compares against them.

- [ ] **Step 3: Check every assumed name**

```bash
grep -rn "pub async fn run_beacon" bin/ethlambda/src/
grep -rn "fn get_forkchoice_store" crates/storage/src/store.rs
grep -rn "pub fn on_block\|pub fn on_tick\|pub fn get_head" crates/beacon/src/fork_choice.rs
grep -rn "fn on_beacon_block" crates/blockchain/src/lib.rs
grep -rn "fn new_beacon_block" crates/net/api/src/lib.rs
grep -rn "compute_fork_digest" crates/net/p2p/src/
grep -rn "BEACON_BLOCKS_BY_RANGE_PROTOCOL_V2\|BeaconBlocksByRangeRequest\|BeaconStatus" crates/net/p2p/src/
grep -rn "BeaconBlocks(" crates/net/p2p/src/req_resp/messages.rs
ls crates/net/p2p/src/beacon/
```

Expected: every grep prints at least one hit. Write down the exact spelling of
any that differs from the "Assumed surface" table and use that spelling for the
rest of this plan.

- [ ] **Step 4: Check whether the root conversion already exists**

```bash
grep -n "beacon::primitives::Root> for H256\|H256> for .*beacon::primitives::Root\|ethereum_types::H256> for H256" crates/common/types/src/primitives.rs
```

Expected: no output, meaning Task 4 adds them. Output here means plan 3 added
them already and Task 4 is a no-op; note that now.

Nothing to commit: this task only verifies.

---

## Task 2: Beacon checkpoint sync client

**Files:**
- Create: `bin/ethlambda/src/beacon_checkpoint.rs`
- Modify: `bin/ethlambda/src/main.rs`
- Test: `bin/ethlambda/src/beacon_checkpoint.rs`

The Beacon API is fetched in an order that makes the anchor pair consistent by
construction, which lean's client cannot do:

```
GET {base}/eth/v2/beacon/blocks/finalized          -> SignedBeaconBlock
       └─ block.state_root  (the root of this block's OWN post-state)
          └─ GET {base}/eth/v2/debug/beacon/states/0x{state_root}  -> BeaconState
```

Lean fetches state and block concurrently and retries when the peer advances
finalization between the two (`try_checkpoint_url` in
`bin/ethlambda/src/checkpoint_sync.rs:253`). Here the second request is
content-addressed by the first's `state_root`, so there is no race and no retry
loop: either the provider has that state or it does not.

- [ ] **Step 1: Write the failing tests**

Create `bin/ethlambda/src/beacon_checkpoint.rs`:

```rust
//! Checkpoint sync for `ethlambda beacon`, against a Beacon API provider.
//!
//! Distinct from `crate::checkpoint_sync`, which speaks lean's `/lean/v0/…`
//! endpoints and lean's `State`. The two share the idea and nothing else: the
//! paths, the SSZ types, the fork-versioning problem and the ordering are all
//! different.
//!
//! The anchor pair is fetched block-first. `block.state_root` is the root of
//! that block's own post-state, so fetching the state *by that root* returns
//! exactly the state the block commits to. `get_forkchoice_store`'s
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
/// a few seconds of SHA-256. `get_forkchoice_store` will do it again; paying it
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
async fn fetch_ssz(client: &Client, url: &str) -> Result<(Option<String>, Vec<u8>), BeaconCheckpointError> {
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
            format!("https://beaconstate.info/eth/v2/debug/beacon/states/0x{}", "ab".repeat(32))
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda --profile release-fast beacon_checkpoint`
Expected: FAIL, `file not found for module 'beacon_checkpoint'` — the module is
not declared yet.

- [ ] **Step 3: Declare the module**

Add to `bin/ethlambda/src/main.rs`, immediately after `mod checkpoint_sync;`:

```rust
mod beacon_checkpoint;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda --profile release-fast beacon_checkpoint`
Expected: PASS, 10 tests.

- [ ] **Step 5: Verify the suites**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "feat(beacon): checkpoint sync against a Beacon API provider

Fetches the finalized block first and then the state by that block's own
state_root, so get_forkchoice_store's state_root assertion holds by
construction. Lean's client fetches both concurrently and retries when the
peer advances finalization between them; a content-addressed second fetch
has no such race to retry.

The fork comes from Eth-Consensus-Version, falling back to the slot read
out of the payload at its fixed offset: the state's first two fields are
fixed-size in every fork, which is what breaks the circle between knowing
the fork and decoding the body."
```

---

## Task 3: Checkpoint sync runs before the swarm

**Files:**
- Modify: `bin/ethlambda/src/beacon_node.rs`
- Test: `bin/ethlambda/src/beacon_node.rs`

The ordering is a requirement, not an implementation detail (spec §6): the fork
digest needs `genesis_validators_root` and `genesis_time`, and both are read off
the anchor state. That is why no mainnet genesis-validators-root constant exists
anywhere in this repository, and why `--checkpoint-sync-url` is required on the
`beacon` subcommand rather than optional as it is on `lean`. Building the swarm
first would mean either hardcoding those two values or subscribing to topics
whose names are not yet known.

The ordering is enforced by shape rather than by a comment: the swarm is built
from a `BeaconNetworkParams` value that only `beacon_network_params` produces,
and that function takes the anchor. There is no way to reach `build_swarm`
without one.

**The epoch the digest is computed for is the wall-clock epoch, not the
anchor's.** The spec is explicit: `epoch = (now - genesis_time) / (seconds_per_slot
* SLOTS_PER_EPOCH)`. The anchor is two epochs behind, so if a fork or
blob-parameter boundary falls between the anchor's epoch and now, the anchor's
epoch yields the *previous* digest and the node joins topics the network has
already left. The anchor supplies `genesis_validators_root` and `genesis_time`;
the clock supplies the epoch.

- [ ] **Step 1: Write the failing tests**

Add to `bin/ethlambda/src/beacon_node.rs`, at the bottom of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::primitives::Root;

    /// Seconds since genesis that put the clock at the first slot of `epoch`.
    fn now_at_epoch(config: &Config, genesis_time: u64, epoch: u64) -> u64 {
        genesis_time + epoch * SLOTS_PER_EPOCH * config.seconds_per_slot
    }

    /// The digest is a function of values that exist only after the anchor is
    /// in hand, so the type carrying the swarm's inputs cannot be built without
    /// one. This fails to compile, not merely to assert, if
    /// `beacon_network_params` ever stops taking the anchor's fields.
    #[test]
    fn network_params_are_derived_from_the_anchor_and_the_clock() {
        let config = Config::mainnet();
        let gvr = Root::repeat_byte(0x2a);
        let genesis_time = 1_606_824_023;
        let now = now_at_epoch(&config, genesis_time, config.fulu_fork_epoch);

        let params = beacon_network_params(&config, gvr, genesis_time, now);

        assert_eq!(params.genesis_validators_root, gvr);
        assert_eq!(params.genesis_time, genesis_time);
        assert_eq!(params.digest_epoch, config.fulu_fork_epoch);
        assert_eq!(
            params.fork_digest,
            ethlambda_p2p::beacon::fork_digest::compute_fork_digest(
                &config,
                gvr,
                config.fulu_fork_epoch,
            )
        );
    }

    /// The clock decides the epoch, not the anchor. The anchor is two epochs
    /// behind the head; if a blob-parameter boundary sits in between, using the
    /// anchor's epoch would join the topics the network has already left.
    #[test]
    fn the_digest_follows_the_wall_clock_across_a_boundary() {
        let config = Config::mainnet();
        let gvr = Root::repeat_byte(0x2a);
        let genesis_time = 1_606_824_023;
        let boundary = config.blob_schedule[1].epoch;

        let before = beacon_network_params(
            &config,
            gvr,
            genesis_time,
            now_at_epoch(&config, genesis_time, boundary - 1),
        );
        let after = beacon_network_params(
            &config,
            gvr,
            genesis_time,
            now_at_epoch(&config, genesis_time, boundary),
        );

        assert_ne!(
            before.fork_digest, after.fork_digest,
            "a blob-parameter boundary changes the digest, so the epoch it is \
             computed for has to be the current one"
        );
    }

    /// A different chain must produce a different digest: the digest is not a
    /// constant that happens to be recomputed.
    #[test]
    fn a_different_genesis_validators_root_changes_the_digest() {
        let config = Config::mainnet();
        let now = now_at_epoch(&config, 0, config.fulu_fork_epoch);

        let one = beacon_network_params(&config, Root::repeat_byte(1), 0, now);
        let two = beacon_network_params(&config, Root::repeat_byte(2), 0, now);

        assert_ne!(one.fork_digest, two.fork_digest);
    }

    /// Startup names the next boundary so a digest going stale under a running
    /// node is diagnosable from the boot log rather than from zero peers.
    #[test]
    fn the_next_boundary_is_the_soonest_scheduled_change() {
        let config = Config::mainnet();
        let boundary = config.blob_schedule[0].epoch;

        assert_eq!(next_digest_boundary(&config, boundary - 1), Some(boundary));
        assert_eq!(
            next_digest_boundary(&config, boundary),
            Some(config.blob_schedule[1].epoch),
            "standing exactly on a boundary, the next one is the one after"
        );
        assert_eq!(
            next_digest_boundary(&config, u64::MAX - 1),
            None,
            "past every scheduled change there is nothing left to warn about"
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda --profile release-fast network_params_are_derived`
Expected: FAIL, `cannot find function 'beacon_network_params' in this scope`.

- [ ] **Step 3: Add the type and the two functions**

Add near the top of `bin/ethlambda/src/beacon_node.rs`, after the imports
(`std::time::SystemTime` too, which Step 5 needs and plan 2's file may not have):

```rust
use std::time::SystemTime;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::Root;

/// Every network parameter that cannot be known before the anchor is fetched.
///
/// Exists to make the startup order structural: `build_swarm` is reachable only
/// through a value of this type, only [`beacon_network_params`] produces one,
/// and it takes the anchor's own fields. See the spec's "Startup order and the
/// fork digest".
pub(crate) struct BeaconNetworkParams {
    pub(crate) fork_digest: [u8; 4],
    pub(crate) genesis_validators_root: Root,
    pub(crate) genesis_time: u64,
    /// The epoch the digest was computed for: the wall-clock epoch at startup,
    /// not the anchor's. Logged so a boundary crossed while running is
    /// diagnosable from the boot log.
    pub(crate) digest_epoch: u64,
}

/// Derive the swarm's network parameters.
///
/// `genesis_validators_root` and `genesis_time` come off the checkpoint anchor;
/// the epoch comes off the clock. The anchor is roughly two epochs behind the
/// head, so computing the digest for *its* epoch would put this node on the
/// previous side of any fork or blob-parameter boundary crossed in between.
pub(crate) fn beacon_network_params(
    config: &Config,
    genesis_validators_root: Root,
    genesis_time: u64,
    now_unix_secs: u64,
) -> BeaconNetworkParams {
    let seconds_per_epoch = config.seconds_per_slot * SLOTS_PER_EPOCH;
    let digest_epoch = now_unix_secs.saturating_sub(genesis_time) / seconds_per_epoch;
    BeaconNetworkParams {
        fork_digest: ethlambda_p2p::beacon::fork_digest::compute_fork_digest(
            config,
            genesis_validators_root,
            digest_epoch,
        ),
        genesis_validators_root,
        genesis_time,
        digest_epoch,
    }
}

/// The soonest scheduled epoch after `epoch` at which the fork digest changes.
///
/// Both kinds of change count: a fork activation and a blob-schedule entry,
/// since fulu's `compute_fork_digest` mixes the active blob parameters in.
/// `None` past every scheduled change, which is where mainnet's far-future
/// forks leave it today.
pub(crate) fn next_digest_boundary(config: &Config, epoch: u64) -> Option<u64> {
    ForkName::ALL
        .into_iter()
        .map(|fork| config.fork_epoch(fork))
        .chain(config.blob_schedule.iter().map(|entry| entry.epoch))
        .filter(|candidate| *candidate != FAR_FUTURE_EPOCH && *candidate > epoch)
        .min()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda --profile release-fast beacon_node`
Expected: PASS, 4 tests.

- [ ] **Step 5: Put the anchor ahead of the swarm in `run_beacon`**

In `bin/ethlambda/src/beacon_node.rs`, inside `run_beacon`, place these steps
*before* the existing `build_swarm` call and pass `params` into it:

```rust
    let config = Config::mainnet();

    let checkpoint_urls: Vec<String> = options
        .checkpoint_sync_url
        .iter()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect();
    // clap already marks the flag required, so this catches only the empty
    // string, which a shell expanding an unset variable produces easily.
    eyre::ensure!(
        !checkpoint_urls.is_empty(),
        "ethlambda beacon requires --checkpoint-sync-url: the fork digest is \
         derived from the anchor state's genesis_validators_root, so there is \
         no network to join without one"
    );

    // Before the swarm, deliberately: `genesis_validators_root` and
    // `genesis_time` are read off the anchor, and the fork digest computed from
    // them names every gossip topic, the ENR `eth2` entry and the discv5
    // admission test. Nothing about the network is knowable earlier.
    //
    // This runs on every boot, including a restart against a populated data
    // directory. Reading the two values back off disk instead would let a
    // restart skip the download, but the resume decision needs a beacon
    // equivalent of `Store::from_db_state`, which is not part of A1/A2.
    let anchor = beacon_checkpoint::fetch_beacon_anchor_from_any(&checkpoint_urls, &config)
        .await
        .wrap_err("beacon checkpoint sync failed")?;

    let now_unix_secs = SystemTime::UNIX_EPOCH
        .elapsed()
        .expect("already past the unix epoch")
        .as_secs();
    let params = beacon_network_params(
        &config,
        anchor.genesis_validators_root(),
        anchor.genesis_time(),
        now_unix_secs,
    );

    let anchor_slot = anchor.slot();
    info!(
        anchor_slot,
        fork = anchor.state.fork_name().as_str(),
        genesis_validators_root = %format_args!("0x{}", hex::encode(params.genesis_validators_root.0)),
        genesis_time = params.genesis_time,
        fork_digest = %hex::encode(params.fork_digest),
        digest_epoch = params.digest_epoch,
        "Beacon checkpoint sync complete"
    );

    // The digest is computed once. Crossing a fork or blob-parameter boundary
    // while running strands this node on topics the network has left, and the
    // only symptom is peers quietly draining away, so name the boundary now.
    match next_digest_boundary(&config, params.digest_epoch) {
        Some(boundary) => {
            let at = params.genesis_time
                + boundary * SLOTS_PER_EPOCH * config.seconds_per_slot;
            warn!(
                boundary_epoch = boundary,
                boundary_unix_time = at,
                "The fork digest is computed once at startup. Restart this node \
                 before the epoch above or it will be left on stale topics"
            );
        }
        None => info!("No further fork or blob-schedule boundary is scheduled"),
    }

    ethlambda_blockchain::metrics::set_sync_anchor_slot(anchor_slot);

    let backend = Arc::new(
        RocksDBBackend::open(&data_dir)
            .map_err(|err| eyre::eyre!("{err}"))
            .wrap_err_with(|| format!("failed to open RocksDB at {}", data_dir.display()))?,
    );
    let store = Store::get_forkchoice_store(backend, anchor.state, anchor.block, &config)
        .map_err(|err| eyre::eyre!("{err}"))
        .wrap_err("failed to initialize the store from the checkpoint anchor")?;
```

`set_sync_anchor_slot` lands in Task 13; until then, delete that one line and
add it back there. If `run_beacon` already opens the backend or builds a store,
replace that code with the block above rather than adding a second one.

- [ ] **Step 6: Verify the suites**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -S -m "feat(beacon): fetch the anchor before building the swarm

The fork digest is computed from the anchor state's genesis_validators_root,
and it names every gossip topic, the ENR eth2 entry and the discv5 admission
test. Running checkpoint sync first is what lets this repository carry no
mainnet genesis-validators-root constant at all.

The epoch it is computed for comes from the clock, not the anchor: the
anchor is two epochs behind, so a fork or blob-parameter boundary crossed in
between would leave this node on the topics the network has already left.

The order is structural rather than commented: build_swarm takes a
BeaconNetworkParams, and the only function that builds one takes the
anchor's own fields."
```

---

## Task 4: Convert between the beacon `Root` and the lean `H256`

**Files:**
- Modify: `crates/common/types/src/primitives.rs`
- Test: `crates/common/types/src/primitives.rs`

`ethlambda_types::beacon::primitives::Root` is `ethereum_types::H256`;
`ethlambda_types::primitives::H256` is this crate's own
`pub struct H256(pub [u8; 32])`. The store keys blocks and states by the latter,
and every beacon block root that reaches a store lookup is the former. Same 32
bytes, two types, so the conversion is total and infallible and belongs in the
type crate rather than being open-coded at each call site.

If Task 1 Step 4 found these impls already present, run Step 2 first: it will
pass, and this task is already done. Skip to Step 5.

- [ ] **Step 1: Write the failing test**

Add to the test module at the bottom of `crates/common/types/src/primitives.rs`
(create one if the file has none):

```rust
#[cfg(test)]
mod beacon_root_conversion_tests {
    use super::H256;
    use crate::beacon::primitives::Root;

    #[test]
    fn a_root_round_trips_through_the_lean_hash() {
        let root = Root::repeat_byte(0x5a);
        let lean: H256 = root.into();
        let back: Root = lean.into();

        assert_eq!(lean.0, root.0, "the bytes must survive unchanged");
        assert_eq!(back, root);
    }

    #[test]
    fn the_conversion_preserves_byte_order() {
        // A non-palindromic value, so a reversed conversion would be visible.
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[31] = 2;

        let lean: H256 = Root::from(bytes).into();

        assert_eq!(lean.0[0], 1);
        assert_eq!(lean.0[31], 2);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-types a_root_round_trips -- --nocapture`
Expected: FAIL, `the trait bound 'H256: From<ethereum_types::H256>' is not satisfied`.

If it PASSES, plan 3 added the impls already; skip to Step 5.

- [ ] **Step 3: Add the impls**

Add to `crates/common/types/src/primitives.rs`, immediately after the `H256`
struct definition:

```rust
/// The beacon `Root` and the lean `H256` are the same 32 bytes in two types:
/// `ethlambda_types::beacon::primitives::Root` is `ethereum_types::H256`, while
/// lean's is this crate's own newtype. Every beacon block root that reaches a
/// store lookup crosses this line, and the conversion is total, so it lives
/// here rather than being open-coded per call site.
impl From<crate::beacon::primitives::Root> for H256 {
    fn from(root: crate::beacon::primitives::Root) -> Self {
        H256(root.0)
    }
}

impl From<H256> for crate::beacon::primitives::Root {
    fn from(hash: H256) -> Self {
        crate::beacon::primitives::Root::from(hash.0)
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p ethlambda-types beacon_root_conversion -- --nocapture`
Expected: PASS, both tests.

- [ ] **Step 5: Verify the suites**

Run: `make test`
Expected: PASS.

Run: `make test-beacon`
Expected: PASS, with the counts from Task 1 Step 2.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "feat(types): convert between the beacon Root and the lean H256

The store keys blocks and states by lean's H256; beacon block roots are
ethereum_types::H256. Same 32 bytes, two types, and the boundary is crossed
by every store lookup on the beacon path, so the conversion belongs in the
type crate rather than being open-coded at each call site."
```

---

## Task 5: `RangeSyncState` gains a per-network batch cap

**Files:**
- Modify: `crates/net/p2p/src/lib.rs:82-143`
- Test: `crates/net/p2p/src/lib.rs`

`next_batch` clamps to lean's `MAX_REQUEST_BLOCKS` (1024).
`beacon_blocks_by_range/2` has been capped at 128 since deneb, and a peer is
entitled to reject a larger `count` outright. The cap becomes a field so both
chains share the state machine; `new` keeps lean's value, so no lean call site
or lean test changes.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/net/p2p/src/lib.rs`:

```rust
    #[test]
    fn range_sync_state_caps_a_batch_at_its_own_limit() {
        // A beacon session batches 128 blocks, not lean's 1024:
        // beacon_blocks_by_range/2 is capped at MAX_REQUEST_BLOCKS_DENEB, and a
        // peer may reject a larger count outright.
        let peer = random_peer();
        let state = RangeSyncState::with_max_batch(10..3000, peer, 2999, 128);

        let (selected, batch) = state.next_batch().expect("batch available");

        assert_eq!(selected, peer);
        assert_eq!(batch, 10..138);
    }

    #[test]
    fn range_sync_state_new_keeps_leans_limit() {
        // The existing constructor must not change behaviour for lean.
        let peer = random_peer();
        let state = RangeSyncState::new(10..30_000, peer, 29_999);

        let (_, batch) = state.next_batch().expect("batch available");

        assert_eq!(batch, 10..(10 + MAX_REQUEST_BLOCKS));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p --profile release-fast range_sync_state_caps -- --nocapture`
Expected: FAIL, `no function or associated item named 'with_max_batch' found`.

- [ ] **Step 3: Add the field and the constructor**

In `crates/net/p2p/src/lib.rs`, replace the `RangeSyncState` struct and its
`new` and `next_batch` with:

```rust
pub(crate) struct RangeSyncState {
    /// Remaining slots to request, with an exclusive end.
    pub(crate) current_range: Range<u64>,
    /// Latest advertised head slot for each peer.
    pub(crate) peer_set: HashMap<PeerId, u64>,
    pub(crate) in_flight: bool,
    /// Largest `count` a single request may ask for.
    ///
    /// Per-network: lean's `blocks_by_range/1` allows [`MAX_REQUEST_BLOCKS`],
    /// while `beacon_blocks_by_range/2` has been capped at
    /// `MAX_REQUEST_BLOCKS_DENEB` since deneb and a peer may refuse a larger
    /// request outright. Everything else about a sync session is identical on
    /// both chains, which is why this is a field rather than a second type.
    pub(crate) max_batch: u64,
}

impl RangeSyncState {
    pub(crate) fn new(current_range: Range<u64>, peer: PeerId, peer_head: u64) -> Self {
        Self::with_max_batch(current_range, peer, peer_head, MAX_REQUEST_BLOCKS)
    }

    pub(crate) fn with_max_batch(
        current_range: Range<u64>,
        peer: PeerId,
        peer_head: u64,
        max_batch: u64,
    ) -> Self {
        Self {
            current_range,
            peer_set: HashMap::from([(peer, peer_head)]),
            in_flight: false,
            max_batch,
        }
    }

    pub(crate) fn merge_peer(&mut self, peer: PeerId, peer_head: u64, end_exclusive: u64) {
        self.peer_set.insert(peer, peer_head);
        self.current_range.end = self.current_range.end.max(end_exclusive);
        self.drop_stale_peers();
    }

    pub(crate) fn next_batch(&self) -> Option<(PeerId, Range<u64>)> {
        if self.in_flight || self.current_range.is_empty() {
            return None;
        }

        let (&peer, &peer_head) = self
            .peer_set
            .iter()
            .filter(|(_, head)| **head >= self.current_range.start)
            .max_by_key(|(_, head)| **head)?;
        let peer_end = peer_head.saturating_add(1);
        let batch_end = self
            .current_range
            .start
            .saturating_add(self.max_batch)
            .min(self.current_range.end)
            .min(peer_end);

        (batch_end > self.current_range.start)
            .then_some((peer, self.current_range.start..batch_end))
    }
```

Leave `complete_batch`, `fail_peer` and `drop_stale_peers` exactly as they are.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p --profile release-fast range_sync_state -- --nocapture`
Expected: PASS, five tests: the two new ones plus the three that already existed
(`range_sync_state_merges_new_peer_ranges`,
`range_sync_state_allows_only_one_batch_in_flight`,
`range_sync_state_advances_and_drops_stale_peers`).

- [ ] **Step 5: Verify the suites**

Run: `make test`
Expected: PASS. The lean path is unchanged: `RangeSyncState::new` is the only
constructor lean calls and it still selects lean's cap.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "refactor(p2p): make the range-sync batch cap per-network

Everything about a forward-sync session is the same on both chains: the
slot range, the per-peer advertised heads, one batch in flight, highest-head
peer selection, stale-peer eviction. The single difference is the request
cap, 1024 on lean's blocks_by_range/1 and 128 on beacon_blocks_by_range/2
since deneb. A field, so the state machine stays one type; `new` keeps
lean's value so no lean call site moves."
```

---

## Task 6: The beacon range-sync decisions

**Files:**
- Create: `crates/net/p2p/src/beacon/range_sync.rs`
- Modify: `crates/net/p2p/src/beacon/mod.rs`
- Test: `crates/net/p2p/src/beacon/range_sync.rs`

Everything decidable without a socket lives here: the gap, the peer choice, the
session open/merge, and the request at each of the range's limits. The actor
wiring is Task 11 and calls only these four functions.

- [ ] **Step 1: Write the failing tests**

Create `crates/net/p2p/src/beacon/range_sync.rs`:

```rust
//! Anchor-to-head forward sync for the Beacon Chain.
//!
//! Checkpoint sync anchors the node at a finalized state roughly two epochs
//! behind the live head, and `fork_choice::on_block` rejects a block whose
//! parent is not in the store. So no gossiped block at the head can be imported
//! until the slots between the anchor and that head have been fetched over
//! `beacon_blocks_by_range/2`. Getting this wrong is a failure mode this
//! project has watched other clients hit: the node tracks the tip, every block
//! it "receives" is orphaned, and justification and finalization stay frozen
//! while the head appears to climb.
//!
//! The session state is [`RangeSyncState`], lean's, unchanged except for the
//! batch cap. Only three decisions differ, and they are the functions here: how
//! wide a gap is worth closing, what goes on the wire, and the fact that the
//! session is re-armed from a timer rather than only on a peer's first
//! `Status`. A session that ends with all its peers failed must be reopenable,
//! or one bad minute ends syncing for the life of the process.

use std::collections::HashMap;
use std::ops::Range;
use std::time::Duration;

use libp2p::PeerId;

use crate::RangeSyncState;
use crate::beacon::req_resp::BeaconBlocksByRangeRequest;

/// `beacon_blocks_by_range/2`'s `count` ceiling from deneb onward.
///
/// Deneb lowered the limit from 1024, and mainnet has been past deneb for
/// years, so 1024 is never a valid count for a request this client sends.
pub(crate) const MAX_REQUEST_BLOCKS_DENEB: u64 = 128;

/// Widest anchor-to-head gap forward sync will try to close in one session.
///
/// 64 full batches, roughly 27 hours of mainnet slots. Past that the anchor is
/// too old to be worth replaying forward from and the operator wants a fresher
/// checkpoint instead.
pub(crate) const MAX_BEACON_SYNC_RANGE: u64 = MAX_REQUEST_BLOCKS_DENEB * 64;

/// Local head lag, in slots, past which the resync timer opens a session.
///
/// The same number as `ethlambda_blockchain`'s `SYNC_LAG_THRESHOLD`, so the
/// node starts fetching at exactly the lag at which it starts reporting itself
/// as syncing.
pub(crate) const BEACON_SYNC_LAG_THRESHOLD: u64 = 4;

/// How often the resync timer re-checks the local head against known peers.
///
/// One mainnet slot.
pub(crate) const BEACON_RESYNC_INTERVAL: Duration = Duration::from_secs(12);

/// The slots to fetch to get from `local_head_slot` to `peer_head_slot`.
///
/// `None` when the peer is at or behind us, which is the common case once the
/// gap is closed. The end is exclusive and equals `peer_head_slot + 1`, so the
/// peer's own head block is included, clamped to [`MAX_BEACON_SYNC_RANGE`].
pub(crate) fn forward_sync_range(local_head_slot: u64, peer_head_slot: u64) -> Option<Range<u64>> {
    let gap = peer_head_slot.checked_sub(local_head_slot)?;
    if gap == 0 {
        return None;
    }
    let start = local_head_slot.saturating_add(1);
    let end = start.saturating_add(gap.min(MAX_BEACON_SYNC_RANGE));
    Some(start..end)
}

/// The known peer with the highest advertised head.
///
/// Ties break on `PeerId` so the choice is deterministic, which a
/// `HashMap`-order maximum would not be.
pub(crate) fn best_peer_head(peer_heads: &HashMap<PeerId, u64>) -> Option<(PeerId, u64)> {
    peer_heads
        .iter()
        .max_by_key(|(peer, head)| (**head, **peer))
        .map(|(peer, head)| (*peer, *head))
}

/// Open a session for this peer's head, or fold the peer into the open one.
///
/// Returns `true` only when this call opened a session that did not exist,
/// which is what the caller logs.
pub(crate) fn start_or_merge(
    session: &mut Option<RangeSyncState>,
    peer: PeerId,
    peer_head_slot: u64,
    local_head_slot: u64,
) -> bool {
    let Some(range) = forward_sync_range(local_head_slot, peer_head_slot) else {
        return false;
    };
    match session {
        Some(state) => {
            state.merge_peer(peer, peer_head_slot, range.end);
            false
        }
        None => {
            *session = Some(RangeSyncState::with_max_batch(
                range,
                peer,
                peer_head_slot,
                MAX_REQUEST_BLOCKS_DENEB,
            ));
            true
        }
    }
}

/// The next request to put on the wire, with the slot range it covers.
///
/// `None` when a batch is already in flight, when the range is closed, or when
/// no remaining peer covers the range's start.
pub(crate) fn next_request(
    session: &RangeSyncState,
) -> Option<(PeerId, BeaconBlocksByRangeRequest, Range<u64>)> {
    let (peer, batch) = session.next_batch()?;
    let request = BeaconBlocksByRangeRequest {
        start_slot: batch.start,
        count: batch.end - batch.start,
    };
    Some((peer, request, batch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn peer_n(n: u8) -> PeerId {
        // Deterministic ids so the tie-break in `best_peer_head` is
        // reproducible: an ed25519 key from a fixed seed.
        let mut seed = [0u8; 32];
        seed[0] = n;
        let keypair = Keypair::ed25519_from_bytes(seed).expect("32 bytes is a valid ed25519 seed");
        PeerId::from_public_key(&keypair.public())
    }

    #[test]
    fn the_gap_runs_from_the_slot_after_the_anchor_to_the_peers_head() {
        // The anchor is at 64 and the peer's head is at 128, the two-epoch lag
        // a fresh checkpoint sync lands at.
        assert_eq!(forward_sync_range(64, 128), Some(65..129));
    }

    #[test]
    fn a_peer_at_our_head_leaves_nothing_to_fetch() {
        assert_eq!(forward_sync_range(128, 128), None);
    }

    #[test]
    fn a_peer_behind_us_leaves_nothing_to_fetch() {
        assert_eq!(forward_sync_range(128, 100), None);
    }

    #[test]
    fn an_absurd_gap_is_clamped_rather_than_attempted() {
        // A month-old anchor. Fetching it forward would take longer than
        // fetching a new checkpoint, so the session covers what it can and the
        // timer reopens it from the new head afterwards.
        let range = forward_sync_range(0, 1_000_000).expect("there is a gap");
        assert_eq!(range, 1..(1 + MAX_BEACON_SYNC_RANGE));
    }

    #[test]
    fn the_highest_head_wins_and_ties_are_deterministic() {
        let heads = HashMap::from([(peer_n(1), 100), (peer_n(2), 300), (peer_n(3), 300)]);

        let (peer, head) = best_peer_head(&heads).expect("three peers are known");

        assert_eq!(head, 300);
        assert_eq!(peer, peer_n(2).max(peer_n(3)));
    }

    #[test]
    fn no_known_peers_means_no_choice() {
        assert_eq!(best_peer_head(&HashMap::new()), None);
    }

    #[test]
    fn the_first_peer_opens_a_session_and_the_second_extends_it() {
        let mut session = None;

        assert!(start_or_merge(&mut session, peer_n(1), 128, 64));
        assert!(!start_or_merge(&mut session, peer_n(2), 200, 64));

        let state = session.expect("a session is open");
        assert_eq!(state.current_range, 65..201);
        assert_eq!(state.peer_set.len(), 2);
        assert_eq!(state.max_batch, MAX_REQUEST_BLOCKS_DENEB);
    }

    #[test]
    fn a_peer_that_is_not_ahead_never_opens_a_session() {
        let mut session = None;

        assert!(!start_or_merge(&mut session, peer_n(1), 64, 64));

        assert!(session.is_none(), "there is nothing to sync");
    }

    #[test]
    fn a_short_gap_is_one_request_for_exactly_the_gap() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 128, 64);

        let (peer, request, batch) =
            next_request(session.as_ref().unwrap()).expect("a batch is available");

        assert_eq!(peer, peer_n(1));
        assert_eq!(request.start_slot, 65);
        assert_eq!(request.count, 64, "the whole gap fits in one request");
        assert_eq!(batch, 65..129);
    }

    #[test]
    fn a_long_gap_is_capped_at_the_protocol_limit() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);

        let (_, request, batch) =
            next_request(session.as_ref().unwrap()).expect("a batch is available");

        assert_eq!(request.count, MAX_REQUEST_BLOCKS_DENEB);
        assert_eq!(batch, 65..(65 + MAX_REQUEST_BLOCKS_DENEB));
    }

    #[test]
    fn a_batch_never_reaches_past_the_chosen_peers_own_head() {
        // The high-head peer opened the range; only the low-head peer survives.
        // Asking it for slots it cannot have would waste a round trip.
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);
        start_or_merge(&mut session, peer_n(2), 100, 64);
        session.as_mut().unwrap().fail_peer(&peer_n(1));

        let (peer, request, _) =
            next_request(session.as_ref().unwrap()).expect("the surviving peer can serve");

        assert_eq!(peer, peer_n(2));
        assert_eq!(request.start_slot, 65);
        assert_eq!(request.count, 36, "slots 65..=100, and no further");
    }

    #[test]
    fn a_batch_in_flight_blocks_the_next_one() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);
        session.as_mut().unwrap().in_flight = true;

        assert!(next_request(session.as_ref().unwrap()).is_none());
    }

    #[test]
    fn a_completed_batch_advances_the_range_and_frees_the_next() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);
        let (_, _, batch) = next_request(session.as_ref().unwrap()).unwrap();
        session.as_mut().unwrap().in_flight = true;

        session.as_mut().unwrap().complete_batch(batch.end - 1);

        let (_, request, _) =
            next_request(session.as_ref().unwrap()).expect("the next batch follows on");
        assert_eq!(request.start_slot, batch.end);
        assert_eq!(request.count, MAX_REQUEST_BLOCKS_DENEB);
    }

    #[test]
    fn a_failed_peer_is_rotated_out_and_the_batch_reissued_to_another() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);
        start_or_merge(&mut session, peer_n(2), 5_000, 64);
        let (chosen, _, _) = next_request(session.as_ref().unwrap()).unwrap();
        session.as_mut().unwrap().in_flight = true;

        session.as_mut().unwrap().fail_peer(&chosen);

        let (retry_peer, request, _) =
            next_request(session.as_ref().unwrap()).expect("the other peer takes over");
        assert_ne!(retry_peer, chosen);
        assert_eq!(
            request.start_slot, 65,
            "the failed batch is reissued from the same slot, not skipped"
        );
    }

    #[test]
    fn the_last_peer_failing_empties_the_session() {
        let mut session = None;
        start_or_merge(&mut session, peer_n(1), 5_000, 64);

        session.as_mut().unwrap().fail_peer(&peer_n(1));

        assert!(
            session.as_ref().unwrap().peer_set.is_empty(),
            "the caller drops the session on an empty peer set and the resync \
             timer reopens it when a peer reappears"
        );
        assert!(next_request(session.as_ref().unwrap()).is_none());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p --profile release-fast range_sync -- --nocapture`
Expected: FAIL, `file not found for module 'range_sync'`.

- [ ] **Step 3: Declare the module**

Add to `crates/net/p2p/src/beacon/mod.rs`:

```rust
pub(crate) mod range_sync;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p --profile release-fast range_sync -- --nocapture`
Expected: PASS, 15 tests.

- [ ] **Step 5: Verify the suites**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "feat(p2p): the beacon anchor-to-head range-sync decisions

Four pure functions over lean's RangeSyncState: how wide a gap to close,
which peer to ask, opening or extending a session, and the request at each
of the range's limits. Every batch-boundary, peer-rotation and
range-exhaustion case is a test here, so the actor wiring that follows has
no decisions of its own left to get wrong."
```

---

## Task 7: The pending-block buffer

**Files:**
- Create: `crates/blockchain/src/beacon_pending.rs`
- Modify: `crates/blockchain/src/lib.rs`
- Test: `crates/blockchain/src/beacon_pending.rs`

Gossip blocks for the live head arrive while the gap is still being fetched.
`on_block` will refuse them, so they are held by the parent root they are
waiting on, and released when that parent imports. This mirrors lean's
`pending_blocks` / `pending_block_parents` pair in `BlockChainServer`
(`crates/blockchain/src/lib.rs:227`), extracted into a type of its own so the
ordering guarantee is testable without an actor, a store, or a network.

- [ ] **Step 1: Write the failing tests**

Create `crates/blockchain/src/beacon_pending.rs`:

```rust
//! Beacon blocks waiting on a parent the store does not have yet.
//!
//! Checkpoint sync anchors two epochs behind the head, so the first gossiped
//! blocks all descend from blocks in the unfetched gap. Dropping them would
//! work — the range fetch reaches those slots eventually — but it wastes the
//! freshest blocks on the network and leaves a window where nothing at the head
//! can ever be imported. Holding them by parent root and releasing them when
//! that parent lands closes the gap from both ends.
//!
//! The same shape as lean's `pending_blocks` / `pending_block_parents` pair on
//! `BlockChainServer`, as a type of its own: the ordering guarantee here is the
//! thing that separates a follower that backfills from one that only tracks the
//! tip, and it deserves tests that need neither an actor nor a store.

use std::collections::{HashMap, HashSet};

use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::primitives::{Root, Slot};

/// Most blocks held at once, across every parent.
///
/// Two epochs of gap is 64 blocks, and forks add a few more; 1024 is far above
/// anything a healthy run reaches, and low enough that a peer feeding
/// fabricated parents cannot grow this without bound. A gossiped block is a few
/// hundred kilobytes at most, so the ceiling is well under a gigabyte.
pub(crate) const MAX_PENDING_BEACON_BLOCKS: usize = 1024;

/// What happened to a block handed to [`PendingBeaconBlocks::insert`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Pending {
    /// Held. The root carried is the deepest ancestor this buffer knows nothing
    /// about: the one worth asking a peer for, since fetching the immediate
    /// parent would only reveal another block already buffered here.
    Buffered(Root),
    /// The buffer is at [`MAX_PENDING_BEACON_BLOCKS`] and the block was dropped.
    Full,
}

/// Blocks held by the parent root they are waiting on.
#[derive(Default)]
pub(crate) struct PendingBeaconBlocks {
    /// Held blocks, keyed by the parent root each is waiting on, paired with
    /// their own root so neither draining nor pruning has to merkleize again.
    by_parent: HashMap<Root, Vec<(Root, SignedBeaconBlock)>>,
    /// Every held block's own root mapped to the parent it waits on, so a newly
    /// arriving block can walk up to the deepest root nothing knows about.
    parent_of: HashMap<Root, Root>,
    len: usize,
}

impl PendingBeaconBlocks {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Hold `block` until its parent imports.
    pub(crate) fn insert(&mut self, block: SignedBeaconBlock) -> Pending {
        let root = block.message_hash_tree_root();
        let parent = block.parent_root();

        if self.parent_of.contains_key(&root) {
            // A duplicate on the gossip mesh. Report the same ancestor without
            // counting the block twice.
            return Pending::Buffered(self.deepest_missing(parent));
        }
        if self.len >= MAX_PENDING_BEACON_BLOCKS {
            return Pending::Full;
        }

        self.parent_of.insert(root, parent);
        self.by_parent.entry(parent).or_default().push((root, block));
        self.len += 1;
        Pending::Buffered(self.deepest_missing(parent))
    }

    /// The deepest root this buffer knows nothing about, walking up from `root`.
    ///
    /// Terminates: blocks name their parents by hash, so a cycle would need a
    /// hash collision.
    fn deepest_missing(&self, root: Root) -> Root {
        let mut current = root;
        while let Some(&parent) = self.parent_of.get(&current) {
            current = parent;
        }
        current
    }

    /// Release every block waiting on `parent`, in ascending slot order.
    ///
    /// Slot order matters when a parent has more than one child: fork choice
    /// must see the earlier slot first, or a later sibling's import can move
    /// the head to a block whose own sibling has not been considered yet.
    pub(crate) fn take_children(&mut self, parent: Root) -> Vec<SignedBeaconBlock> {
        let Some(mut children) = self.by_parent.remove(&parent) else {
            return Vec::new();
        };
        children.sort_by_key(|(_, block)| block.slot());
        self.len -= children.len();
        children
            .into_iter()
            .map(|(root, block)| {
                self.parent_of.remove(&root);
                block
            })
            .collect()
    }

    /// Drop every held block at or below `slot`, returning how many went.
    ///
    /// Called when finalization advances: a block at or below the finalized
    /// slot can never become importable, so holding it only wastes the budget
    /// that a live fork needs.
    pub(crate) fn prune_below(&mut self, slot: Slot) -> usize {
        let mut removed = 0usize;
        self.by_parent.retain(|_, children| {
            children.retain(|(_, block)| {
                let keep = block.slot() > slot;
                if !keep {
                    removed += 1;
                }
                keep
            });
            !children.is_empty()
        });
        let surviving: HashSet<Root> = self
            .by_parent
            .values()
            .flatten()
            .map(|(root, _)| *root)
            .collect();
        self.parent_of.retain(|root, _| surviving.contains(root));
        self.len -= removed;
        removed
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::containers::phase0;

    /// A block with an empty body, for tests that care only about its slot and
    /// its place in the chain. Phase0-shaped: nothing here reads a
    /// fork-specific field.
    fn block(slot: Slot, parent_root: Root) -> SignedBeaconBlock {
        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: Root::zero(),
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: Root::zero(),
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

    /// A chain where slot `s` has parent slot `s - 1`. Returns the blocks
    /// keyed by slot together with their roots, so a test can name any link.
    fn chain(from: Slot, to: Slot, anchor_root: Root) -> Vec<(Slot, Root, SignedBeaconBlock)> {
        let mut built = Vec::new();
        let mut parent = anchor_root;
        for slot in from..=to {
            let signed = block(slot, parent);
            let root = signed.message_hash_tree_root();
            built.push((slot, root, signed));
            parent = root;
        }
        built
    }

    #[test]
    fn an_orphan_reports_its_own_parent_as_the_root_to_fetch() {
        let mut pending = PendingBeaconBlocks::new();
        let parent = Root::repeat_byte(9);

        let outcome = pending.insert(block(100, parent));

        assert_eq!(outcome, Pending::Buffered(parent));
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn a_chain_of_orphans_reports_the_deepest_one() {
        // Fetching the immediate parent of the newest block would return a
        // block already held here, costing a round trip and learning nothing.
        let mut pending = PendingBeaconBlocks::new();
        let anchor = Root::repeat_byte(9);
        let built = chain(100, 104, anchor);

        for (_, _, signed) in &built {
            assert_eq!(pending.insert(signed.clone()), Pending::Buffered(anchor));
        }

        assert_eq!(pending.len(), 5);
    }

    #[test]
    fn a_duplicate_is_not_counted_twice() {
        let mut pending = PendingBeaconBlocks::new();
        let parent = Root::repeat_byte(9);

        pending.insert(block(100, parent));
        pending.insert(block(100, parent));

        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn the_buffer_refuses_rather_than_growing_without_bound() {
        // A peer feeding fabricated parents must not be able to grow this.
        let mut pending = PendingBeaconBlocks::new();
        for slot in 0..MAX_PENDING_BEACON_BLOCKS as u64 {
            let parent = Root::from_low_u64_be(slot + 1_000_000);
            assert!(matches!(
                pending.insert(block(slot, parent)),
                Pending::Buffered(_)
            ));
        }

        let overflow = pending.insert(block(9_999, Root::repeat_byte(7)));

        assert_eq!(overflow, Pending::Full);
        assert_eq!(pending.len(), MAX_PENDING_BEACON_BLOCKS);
    }

    #[test]
    fn children_come_out_in_slot_order_and_only_once() {
        let mut pending = PendingBeaconBlocks::new();
        let parent = Root::repeat_byte(9);
        pending.insert(block(103, parent));
        pending.insert(block(101, parent));
        pending.insert(block(102, parent));

        let released = pending.take_children(parent);

        let slots: Vec<Slot> = released.iter().map(|b| b.slot()).collect();
        assert_eq!(slots, vec![101, 102, 103]);
        assert_eq!(pending.len(), 0);
        assert!(pending.take_children(parent).is_empty());
    }

    #[test]
    fn a_root_with_no_children_releases_nothing() {
        let mut pending = PendingBeaconBlocks::new();
        pending.insert(block(100, Root::repeat_byte(9)));

        assert!(pending.take_children(Root::repeat_byte(1)).is_empty());
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn finalization_drops_what_can_never_import() {
        let mut pending = PendingBeaconBlocks::new();
        let anchor = Root::repeat_byte(9);
        for (_, _, signed) in chain(100, 109, anchor) {
            pending.insert(signed);
        }

        let dropped = pending.prune_below(104);

        assert_eq!(dropped, 5, "slots 100 through 104");
        assert_eq!(pending.len(), 5);
        // The surviving blocks still resolve their ancestry, so the walk did
        // not leave a dangling entry behind in `parent_of`.
        let survivor_parent = Root::repeat_byte(0xff);
        assert_eq!(
            pending.insert(block(110, survivor_parent)),
            Pending::Buffered(survivor_parent)
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-blockchain --profile release-fast beacon_pending -- --nocapture`
Expected: FAIL, `file not found for module 'beacon_pending'`.

- [ ] **Step 3: Declare the module**

Add to `crates/blockchain/src/lib.rs`, alongside the other `mod` declarations:

```rust
mod beacon_pending;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-blockchain --profile release-fast beacon_pending -- --nocapture`
Expected: PASS, 7 tests.

- [ ] **Step 5: Verify the suites**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "feat(blockchain): hold beacon blocks whose parent is unknown

Checkpoint sync anchors two epochs behind the head, so every early gossip
block descends from the unfetched gap. Holding them by parent root, and
releasing them in slot order when that parent imports, closes the gap from
both ends instead of throwing away the freshest blocks on the network.

Same shape as lean's pending_blocks pair, as a type of its own: the ordering
guarantee is what separates a backfilling follower from a tip-tracking one,
and it should be testable without an actor or a store."
```

---

## Task 8: The tip-only regression test

**Files:**
- Modify: `crates/blockchain/src/beacon_pending.rs`
- Test: `crates/blockchain/src/beacon_pending.rs`

This is the test the plan exists for. A follower that imports gossip blocks at
the tip without ever fetching the anchor-to-head gap looks healthy from the
outside — its head climbs — while every block it accepted is orphaned and
justification and finalization stay frozen. This project has watched several
clients do exactly that.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/blockchain/src/beacon_pending.rs`:

```rust
    /// Drive the buffer the way the block handler does: import a block, release
    /// its children, import each of those, and so on. Returns the slots in the
    /// order they became importable.
    fn drain_cascade(pending: &mut PendingBeaconBlocks, imported_root: Root) -> Vec<Slot> {
        let mut order = Vec::new();
        let mut queue = std::collections::VecDeque::from(pending.take_children(imported_root));
        while let Some(block) = queue.pop_front() {
            order.push(block.slot());
            for child in pending.take_children(block.message_hash_tree_root()) {
                queue.push_back(child);
            }
        }
        order
    }

    /// The failure this whole plan exists to prevent.
    ///
    /// A follower that tracks the tip without backfilling accepts gossip blocks
    /// whose parents it has never seen. Its head climbs while justification and
    /// finalization stay frozen, because nothing it imported is actually on a
    /// chain it can evaluate. Two properties separate that behaviour from a
    /// correct one, and this test asserts both:
    ///
    ///   1. While the gap is unfilled, no block at the tip is importable. A
    ///      tip-only follower has them all importable immediately.
    ///   2. Once the gap is walked forward from the anchor, every held block
    ///      comes out exactly once, contiguously, in ascending slot order. A
    ///      tip-only follower has nothing left to release here, so the drained
    ///      order is empty.
    #[test]
    fn tip_blocks_are_not_importable_until_the_gap_is_filled() {
        let anchor = Root::repeat_byte(0xa0);
        // The anchor is at slot 64; the live head is at 128. Slots 65..=119 are
        // the gap the range fetch will bring; 120..=128 arrive on gossip first.
        let full = chain(65, 128, anchor);
        let mut pending = PendingBeaconBlocks::new();

        // --- The tip arrives first, out of a chain the node cannot evaluate.
        for (slot, _, signed) in &full {
            if *slot >= 120 {
                assert_eq!(
                    pending.insert(signed.clone()),
                    Pending::Buffered(full[(119 - 65) as usize].1),
                    "every tip block must point at the same unknown ancestor, \
                     the last block of the gap"
                );
            }
        }
        assert_eq!(pending.len(), 9, "slots 120 through 128 are held");

        // Property 1: with the gap unfilled, nothing at the tip is importable.
        // The anchor's children are not here, and neither is anything else the
        // node currently has a state for.
        assert!(
            drain_cascade(&mut pending, anchor).is_empty(),
            "a tip block must not become importable just because it arrived"
        );
        assert_eq!(pending.len(), 9, "and nothing may be silently dropped");

        // --- The range fetch walks the gap forward from the anchor.
        let mut applied = Vec::new();
        for (slot, root, _) in full.iter().filter(|(slot, _, _)| *slot < 120) {
            applied.push(*slot);
            applied.extend(drain_cascade(&mut pending, *root));
        }

        // Property 2: the held tip blocks came out, once each, in slot order,
        // and the whole chain is contiguous from the anchor to the head.
        let expected: Vec<Slot> = (65..=128).collect();
        assert_eq!(
            applied, expected,
            "the chain must be applied contiguously from the anchor to the head"
        );
        assert_eq!(pending.len(), 0, "the buffer must be empty afterwards");
    }
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p ethlambda-blockchain --profile release-fast tip_blocks_are_not_importable -- --nocapture`
Expected: **PASS.** Task 7 already built the behaviour this asserts.

That is the correct outcome here, and only here: this is a regression test for a
failure mode, not a driver for new code, so the TDD step that proves it is worth
having is Step 3, which breaks the behaviour on purpose and watches it go red. A
regression test never seen red is not a test.

- [ ] **Step 3: Prove the test can fail**

Temporarily change `take_children` in `crates/blockchain/src/beacon_pending.rs`
to return everything it holds regardless of parent, which is what a tip-only
follower effectively does:

```rust
    pub(crate) fn take_children(&mut self, _parent: Root) -> Vec<SignedBeaconBlock> {
        let mut all: Vec<(Root, SignedBeaconBlock)> =
            self.by_parent.drain().flat_map(|(_, v)| v).collect();
        all.sort_by_key(|(_, block)| block.slot());
        self.len = 0;
        self.parent_of.clear();
        all.into_iter().map(|(_, block)| block).collect()
    }
```

Run: `cargo test -p ethlambda-blockchain --profile release-fast tip_blocks_are_not_importable -- --nocapture`
Expected: FAIL, on the first assertion:
`a tip block must not become importable just because it arrived`.

Then revert the change:

```bash
git checkout -- crates/blockchain/src/beacon_pending.rs
```

and re-add the test from Step 1 if the checkout removed it.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p ethlambda-blockchain --profile release-fast beacon_pending -- --nocapture`
Expected: PASS, 8 tests.

- [ ] **Step 5: Verify the suites**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "test(blockchain): pin the tip-without-backfill failure mode

A follower that imports gossip blocks whose parents it never fetched looks
healthy from outside: its head climbs. Every block it took is orphaned, so
justification and finalization stay frozen. Several clients on this network
have shipped exactly that.

Two assertions separate the two behaviours: nothing at the tip is
importable while the gap is open, and once the gap is walked forward every
held block comes out once, contiguously, in slot order. A tip-only
implementation fails both."
```

---

## Task 9: `on_block` refuses a block whose parent is missing

**Files:**
- Modify: `crates/beacon/src/fork_choice.rs`
- Test: `crates/beacon/src/fork_choice.rs`

The buffer in Task 7 is only worth having because the handler underneath it
really does refuse. `on_block`'s first act is
`verify(store.block_states.contains_key(&parent_root), …)` — after plan 3, the
DB-backed equivalent. This test pins that against the real handler rather than
against a fake, and it runs under `make test-beacon` because that is where
`ethlambda-beacon`'s tests run.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/beacon/src/fork_choice.rs`:

```rust
    /// The refusal the whole anchor-to-head fetch exists to work around.
    ///
    /// A checkpoint-synced node's store holds exactly one block, the anchor.
    /// A gossiped block from the live head names a parent two epochs newer, so
    /// it is refused, and stays refused until the slots between are fetched.
    /// Nothing here reaches a state transition or a signature check: the parent
    /// test is the first thing `on_block` does, deliberately, so a block on an
    /// unknown chain costs nothing to reject.
    #[test]
    fn on_block_refuses_a_block_whose_parent_is_unknown() {
        let config = Config::active();
        let anchor_state = crate::helpers::test_state::with_validators(1);
        let anchor_slot = anchor_state.slot();
        let anchor_block = {
            let mut signed = block(anchor_slot, Root::zero());
            let SignedBeaconBlock::Phase0(inner) = &mut signed else {
                panic!("`block` builds a phase0 block");
            };
            inner.message.state_root = anchor_state.hash_tree_root();
            signed
        };
        let mut store =
            get_forkchoice_store(anchor_state, anchor_block, &config).expect("the pair matches");

        // A block from the live head: two epochs on, naming a parent that only
        // a node which fetched the gap could possibly have.
        let orphan = block(
            anchor_slot + 2 * preset::SLOTS_PER_EPOCH,
            Root::repeat_byte(0xbe),
        );
        let orphan_root = orphan.message_hash_tree_root();

        let result = on_block(&mut store, orphan, &config, &DataAvailability::NotRequired);

        assert!(
            result.is_err(),
            "a block whose parent is not in the store must not import"
        );
        assert!(
            !store.blocks.contains_key(&orphan_root),
            "a refused block must leave the store untouched"
        );
    }
```

After plan 3 the store is `ethlambda_storage::Store`, so the final assertion
reads `!store.has_state(&orphan_root.into()).unwrap()` and
`get_forkchoice_store` takes a backend as its first argument. Task 1 Step 3
recorded the real signature; use it.

- [ ] **Step 2: Run the test**

Run: `cargo test -p ethlambda-beacon --profile release-fast on_block_refuses_a_block -- --nocapture`
Expected: **PASS.** The behaviour already exists; this is a regression test for
it, exactly as in Task 8, so the step that earns it is Step 3.

- [ ] **Step 3: Prove the test can fail**

Temporarily comment out the parent check at the top of `on_block`:

```rust
    // Parent block must be known.
    // verify(
    //     store.block_states.contains_key(&parent_root),
    //     "block.parent_root in store.block_states",
    // )?;
```

Run: `cargo test -p ethlambda-beacon --profile release-fast on_block_refuses_a_block -- --nocapture`
Expected: FAIL — either the assertion fires or the handler panics reaching for
the parent's post-state. Either is proof the check is load-bearing.

Then revert:

```bash
git checkout -- crates/beacon/src/fork_choice.rs
```

and re-add the test from Step 1.

- [ ] **Step 4: Verify the suites**

Run: `make test-beacon`
Expected: PASS both presets, with the counts from Task 1 Step 2 unchanged.

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -S -m "test(beacon): pin on_block's refusal of an unknown parent

The anchor-to-head fetch and the pending buffer both exist because of this
one check. Asserting it against the real handler, on a store built from a
checkpoint anchor holding exactly one block, is what keeps the reason for
both from quietly disappearing."
```

---

## Task 10: `fetch_beacon_block` on the actor protocol

**Files:**
- Modify: `crates/net/api/src/lib.rs`
- Test: `crates/net/api/src/lib.rs`

A block that is still orphaned once the range fetch has passed its slot is
fetched individually over `beacon_blocks_by_root/2` (spec §9). The blockchain
actor is what notices, so it needs a way to ask the P2P actor. Lean's
`fetch_block(root: H256)` cannot carry a beacon `Root`; adding a sibling keeps
each chain's roots in its own type rather than converting at the actor boundary.

- [ ] **Step 1: Write the failing test**

Add to `crates/net/api/src/lib.rs`, at the bottom of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Each chain's root type reaches the P2P actor unconverted. Lean's
    /// `fetch_block` takes lean's `H256`; the beacon sibling takes the beacon
    /// `Root`, which is a different type carrying the same bytes. Converting at
    /// the actor boundary instead would put the two roots one typo apart.
    #[test]
    fn the_two_fetch_messages_carry_different_root_types() {
        let lean: H256 = H256::ZERO;
        let beacon: ethlambda_types::beacon::primitives::Root =
            ethlambda_types::beacon::primitives::Root::zero();

        let lean_message = block_chain_to_p2p::FetchBlock { root: lean };
        let beacon_message = block_chain_to_p2p::FetchBeaconBlock { root: beacon };

        assert_eq!(lean_message.root, lean);
        assert_eq!(beacon_message.root, beacon);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-network-api --profile release-fast the_two_fetch_messages -- --nocapture`
Expected: FAIL, `cannot find struct 'FetchBeaconBlock' in module 'block_chain_to_p2p'`.

- [ ] **Step 3: Add the protocol method**

In `crates/net/api/src/lib.rs`, add to the `BlockChainToP2P` trait, after
`fetch_block`:

```rust
    /// Fetch a beacon block by root over `beacon_blocks_by_root/2`.
    ///
    /// Separate from [`BlockChainToP2P::fetch_block`] because the two chains'
    /// roots are different types over the same 32 bytes: lean's
    /// `ethlambda_types::primitives::H256` and the beacon `Root`, which is
    /// `ethereum_types::H256`. Converting at this boundary would leave the two
    /// one typo apart at every call site.
    fn fetch_beacon_block(
        &self,
        root: ethlambda_types::beacon::primitives::Root,
    ) -> Result<(), ActorError>;
```

- [ ] **Step 4: Add the P2P-side handler stub**

`#[protocol]` generates the message type and the `Recipient` plumbing, so
`P2PServer` needs a `Handler` for it or the crate will not compile. Add to
`crates/net/p2p/src/lib.rs`, beside the existing `impl Handler<FetchBlock>`:

```rust
impl Handler<FetchBeaconBlock> for P2PServer {
    async fn handle(&mut self, msg: FetchBeaconBlock, _ctx: &Context<Self>) {
        let root = msg.root;
        if self.beacon_pending_root_requests.contains_key(&root) {
            trace!(%root, "Beacon block fetch already in progress, ignoring duplicate");
            return;
        }
        beacon::sync::fetch_beacon_block_from_peer(self, root).await;
    }
}
```

`beacon_pending_root_requests` and `beacon::sync` land in Task 11. Until then,
make the body just `let _ = msg;` and replace it there.

Add `FetchBeaconBlock` to the `block_chain_to_p2p::{…}` import list at the top of
`crates/net/p2p/src/lib.rs`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p ethlambda-network-api --profile release-fast the_two_fetch_messages -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Verify the suites**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -S -m "feat(network-api): add fetch_beacon_block to the actor protocol

A block still orphaned after the range fetch passed its slot is fetched by
root. The blockchain actor is what notices, so it needs a way to ask P2P.
A sibling rather than a widened fetch_block, because the two chains' roots
are different types over the same bytes and converting at the actor
boundary would leave them one typo apart."
```

---

## Task 11: Wire the range driver into the P2P actor

**Files:**
- Create: `crates/net/p2p/src/beacon/sync.rs`
- Modify: `crates/net/p2p/src/beacon/mod.rs`
- Modify: `crates/net/p2p/src/lib.rs`
- Modify: `crates/net/p2p/src/req_resp/handlers.rs`
- Test: `crates/net/p2p/src/beacon/sync.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/net/p2p/src/beacon/sync.rs` with the actor wiring and its tests:

```rust
//! The actor side of the beacon anchor-to-head fetch.
//!
//! Every decision lives in [`crate::beacon::range_sync`]; this module only
//! moves them onto the wire and back. The four entry points are a peer's
//! `Status` response (opens or extends a session), a `BeaconBlocks` response
//! (imports, completes the batch and asks for the next), a failure of either
//! kind (rotates the peer out), and a timer (reopens a session the failures
//! closed).

use std::collections::HashSet;

use ethlambda_network_api::BlockSource;
use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::primitives::Root;
use libp2p::PeerId;
use rand::seq::SliceRandom;
use tracing::{debug, error, info, warn};

use crate::beacon::range_sync::{
    BEACON_SYNC_LAG_THRESHOLD, best_peer_head, next_request, start_or_merge,
};
use crate::beacon::req_resp::{
    BEACON_BLOCKS_BY_RANGE_PROTOCOL_V2, BEACON_BLOCKS_BY_ROOT_PROTOCOL_V2,
    BeaconBlocksByRootRequest, BeaconRequestedBlockRoots, BeaconStatus,
};
use crate::req_resp::Request;
use crate::{P2PServer, PendingRequest, PendingRequestKind};

/// Record a peer's advertised head and open or extend the sync session.
pub(crate) async fn on_beacon_status(server: &mut P2PServer, peer: PeerId, status: &BeaconStatus) {
    server.beacon_peer_heads.insert(peer, status.head_slot);

    let local_head_slot = server.store.head_slot();
    let opened = start_or_merge(
        &mut server.beacon_range_sync,
        peer,
        status.head_slot,
        local_head_slot,
    );
    if opened {
        info!(
            %peer,
            local_head_slot,
            peer_head_slot = status.head_slot,
            gap = status.head_slot.saturating_sub(local_head_slot),
            "Anchor-to-head range sync started"
        );
    }
    request_next_beacon_batch(server).await;
}

/// Re-open a session that failures closed, or that the node fell behind after.
///
/// Lean only ever opens a session from a peer's first `Status`, which is enough
/// for a node that joins and catches up once. A beacon follower has to *stay*
/// at the head, so a session whose peers all failed must be reopenable without
/// a reconnect.
pub(crate) async fn on_beacon_resync_check(server: &mut P2PServer) {
    if server.beacon_range_sync.is_some() {
        return;
    }
    // Cloned rather than borrowed through `server`: two disjoint fields of the
    // same struct, one mutably, is a rule the reader should not have to check.
    // A `HashSet<PeerId>` of at most a few dozen entries, every 12 seconds.
    let connected = server.connected_peers.clone();
    server.beacon_peer_heads.retain(|peer, _| connected.contains(peer));

    let Some((peer, peer_head_slot)) = best_peer_head(&server.beacon_peer_heads) else {
        return;
    };
    let local_head_slot = server.store.head_slot();
    if peer_head_slot.saturating_sub(local_head_slot) <= BEACON_SYNC_LAG_THRESHOLD {
        return;
    }
    if start_or_merge(
        &mut server.beacon_range_sync,
        peer,
        peer_head_slot,
        local_head_slot,
    ) {
        info!(
            %peer,
            local_head_slot,
            peer_head_slot,
            "Anchor-to-head range sync reopened by the resync timer"
        );
    }
    request_next_beacon_batch(server).await;
}

/// Put the next batch on the wire, if there is one and nothing is in flight.
pub(crate) async fn request_next_beacon_batch(server: &mut P2PServer) {
    let Some((peer, request, batch)) = server
        .beacon_range_sync
        .as_ref()
        .and_then(next_request)
    else {
        return;
    };

    let start_slot = request.start_slot;
    let count = request.count;
    let Some(request_id) = server
        .swarm_handle
        .send_request(
            peer,
            Request::BeaconBlocksByRange(request),
            libp2p::StreamProtocol::new(BEACON_BLOCKS_BY_RANGE_PROTOCOL_V2),
        )
        .await
    else {
        warn!(%peer, start_slot, count, "Failed to send BeaconBlocksByRange request");
        fail_beacon_range_request(server, &peer);
        return;
    };

    debug!(%peer, start_slot, count, "Sent BeaconBlocksByRange request");
    if let Some(state) = &mut server.beacon_range_sync {
        state.in_flight = true;
    }
    server.outbound_requests.insert(
        request_id,
        PendingRequestKind::BeaconRange {
            start_slot: batch.start,
            end_slot: batch.end - 1,
        },
    );
}

/// Hand a batch to the blockchain actor and ask for the next one.
pub(crate) async fn on_beacon_blocks_by_range_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBeaconBlock>,
    peer: PeerId,
    start_slot: u64,
    end_slot: u64,
) {
    if blocks.is_empty() {
        warn!(%peer, start_slot, end_slot, "Empty BeaconBlocksByRange response");
        fail_beacon_range_request(server, &peer);
        request_next_beacon_batch(server).await;
        return;
    }

    let Some(blockchain) = server.blockchain.as_ref() else {
        server.beacon_range_sync = None;
        warn!(%peer, "No blockchain handler available");
        return;
    };

    let mut forwarded = 0u64;
    for block in blocks {
        let slot = block.slot();
        if slot < start_slot || slot > end_slot {
            warn!(%peer, slot, start_slot, end_slot, "Beacon block outside the requested range");
            continue;
        }
        match blockchain.new_beacon_block(block, BlockSource::Sync) {
            Ok(()) => forwarded += 1,
            Err(err) => error!(%err, slot, %peer, "Failed to forward range-fetched beacon block"),
        }
    }
    debug!(%peer, start_slot, end_slot, forwarded, "BeaconBlocksByRange batch applied");

    if let Some(state) = &mut server.beacon_range_sync {
        state.complete_batch(end_slot);
        if state.current_range.is_empty() {
            info!(end_slot, "Anchor-to-head range sync complete");
            server.beacon_range_sync = None;
            return;
        }
        if state.peer_set.is_empty() {
            warn!("Anchor-to-head range sync has no peers left; the resync timer will reopen it");
            server.beacon_range_sync = None;
            return;
        }
    }
    request_next_beacon_batch(server).await;
}

/// Drop a peer from the session, and the session itself if it was the last.
pub(crate) fn fail_beacon_range_request(server: &mut P2PServer, peer: &PeerId) {
    server.beacon_peer_heads.remove(peer);
    let emptied = match &mut server.beacon_range_sync {
        Some(state) => {
            state.fail_peer(peer);
            state.peer_set.is_empty()
        }
        None => false,
    };
    if emptied {
        server.beacon_range_sync = None;
    }
}

/// Ask a random connected peer for one block by root.
///
/// The fallback for a block still orphaned after the range fetch has passed its
/// slot: the gap was fetched on the canonical chain, and this block is on a
/// fork off it.
pub(crate) async fn fetch_beacon_block_from_peer(server: &mut P2PServer, root: Root) -> bool {
    let failed = server
        .beacon_pending_root_requests
        .get(&root)
        .map(|pending| &pending.failed_peers);
    let pool: Vec<PeerId> = server
        .connected_peers
        .iter()
        .copied()
        .filter(|peer| failed.is_none_or(|set| !set.contains(peer)))
        .collect();
    // Every peer has failed for this root, so start a fresh round of
    // elimination: peers may have caught up, and new ones may have connected.
    let pool = if pool.is_empty() {
        if let Some(pending) = server.beacon_pending_root_requests.get_mut(&root) {
            pending.failed_peers.clear();
        }
        server.connected_peers.iter().copied().collect()
    } else {
        pool
    };

    let Some(&peer) = pool.choose(&mut rand::thread_rng()) else {
        warn!(%root, "Cannot fetch beacon block: no connected peers");
        return false;
    };

    let mut roots = BeaconRequestedBlockRoots::new();
    roots
        .push(root)
        .expect("one root is within the request list's bound");
    let request = BeaconBlocksByRootRequest { roots };
    let Some(request_id) = server
        .swarm_handle
        .send_request(
            peer,
            Request::BeaconBlocksByRoot(request),
            libp2p::StreamProtocol::new(BEACON_BLOCKS_BY_ROOT_PROTOCOL_V2),
        )
        .await
    else {
        warn!(%root, "Failed to send BeaconBlocksByRoot request");
        return false;
    };

    info!(%peer, %root, "Fetching a still-orphaned beacon block by root");
    server
        .beacon_pending_root_requests
        .entry(root)
        .or_insert(PendingRequest {
            attempts: 1,
            failed_peers: HashSet::new(),
        });
    server
        .outbound_requests
        .insert(request_id, PendingRequestKind::BeaconRoot(root));
    true
}

/// Hand a by-root result to the blockchain actor.
pub(crate) async fn on_beacon_blocks_by_root_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBeaconBlock>,
    peer: PeerId,
    requested_root: Root,
) {
    if blocks.is_empty() {
        warn!(%peer, %requested_root, "Empty BeaconBlocksByRoot response");
        if let Some(pending) = server.beacon_pending_root_requests.get_mut(&requested_root) {
            pending.failed_peers.insert(peer);
        }
        return;
    }
    server.beacon_pending_root_requests.remove(&requested_root);
    let Some(blockchain) = server.blockchain.as_ref() else {
        return;
    };
    for block in blocks {
        if block.message_hash_tree_root() != requested_root {
            warn!(%peer, %requested_root, "Beacon block root mismatch, ignoring");
            continue;
        }
        let _ = blockchain
            .new_beacon_block(block, BlockSource::Sync)
            .inspect_err(|err| error!(%err, "Failed to forward a by-root beacon block"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RangeSyncState;
    use crate::beacon::range_sync::MAX_REQUEST_BLOCKS_DENEB;
    use libp2p::identity::Keypair;

    fn peer_n(n: u8) -> PeerId {
        let mut seed = [0u8; 32];
        seed[0] = n;
        let keypair = Keypair::ed25519_from_bytes(seed).expect("32 bytes is a valid ed25519 seed");
        PeerId::from_public_key(&keypair.public())
    }

    /// `fail_beacon_range_request` without a `P2PServer`: the two effects it
    /// has on the session are the whole of its behaviour, and neither needs a
    /// swarm to observe.
    fn fail(session: &mut Option<RangeSyncState>, peer: &PeerId) {
        let emptied = match session {
            Some(state) => {
                state.fail_peer(peer);
                state.peer_set.is_empty()
            }
            None => false,
        };
        if emptied {
            *session = None;
        }
    }

    #[test]
    fn a_failure_with_another_peer_left_keeps_the_session_open() {
        let mut session = Some(RangeSyncState::with_max_batch(
            65..200,
            peer_n(1),
            199,
            MAX_REQUEST_BLOCKS_DENEB,
        ));
        session.as_mut().unwrap().merge_peer(peer_n(2), 199, 200);
        session.as_mut().unwrap().in_flight = true;

        fail(&mut session, &peer_n(1));

        let state = session.expect("one peer is left");
        assert!(!state.in_flight, "the batch must be reissuable at once");
        assert_eq!(state.current_range.start, 65, "and from the same slot");
        assert_eq!(state.peer_set.len(), 1);
    }

    #[test]
    fn the_last_failure_closes_the_session_for_the_timer_to_reopen() {
        let mut session = Some(RangeSyncState::with_max_batch(
            65..200,
            peer_n(1),
            199,
            MAX_REQUEST_BLOCKS_DENEB,
        ));

        fail(&mut session, &peer_n(1));

        assert!(
            session.is_none(),
            "an empty peer set ends the session; on_beacon_resync_check reopens \
             it once a peer with a higher head is known again"
        );
    }

    #[test]
    fn the_resync_threshold_ignores_a_lag_inside_the_band() {
        // Mirrors the guard in `on_beacon_resync_check`. A one-slot lag is what
        // a healthy follower has for most of every slot, and reopening a
        // session for it would put a request on the wire every 12 seconds
        // forever.
        let local_head_slot = 1_000u64;
        for peer_head in local_head_slot..=(local_head_slot + BEACON_SYNC_LAG_THRESHOLD) {
            assert!(
                peer_head.saturating_sub(local_head_slot) <= BEACON_SYNC_LAG_THRESHOLD,
                "a lag of {} slots must not reopen a session",
                peer_head - local_head_slot
            );
        }
        let over = local_head_slot + BEACON_SYNC_LAG_THRESHOLD + 1;
        assert!(over.saturating_sub(local_head_slot) > BEACON_SYNC_LAG_THRESHOLD);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p --profile release-fast beacon::sync -- --nocapture`
Expected: FAIL, `file not found for module 'sync'`.

- [ ] **Step 3: Declare the module and add the actor state**

Add to `crates/net/p2p/src/beacon/mod.rs`:

```rust
pub(crate) mod sync;
```

In `crates/net/p2p/src/lib.rs`, add to `PendingRequestKind`:

```rust
pub(crate) enum PendingRequestKind {
    Root(H256),
    Range { start_slot: u64, end_slot: u64 },
    /// A beacon anchor-to-head batch, and the slots it covers.
    BeaconRange { start_slot: u64, end_slot: u64 },
    /// One beacon block, fetched because it stayed orphaned after the range
    /// fetch passed its slot.
    BeaconRoot(ethlambda_types::beacon::primitives::Root),
}
```

Add to `P2PServer`, beside `range_sync_state`:

```rust
    /// The open beacon anchor-to-head session, if any.
    pub(crate) beacon_range_sync: Option<RangeSyncState>,
    /// Every connected beacon peer's last advertised head slot.
    ///
    /// Outlives the session on purpose: `on_beacon_resync_check` needs to know
    /// who to reopen a session with after every peer in the previous one
    /// failed, and a `Status` is only exchanged on connect.
    pub(crate) beacon_peer_heads: HashMap<PeerId, u64>,
    /// In-flight `beacon_blocks_by_root/2` fetches, keyed by the requested root.
    pub(crate) beacon_pending_root_requests:
        HashMap<ethlambda_types::beacon::primitives::Root, PendingRequest>,
```

Initialize all three in `P2P::spawn`, beside `range_sync_state: None`:

```rust
            beacon_range_sync: None,
            beacon_peer_heads: HashMap::new(),
            beacon_pending_root_requests: HashMap::new(),
```

Add the timer to the actor protocol in `crates/net/p2p/src/lib.rs`:

```rust
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn beacon_resync_check(&self) -> Result<(), ActorError>;
```

and its handler inside `#[actor(protocol = P2PProtocol)] impl P2PServer`:

```rust
    #[send_handler]
    async fn handle_beacon_resync_check(
        &mut self,
        _msg: p2p_protocol::BeaconResyncCheck,
        ctx: &Context<Self>,
    ) {
        // Reschedule first, so an early return can never stop the loop.
        send_after(
            crate::beacon::range_sync::BEACON_RESYNC_INTERVAL,
            ctx.clone(),
            p2p_protocol::BeaconResyncCheck,
        );
        beacon::sync::on_beacon_resync_check(self).await;
    }
```

Schedule the first tick in `P2P::spawn`, beside the discovery one:

```rust
        send_after(
            crate::beacon::range_sync::BEACON_RESYNC_INTERVAL,
            handle.context(),
            p2p_protocol::BeaconResyncCheck,
        );
```

- [ ] **Step 4: Route the beacon responses**

In `crates/net/p2p/src/req_resp/handlers.rs`, add to the
`request_response::Message::Response` arm's `ResponsePayload` match:

```rust
                        ResponsePayload::BeaconStatus(status) => {
                            crate::beacon::sync::on_beacon_status(server, peer, &status).await;
                        }
                        ResponsePayload::BeaconBlocks(blocks) => {
                            match server.outbound_requests.remove(&request_id) {
                                Some(PendingRequestKind::BeaconRange {
                                    start_slot,
                                    end_slot,
                                }) => {
                                    crate::beacon::sync::on_beacon_blocks_by_range_response(
                                        server, blocks, peer, start_slot, end_slot,
                                    )
                                    .await;
                                }
                                Some(PendingRequestKind::BeaconRoot(root)) => {
                                    crate::beacon::sync::on_beacon_blocks_by_root_response(
                                        server, blocks, peer, root,
                                    )
                                    .await;
                                }
                                other => {
                                    warn!(%peer, ?request_id, "Beacon blocks response for an unexpected request");
                                    if let Some(kind) = other {
                                        server.outbound_requests.insert(request_id, kind);
                                    }
                                }
                            }
                        }
```

and to the `OutboundFailure` arm's match:

```rust
                Some(PendingRequestKind::BeaconRange {
                    start_slot,
                    end_slot,
                }) => {
                    warn!(%peer, start_slot, end_slot, "BeaconBlocksByRange request failed; rotating peer");
                    crate::beacon::sync::fail_beacon_range_request(server, &peer);
                    crate::beacon::sync::request_next_beacon_batch(server).await;
                }
                Some(PendingRequestKind::BeaconRoot(root)) => {
                    warn!(%peer, %root, "BeaconBlocksByRoot request failed");
                    if let Some(pending) = server.beacon_pending_root_requests.get_mut(&root) {
                        pending.failed_peers.insert(peer);
                    }
                }
```

and the same two arms to the `Response::Error` match, which today handles
`PendingRequestKind::{Range, Root}` only:

```rust
                            Some(PendingRequestKind::BeaconRange { .. }) => {
                                crate::beacon::sync::fail_beacon_range_request(server, &peer);
                                crate::beacon::sync::request_next_beacon_batch(server).await;
                            }
                            Some(PendingRequestKind::BeaconRoot(root)) => {
                                if let Some(pending) =
                                    server.beacon_pending_root_requests.get_mut(&root)
                                {
                                    pending.failed_peers.insert(peer);
                                }
                            }
```

An error response is a peer declining to serve, not a transport fault, so it is
handled exactly like an outbound failure: rotate the peer out and keep the
session's range where it is. Nothing is retried in place, because a peer that
answered `RESOURCE_UNAVAILABLE` once will answer it again.

Replace the Task 10 Step 4 stub body of `impl Handler<FetchBeaconBlock>` with
the real one given there.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p --profile release-fast beacon::sync -- --nocapture`
Expected: PASS, 3 tests.

- [ ] **Step 6: Verify the suites**

Run: `make test`
Expected: PASS. The lean range-sync path is untouched: it uses
`PendingRequestKind::{Root, Range}` and `range_sync_state`, none of which moved.

Run: `make lint`
Expected: PASS with no warnings.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -S -m "feat(p2p): drive the beacon anchor-to-head fetch

Status responses open or extend a session, block responses complete a batch
and ask for the next, both kinds of failure rotate the peer out, and a
12-second timer reopens a session that failures closed.

The timer is the one piece lean has no equivalent of. Lean opens a session
from a peer's first Status and never reopens it, which is enough for a node
that joins and catches up once; a follower that must stay at the head
cannot let one bad minute end syncing for the life of the process."
```

---

## Task 12: Buffer and cascade in the beacon block handler

**Files:**
- Modify: `crates/blockchain/src/lib.rs`
- Test: covered by Tasks 7 and 8

- [ ] **Step 1: Add the buffer to the actor state**

In `crates/blockchain/src/lib.rs`, add to `BlockChainServer`:

```rust
    /// Beacon blocks held on a parent the store does not have yet.
    ///
    /// Empty on the lean path: nothing outside `on_beacon_block` touches it.
    beacon_pending: beacon_pending::PendingBeaconBlocks,
```

and to the struct literal in `BlockChain::spawn`:

```rust
            beacon_pending: beacon_pending::PendingBeaconBlocks::new(),
```

- [ ] **Step 2: Replace the beacon block handler body**

Replace `BlockChainServer::on_beacon_block` in `crates/blockchain/src/lib.rs`
with the cascade, keeping whatever plan 3 put inside `import_beacon_block`:

```rust
    /// Process a beacon block, and any held blocks it unblocks.
    ///
    /// Iterative rather than recursive, like the lean cascade above it: an
    /// anchor-to-head gap is dozens of blocks deep and a recursive drain would
    /// put that on the stack.
    ///
    /// `source` reaches this from `P2PToBlockChain::new_beacon_block` and is
    /// only used to count: `lean_sync_range_blocks_total` must count blocks the
    /// node *fetched*, since a counter that also moved on gossip could not tell
    /// a closed gap from a node happily tracking a tip it cannot evaluate.
    /// Blocks released from the buffer inherit their releaser's source, which
    /// is the honest answer: they became importable because of a fetch.
    fn on_beacon_block(&mut self, signed_block: SignedBeaconBlock, source: BlockSource) {
        let mut queue = VecDeque::new();
        queue.push_back(signed_block);
        while let Some(block) = queue.pop_front() {
            self.process_or_hold_beacon_block(block, source, &mut queue);
        }
        metrics::set_sync_pending_blocks(self.beacon_pending.len() as u64);
    }

    /// Import one beacon block, or hold it if the store has no state for its
    /// parent. On success, queue whatever the import unblocked.
    fn process_or_hold_beacon_block(
        &mut self,
        signed_block: SignedBeaconBlock,
        source: BlockSource,
        queue: &mut VecDeque<SignedBeaconBlock>,
    ) {
        let slot = signed_block.slot();
        let block_root = signed_block.message_hash_tree_root();
        let parent_root = signed_block.parent_root();

        let parent_known = self
            .store
            .has_state(&parent_root.into())
            .expect("DB read should succeed");
        if !parent_known {
            match self.beacon_pending.insert(signed_block) {
                beacon_pending::Pending::Full => {
                    warn!(
                        %slot,
                        "Pending beacon block buffer is full; dropping block"
                    );
                    metrics::inc_sync_pending_dropped();
                }
                beacon_pending::Pending::Buffered(missing) => {
                    debug!(
                        %slot,
                        block_root = %block_root,
                        parent_root = %parent_root,
                        missing_ancestor = %missing,
                        "Beacon block parent missing; held"
                    );
                    // Only worth asking for once the range fetch has already
                    // passed this slot. Below that, the batch on the wire will
                    // bring the parent anyway and a by-root request would only
                    // duplicate it.
                    if self.store.head_slot() >= slot {
                        self.request_missing_beacon_block(missing);
                    }
                }
            }
            return;
        }

        match self.import_beacon_block(signed_block) {
            Ok(()) => {
                info!(%slot, block_root = %block_root, "Beacon block imported");
                if source == BlockSource::Sync {
                    metrics::inc_sync_range_blocks();
                }
                for child in self.beacon_pending.take_children(block_root) {
                    queue.push_back(child);
                }
            }
            Err(err) => {
                warn!(%slot, block_root = %block_root, %err, "Failed to import beacon block");
            }
        }
    }

    /// Ask the P2P actor for a block by root.
    fn request_missing_beacon_block(&self, root: ethlambda_types::beacon::primitives::Root) {
        let Some(p2p) = self.p2p.as_ref() else {
            return;
        };
        let _ = p2p
            .fetch_beacon_block(root)
            .inspect_err(|err| warn!(%err, %root, "Failed to request a missing beacon block"));
    }
```

`import_beacon_block` is plan 3's per-block work: `fork_choice::on_block`
followed by `on_attestation(.., is_from_block = true)` for each attestation in
the body. If plan 3 named it differently, or inlined it into `on_beacon_block`,
extract it under this name so the cascade above has one thing to call.

`on_beacon_block` gains a `source` parameter, so update its one caller, the
`Handler<NewBeaconBlock>` impl plan 3 added:

```rust
        self.on_beacon_block(msg.block, msg.source);
```

Add `BlockSource` to the `ethlambda_network_api::{…}` import list at the top of
`crates/blockchain/src/lib.rs` if it is not already there.

- [ ] **Step 3: Prune the buffer when finalization advances**

In the beacon arm of the tick handler, after the finalized checkpoint is read,
add:

```rust
        // A block at or below the finalized slot can never import, so holding
        // it only spends buffer the live fork needs.
        let dropped = self.beacon_pending.prune_below(finalized_slot);
        if dropped > 0 {
            debug!(finalized_slot, dropped, "Pruned held beacon blocks below finalization");
        }
        metrics::set_sync_pending_blocks(self.beacon_pending.len() as u64);
```

- [ ] **Step 4: Verify the suites**

Run: `cargo test -p ethlambda-blockchain --profile release-fast beacon_pending -- --nocapture`
Expected: PASS, 8 tests.

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -S -m "feat(blockchain): hold and cascade beacon blocks on import

A gossip block whose parent the store lacks is held rather than dropped,
and released the moment that parent imports. The by-root fallback fires
only once the range fetch has already passed the held block's slot: below
that, the batch on the wire will bring its parent anyway and a by-root
request would just duplicate it.

Iterative, like the lean cascade beside it: an anchor-to-head gap is dozens
of blocks deep and draining it recursively would put that on the stack."
```

---

## Task 13: Sync status and metrics

**Files:**
- Modify: `crates/blockchain/src/metrics.rs`
- Modify: `crates/blockchain/src/lib.rs`
- Test: `crates/blockchain/src/metrics.rs`

"Head tracks wall clock" cannot be asserted by a test, so it has to be
observable. These four series are what the manual procedure in Task 14 reads,
and together they distinguish the three ways this can go wrong: the fetch never
started, the fetch stalled, and the node is tracking a tip it cannot evaluate.

The existing `lean_head_slot`, `lean_current_slot`, `lean_latest_justified_slot`
and `lean_latest_finalized_slot` are reused rather than duplicated with a
`beacon_` prefix: a process follows one chain, the meaning of each is unchanged,
and every dashboard and the finality alert already read them.

- [ ] **Step 1: Write the failing test**

Add to the test module at the bottom of `crates/blockchain/src/metrics.rs`
(create one if the file has none):

```rust
#[cfg(test)]
mod sync_metric_tests {
    use super::*;

    /// The three anchor-to-head series exist and move. Prometheus registration
    /// panics on a duplicate name, so simply calling each setter once proves
    /// the names do not collide with anything already registered.
    #[test]
    fn the_anchor_to_head_series_register_and_move() {
        set_sync_anchor_slot(12_345);
        set_sync_pending_blocks(7);
        inc_sync_pending_dropped();
        inc_sync_range_blocks();

        let gathered = ethlambda_metrics::gather_default_metrics()
            .expect("metrics gather succeeds");

        for name in [
            "lean_sync_anchor_slot",
            "lean_sync_pending_blocks",
            "lean_sync_pending_dropped_total",
            "lean_sync_range_blocks_total",
        ] {
            assert!(
                gathered.contains(name),
                "{name} must be exported: the manual verification procedure reads it"
            );
        }
        assert!(gathered.contains("lean_sync_anchor_slot 12345"));
        assert!(gathered.contains("lean_sync_pending_blocks 7"));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-blockchain --profile release-fast the_anchor_to_head_series -- --nocapture`
Expected: FAIL, `cannot find function 'set_sync_anchor_slot' in this scope`.

- [ ] **Step 3: Add the metrics**

Add to the gauge block near the top of `crates/blockchain/src/metrics.rs`:

```rust
static LEAN_SYNC_ANCHOR_SLOT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!(
        "lean_sync_anchor_slot",
        "Slot of the checkpoint-sync anchor this process started from"
    )
    .unwrap()
});

static LEAN_SYNC_PENDING_BLOCKS: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!(
        "lean_sync_pending_blocks",
        "Blocks held waiting on a parent the store does not have yet"
    )
    .unwrap()
});

static LEAN_SYNC_PENDING_DROPPED: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_sync_pending_dropped_total",
            "Blocks dropped because the pending buffer was full"
        )
        .unwrap()
    });

static LEAN_SYNC_RANGE_BLOCKS: std::sync::LazyLock<IntCounter> = std::sync::LazyLock::new(|| {
    register_int_counter!(
        "lean_sync_range_blocks_total",
        "Beacon blocks imported while closing the anchor-to-head gap"
    )
    .unwrap()
});
```

and the setters beside the existing ones:

```rust
/// Record the checkpoint-sync anchor slot, once, at startup.
///
/// The floor every other slot series is read against: `lean_head_slot` sitting
/// at this value while `lean_sync_pending_blocks` climbs is the anchor-to-head
/// fetch having never started or never finished.
pub fn set_sync_anchor_slot(slot: u64) {
    LEAN_SYNC_ANCHOR_SLOT.set(slot.try_into().unwrap());
}

pub fn set_sync_pending_blocks(count: u64) {
    LEAN_SYNC_PENDING_BLOCKS.set(count.try_into().unwrap());
}

pub fn inc_sync_pending_dropped() {
    LEAN_SYNC_PENDING_DROPPED.inc();
}

pub fn inc_sync_range_blocks() {
    LEAN_SYNC_RANGE_BLOCKS.inc();
}
```

- [ ] **Step 4: Report the beacon head and sync status each tick**

In the beacon arm of the tick handler in `crates/blockchain/src/lib.rs`, after
`get_head` has run, add the block below. `config`, `genesis_time_ms`,
`head_slot`, `justified_slot` and `finalized_slot` are plan 3's: they are the
values that arm already computes from `get_head` and the store's checkpoints. If
plan 3 spelled any of them differently, use its names.

```rust
        let wall_clock_slot = unix_now_ms().saturating_sub(genesis_time_ms) / 1_000
            / config.seconds_per_slot;
        metrics::update_current_slot(wall_clock_slot);
        metrics::update_head_slot(head_slot);
        metrics::update_latest_justified_slot(justified_slot);
        metrics::update_latest_finalized_slot(finalized_slot);

        // Observe-only on the beacon path: this node publishes nothing, so
        // there are no duties for the gate to suppress. The status is still
        // what `lean_node_sync_status` and `/lean/v0/node/syncing` report, and
        // it is how "head tracks wall clock" is read off a running node.
        let status = self
            .sync_status
            .update(wall_clock_slot, head_slot, wall_clock_slot);
        metrics::set_node_sync_status(status);
        self.sync_status_controller.set(status);
```

The tracker is constructed with `SyncStatusTracker::new(gate_duties)`; the
beacon subcommand passes `gate_duties: false`, since suppressing duties that do
not exist would only make the status harder to read.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p ethlambda-blockchain --profile release-fast the_anchor_to_head_series -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Verify the suites**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make fmt`
Expected: no diff.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -S -m "feat(metrics): make the anchor-to-head fetch observable

Head tracking wall clock is a live-network property no test can assert, so
it has to be readable off a running node. Four series distinguish the three
ways it fails: the fetch never started (head pinned at the anchor slot,
pending climbing), the fetch stalled (range counter flat, pending climbing),
and the node tracking a tip it cannot evaluate (head climbing, finalized
flat).

The existing head/justified/finalized/current gauges are reused rather than
duplicated under a beacon_ prefix: a process follows one chain, the meaning
of each is unchanged, and the dashboards and the finality alert already
read them."
```

---

## Task 14: Document the operator procedure

**Files:**
- Create: `docs/beacon_sync.md`
- Modify: `docs/SUMMARY.md`
- Modify: `docs/checkpoint_sync.md`

- [ ] **Step 1: Write the page**

Create `docs/beacon_sync.md`:

````markdown
# Beacon Chain Sync

How `ethlambda beacon` gets from nothing to following the mainnet head, and how
to tell whether it did.

## Startup order

Checkpoint sync runs **before** the libp2p swarm exists. This is not an
implementation accident:

```
fetch the finalized block         GET /eth/v2/beacon/blocks/finalized
  └─ block.state_root
     └─ fetch that exact state    GET /eth/v2/debug/beacon/states/0x{state_root}
        ├─ genesis_validators_root ─┐
        ├─ genesis_time             ├─► fork digest
        └─ slot ──► epoch ──────────┘      ├─► gossip topic names
                                           ├─► ENR `eth2` entry
                                           └─► discv5 admission
                                                └─► build the swarm
```

`genesis_validators_root` and `genesis_time` are read off the anchor state, and
the fork digest computed from them names every topic this node subscribes to,
the `eth2` entry in its ENR, and the test it applies to every discovered peer.
None of that is knowable earlier, which is why this repository carries **no
hardcoded mainnet genesis-validators-root** anywhere and why
`--checkpoint-sync-url` is required on `beacon` while it is optional on `lean`.

The block is fetched first and the state second, *by that block's own
`state_root`*. The second request is therefore content-addressed, so the pair
cannot disagree and there is no retry loop for a provider that advances
finalization mid-fetch. Lean's client, which fetches both concurrently from
endpoints that each mean "whatever is finalized right now", does need one.

The epoch the digest is computed for is the **wall-clock** epoch, not the
anchor's. The anchor is two epochs behind, so a fork or blob-parameter boundary
falling in between would otherwise leave this node on the previous side of it.

The digest is computed once and never recomputed. A boundary crossed while
running strands the node on topics the network has left, and the only symptom is
peers quietly draining away, so startup logs the next boundary's epoch and
wall-clock time as a warning. Restart before it. Re-subscribing across a
boundary is out of scope here.

### Every boot checkpoint-syncs

`ethlambda beacon` fetches a fresh anchor on every start, including a restart
against a populated `--data-dir`. `--checkpoint-sync-url` is required for the
same reason: the fork digest needs `genesis_validators_root`, and reading that
back off disk needs a beacon equivalent of lean's `Store::from_db_state`, which
is separate work. The cost is one state download per restart; the benefit is
that the node can never boot onto a digest derived from stale data.

## Anchor to head

The anchor is a **finalized** state, roughly two epochs (~64 slots) behind the
live head, and `on_block` refuses a block whose parent is not in the store. So
the first gossiped block at the head lands on a chain this node knows nothing
about:

```
anchor (finalized)                                    head (wall clock)
   |<----------------- ~64 slots to fetch ----------------->|
   |                                                        |
   └─ beacon_blocks_by_range/2, 128 slots per batch, from ───┘
      the highest-head peer; blocks arriving on gossip
      meanwhile are held by parent root and released in
      slot order the moment that parent imports
```

A block still held after the range fetch has passed its slot is on a fork off
the canonical chain, so it is fetched individually with
`beacon_blocks_by_root/2`.

Forward only. Backfill below the anchor, which a node needs before it can serve
historical requests, is a separate piece of work.

### Why this is worth being careful about

The failure mode is not a crash. A follower that imports tip blocks without
fetching the gap has a head that climbs normally and a finalized checkpoint that
never moves, because every block it accepted is orphaned. It looks healthy from
the outside. Several clients on this network have shipped exactly that, and the
metrics below exist to make it visible in seconds rather than days.

## Metrics

| Series | Meaning |
|---|---|
| `lean_sync_anchor_slot` | The checkpoint anchor this process started from. Constant for the life of the process |
| `lean_head_slot` | Current fork-choice head |
| `lean_current_slot` | Wall-clock slot |
| `lean_latest_justified_slot`, `lean_latest_finalized_slot` | The FFG checkpoints |
| `lean_sync_pending_blocks` | Blocks held on a parent the store does not have |
| `lean_sync_pending_dropped_total` | Blocks dropped because that buffer was full |
| `lean_sync_range_blocks_total` | Blocks imported while closing the gap |
| `lean_node_sync_status` | 0 idle, 1 syncing, 2 synced |

Reading them together:

| Symptom | Diagnosis |
|---|---|
| `head_slot == sync_anchor_slot`, `sync_pending_blocks` climbing | The range fetch never started. No peer's `Status` arrived, or every peer is at or behind the anchor |
| `sync_range_blocks_total` flat, `sync_pending_blocks` climbing | The range fetch stalled. Check for `rotating peer` warnings |
| `head_slot` climbing, `latest_finalized_slot` frozen | Tip tracking without backfill, the failure this page is about |
| `sync_pending_dropped_total` rising | A peer is feeding blocks on fabricated parents, or the gap is wider than the buffer |
| `current_slot - head_slot <= 1`, finalized advancing every 32 slots | Healthy |

## Manual verification

No test in this repository can assert that the head tracks wall clock: it needs
reachable mainnet peers and a finalizing chain. This procedure is the check.

### 1. Build and prepare

```bash
make lint && make test && make test-beacon
cargo build --profile release-fast --bin ethlambda
openssl rand -hex 32 > /tmp/beacon-node.key
rm -rf /tmp/beacon-data && mkdir -p /tmp/beacon-data
```

### 2. Run

```bash
./target/release-fast/ethlambda beacon \
  --checkpoint-sync-url https://beaconstate.info \
  --node-key /tmp/beacon-node.key \
  --node-id ethlambda_beacon_0 \
  --data-dir /tmp/beacon-data \
  --gossipsub-port 9000 \
  --api-port 5052 \
  --metrics-port 5054 \
  2>&1 | tee /tmp/beacon-run.log
```

`https://mainnet-checkpoint-sync.attestant.io` is a second provider if the
first is down. Discovery is forced on for `beacon` and its port defaults to
`--gossipsub-port + 1`, so neither needs a flag.

### 3. Watch the log, in order

| Within | Line | What it proves |
|---|---|---|
| ~60s | `Beacon checkpoint sync complete` with `anchor_slot`, `genesis_validators_root`, `fork_digest`, `digest_epoch` | The anchor downloaded and verified. The whole mainnet state is a few hundred megabytes, so this is the slow step |
| immediately after | the same line's `fork_digest` | Must match the digest recorded for the current epoch in [`discovery.md`](./discovery.md). A wrong digest means zero peers, silently |
| immediately after | `Restart this node before the epoch above` with `boundary_epoch` and `boundary_unix_time` | The next boundary is named. If `boundary_unix_time` is in the past, the digest is already stale and no peer will match |
| ~2 min | `Peer connected` at least 8 times | QUIC-only peering found enough of the network. Fewer than 4 after five minutes means the QUIC-only trade-off is biting |
| ~2 min | `Anchor-to-head range sync started` with `gap` near 64 | A peer's `Status` opened a session |
| ~3 min | `Anchor-to-head range sync complete` | The gap closed. A ~64-slot gap is one 128-block batch |
| continuously | `Beacon block imported` roughly every 12s | Gossip is now importable, which it was not before the line above |

### 4. Watch the metrics

```bash
while true; do
  date +%H:%M:%S | tr -d '\n'
  curl -s localhost:5054/metrics \
    | grep -E '^lean_(sync_anchor_slot|head_slot|current_slot|latest_finalized_slot|sync_pending_blocks|sync_range_blocks_total) ' \
    | sed 's/^lean_//' | tr '\n' ' '
  echo
  sleep 12
done
```

### 5. Call it healthy after 15 minutes

Fifteen minutes, not five: two epochs of finalization lag is 12.8 minutes, so a
shorter window cannot distinguish a node that finalizes from one that only
appears to. All five must hold:

```
current_slot - head_slot          <= 1
sync_pending_blocks               == 0
sync_range_blocks_total           >  0        (the gap really was fetched)
latest_finalized_slot             >  sync_anchor_slot
latest_finalized_slot             advanced by >= 32 during the window
```

The fourth and fifth are the ones that matter. A head within one slot of wall
clock proves nothing on its own: that is exactly what the failure mode looks
like.

### 6. Check the restart path

Ctrl-C the node, then start it again with the same command.

Expected: a second `Beacon checkpoint sync complete`, with an
`anchor_slot` **higher** than the first run's, since the chain finalized while
the node was up. `lean_sync_anchor_slot` reports the new one. The node reaches
the head again and §5's five conditions hold within another 15 minutes.

Re-downloading the anchor is the intended behaviour, not a regression: see
"Every boot checkpoint-syncs" above.
````

- [ ] **Step 2: Link it from the book**

In `docs/SUMMARY.md`, add under `# Beacon Chain`:

```markdown
- [Beacon Chain Sync](./beacon_sync.md)
```

- [ ] **Step 3: Cross-reference from the lean page**

In `docs/checkpoint_sync.md`, add immediately after the `## Overview` paragraph:

```markdown
This page describes checkpoint sync for `ethlambda lean`, over the `/lean/v0/…`
endpoints and lean's `State`. `ethlambda beacon` has its own, over the Beacon
API and with a different fetch order and a different set of checks: see
[Beacon Chain Sync](./beacon_sync.md).
```

- [ ] **Step 4: Verify the docs build**

Run: `make docs`
Expected: mdbook builds with no broken-link warnings.

- [ ] **Step 5: Run the manual procedure**

Follow `docs/beacon_sync.md` §2 through §6 end to end and record the observed
values. If any of the five conditions in §5 fails, that is a bug in this plan's
implementation, not in the procedure.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "docs(beacon): the anchor-to-head path and how to verify it

Head tracking wall clock is a live-network property, so 'done' for it is a
written procedure rather than a test: exact command, the log lines in the
order they must appear, the metric expressions, and fifteen minutes as the
wait, because two epochs of finalization lag is 12.8 of them and a shorter
window cannot tell a node that finalizes from one that only looks like it."
```

---

## Done when

**Automated.** Every item below is checked by a command in this repository.

- [ ] `make fmt` produces no diff
- [ ] `make lint` passes with no warnings
- [ ] `make test` passes
- [ ] `make test-beacon` passes both presets with the Task 1 Step 2 counts
      unchanged: mainnet 5705 / 152 ignored, minimal 40009 / 3692 ignored
- [ ] `forward_sync_range` covers the anchor-to-head gap, a peer at or behind
      the local head, and a gap wider than `MAX_BEACON_SYNC_RANGE` (Task 6)
- [ ] `next_request` is correct at every range limit: shorter than the cap,
      longer than the cap, clamped to the chosen peer's own head, blocked while
      a batch is in flight, and advancing after one completes (Task 6)
- [ ] A failed peer is rotated out and the same batch reissued to another; the
      last failure closes the session for the timer to reopen (Tasks 6, 11)
- [ ] `on_block` refuses a block whose parent is not in the store, and the
      refusal is proven load-bearing by breaking it on purpose (Task 9)
- [ ] `tip_blocks_are_not_importable_until_the_gap_is_filled` passes, and fails
      when `take_children` is made to ignore parentage (Task 8)
- [ ] Held blocks drain exactly once, contiguously, in ascending slot order
      (Task 8)
- [ ] The anchor pair is verified before it reaches disk, and the fork comes
      from `Eth-Consensus-Version` or from the slot at its fixed SSZ offset
      (Task 2)
- [ ] `build_swarm` is unreachable without a `BeaconNetworkParams`, which only
      `beacon_network_params` produces and which takes the anchor's own fields
      (Task 3)
- [ ] The lean path is untouched: `RangeSyncState::new` still selects lean's
      cap, and the lean range-sync and pending-block code is unmodified

**Manual.** These are live-network properties. `docs/beacon_sync.md` §2 to §6 is
the procedure; run it and record the values.

- [ ] `Beacon checkpoint sync complete` within ~60s, with a `fork_digest`
      matching the value recorded for the current epoch in `docs/discovery.md`
- [ ] At least 8 `Peer connected` lines within ~2 minutes
- [ ] `Anchor-to-head range sync started` then `complete` within ~3 minutes
- [ ] After 15 minutes: `current_slot - head_slot <= 1`,
      `sync_pending_blocks == 0`, `sync_range_blocks_total > 0`,
      `latest_finalized_slot > sync_anchor_slot`, and `latest_finalized_slot`
      advanced by at least 32 during the window
- [ ] A restart against the same `--data-dir` reaches the head again without
      re-downloading the anchor

This is the last plan in the series. With it green, sub-projects A1 and A2 are
complete and B, C, D and E are unblocked.
