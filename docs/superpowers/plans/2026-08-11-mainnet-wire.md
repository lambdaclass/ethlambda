# Mainnet Wire Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put ethlambda on Ethereum mainnet's wire — mainnet gossipsub topic names and req/resp protocol ids, a fork digest computed from the fork schedule, discv5 forced on with built-in mainnet bootnodes, QUIC-only transport — so that `ethlambda beacon` peers with mainnet and decodes a `beacon_block` within about 30 seconds.

**Architecture:** Everything mainnet-specific lands in a new `crates/net/p2p/src/beacon/` module and a new `ethlambda_types::beacon::fork_digest`. `P2PServer` grows a `Wire` enum with `Lean` and `Beacon` variants so one actor serves both networks, mirroring the single-`match` dispatch plan 3 gives `BlockChainServer`. Six of the twelve tasks add pure, unit-testable pieces (digest, topic names, protocol ids, message containers, bootnodes, decode) before anything touches the swarm, so the tree stays green and the lean path stays untouched until the one mechanical refactor in Task 8.

**Tech Stack:** Rust 1.97.1 (edition 2024), libp2p (LambdaClass fork) with QUIC and gossipsub, ethrex discv5 (`feat/discovery-peer-requirements`), `libssz` / `libssz-derive` / `libssz-merkle` / `libssz-types`, `snap`, `sha2`, `reqwest`.

---

## Plan series

This is plan 4 of 5 for sub-projects A1 and A2 of
`docs/superpowers/specs/2026-08-10-mainnet-network-design.md`. Each plan ends
with a working, testable tree.

| # | Plan | Ends when |
|---|---|---|
| 1 | Beacon type unification | Types live in `ethlambda-types`, `BeaconState::Lean` exists, every fixture suite green |
| 2 | CLI subcommands | `ethlambda lean` and `ethlambda beacon` parse, bare flags still resolve to `lean`, devnet unchanged |
| 3 | Beacon handlers on the DB-backed `Store`, and the `BlockChainServer` variant dispatch (spec §4, §5) | `fork_choice::Store` deleted, all 150 `fork_choice` fixture cases green against `ethlambda_storage::Store` |
| 4 | **Mainnet wire** (this plan) | Node peers with mainnet, decodes a `beacon_block` within ~30s |
| 5 | Anchor and follow | Checkpoint sync, anchor-to-head range fetch, head tracks wall clock |

**Dependencies.** Plans 1, 2 and 3 must be complete before this one starts:

- Plan 1 puts the beacon containers at `ethlambda_types::beacon::*`. Task 1 adds a
  module beside them and Task 6 decodes into them.
- Plan 2 adds `Commands::Beacon(BeaconOptions)` to `bin/ethlambda/src/cli.rs` with
  `--checkpoint-sync-url` required, and the argv-injection that keeps bare flags
  resolving to `lean`. Task 11 fills in the `beacon` arm's body; without plan 2
  there is no arm to fill.
- Plan 3 puts the beacon fork-choice handlers on `ethlambda_storage::Store`. This
  plan does **not** call them: it decodes and counts, and plan 5 wires the decoded
  objects into `BlockChainServer`. The dependency is only that plan 3's `Store`
  changes have already churned `crates/storage`, so doing them after this plan
  would conflict with Task 8.

---

## Deliberate deviations from the spec, and where they land

Read this before Task 1. Each row is a place where this plan does less, or
something different, than `2026-08-10-mainnet-network-design.md` says.

| Spec says | This plan does | Why |
|---|---|---|
| §7 registers `beacon_blocks_by_range/2` and `beacon_blocks_by_root/2` outbound | Does **not** register them | Nothing calls them until plan 5's anchor-to-head fetch. Registering a protocol whose codec arm has no caller means shipping an untested encoder, and `BeaconBlocksByRangeRequest`'s `step` field differs between spec revisions, so the shape would be guessed rather than driven by a consumer. Plan 5 adds both, with the driver that exercises them |
| §7 `seen_ttl` "385s (`SLOTS_PER_EPOCH * SECONDS_PER_SLOT * 2`)" | Uses the formula, which is **768s** on mainnet | The parenthetical number and the parenthetical formula in the spec disagree: `32 * 12 * 2 = 768`, not 385. The formula is the one the beacon p2p interface states, and lean's own `duplicate_cache_time` is written as the same `X * Y * 2` shape, so the formula wins and is written out so it stays self-checking |
| §7 registers `metadata/1,2,3` | Registers all three | The recovered probe registered only `metadata/2` and `metadata/3`. Following the spec here is safe: v1 is a strict prefix of v2, and a peer that asks for v1 gets a correct answer instead of a stream-negotiation refusal. Flagged because it is a widening relative to the probe |
| §7 inbound `status/1,2` answers "a real `Status` built from `Store`" | Answers a `Status` carrying the computed `fork_digest` and **zero** roots, epochs and slots | There is no beacon chain in the store until plan 5. An all-zero `finalized_root` is the honest "we have nothing" answer, and lighthouse's relevance check explicitly excludes `Hash256::zero()` from its finalized-root comparison, so a zero Status is read as "peer is syncing" rather than `IrrelevantPeer`. This is exactly why the probe kept its peers. Plan 5 replaces it with the store-derived Status |
| §11 "Decode: fork-aware decode driven by the `ssz_static` fixtures already in the tree" | Round-trips containers built in-test | `ssz_static` lives under `consensus-spec-tests/`, which only `make test-beacon` downloads; `ethlambda-p2p`'s tests run under `make test`. More importantly `ssz_static` gates container *shapes*, which `make test-beacon` already does — what this plan adds is *fork selection from a slot*, and a round-trip through `decode_gossip` targets exactly that |
| §8 decode hands objects to the handlers | Decodes, logs and counts; forwards nothing | Driving `on_block` / `on_attestation` is spec §9, which is plan 5 |
| §6 startup derives every parameter from the **anchor state** | Derives them from `GET /eth/v1/beacon/genesis` | The anchor state is a ~350 MB download that plan 5 owns. `genesis_time` and `genesis_validators_root` are the only two fields the digest needs, and the Beacon API serves both in a ~200-byte JSON from the same `--checkpoint-sync-url`. Plan 5 replaces the call and must check the two agree |

---

## File structure

| File | Responsibility |
|---|---|
| `crates/common/types/src/beacon/fork_digest.rs` | **Create.** `compute_fork_data_root`, fulu's `compute_fork_digest` (EIP-7892), `next_fork_boundary` |
| `crates/common/types/src/beacon/mod.rs` | **Modify.** Add `pub mod fork_digest;` |
| `crates/beacon/src/helpers/misc.rs` | **Modify.** `compute_fork_data_root` becomes a re-export of the moved one |
| `crates/net/p2p/src/beacon/mod.rs` | **Create.** Module root; the networking constants `config.rs` deliberately excludes |
| `crates/net/p2p/src/beacon/topics.rs` | **Create.** The 7 gossip topic names and `BeaconTopics` |
| `crates/net/p2p/src/beacon/protocols.rs` | **Create.** Req/resp protocol id strings and the registration list |
| `crates/net/p2p/src/beacon/messages.rs` | **Create.** `Status` v1/v2, `MetaData` v1/2/3, `Ping`, `Goodbye` |
| `crates/net/p2p/src/beacon/bootnodes.rs` | **Create.** The built-in `eth-clients/mainnet` ENR list |
| `crates/net/p2p/src/beacon/enr.rs` | **Create.** The mainnet `ENRForkID`, `attnets`, `cgc` entries |
| `crates/net/p2p/src/beacon/decode.rs` | **Create.** Fork-aware SSZ decode of every subscribed topic |
| `crates/net/p2p/src/beacon/swarm.rs` | **Create.** `build_beacon_swarm` |
| `crates/net/p2p/src/beacon/handler.rs` | **Create.** Beacon gossip handler, handshake, inbound responder |
| `crates/net/p2p/src/lib.rs` | **Modify.** `Wire` enum, `LeanWire`, shared gossipsub config, dispatch |
| `crates/net/p2p/src/gossipsub/handler.rs` | **Modify.** Read the lean topics off `Wire::Lean` |
| `crates/net/p2p/src/req_resp/messages.rs` | **Modify.** `Request`/`ResponsePayload` gain a `Beacon` arm |
| `crates/net/p2p/src/req_resp/codec.rs` | **Modify.** Encode/decode the beacon protocols |
| `crates/net/p2p/src/req_resp/handlers.rs` | **Modify.** Route `Request::Beacon` to the beacon responder |
| `crates/net/p2p/src/discovery/mod.rs` | **Modify.** Take the fork id and `cgc` from config instead of `EnrForkId::local()` |
| `crates/net/p2p/src/discovery/enr.rs` | **Modify.** Same, plus the `cgc` entry |
| `crates/net/p2p/src/metrics.rs` | **Modify.** Beacon gossip counter and fork-digest gauge |
| `crates/net/p2p/Cargo.toml` | **Modify.** Promote `hex` to a real dependency |
| `bin/ethlambda/src/beacon.rs` | **Create.** `ethlambda beacon`'s startup path |
| `bin/ethlambda/src/main.rs` | **Modify.** Call it from plan 2's `beacon` arm; adapt to `BuiltSwarm.wire` |
| `docs/beacon_wire.md` | **Create.** Operator-facing description of the mainnet wire |
| `docs/SUMMARY.md` | **Modify.** Register the new page |
| `docs/discovery.md` | **Modify.** Point the probe section at the shipped code |

---

## Task 1: Compute the fork digest from the fork schedule

**Files:**
- Create: `crates/common/types/src/beacon/fork_digest.rs`
- Modify: `crates/common/types/src/beacon/mod.rs`
- Modify: `crates/beacon/src/helpers/misc.rs`
- Test: `crates/common/types/src/beacon/fork_digest.rs`

`compute_fork_data_root` lives in `ethlambda-beacon` today, but `ethlambda-p2p`
needs the digest and must not depend on `ethlambda-beacon` (that would drag
`blst` and `c-kzg` into the networking crate). It moves to `ethlambda-types`
beside the `ForkData` container it hashes, and `ethlambda-beacon` re-exports it
at its old path — the same pattern plan 1 used for every moved module.

- [ ] **Step 1: Write the failing tests**

Create `crates/common/types/src/beacon/fork_digest.rs` with only its test module
for now:

```rust
//! The four bytes that separate one network, fork, and blob schedule from
//! another on the wire.
//!
//! Lives here rather than in `ethlambda-beacon` because the networking crate
//! needs it and must not depend on the state transition: `ethlambda-beacon`
//! pulls in `blst` and `c-kzg`, neither of which a gossip topic name has any
//! business requiring. `ethlambda_beacon::helpers::misc` re-exports
//! [`compute_fork_data_root`] at its old path.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::config::Config;
    use crate::beacon::primitives::Root;

    /// Ethereum mainnet's `genesis_validators_root`.
    fn mainnet_gvr() -> Root {
        Root::from_slice(
            &hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .expect("valid hex"),
        )
    }

    #[test]
    fn mainnet_digests_match_the_ones_observed_on_the_wire() {
        // Every value here was read off a live mainnet discv5 crawl and is
        // recorded in docs/discovery.md. Both branches of the fulu rule are
        // covered: the pre-fulu truncation and the EIP-7892 blob-parameter xor.
        let config = Config::mainnet();
        let gvr = mainnet_gvr();
        let cases = [
            // phase0, still advertised by bootnode records never re-published.
            (0u64, [0xb5, 0x30, 0x3f, 0x2a]),
            // electra.
            (364_032u64, [0xad, 0x53, 0x2c, 0xeb]),
            // fulu, before the first blob-schedule entry: the parameters fall
            // back to (electra_fork_epoch, max_blobs_per_block_electra).
            (411_392u64, [0xcc, 0x2c, 0x5c, 0xdb]),
            // fulu, first BPO fork.
            (412_672u64, [0xcb, 0x0d, 0x1a, 0xcc]),
            // fulu, second BPO fork: mainnet's current digest.
            (419_072u64, [0x8c, 0x9f, 0x62, 0xfe]),
        ];
        for (epoch, expected) in cases {
            assert_eq!(
                compute_fork_digest(&config, gvr, epoch),
                expected,
                "digest at epoch {epoch}"
            );
        }
    }

    #[test]
    fn the_digest_holds_between_boundaries() {
        // A digest that changed every epoch would mean the node re-subscribed
        // constantly; it must only move at a fork or blob-schedule boundary.
        let config = Config::mainnet();
        let gvr = mainnet_gvr();
        assert_eq!(
            compute_fork_digest(&config, gvr, 419_072),
            compute_fork_digest(&config, gvr, 419_072 + 5_000)
        );
        assert_ne!(
            compute_fork_digest(&config, gvr, 419_071),
            compute_fork_digest(&config, gvr, 419_072)
        );
    }

    #[test]
    fn next_boundary_covers_both_fork_and_blob_schedule_epochs() {
        let config = Config::mainnet();
        // A plain fork boundary.
        assert_eq!(next_fork_boundary(&config, 0), Some(74_240));
        // A blob-parameter-only fork is a boundary too: it moves the digest.
        assert_eq!(next_fork_boundary(&config, 411_392), Some(412_672));
        assert_eq!(next_fork_boundary(&config, 412_672), Some(419_072));
        // Past the last scheduled boundary there is nothing left to warn about.
        assert_eq!(next_fork_boundary(&config, 419_072), None);
    }

    #[test]
    fn far_future_forks_are_not_boundaries() {
        // Minimal leaves every fork after phase0 at FAR_FUTURE_EPOCH, which is a
        // real, enormous Epoch rather than a None; treating it as a boundary
        // would schedule a warning for the heat death of the universe.
        assert_eq!(next_fork_boundary(&Config::minimal(), 0), None);
    }

    #[test]
    fn fork_data_root_binds_the_version_and_the_chain() {
        let a = compute_fork_data_root([1, 0, 0, 0], Root::zero());
        let b = compute_fork_data_root([2, 0, 0, 0], Root::zero());
        let c = compute_fork_data_root([1, 0, 0, 0], Root::repeat_byte(1));
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
```

Add to `crates/common/types/src/beacon/mod.rs`, keeping the existing modules in
alphabetical position:

```rust
pub mod fork_digest;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-types fork_digest -- --nocapture`
Expected: FAIL, `cannot find function 'compute_fork_digest' in this scope`.

- [ ] **Step 3: Write the implementation**

Insert above the `#[cfg(test)] mod tests` block in
`crates/common/types/src/beacon/fork_digest.rs`:

```rust
use sha2::{Digest as _, Sha256};

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::shared::ForkData;
use crate::beacon::fork::ForkName;
use crate::beacon::primitives::{Epoch, ForkDigest, HashTreeRoot as _, Root, Version};

/// The root binding a fork version to a chain's genesis validator set.
///
/// Mixing both into every signing domain and into the fork digest is what keeps
/// a signature, or a gossip topic, from one chain or fork from being valid on
/// another.
pub fn compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root {
    ForkData {
        current_version,
        genesis_validators_root,
    }
    .hash_tree_root()
}

/// The blob parameters in effect at `epoch`, as `(epoch, max_blobs_per_block)`.
///
/// Mirrors `get_blob_parameters`: the schedule is searched backward for the
/// first entry at or before `epoch`, falling back to electra's fixed pair when
/// the schedule is empty or every entry is still in the future. The fallback's
/// *epoch* matters as much as its limit, because both are hashed below.
fn blob_parameters(config: &Config, epoch: Epoch) -> (Epoch, u64) {
    config
        .blob_schedule
        .iter()
        .rev()
        .find(|entry| entry.epoch <= epoch)
        .map(|entry| (entry.epoch, entry.max_blobs_per_block))
        .unwrap_or((config.electra_fork_epoch, config.max_blobs_per_block_electra))
}

/// The four bytes every gossip topic name and the `eth2` ENR entry carry, for a
/// chain with this schedule, this genesis validator set, and this epoch.
///
/// This is fulu's `compute_fork_digest` (EIP-7892). Before fulu the digest is
/// simply the fork data root's first four bytes. From fulu on, the blob
/// parameters are xored in, so that a blob-parameter-only fork moves the digest
/// and therefore the topic names without needing a new fork version.
pub fn compute_fork_digest(
    config: &Config,
    genesis_validators_root: Root,
    epoch: Epoch,
) -> ForkDigest {
    let fork = config.fork_at_epoch(epoch);
    let base = compute_fork_data_root(config.fork_version(fork), genesis_validators_root);

    if epoch < config.fulu_fork_epoch {
        return base.0[..4].try_into().expect("a Root is 32 bytes");
    }

    let (bp_epoch, bp_max_blobs) = blob_parameters(config, epoch);
    let mut hasher = Sha256::new();
    hasher.update(bp_epoch.to_le_bytes());
    hasher.update(bp_max_blobs.to_le_bytes());
    let mask = hasher.finalize();

    let mut digest = [0u8; 4];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = base.0[index] ^ mask[index];
    }
    digest
}

/// The next epoch at which [`compute_fork_digest`] changes, if there is one.
///
/// Both fork activations and blob-schedule entries qualify: crossing either one
/// strands a running node on topic names no peer is publishing to. Unscheduled
/// forks carry [`constants::FAR_FUTURE_EPOCH`], a real value rather than a
/// `None`, so they are filtered out before the minimum is taken.
pub fn next_fork_boundary(config: &Config, epoch: Epoch) -> Option<Epoch> {
    ForkName::ALL
        .into_iter()
        .map(|fork| config.fork_epoch(fork))
        .chain(config.blob_schedule.iter().map(|entry| entry.epoch))
        .filter(|&boundary| boundary != constants::FAR_FUTURE_EPOCH && boundary > epoch)
        .min()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-types fork_digest -- --nocapture`
Expected: PASS, all five tests.

- [ ] **Step 5: Re-export from the beacon crate**

In `crates/beacon/src/helpers/misc.rs`, delete the `compute_fork_data_root`
function body and its doc comment, and replace them with a re-export placed
directly under the `use` block:

```rust
pub use ethlambda_types::beacon::fork_digest::compute_fork_data_root;
```

Then delete the now-unused import of `ForkData` from that file's `use
crate::containers::shared::{ForkData, SigningData};`, leaving:

```rust
use crate::containers::shared::SigningData;
```

`compute_domain` in the same file keeps calling `compute_fork_data_root`
unqualified, and so does the file's own
`domain_carries_the_type_then_the_fork_data_prefix` test; both now resolve
through the re-export.

- [ ] **Step 6: Verify the suites**

Run: `make test-beacon`
Expected: PASS for both presets, with the fixture counts from plan 1:
mainnet 5705 cases / 152 ignored, minimal 40009 / 3692.

Run: `make test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -S -m "feat(types): compute the fork digest from the fork schedule

The gossip topic names and the eth2 ENR entry both need it, and both live
in ethlambda-p2p, which must not depend on ethlambda-beacon: that crate
pulls in blst and c-kzg, neither of which a topic name should require. So
compute_fork_data_root moves next to the ForkData it hashes and the beacon
crate re-exports it, exactly as plan 1 moved everything else.

The fulu branch is EIP-7892's: a blob-parameter-only fork perturbs the
digest, so mainnet's is 8c9f62fe rather than fulu's bare 82fae541. All
five vectors in the test were read off a live crawl."
```

---

## Task 2: Beacon gossip topic names

**Files:**
- Create: `crates/net/p2p/src/beacon/mod.rs`
- Create: `crates/net/p2p/src/beacon/topics.rs`
- Modify: `crates/net/p2p/src/lib.rs`
- Modify: `crates/net/p2p/Cargo.toml`
- Test: `crates/net/p2p/src/beacon/topics.rs`

Seven topics, no subnet families. The exclusion is a deliberate design decision
(spec §7), so it gets a test of its own rather than being left implicit in the
length of an array.

- [ ] **Step 1: Declare the module before it exists**

Create `crates/net/p2p/src/beacon/mod.rs`:

```rust
//! Ethereum mainnet's wire: topic names, req/resp protocol ids, ENR entries,
//! bootnodes, and fork-aware decode.
//!
//! Nothing here is shared with lean. What *is* shared is one layer down: the
//! discv5 stack in [`crate::discovery`], the `ssz_snappy` framing in
//! [`crate::req_resp::encoding`], and `compute_message_id` in [`crate`], all of
//! which are the beacon spec's to begin with.

pub mod topics;

/// Beacon-chain networking constants.
///
/// `ethlambda_types::beacon::config` deliberately carries no networking values
/// (see its module doc), so subnet counts and the custody requirement live with
/// the code that reads them.
pub mod constants {
    /// `ATTESTATION_SUBNET_COUNT`. The `attnets` bitfield is this wide even
    /// though this node subscribes to none of them.
    pub const ATTESTATION_SUBNET_COUNT: u64 = 64;

    /// `SYNC_COMMITTEE_SUBNET_COUNT`. The width of `MetaData`'s `syncnets`.
    pub const SYNC_COMMITTEE_SUBNET_COUNT: usize = 4;

    /// `CUSTODY_REQUIREMENT`. Advertised in the `cgc` ENR entry and in
    /// `MetaData` v3 even though nothing is custodied until data availability
    /// lands: peers may reject a lower value outright, which would defeat the
    /// mode.
    pub const CUSTODY_REQUIREMENT: u64 = 4;
}
```

Add to `crates/net/p2p/src/lib.rs`, beside the other module declarations:

```rust
pub mod beacon;
```

`hex` is currently a dev-dependency of `ethlambda-p2p` and is about to be used
by non-test code. In `crates/net/p2p/Cargo.toml`, move it: delete the
`[dev-dependencies]` block's `hex.workspace = true` line and add to
`[dependencies]`, beside `sha2`:

```toml
hex.workspace = true
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p beacon::topics -- --nocapture`
Expected: FAIL to compile, `file not found for module 'topics'`.

- [ ] **Step 3: Write the module and its tests**

Create `crates/net/p2p/src/beacon/topics.rs`:

```rust
//! The gossipsub topics `ethlambda beacon` subscribes to.
//!
//! Seven global topics and no subnet family. The rule is that this node
//! subscribes only to what it consumes, so `beacon_attestation_{0..63}`,
//! `sync_committee_{0..3}`, `data_column_sidecar_{0..127}` and
//! `blob_sidecar_{subnet_id}` are all absent; each arrives with the sub-project
//! that reads it. That is 7 subscriptions rather than 203.

use ethlambda_types::beacon::primitives::ForkDigest;
use libp2p::gossipsub::IdentTopic;

/// Topic kind for beacon block gossip.
pub const BEACON_BLOCK: &str = "beacon_block";
/// Topic kind for aggregated attestations with their selection proofs.
pub const BEACON_AGGREGATE_AND_PROOF: &str = "beacon_aggregate_and_proof";
/// Topic kind for voluntary exits.
pub const VOLUNTARY_EXIT: &str = "voluntary_exit";
/// Topic kind for proposer slashings.
pub const PROPOSER_SLASHING: &str = "proposer_slashing";
/// Topic kind for attester slashings.
pub const ATTESTER_SLASHING: &str = "attester_slashing";
/// Topic kind for BLS-to-execution withdrawal credential changes.
pub const BLS_TO_EXECUTION_CHANGE: &str = "bls_to_execution_change";
/// Topic kind for aggregated sync committee contributions.
pub const SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF: &str = "sync_committee_contribution_and_proof";

/// Every topic kind this node subscribes to, in the order they are subscribed.
pub const SUBSCRIBED_TOPIC_KINDS: [&str; 7] = [
    BEACON_BLOCK,
    BEACON_AGGREGATE_AND_PROOF,
    VOLUNTARY_EXIT,
    PROPOSER_SLASHING,
    ATTESTER_SLASHING,
    BLS_TO_EXECUTION_CHANGE,
    SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF,
];

/// Build one topic name: `/eth2/{fork_digest}/{kind}/ssz_snappy`.
///
/// `fork_digest` is lowercase hex with no `0x` prefix, which is what every
/// beacon client emits and what the topic hash is therefore taken over.
pub fn topic_name(fork_digest: ForkDigest, kind: &str) -> String {
    format!("/eth2/{}/{kind}/ssz_snappy", hex::encode(fork_digest))
}

/// The topic kind embedded in a full topic name, or `None` if the name is not
/// shaped like a beacon topic.
///
/// `/eth2/{digest}/{kind}/ssz_snappy` splits on `/` into
/// `["", "eth2", digest, kind, "ssz_snappy"]`, so the kind is at index 3 —
/// the same index lean's `/leanconsensus/…` names put it at.
pub fn topic_kind(topic: &str) -> Option<&str> {
    topic.split('/').nth(3)
}

/// The subscribed topics for one fork digest, built once at startup.
#[derive(Debug, Clone)]
pub struct BeaconTopics {
    pub fork_digest: ForkDigest,
    /// Parallel to [`SUBSCRIBED_TOPIC_KINDS`].
    pub topics: Vec<IdentTopic>,
}

impl BeaconTopics {
    pub fn new(fork_digest: ForkDigest) -> Self {
        let topics = SUBSCRIBED_TOPIC_KINDS
            .iter()
            .map(|kind| IdentTopic::new(topic_name(fork_digest, kind)))
            .collect();
        Self {
            fork_digest,
            topics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet's current digest, per docs/discovery.md.
    const MAINNET: ForkDigest = [0x8c, 0x9f, 0x62, 0xfe];

    #[test]
    fn topic_names_are_the_mainnet_strings() {
        assert_eq!(
            topic_name(MAINNET, BEACON_BLOCK),
            "/eth2/8c9f62fe/beacon_block/ssz_snappy"
        );
        assert_eq!(
            topic_name(MAINNET, BEACON_AGGREGATE_AND_PROOF),
            "/eth2/8c9f62fe/beacon_aggregate_and_proof/ssz_snappy"
        );
        assert_eq!(
            topic_name(MAINNET, SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF),
            "/eth2/8c9f62fe/sync_committee_contribution_and_proof/ssz_snappy"
        );
    }

    #[test]
    fn the_digest_is_lowercase_hex_without_a_prefix() {
        // A leading 0x, uppercase, or a Debug-formatted byte array would all
        // produce a topic hash no peer agrees with, and gossipsub would report
        // a healthy mesh of zero peers rather than an error.
        let name = topic_name([0x0a, 0xbc, 0xde, 0xf0], BEACON_BLOCK);
        assert!(name.starts_with("/eth2/0abcdef0/"), "got {name}");
    }

    #[test]
    fn subscriptions_are_exactly_the_seven_global_topics() {
        let topics = BeaconTopics::new(MAINNET);
        assert_eq!(topics.topics.len(), 7);
    }

    #[test]
    fn no_subnet_family_is_subscribed() {
        // The narrow subscription set is a design decision, not an accident of
        // how many topics happened to be listed: widening it is what pulls in
        // ~30k BLS verifications per epoch and the whole column bandwidth.
        let excluded = [
            "beacon_attestation_",
            "sync_committee_",
            "blob_sidecar_",
            "data_column_sidecar_",
        ];
        for topic in BeaconTopics::new(MAINNET).topics {
            let name = topic.to_string();
            for prefix in excluded {
                let subnet_topic = format!("/eth2/8c9f62fe/{prefix}");
                assert!(
                    !name.starts_with(&subnet_topic),
                    "{name} is a {prefix} subnet topic"
                );
            }
        }
    }

    #[test]
    fn topic_kind_reads_the_name_back() {
        for kind in SUBSCRIBED_TOPIC_KINDS {
            assert_eq!(topic_kind(&topic_name(MAINNET, kind)), Some(kind));
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p beacon::topics -- --nocapture`
Expected: PASS, all five tests.

- [ ] **Step 5: Verify the lean suite**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "feat(p2p): the seven mainnet gossip topics

Seven global topics and no subnet family, per the design's
subscribe-only-what-you-consume rule. The exclusion has its own test:
it is a decision worth ~30k BLS verifications an epoch plus the whole
column bandwidth, not an accident of how many names were listed.

The digest is formatted as lowercase hex with no prefix because that is
what the topic hash is taken over; getting it wrong yields a healthy mesh
of zero peers rather than an error."
```

---

## Task 3: Beacon req/resp protocol ids

**Files:**
- Create: `crates/net/p2p/src/beacon/protocols.rs`
- Modify: `crates/net/p2p/src/beacon/mod.rs`
- Test: `crates/net/p2p/src/beacon/protocols.rs`

Every string here was read verbatim off the `mainnet_gossip` probe binary, which
completed the handshake against live mainnet clients. `metadata/1` is the one
addition; see the deviations table.

- [ ] **Step 1: Declare the module before it exists**

Add to `crates/net/p2p/src/beacon/mod.rs`, above `pub mod topics;`:

```rust
pub mod protocols;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p beacon::protocols -- --nocapture`
Expected: FAIL to compile, `file not found for module 'protocols'`.

- [ ] **Step 3: Write the module and its tests**

Create `crates/net/p2p/src/beacon/protocols.rs`:

```rust
//! The request/response protocols `ethlambda beacon` registers.
//!
//! Registered by direction, following the same subscribe-only-what-you-consume
//! rule the topics follow. `beacon_blocks_by_{range,root}/2` are deliberately
//! absent: nothing calls them until the anchor-to-head fetch lands, and an
//! unregistered protocol is refused at stream negotiation rather than answered
//! with a lie. The sidecar protocols are absent for the same reason.

use libp2p::StreamProtocol;
use libp2p::request_response::ProtocolSupport;

pub const STATUS_V1: &str = "/eth2/beacon_chain/req/status/1/ssz_snappy";
pub const STATUS_V2: &str = "/eth2/beacon_chain/req/status/2/ssz_snappy";
pub const PING_V1: &str = "/eth2/beacon_chain/req/ping/1/ssz_snappy";
pub const METADATA_V1: &str = "/eth2/beacon_chain/req/metadata/1/ssz_snappy";
pub const METADATA_V2: &str = "/eth2/beacon_chain/req/metadata/2/ssz_snappy";
pub const METADATA_V3: &str = "/eth2/beacon_chain/req/metadata/3/ssz_snappy";
pub const GOODBYE_V1: &str = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy";

/// The protocols this node registers, with the direction it supports each in.
///
/// `goodbye/1` is inbound only: this node logs the reason code a peer sends and
/// never sends one itself, because it has no opinion worth disconnecting over.
/// Everything else is bidirectional, since the handshake runs in both
/// directions on every connection.
pub fn registrations() -> Vec<(StreamProtocol, ProtocolSupport)> {
    vec![
        (StreamProtocol::new(STATUS_V1), ProtocolSupport::Full),
        (StreamProtocol::new(STATUS_V2), ProtocolSupport::Full),
        (StreamProtocol::new(PING_V1), ProtocolSupport::Full),
        (StreamProtocol::new(METADATA_V1), ProtocolSupport::Full),
        (StreamProtocol::new(METADATA_V2), ProtocolSupport::Full),
        (StreamProtocol::new(METADATA_V3), ProtocolSupport::Full),
        (StreamProtocol::new(GOODBYE_V1), ProtocolSupport::Inbound),
    ]
}

/// Short label for the `protocol` dimension on req/resp size metrics.
pub fn label(protocol: &str) -> Option<&'static str> {
    match protocol {
        STATUS_V1 => Some("beacon_status_v1"),
        STATUS_V2 => Some("beacon_status_v2"),
        PING_V1 => Some("beacon_ping"),
        METADATA_V1 => Some("beacon_metadata_v1"),
        METADATA_V2 => Some("beacon_metadata_v2"),
        METADATA_V3 => Some("beacon_metadata_v3"),
        GOODBYE_V1 => Some("beacon_goodbye"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ids_are_the_mainnet_strings() {
        // Read verbatim off the mainnet_gossip probe binary, which completed
        // the handshake against live mainnet clients with exactly these.
        assert_eq!(STATUS_V1, "/eth2/beacon_chain/req/status/1/ssz_snappy");
        assert_eq!(STATUS_V2, "/eth2/beacon_chain/req/status/2/ssz_snappy");
        assert_eq!(PING_V1, "/eth2/beacon_chain/req/ping/1/ssz_snappy");
        assert_eq!(METADATA_V2, "/eth2/beacon_chain/req/metadata/2/ssz_snappy");
        assert_eq!(METADATA_V3, "/eth2/beacon_chain/req/metadata/3/ssz_snappy");
        assert_eq!(GOODBYE_V1, "/eth2/beacon_chain/req/goodbye/1/ssz_snappy");
    }

    #[test]
    fn every_registration_has_a_metric_label() {
        for (protocol, _) in registrations() {
            assert!(
                label(protocol.as_ref()).is_some(),
                "{protocol} has no metric label"
            );
        }
    }

    #[test]
    fn goodbye_is_inbound_only() {
        let goodbye = registrations()
            .into_iter()
            .find(|(protocol, _)| protocol.as_ref() == GOODBYE_V1)
            .expect("goodbye is registered");
        assert!(matches!(goodbye.1, ProtocolSupport::Inbound));
    }

    #[test]
    fn no_block_or_sidecar_protocol_is_registered() {
        // Deliberate: nothing consumes them until the anchor-to-head fetch
        // lands, and a registered protocol with no caller is an untested
        // encoder that peers can reach.
        let absent = [
            "beacon_blocks_by_range",
            "beacon_blocks_by_root",
            "blob_sidecars_by_range",
            "blob_sidecars_by_root",
            "data_column_sidecars_by_range",
            "data_column_sidecars_by_root",
        ];
        for (protocol, _) in registrations() {
            for name in absent {
                assert!(
                    !protocol.as_ref().contains(name),
                    "{protocol} must not be registered yet"
                );
            }
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p beacon::protocols -- --nocapture`
Expected: PASS, all four tests.

- [ ] **Step 5: Verify the lean suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "feat(p2p): the beacon req/resp protocol ids

Verbatim from the probe binary that completed the handshake against live
mainnet clients. metadata/1 is added on top of what the probe registered:
v1 is a strict prefix of v2, so a peer asking for it gets a real answer
instead of a stream-negotiation refusal.

The block and sidecar protocols stay unregistered, with a test saying so.
Registering one with no caller ships an encoder nothing exercises but
peers can reach; they arrive with the fetch that needs them."
```

---

## Task 4: Beacon req/resp message containers

**Files:**
- Create: `crates/net/p2p/src/beacon/messages.rs`
- Modify: `crates/net/p2p/src/beacon/mod.rs`
- Test: `crates/net/p2p/src/beacon/messages.rs`

Every one of these is a fixed-size SSZ container, so the wire sizes are exact
constants and a wrong field order shows up as a length mismatch rather than as a
silently misparsed peer.

- [ ] **Step 1: Declare the module before it exists**

Add to `crates/net/p2p/src/beacon/mod.rs`, in alphabetical position among the
module declarations:

```rust
pub mod messages;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p beacon::messages -- --nocapture`
Expected: FAIL to compile, `file not found for module 'messages'`.

- [ ] **Step 3: Write the module and its tests**

Create `crates/net/p2p/src/beacon/messages.rs`:

```rust
//! The beacon request/response payloads this node speaks.
//!
//! All fixed-size, so every one has an exact wire length. The tests assert
//! those lengths, which is what catches a reordered or mistyped field: SSZ has
//! no field names on the wire, so a swapped pair of same-width fields is
//! otherwise invisible until a peer disagrees about our chain.

use ethlambda_types::beacon::primitives::{Epoch, ForkDigest, Root, Slot};
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszBitvector;

use super::constants::{ATTESTATION_SUBNET_COUNT, SYNC_COMMITTEE_SUBNET_COUNT};

/// `attnets`: which attestation subnets a node serves.
pub type AttnetsBits = SszBitvector<{ ATTESTATION_SUBNET_COUNT as usize }>;
/// `syncnets`: which sync committee subnets a node serves.
pub type SyncnetsBits = SszBitvector<SYNC_COMMITTEE_SUBNET_COUNT>;

/// `Status` v1: the pre-fulu handshake.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct StatusV1 {
    pub fork_digest: ForkDigest,
    pub finalized_root: Root,
    pub finalized_epoch: Epoch,
    pub head_root: Root,
    pub head_slot: Slot,
}

/// `Status` v2: v1 plus the oldest slot the peer can serve, which fulu adds so
/// a peer can advertise how far its backfill reaches.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct StatusV2 {
    pub fork_digest: ForkDigest,
    pub finalized_root: Root,
    pub finalized_epoch: Epoch,
    pub head_root: Root,
    pub head_slot: Slot,
    pub earliest_available_slot: Slot,
}

/// A `Status` in whichever version the negotiated protocol asked for.
///
/// The version is a property of the stream, not of the value, so it is carried
/// alongside the fields rather than being recovered from them: v1 and v2 differ
/// only by a trailing `uint64`, which SSZ cannot tell apart from a truncated
/// v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconStatus {
    V1(StatusV1),
    V2(StatusV2),
}

impl BeaconStatus {
    pub fn fork_digest(&self) -> ForkDigest {
        match self {
            BeaconStatus::V1(status) => status.fork_digest,
            BeaconStatus::V2(status) => status.fork_digest,
        }
    }

    pub fn head_slot(&self) -> Slot {
        match self {
            BeaconStatus::V1(status) => status.head_slot,
            BeaconStatus::V2(status) => status.head_slot,
        }
    }

    pub fn finalized_epoch(&self) -> Epoch {
        match self {
            BeaconStatus::V1(status) => status.finalized_epoch,
            BeaconStatus::V2(status) => status.finalized_epoch,
        }
    }
}

/// `Ping`, and its response: a metadata sequence number, so a peer can tell
/// whether the `MetaData` it holds for us is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode)]
pub struct Ping {
    pub seq_number: u64,
}

/// `Goodbye`: a reason code. This node only ever receives one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode)]
pub struct Goodbye {
    pub reason: u64,
}

/// `MetaData` v1: phase0.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct MetaDataV1 {
    pub seq_number: u64,
    pub attnets: AttnetsBits,
}

/// `MetaData` v2: altair adds the sync committee subnets.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct MetaDataV2 {
    pub seq_number: u64,
    pub attnets: AttnetsBits,
    pub syncnets: SyncnetsBits,
}

/// `MetaData` v3: fulu adds the custody group count.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct MetaDataV3 {
    pub seq_number: u64,
    pub attnets: AttnetsBits,
    pub syncnets: SyncnetsBits,
    pub custody_group_count: u64,
}

/// A `MetaData` in whichever version the negotiated protocol asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconMetaData {
    V1(MetaDataV1),
    V2(MetaDataV2),
    V3(MetaDataV3),
}

#[cfg(test)]
mod tests {
    use super::*;
    use libssz::{SszDecode as _, SszEncode as _};

    fn status_v2() -> StatusV2 {
        StatusV2 {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            finalized_root: Root::repeat_byte(1),
            finalized_epoch: 419_072,
            head_root: Root::repeat_byte(2),
            head_slot: 13_410_304,
            earliest_available_slot: 13_400_000,
        }
    }

    #[test]
    fn status_has_the_spec_wire_lengths() {
        // v1: 4 + 32 + 8 + 32 + 8. v2 appends one more uint64.
        let v1 = StatusV1 {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            finalized_root: Root::repeat_byte(1),
            finalized_epoch: 419_072,
            head_root: Root::repeat_byte(2),
            head_slot: 13_410_304,
        };
        assert_eq!(v1.to_ssz().len(), 84);
        assert_eq!(status_v2().to_ssz().len(), 92);
    }

    #[test]
    fn status_round_trips() {
        let encoded = status_v2().to_ssz();
        assert_eq!(StatusV2::from_ssz_bytes(&encoded).unwrap(), status_v2());
    }

    #[test]
    fn a_v2_status_does_not_decode_as_v1() {
        // The two differ only by a trailing uint64, so this is the one thing
        // that stops a v1 stream from silently accepting a v2 payload.
        assert!(StatusV1::from_ssz_bytes(&status_v2().to_ssz()).is_err());
    }

    #[test]
    fn metadata_has_the_spec_wire_lengths() {
        // v1: 8 + 8 (64 bits of attnets). v2 adds 1 byte of syncnets. v3 adds
        // a uint64 custody group count.
        let v1 = MetaDataV1 {
            seq_number: 0,
            attnets: AttnetsBits::default(),
        };
        let v2 = MetaDataV2 {
            seq_number: 0,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
        };
        let v3 = MetaDataV3 {
            seq_number: 0,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
            custody_group_count: super::super::constants::CUSTODY_REQUIREMENT,
        };
        assert_eq!(v1.to_ssz().len(), 16);
        assert_eq!(v2.to_ssz().len(), 17);
        assert_eq!(v3.to_ssz().len(), 25);
    }

    #[test]
    fn metadata_round_trips() {
        let v3 = MetaDataV3 {
            seq_number: 7,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
            custody_group_count: 4,
        };
        let encoded = v3.to_ssz();
        assert_eq!(MetaDataV3::from_ssz_bytes(&encoded).unwrap(), v3);
    }

    #[test]
    fn ping_and_goodbye_are_bare_uint64s() {
        assert_eq!(Ping { seq_number: 3 }.to_ssz().len(), 8);
        assert_eq!(Goodbye { reason: 1 }.to_ssz().len(), 8);
        assert_eq!(
            Ping::from_ssz_bytes(&Ping { seq_number: 3 }.to_ssz()).unwrap(),
            Ping { seq_number: 3 }
        );
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p beacon::messages -- --nocapture`
Expected: PASS, all six tests.

If `status_has_the_spec_wire_lengths` reports 92 for v1, the `earliest_available_slot`
field was added to the wrong struct. If `metadata_has_the_spec_wire_lengths`
reports 24 for v3, `SYNC_COMMITTEE_SUBNET_COUNT` is being read as 0 rather than
4 and `syncnets` collapsed to no bytes.

- [ ] **Step 5: Verify the lean suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "feat(p2p): the beacon Status, Ping, MetaData and Goodbye payloads

All fixed-size, so the tests assert exact wire lengths. SSZ carries no
field names, so a swapped pair of same-width fields is invisible until a
peer disagrees about our chain; a length assertion is the cheapest thing
that catches it at build time.

Status v1 and v2 differ only by a trailing uint64, which SSZ cannot tell
from a truncated v2, so the version rides alongside the value rather than
being recovered from it."
```

---

## Task 5: The built-in mainnet bootnode list

**Files:**
- Create: `crates/net/p2p/src/beacon/bootnodes.rs`
- Modify: `crates/net/p2p/src/beacon/mod.rs`
- Test: `crates/net/p2p/src/beacon/bootnodes.rs`

`ethlambda beacon` must work with no extra flags, and none of these records is
statically dialable — every one advertises `udp` and none advertises `quic` — so
discovery is not an optimization here, it is the only way to peer at all.

- [ ] **Step 1: Declare the module before it exists**

Add to `crates/net/p2p/src/beacon/mod.rs`, in alphabetical position:

```rust
pub mod bootnodes;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p beacon::bootnodes -- --nocapture`
Expected: FAIL to compile, `file not found for module 'bootnodes'`.

- [ ] **Step 3: Write the module and its tests**

Create `crates/net/p2p/src/beacon/bootnodes.rs`:

```rust
//! Ethereum mainnet's consensus-layer bootnodes.
//!
//! Copied from `eth-clients/mainnet`'s `metadata/bootstrap_nodes.yaml`, with the
//! maintainer comments kept so a stale entry can be traced back to whoever runs
//! it. `--bootnodes` overrides the whole list.
//!
//! Not one of these advertises a `quic` entry, so `build_beacon_swarm` dials
//! none of them: they are discv5 seeds only. That is why discovery is forced on
//! for the beacon subcommand rather than being a flag.

/// The ENRs `ethlambda beacon` seeds discv5 from when `--bootnodes` is unset.
pub const MAINNET_BOOTNODES: [&str; 17] = [
    // Teku team's bootnodes
    // 3.147.37.0 | aws-us-east-2-ohio
    "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo",
    // 3.107.124.68 | aws-ap-southeast-2-sydney
    "enr:-Iu4QEDJ4Wa_UQNbK8Ay1hFEkXvd8psolVK6OhfTL9irqz3nbXxxWyKwEplPfkju4zduVQj6mMhUCm9R2Lc4YM5jPcIBgmlkgnY0gmlwhANrfESJc2VjcDI1NmsxoQJCYz2-nsqFpeEj6eov9HSi9QssIVIVNr0I89J1vXM9foN0Y3CCIyiDdWRwgiMo",
    // Prylab team's bootnodes
    // 18.223.219.100 | aws-us-east-2-ohio
    "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
    // 18.223.219.100 | aws-us-east-2-ohio
    "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
    // 18.223.219.100 | aws-us-east-2-ohio
    "enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg",
    // Lighthouse team's bootnodes
    // 172.105.173.25 | linode-au-sydney
    "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
    // 139.162.196.49 | linode-uk-london
    "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
    // 139.99.217.220 | ovh-au-sydney
    "enr:-Le4QH6LQrusDbAHPjU_HcKOuMeXfdEB5NJyXgHWFadfHgiySqeDyusQMvfphdYWOzuSZO9Uq2AMRJR5O4ip7OvVma8BhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY9ncg2lwNpAkAh8AgQIBAAAAAAAAAAmXiXNlY3AyNTZrMaECDYCZTZEksF-kmgPholqgVt8IXr-8L7Nu7YrZ7HUpgxmDdWRwgiMohHVkcDaCI4I",
    // 139.99.78.39 | ovh-singapore
    "enr:-Le4QIqLuWybHNONr933Lk0dcMmAB5WgvGKRyDihy1wHDIVlNuuztX62W51voT4I8qD34GcTEOTmag1bcdZ_8aaT4NUBhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY04ng2lwNpAkAh8AgAIBAAAAAAAAAA-fiXNlY3AyNTZrMaEDscnRV6n1m-D9ID5UsURk0jsoKNXt1TIrj8uKOGW6iluDdWRwgiMohHVkcDaCI4I",
    // EF bootnodes
    // 3.17.30.69 | aws-us-east-2-ohio
    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
    // 18.216.248.220 | aws-us-east-2-ohio
    "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
    // 54.178.44.198 | aws-ap-northeast-1-tokyo
    "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
    // 54.65.172.253 | aws-ap-northeast-1-tokyo
    "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",
    // Nimbus team's bootnodes
    // 3.120.104.18 | aws-eu-central-1-frankfurt
    "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
    // 3.64.117.223 | aws-eu-central-1-frankfurt
    "enr:-LK4QKWrXTpV9T78hNG6s8AM6IO4XH9kFT91uZtFg1GcsJ6dKovDOr1jtAAFPnS2lvNltkOGA9k29BUN7lFh_sjuc9QBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhANAdd-Jc2VjcDI1NmsxoQLQa6ai7y9PMN5hpLe5HmiJSlYzMuzP7ZhwRiwHvqNXdoN0Y3CCI4yDdWRwgiOM",
    // Lodestar team's bootnodes
    // 160.119.254.161 | hostafrica-southafrica
    "enr:-IS4QPi-onjNsT5xAIAenhCGTDl4z-4UOR25Uq-3TmG4V3kwB9ljLTb_Kp1wdjHNj-H8VVLRBSSWVZo3GUe3z6k0E-IBgmlkgnY0gmlwhKB3_qGJc2VjcDI1NmsxoQMvAfgB4cJXvvXeM6WbCG86CstbSxbQBSGx31FAwVtOTYN1ZHCCIyg",
    // 83.229.71.210 | kamatera-telaviv-israel
    "enr:-KG4QPUf8-g_jU-KrwzG42AGt0wWM1BTnQxgZXlvCEIfTQ5hSmptkmgmMbRkpOqv6kzb33SlhPHJp7x4rLWWiVq5lSECgmlkgnY0gmlwhFPlR9KDaXA2kCoGxcAJAAAVAAAAAAAAABCJc2VjcDI1NmsxoQLdUv9Eo9sxCt0tc_CheLOWnX59yHJtkBSOL7kpxdJ6GYN1ZHCCIyiEdWRwNoIjKA",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_enrs;

    #[test]
    fn every_bootnode_parses() {
        let parsed = parse_enrs(MAINNET_BOOTNODES.iter().map(|s| s.to_string()).collect());
        assert_eq!(
            parsed.len(),
            MAINNET_BOOTNODES.len(),
            "a bootnode ENR failed to parse; parse_enrs warns per skipped entry"
        );
    }

    #[test]
    fn every_bootnode_can_seed_discv5() {
        // A record with no `udp` entry contributes nothing to discovery, and
        // since none of these is dialable over QUIC either, such an entry would
        // be dead weight in the list.
        let parsed = parse_enrs(MAINNET_BOOTNODES.iter().map(|s| s.to_string()).collect());
        for bootnode in &parsed {
            assert!(
                bootnode.as_discovery_node().is_some(),
                "a mainnet bootnode advertises no udp port"
            );
        }
    }

    #[test]
    fn no_bootnode_is_statically_dialable() {
        // This is why discovery is forced on for the beacon subcommand: with no
        // `quic` entry there is nothing for build_beacon_swarm to dial, so a
        // node relying on the static list alone would peer with nobody.
        let parsed = parse_enrs(MAINNET_BOOTNODES.iter().map(|s| s.to_string()).collect());
        assert!(
            parsed.iter().all(|bootnode| bootnode.quic_port.is_none()),
            "a mainnet bootnode now advertises quic; static dialing could be re-enabled"
        );
    }
}
```

`Bootnode::quic_port` and `Bootnode::as_discovery_node` are `pub(crate)` in
`crates/net/p2p/src/lib.rs`, so the test module reaches them without any
visibility change.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p beacon::bootnodes -- --nocapture`
Expected: PASS, all three tests.

- [ ] **Step 5: Check the list against upstream**

The list above was captured on 2026-08-11. Confirm it still matches:

```bash
gh repo clone eth-clients/mainnet "${TMPDIR:-/tmp}/eth-clients-mainnet" -- --depth 1
grep -c '^- enr:' "${TMPDIR:-/tmp}/eth-clients-mainnet/metadata/bootstrap_nodes.yaml"
```

Expected: `17`. If the count differs, diff the ENR strings and update
`MAINNET_BOOTNODES` before committing; a stale bootnode is a slow start, not a
failure, so this is a freshness check rather than a gate.

- [ ] **Step 6: Verify the lean suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -S -m "feat(p2p): built-in mainnet bootnodes

Seventeen records from eth-clients/mainnet, maintainer comments kept so a
stale entry can be traced to whoever runs it.

Not one advertises a quic entry, which is the whole reason discovery is
forced on for the beacon subcommand: with nothing statically dialable, a
node relying on the bootnode list alone peers with nobody. There is a test
that fails if that ever stops being true."
```

---

## Task 6: Fork-aware gossip decode

**Files:**
- Create: `crates/net/p2p/src/beacon/decode.rs`
- Modify: `crates/net/p2p/src/beacon/mod.rs`
- Test: `crates/net/p2p/src/beacon/decode.rs`

The SSZ type of a payload depends on the fork, which depends on the slot, which
is inside the payload. Only three of the seven topics need this: the other four
carry containers whose shape is identical from the fork that introduced them
through fulu.

- [ ] **Step 1: Declare the module before it exists**

Add to `crates/net/p2p/src/beacon/mod.rs`, in alphabetical position:

```rust
pub mod decode;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p beacon::decode -- --nocapture`
Expected: FAIL to compile, `file not found for module 'decode'`.

- [ ] **Step 3: Write the module and its tests**

Create `crates/net/p2p/src/beacon/decode.rs`:

```rust
//! Fork-aware decode of every subscribed gossip topic.
//!
//! SSZ carries no type tag, so the fork has to come from context. For three
//! topics the context is inside the payload: the slot sits at a position fixed
//! by the container's layout, and slot maps to epoch maps to [`ForkName`]. The
//! other four topics carry containers whose shape has not changed since the
//! fork that introduced them, so they decode with no fork lookup at all.
//!
//! | Topic | Fork-dependent |
//! |---|---|
//! | `beacon_block` | Yes, every fork |
//! | `beacon_aggregate_and_proof` | Yes, at electra |
//! | `attester_slashing` | Yes, at electra |
//! | `voluntary_exit`, `proposer_slashing` | No |
//! | `bls_to_execution_change` | No, capella onward |
//! | `sync_committee_contribution_and_proof` | No, altair onward |

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{
    SignedBeaconBlock, altair, capella, electra, phase0, shared,
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::Slot;
use libssz::SszDecode as _;

use super::topics;

/// An aggregate attestation with its selection proof, in whichever shape the
/// slot's fork gives it. Electra widened `Attestation` with `committee_bits`.
#[derive(Debug, Clone, PartialEq)]
pub enum SignedAggregateAndProof {
    Phase0(phase0::SignedAggregateAndProof),
    Electra(electra::SignedAggregateAndProof),
}

/// Slashing evidence, in whichever shape the slot's fork gives it. Electra
/// widened `IndexedAttestation`'s committee bound.
#[derive(Debug, Clone, PartialEq)]
pub enum AttesterSlashing {
    Phase0(phase0::AttesterSlashing),
    Electra(electra::AttesterSlashing),
}

/// A decoded gossip payload, one variant per subscribed topic.
#[derive(Debug, Clone, PartialEq)]
pub enum BeaconGossip {
    Block(Box<SignedBeaconBlock>),
    AggregateAndProof(Box<SignedAggregateAndProof>),
    AttesterSlashing(Box<AttesterSlashing>),
    VoluntaryExit(shared::SignedVoluntaryExit),
    ProposerSlashing(shared::ProposerSlashing),
    BlsToExecutionChange(capella::SignedBLSToExecutionChange),
    SyncCommitteeContribution(Box<altair::SignedContributionAndProof>),
}

impl BeaconGossip {
    /// The topic kind this payload came from, for logs and metrics.
    pub fn topic_kind(&self) -> &'static str {
        match self {
            BeaconGossip::Block(_) => topics::BEACON_BLOCK,
            BeaconGossip::AggregateAndProof(_) => topics::BEACON_AGGREGATE_AND_PROOF,
            BeaconGossip::AttesterSlashing(_) => topics::ATTESTER_SLASHING,
            BeaconGossip::VoluntaryExit(_) => topics::VOLUNTARY_EXIT,
            BeaconGossip::ProposerSlashing(_) => topics::PROPOSER_SLASHING,
            BeaconGossip::BlsToExecutionChange(_) => topics::BLS_TO_EXECUTION_CHANGE,
            BeaconGossip::SyncCommitteeContribution(_) => {
                topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A topic this node never subscribed to.
    UnknownTopic,
    /// The payload is shorter than the offsets it claims to carry.
    Truncated,
    /// SSZ rejected the payload for the fork the slot selected.
    Ssz,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTopic => write!(f, "unsubscribed topic"),
            Self::Truncated => write!(f, "payload truncated before the slot"),
            Self::Ssz => write!(f, "ssz decode failed"),
        }
    }
}

/// The four-byte little-endian SSZ offset at `at`.
fn read_offset(bytes: &[u8], at: usize) -> Result<usize, DecodeError> {
    let raw: [u8; 4] = bytes
        .get(at..at + 4)
        .ok_or(DecodeError::Truncated)?
        .try_into()
        .expect("the slice is exactly four bytes");
    Ok(u32::from_le_bytes(raw) as usize)
}

/// The eight-byte little-endian `uint64` at `at`.
fn read_u64(bytes: &[u8], at: usize) -> Result<u64, DecodeError> {
    let raw: [u8; 8] = bytes
        .get(at..at + 8)
        .ok_or(DecodeError::Truncated)?
        .try_into()
        .expect("the slice is exactly eight bytes");
    Ok(u64::from_le_bytes(raw))
}

/// The `slot` of a `SignedBeaconBlock`.
///
/// The container's fixed part is the offset to `message` followed by
/// `signature`, so the first variable element starts at the offset the first
/// four bytes carry, and `BeaconBlock`'s own first field is `slot`. Reading the
/// offset rather than assuming its value keeps this correct even if a future
/// fork adds a fixed field ahead of `message`.
pub fn block_slot(bytes: &[u8]) -> Result<Slot, DecodeError> {
    read_u64(bytes, read_offset(bytes, 0)?)
}

/// The `slot` of a `SignedAggregateAndProof`.
///
/// `message` is the first variable element of the outer container.
/// `AggregateAndProof`'s fixed part is `aggregator_index`, then the offset to
/// `aggregate`, then `selection_proof`, so the aggregate's offset sits eight
/// bytes into the message. `Attestation`'s fixed part opens with the offset to
/// `aggregation_bits` and is followed immediately by `data`, whose first field
/// is `slot`, at every fork.
pub fn aggregate_slot(bytes: &[u8]) -> Result<Slot, DecodeError> {
    let message = read_offset(bytes, 0)?;
    let aggregate = message
        .checked_add(read_offset(bytes, message.checked_add(8).ok_or(DecodeError::Truncated)?)?)
        .ok_or(DecodeError::Truncated)?;
    read_u64(bytes, aggregate.checked_add(4).ok_or(DecodeError::Truncated)?)
}

/// The `slot` of an `AttesterSlashing`, taken from its first attestation.
///
/// The container is two offsets. `IndexedAttestation`'s fixed part opens with
/// the offset to `attesting_indices` and is followed immediately by `data`.
pub fn attester_slashing_slot(bytes: &[u8]) -> Result<Slot, DecodeError> {
    let attestation_1 = read_offset(bytes, 0)?;
    read_u64(
        bytes,
        attestation_1.checked_add(4).ok_or(DecodeError::Truncated)?,
    )
}

/// The fork whose rules apply to `slot`.
pub fn fork_at_slot(config: &Config, slot: Slot) -> ForkName {
    config.fork_at_epoch(slot / preset::SLOTS_PER_EPOCH)
}

/// Decode a decompressed gossip payload according to its topic kind.
///
/// The caller has already snappy-decompressed and already matched the topic
/// against the subscribed set, so an `UnknownTopic` here means the gossipsub
/// subscription set and this function have drifted apart.
pub fn decode_gossip(
    config: &Config,
    topic_kind: &str,
    bytes: &[u8],
) -> Result<BeaconGossip, DecodeError> {
    match topic_kind {
        topics::BEACON_BLOCK => {
            let fork = fork_at_slot(config, block_slot(bytes)?);
            SignedBeaconBlock::from_ssz(fork, bytes)
                .map(|block| BeaconGossip::Block(Box::new(block)))
                .map_err(|_| DecodeError::Ssz)
        }
        topics::BEACON_AGGREGATE_AND_PROOF => {
            let fork = fork_at_slot(config, aggregate_slot(bytes)?);
            let decoded = if fork >= ForkName::Electra {
                electra::SignedAggregateAndProof::from_ssz_bytes(bytes)
                    .map(SignedAggregateAndProof::Electra)
            } else {
                phase0::SignedAggregateAndProof::from_ssz_bytes(bytes)
                    .map(SignedAggregateAndProof::Phase0)
            };
            decoded
                .map(|value| BeaconGossip::AggregateAndProof(Box::new(value)))
                .map_err(|_| DecodeError::Ssz)
        }
        topics::ATTESTER_SLASHING => {
            let fork = fork_at_slot(config, attester_slashing_slot(bytes)?);
            let decoded = if fork >= ForkName::Electra {
                electra::AttesterSlashing::from_ssz_bytes(bytes).map(AttesterSlashing::Electra)
            } else {
                phase0::AttesterSlashing::from_ssz_bytes(bytes).map(AttesterSlashing::Phase0)
            };
            decoded
                .map(|value| BeaconGossip::AttesterSlashing(Box::new(value)))
                .map_err(|_| DecodeError::Ssz)
        }
        topics::VOLUNTARY_EXIT => shared::SignedVoluntaryExit::from_ssz_bytes(bytes)
            .map(BeaconGossip::VoluntaryExit)
            .map_err(|_| DecodeError::Ssz),
        topics::PROPOSER_SLASHING => shared::ProposerSlashing::from_ssz_bytes(bytes)
            .map(BeaconGossip::ProposerSlashing)
            .map_err(|_| DecodeError::Ssz),
        topics::BLS_TO_EXECUTION_CHANGE => {
            capella::SignedBLSToExecutionChange::from_ssz_bytes(bytes)
                .map(BeaconGossip::BlsToExecutionChange)
                .map_err(|_| DecodeError::Ssz)
        }
        topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF => {
            altair::SignedContributionAndProof::from_ssz_bytes(bytes)
                .map(|value| BeaconGossip::SyncCommitteeContribution(Box::new(value)))
                .map_err(|_| DecodeError::Ssz)
        }
        _ => Err(DecodeError::UnknownTopic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::primitives::{BlsSignature, Bytes32, Root};
    use libssz::SszEncode as _;

    /// The first slot of `epoch`.
    fn slot_of(epoch: u64) -> Slot {
        epoch * preset::SLOTS_PER_EPOCH
    }

    fn phase0_block(slot: Slot) -> phase0::SignedBeaconBlock {
        phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 7,
                parent_root: Root::repeat_byte(1),
                state_root: Root::repeat_byte(2),
                body: phase0::BeaconBlockBody {
                    randao_reveal: BlsSignature::default(),
                    eth1_data: shared::Eth1Data::default(),
                    graffiti: Bytes32::zero(),
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: BlsSignature::default(),
        }
    }

    #[test]
    fn the_preset_is_mainnet() {
        // Every epoch computed here divides by this. If `preset-minimal` ever
        // leaks into ethlambda-p2p's feature resolution, the beacon wire would
        // silently compute epochs eight slots wide and pick the wrong fork.
        assert_eq!(preset::SLOTS_PER_EPOCH, 32);
    }

    #[test]
    fn block_slot_is_read_from_the_encoding() {
        let slot = slot_of(1_000);
        let bytes = phase0_block(slot).to_ssz();
        assert_eq!(block_slot(&bytes), Ok(slot));
    }

    #[test]
    fn fork_selection_follows_the_mainnet_schedule() {
        let config = Config::mainnet();
        let boundaries = [
            (0u64, ForkName::Phase0),
            (74_240, ForkName::Altair),
            (144_896, ForkName::Bellatrix),
            (194_048, ForkName::Capella),
            (269_568, ForkName::Deneb),
            (364_032, ForkName::Electra),
            (411_392, ForkName::Fulu),
        ];
        for (epoch, fork) in boundaries {
            assert_eq!(fork_at_slot(&config, slot_of(epoch)), fork, "epoch {epoch}");
            if epoch > 0 {
                assert_ne!(
                    fork_at_slot(&config, slot_of(epoch) - 1),
                    fork,
                    "the slot before epoch {epoch} must still be the previous fork"
                );
            }
        }
    }

    #[test]
    fn a_phase0_block_round_trips_through_decode_gossip() {
        let config = Config::mainnet();
        let block = phase0_block(slot_of(10));
        let decoded =
            decode_gossip(&config, topics::BEACON_BLOCK, &block.to_ssz()).expect("decodes");
        assert_eq!(
            decoded,
            BeaconGossip::Block(Box::new(SignedBeaconBlock::Phase0(block)))
        );
        assert_eq!(decoded.topic_kind(), topics::BEACON_BLOCK);
    }

    #[test]
    fn the_slot_actually_drives_which_shape_is_decoded() {
        // A phase0-shaped payload whose slot lands in fulu must be refused, not
        // decoded as phase0. Without this, `decode_gossip` could ignore the
        // slot entirely and every test above would still pass.
        let config = Config::mainnet();
        let bytes = phase0_block(slot_of(config.fulu_fork_epoch)).to_ssz();
        assert_eq!(
            decode_gossip(&config, topics::BEACON_BLOCK, &bytes),
            Err(DecodeError::Ssz)
        );
    }

    #[test]
    fn a_voluntary_exit_needs_no_fork_lookup() {
        let config = Config::mainnet();
        let exit = shared::SignedVoluntaryExit::default();
        let decoded =
            decode_gossip(&config, topics::VOLUNTARY_EXIT, &exit.to_ssz()).expect("decodes");
        assert_eq!(decoded, BeaconGossip::VoluntaryExit(exit));
    }

    #[test]
    fn a_proposer_slashing_needs_no_fork_lookup() {
        let config = Config::mainnet();
        let slashing = shared::ProposerSlashing::default();
        let decoded =
            decode_gossip(&config, topics::PROPOSER_SLASHING, &slashing.to_ssz()).expect("decodes");
        assert_eq!(decoded, BeaconGossip::ProposerSlashing(slashing));
    }

    #[test]
    fn an_unsubscribed_topic_is_refused() {
        let config = Config::mainnet();
        assert_eq!(
            decode_gossip(&config, "beacon_attestation_3", &[0u8; 8]),
            Err(DecodeError::UnknownTopic)
        );
    }

    #[test]
    fn a_truncated_payload_is_refused_rather_than_panicking() {
        // Every slot read indexes into attacker-supplied bytes, so this is the
        // property that stops a two-byte gossip message from taking the node
        // down.
        let config = Config::mainnet();
        for length in 0..16 {
            let bytes = vec![0xffu8; length];
            for kind in topics::SUBSCRIBED_TOPIC_KINDS {
                let result = decode_gossip(&config, kind, &bytes);
                assert!(result.is_err(), "{kind} accepted {length} junk bytes");
            }
        }
    }
}
```

The test module builds only phase0 containers, whose every field has a zero
value reachable through `Default::default()`, `BlsSignature::default()`,
`Eth1Data::default()` or `Bytes32::zero()`. No later fork's `BeaconBlockBody`
derives `Default` (they carry an `ExecutionPayload`), which is why the fulu case
above is expressed as a refused decode rather than as a constructed block.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p beacon::decode -- --nocapture`
Expected: PASS, all nine tests.

If `the_preset_is_mainnet` fails, something in the workspace has turned on
`ethlambda-types/preset-minimal` for a build that reaches `ethlambda-p2p`; fix
that rather than the assertion.

- [ ] **Step 5: Verify the lean suite**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "feat(p2p): fork-aware decode of every subscribed beacon topic

SSZ has no type tag, so the fork comes from the slot, which is inside the
payload. Three of the seven topics need that; the other four carry shapes
that have not moved since the fork that introduced them.

Each slot read walks the container's own offsets rather than assuming
where they land, and every read is bounds-checked: these bytes come from
gossip, so a two-byte message must be a counted drop and not a panic.
There is a test that feeds every topic sixteen lengths of junk."
```

---

## Task 7: Parameterise the ENR and admission on a supplied fork id

**Files:**
- Modify: `crates/net/p2p/src/discovery/enr.rs`
- Modify: `crates/net/p2p/src/discovery/mod.rs`
- Modify: `crates/net/p2p/src/lib.rs`
- Modify: `bin/ethlambda/src/main.rs`
- Test: `crates/net/p2p/src/discovery/enr.rs`

Today `LocalEnrParams::local_pairs` hardcodes `EnrForkId::local()` and publishes
no `cgc`. The beacon wire needs a computed fork id and a custody group count,
and the dial loop needs to compare against that fork id rather than lean's. This
task changes no lean behavior: the lean caller passes `EnrForkId::local()` and
`None`, which is what the code does today.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/net/p2p/src/discovery/enr.rs`:

```rust
    #[test]
    fn the_published_fork_id_is_the_one_supplied() {
        // Lean's is a compile-time constant, but the beacon wire computes its
        // digest from the fork schedule at startup, so the ENR builder must not
        // reach for EnrForkId::local() behind the caller's back.
        let supplied = EnrForkId {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            next_fork_version: [0x06, 0x00, 0x00, 0x00],
            next_fork_epoch: u64::MAX,
        };
        let record = build_local_enr(&LocalEnrParams {
            signer: test_signer(),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            quic_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 64,
            fork_id: supplied,
            custody_group_count: None,
        })
        .expect("ENR builds");

        let raw = read_extra(&record, ETH2_ENR_KEY).expect("eth2 entry present");
        assert_eq!(EnrForkId::from_ssz_bytes(&raw).unwrap(), supplied);
    }

    #[test]
    fn the_custody_group_count_is_published_only_when_asked_for() {
        // Lean has no data-availability domain, so publishing a cgc there would
        // advertise a claim with no meaning behind it.
        let record = build();
        assert_eq!(read_extra(&record, CGC_ENR_KEY), None);

        let with_cgc = build_local_enr(&LocalEnrParams {
            signer: test_signer(),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            quic_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 64,
            fork_id: EnrForkId::local(),
            custody_group_count: Some(4),
        })
        .expect("ENR builds");
        assert_eq!(with_cgc.pairs().extra_int::<u64>(CGC_ENR_KEY), Some(4));
    }

    #[test]
    fn a_sixty_four_wide_attnets_is_eight_bytes_of_zeroes() {
        // What a node subscribing to no attestation subnet actually serves.
        // Publishing a shorter bitfield would be a different claim: readers
        // treat bits past the end as unset, but the beacon spec's attnets is a
        // fixed-width Bitvector and a short one is malformed to a strict reader.
        let record = build_local_enr(&LocalEnrParams {
            signer: test_signer(),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            quic_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 64,
            fork_id: EnrForkId::local(),
            custody_group_count: Some(4),
        })
        .expect("ENR builds");
        assert_eq!(read_extra(&record, ATTNETS_ENR_KEY), Some(vec![0u8; 8]));
    }
```

The existing `build()` helper in that module must gain the two new fields so it
keeps compiling; that is Step 3.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p discovery::enr -- --nocapture`
Expected: FAIL to compile, `struct 'LocalEnrParams' has no field named 'fork_id'`.

- [ ] **Step 3: Add the two fields**

In `crates/net/p2p/src/discovery/enr.rs`, add the key constant beside the others:

```rust
pub const CGC_ENR_KEY: &[u8] = b"cgc";
```

Add the two fields to `LocalEnrParams`:

```rust
    pub subscription_subnets: HashSet<u64>,
    pub attestation_committee_count: u64,
    /// The `eth2` entry to publish.
    ///
    /// Lean's is a compile-time constant, but the beacon wire computes its
    /// digest from the fork schedule and the anchor's genesis validators root
    /// at startup, so this cannot be reached for internally.
    pub fork_id: EnrForkId,
    /// The `cgc` entry to publish, or `None` to omit it.
    ///
    /// `Some(CUSTODY_REQUIREMENT)` on the beacon wire, even though nothing is
    /// custodied yet: peers may reject a lower value outright, which would
    /// defeat the mode. `None` on lean, which has no data-availability domain.
    pub custody_group_count: Option<u64>,
```

In `local_pairs`, replace the `eth2` line and append the `cgc` entry:

```rust
        let attnets = encode_attnets(&self.subscription_subnets, self.attestation_committee_count);
        pairs.set_extra(ATTNETS_ENR_KEY, attnets);
        pairs.set_extra(ETH2_ENR_KEY, self.fork_id.to_ssz());
        pairs.set_extra_int(QUIC_ENR_KEY, self.quic_port);
        if let Some(count) = self.custody_group_count {
            pairs.set_extra_int(CGC_ENR_KEY, count);
        }
        pairs
```

Update the `build()` test helper in the same file to pass the new fields:

```rust
    fn build() -> NodeRecord {
        build_local_enr(&LocalEnrParams {
            signer: test_signer(),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            quic_port: 9001,
            subscription_subnets: HashSet::from([1u64, 4]),
            attestation_committee_count: 8,
            fork_id: EnrForkId::local(),
            custody_group_count: None,
        })
        .expect("ENR builds")
    }
```

- [ ] **Step 4: Thread the fields through `spawn_discovery`**

In `crates/net/p2p/src/discovery/mod.rs`, add to `DiscoverySpawnConfig`:

```rust
    /// The `eth2` entry to publish and to compare discovered peers against.
    pub fork_id: EnrForkId,
    /// The `cgc` entry to publish, or `None` to omit it.
    pub custody_group_count: Option<u64>,
```

In `spawn_discovery`, pass them into `LocalEnrParams` and stop calling
`EnrForkId::local()`:

```rust
    let params = LocalEnrParams {
        signer: config.node_key,
        ip: config.advertise_ip.unwrap_or(config.bind_ip),
        discovery_port: bound.port(),
        quic_port: config.quic_port,
        subscription_subnets: config.subscription_subnets,
        attestation_committee_count: config.attestation_committee_count,
        fork_id: config.fork_id,
        custody_group_count: config.custody_group_count,
    };
```

Add a field to `DiscoveryHandle` so the dial loop can clamp a peer's advertised
subnets without reading a lean-shaped field off `P2PServer`:

```rust
    /// Subnet ids at or beyond this are dropped from a discovered peer's
    /// `attnets`. Lean's attestation committee count, or
    /// `ATTESTATION_SUBNET_COUNT` on the beacon wire.
    pub subnet_count: u64,
```

and populate both new fields in the returned handle:

```rust
    Ok(DiscoveryHandle {
        peer_table,
        local_enr,
        local_fork_id: params.fork_id,
        subnet_count: config.attestation_committee_count,
        bound_addr: bound,
    })
```

`params.fork_id` is read after `params` was partially moved into
`build_local_enr`, which takes `&params`, so the field is still available;
`EnrForkId` is `Copy`.

Update the three tests in that module's `tests` block to pass the new config
fields. Each one gains:

```rust
            fork_id: EnrForkId::local(),
            custody_group_count: None,
```

- [ ] **Step 5: Give the dial loop its own subnet count**

In `crates/net/p2p/src/lib.rs`, add to `DiscoveryState`:

```rust
    /// Subnet ids at or beyond this are dropped from a peer's `attnets`.
    pub(crate) subnet_count: u64,
```

Populate it in `P2P::spawn`:

```rust
            discovery: discovery.map(|handle| DiscoveryState {
                peer_table: handle.peer_table,
                local_fork_id: handle.local_fork_id,
                subnet_count: handle.subnet_count,
                candidates: VecDeque::new(),
                peer_attnets: HashMap::new(),
            }),
```

In `handle_discover_peers`, replace the snapshot tuple and the
`select_candidates` call so the count comes from discovery rather than from the
lean-shaped `self.attestation_committee_count`:

```rust
        let Some((peer_table, local_fork_id, subnet_count, needs_refill)) =
            self.discovery.as_ref().map(|discovery| {
                (
                    discovery.peer_table.clone(),
                    discovery.local_fork_id,
                    discovery.subnet_count,
                    discovery.candidates.is_empty(),
                )
            })
        else {
            return;
        };
```

and:

```rust
            let (mut admitted, unwanted) =
                select_candidates(contacts, &local_fork_id, subnet_count);
```

- [ ] **Step 6: Update the lean caller**

In `bin/ethlambda/src/main.rs`, add the two fields to the
`DiscoverySpawnConfig` literal, preserving today's behavior exactly:

```rust
                bootnodes: discovery_bootnodes,
                advertise_ip,
                fork_id: ethlambda_types::enr::EnrForkId::local(),
                custody_group_count: None,
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p discovery -- --nocapture`
Expected: PASS, including the three new tests and the six that already existed
(`local_enr_advertises_udp_and_quic_but_no_tcp`, `local_enr_carries_the_fork_id`,
`local_enr_carries_the_subscribed_subnets`,
`local_enr_is_signed_and_survives_a_round_trip`,
`local_enr_is_a_valid_discv5_node`, and the three `spawn_*` tests).

- [ ] **Step 8: Verify the lean suite**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make fmt`
Expected: no diff.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -S -m "refactor(p2p): take the ENR fork id and cgc from the caller

The ENR builder reached for EnrForkId::local() internally, which is right
for lean (a compile-time constant) and impossible for the beacon wire,
whose digest is computed from the fork schedule and the genesis validators
root at startup. Same for the subnet count the dial loop clamps a peer's
attnets against: it was reading a lean-shaped field off P2PServer.

cgc is optional rather than always-present: lean has no data-availability
domain, so publishing one there would advertise a claim with nothing
behind it. Lean behaviour is unchanged; the lean caller passes exactly
what the code used to reach for."
```

---

## Task 8: Thread a `Wire` profile through the swarm and the actor

**Files:**
- Modify: `crates/net/p2p/src/lib.rs`
- Modify: `crates/net/p2p/src/gossipsub/handler.rs`
- Modify: `bin/ethlambda/src/main.rs`
- Test: `crates/net/p2p/src/lib.rs`

A pure refactor: `P2PServer`'s four lean topic fields become one `Wire` enum
whose only variant so far is `Lean`. No behavior changes. Doing it separately
from Task 9 means that if the lean devnet regresses, it regresses in a commit
that added no beacon code.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module at the bottom of `crates/net/p2p/src/lib.rs`:

```rust
    #[test]
    fn a_lean_wire_reports_its_topics_and_no_beacon_wire() {
        // The enum is what makes "subscribed to lean topics and beacon topics
        // at once" unrepresentable. `P2PServer` dispatches on it once per
        // handler, the same way `BlockChainServer` dispatches on the state
        // variant.
        let wire = Wire::Lean(LeanWire {
            attestation_topics: HashMap::new(),
            attestation_committee_count: 4,
            block_topic: block_topic(),
            aggregation_topic: aggregation_topic(),
        });
        assert!(wire.beacon().is_none());
        let lean = wire.lean().expect("a lean wire");
        assert_eq!(lean.attestation_committee_count, 4);
        assert!(lean.block_topic.to_string().starts_with("/leanconsensus/"));
    }
```

`block_topic` and `aggregation_topic` are already imported by name at the top of
`lib.rs`, and the test module's `use super::*` picks them up.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-p2p a_lean_wire_reports -- --nocapture`
Expected: FAIL to compile, `cannot find type 'Wire' in this scope`.

- [ ] **Step 3: Add the enum**

In `crates/net/p2p/src/lib.rs`, add above `BuiltSwarm`:

```rust
/// Which network's wire this node speaks.
///
/// One `P2PServer` serves both, dispatching on this once at the top of each
/// handler, exactly as `BlockChainServer` dispatches on the state variant.
/// Nothing is shared below the match: the topic names, the req/resp protocol
/// ids, the handshake and the decode are all different, and the parts that
/// genuinely coincide (the discv5 stack, the `ssz_snappy` framing,
/// `compute_message_id`) sit one layer down and are the beacon spec's anyway.
pub enum Wire {
    Lean(LeanWire),
    Beacon(beacon::BeaconWire),
}

/// The lean network's gossip topics.
pub struct LeanWire {
    pub(crate) attestation_topics: HashMap<u64, libp2p::gossipsub::IdentTopic>,
    pub(crate) attestation_committee_count: u64,
    pub(crate) block_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) aggregation_topic: libp2p::gossipsub::IdentTopic,
}

impl Wire {
    pub(crate) fn lean(&self) -> Option<&LeanWire> {
        match self {
            Wire::Lean(lean) => Some(lean),
            Wire::Beacon(_) => None,
        }
    }

    pub(crate) fn beacon(&self) -> Option<&beacon::BeaconWire> {
        match self {
            Wire::Beacon(beacon) => Some(beacon),
            Wire::Lean(_) => None,
        }
    }
}
```

`beacon::BeaconWire` does not exist yet. Add it to
`crates/net/p2p/src/beacon/mod.rs` now, so this task compiles on its own:

```rust
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::primitives::ForkDigest;

/// Everything the beacon wire needs after startup has computed it.
///
/// `config` and `genesis_time` are carried rather than looked up because the
/// fork a gossip payload decodes under is derived from its slot, and that
/// derivation must use the same schedule the fork digest was computed from.
pub struct BeaconWire {
    pub fork_digest: ForkDigest,
    pub topics: topics::BeaconTopics,
    pub config: Config,
    pub genesis_time: u64,
    /// Advertised in `Ping` responses and in `MetaData`. Never bumped today:
    /// nothing this node advertises changes at runtime.
    pub metadata_seq_number: u64,
}
```

- [ ] **Step 4: Replace the four fields on `BuiltSwarm` and `P2PServer`**

In `crates/net/p2p/src/lib.rs`, change `BuiltSwarm` to:

```rust
pub struct BuiltSwarm {
    /// This node's libp2p peer ID, derived from the node key. Exposed so the
    /// caller can report it (e.g. via the RPC `/lean/v0/node/identity` endpoint).
    pub local_peer_id: PeerId,
    pub(crate) swarm: libp2p::Swarm<Behaviour>,
    pub(crate) wire: Wire,
    pub(crate) bootnode_addrs: HashMap<PeerId, Multiaddr>,
}
```

At the end of `build_swarm`, replace the returned struct literal:

```rust
    Ok(BuiltSwarm {
        local_peer_id,
        swarm,
        wire: Wire::Lean(LeanWire {
            attestation_topics,
            attestation_committee_count: config.attestation_committee_count,
            block_topic,
            aggregation_topic,
        }),
        bootnode_addrs,
    })
```

In `P2PServer`, delete the four fields
(`attestation_topics`, `attestation_committee_count`, `block_topic`,
`aggregation_topic`) and add:

```rust
    pub(crate) wire: Wire,
```

In `P2P::spawn`, replace the four initializers with:

```rust
            wire: built.wire,
```

- [ ] **Step 5: Update the lean gossip handler**

In `crates/net/p2p/src/gossipsub/handler.rs`, `publish_attestation` reads two
fields off the server. Replace its opening lines:

```rust
pub async fn publish_attestation(server: &mut P2PServer, attestation: SignedAttestation) {
    let slot = attestation.data.slot;
    let validator = attestation.validator_id;
    let Some(lean) = server.wire.lean() else {
        warn!("Publishing is suppressed on the beacon wire; dropping attestation");
        return;
    };
    let subnet_id = validator % lean.attestation_committee_count;

    // Encode to SSZ
    let ssz_bytes = attestation.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_attestation_size(ssz_bytes.len(), compressed.len());

    // Look up subscribed topic or construct on-the-fly for gossipsub fanout
    let topic = lean
        .attestation_topics
        .get(&subnet_id)
        .cloned()
        .unwrap_or_else(|| attestation_subnet_topic(subnet_id));

    server.swarm_handle.publish(topic, compressed);
```

leaving the trailing `info!` unchanged.

In `publish_block`, replace the publish line:

```rust
    let Some(topic) = server.wire.lean().map(|lean| lean.block_topic.clone()) else {
        warn!("Publishing is suppressed on the beacon wire; dropping block");
        return;
    };
    server.swarm_handle.publish(topic, compressed);
```

In `publish_aggregated_attestation`, the same:

```rust
    let Some(topic) = server.wire.lean().map(|lean| lean.aggregation_topic.clone()) else {
        warn!("Publishing is suppressed on the beacon wire; dropping aggregate");
        return;
    };
    server.swarm_handle.publish(topic, compressed);
```

Add `warn` to that file's `tracing` import:

```rust
use tracing::{error, info, trace, warn};
```

- [ ] **Step 6: Update the binary**

In `bin/ethlambda/src/main.rs` nothing reads the removed fields, so no change is
needed beyond what Task 7 already made. Confirm with:

```bash
grep -rn "attestation_topics\|\.block_topic\|\.aggregation_topic" bin/ethlambda/src/
```

Expected: no output.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p -- --nocapture`
Expected: PASS, including the new `a_lean_wire_reports_its_topics_and_no_beacon_wire`.

- [ ] **Step 8: Verify the lean suite**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make fmt`
Expected: no diff.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -S -m "refactor(p2p): give P2PServer a Wire profile

The four lean topic fields become one enum with a Lean variant, so a
Beacon variant can be added next without either network's topics being
reachable from the other's handler. Same shape as the BlockChainServer
dispatch: one match at the top, nothing shared below it.

Split out from the beacon work deliberately. If the lean devnet regresses
here, it regresses in a commit that added no beacon code."
```

---

## Task 9: `build_beacon_swarm` and the beacon codec

**Files:**
- Modify: `crates/net/p2p/src/lib.rs`
- Create: `crates/net/p2p/src/beacon/swarm.rs`
- Modify: `crates/net/p2p/src/beacon/mod.rs`
- Modify: `crates/net/p2p/src/req_resp/messages.rs`
- Modify: `crates/net/p2p/src/req_resp/codec.rs`
- Test: `crates/net/p2p/src/req_resp/codec.rs`, `crates/net/p2p/src/beacon/swarm.rs`

One `Codec` serves both wires, dispatching on the protocol id it is already
given. That keeps a single `request_response::Behaviour` and a single swarm
adapter.

- [ ] **Step 1: Write the failing tests**

Add a `tests` module at the bottom of `crates/net/p2p/src/req_resp/codec.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::messages::{
        AttnetsBits, BeaconMetaData, BeaconStatus, Goodbye, MetaDataV3, Ping, StatusV1,
        SyncnetsBits,
    };
    use crate::beacon::protocols;
    use crate::req_resp::messages::{BeaconRequest, BeaconResponse};
    use ethlambda_types::beacon::primitives::Root;
    use futures::io::Cursor;
    use libp2p::StreamProtocol;
    use libp2p::request_response::Codec as _;

    fn status() -> BeaconStatus {
        BeaconStatus::V1(StatusV1 {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            finalized_root: Root::zero(),
            finalized_epoch: 0,
            head_root: Root::zero(),
            head_slot: 0,
        })
    }

    /// Write a request, then read it back off the same buffer.
    async fn request_round_trip(protocol: &str, request: Request) -> Request {
        let stream_protocol = StreamProtocol::new(protocol);
        let mut buffer = Cursor::new(Vec::new());
        Codec
            .write_request(&stream_protocol, &mut buffer, request)
            .await
            .expect("writes");
        let mut buffer = Cursor::new(buffer.into_inner());
        Codec
            .read_request(&stream_protocol, &mut buffer)
            .await
            .expect("reads")
    }

    /// Write a response, then read it back off the same buffer.
    async fn response_round_trip(protocol: &str, response: Response) -> Response {
        let stream_protocol = StreamProtocol::new(protocol);
        let mut buffer = Cursor::new(Vec::new());
        Codec
            .write_response(&stream_protocol, &mut buffer, response)
            .await
            .expect("writes");
        let mut buffer = Cursor::new(buffer.into_inner());
        Codec
            .read_response(&stream_protocol, &mut buffer)
            .await
            .expect("reads")
    }

    #[tokio::test]
    async fn a_status_v1_request_round_trips_through_the_snappy_framing() {
        let decoded =
            request_round_trip(protocols::STATUS_V1, Request::Beacon(BeaconRequest::Status(status())))
                .await;
        assert!(matches!(
            decoded,
            Request::Beacon(BeaconRequest::Status(BeaconStatus::V1(_)))
        ));
    }

    #[tokio::test]
    async fn the_protocol_version_selects_the_status_shape() {
        // A v1 payload on a v2 stream would be eight bytes short, so the
        // version has to come from the negotiated protocol rather than from
        // whichever variant the caller happened to build.
        let stream_protocol = StreamProtocol::new(protocols::STATUS_V2);
        let mut buffer = Cursor::new(Vec::new());
        let result = Codec
            .write_request(
                &stream_protocol,
                &mut buffer,
                Request::Beacon(BeaconRequest::Status(status())),
            )
            .await;
        assert!(
            result.is_err(),
            "writing a v1 Status on a v2 stream must be refused, not truncated"
        );
    }

    #[tokio::test]
    async fn a_ping_round_trips() {
        let decoded = request_round_trip(
            protocols::PING_V1,
            Request::Beacon(BeaconRequest::Ping(Ping { seq_number: 5 })),
        )
        .await;
        assert!(matches!(
            decoded,
            Request::Beacon(BeaconRequest::Ping(Ping { seq_number: 5 }))
        ));

        let decoded = response_round_trip(
            protocols::PING_V1,
            Response::success(ResponsePayload::Beacon(BeaconResponse::Pong(Ping {
                seq_number: 5,
            }))),
        )
        .await;
        assert!(matches!(
            decoded,
            Response::Success {
                payload: ResponsePayload::Beacon(BeaconResponse::Pong(Ping { seq_number: 5 }))
            }
        ));
    }

    #[tokio::test]
    async fn a_metadata_request_carries_no_payload() {
        // The spec's MetaData request is empty. `write_payload` of an empty
        // slice emits nothing at all, and `decode_payload` reads a zero-length
        // varint back, so the two agree on an empty stream.
        let decoded = request_round_trip(
            protocols::METADATA_V3,
            Request::Beacon(BeaconRequest::MetaData(protocols::METADATA_V3)),
        )
        .await;
        assert!(matches!(
            decoded,
            Request::Beacon(BeaconRequest::MetaData(protocols::METADATA_V3))
        ));
    }

    #[tokio::test]
    async fn a_metadata_v3_response_round_trips() {
        let metadata = BeaconMetaData::V3(MetaDataV3 {
            seq_number: 0,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
            custody_group_count: 4,
        });
        let decoded = response_round_trip(
            protocols::METADATA_V3,
            Response::success(ResponsePayload::Beacon(BeaconResponse::MetaData(metadata))),
        )
        .await;
        let Response::Success {
            payload: ResponsePayload::Beacon(BeaconResponse::MetaData(BeaconMetaData::V3(v3))),
        } = decoded
        else {
            panic!("expected a v3 MetaData");
        };
        assert_eq!(v3.custody_group_count, 4);
    }

    #[tokio::test]
    async fn a_goodbye_round_trips() {
        let decoded = request_round_trip(
            protocols::GOODBYE_V1,
            Request::Beacon(BeaconRequest::Goodbye(Goodbye { reason: 128 })),
        )
        .await;
        assert!(matches!(
            decoded,
            Request::Beacon(BeaconRequest::Goodbye(Goodbye { reason: 128 }))
        ));
    }
}
```

Create `crates/net/p2p/src/beacon/swarm.rs` with its test module already
written:

```rust
//! Building the swarm `ethlambda beacon` runs on.
//!
//! Everything except the topic set, the protocol set, the `seen_ttl` and the
//! identify protocol version is shared with lean, because those are the only
//! four things the two networks disagree about at the swarm level.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::ForkDigest;
use libp2p::identity::secp256k1;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, request_response};
use tracing::{debug, info};

use super::{BeaconWire, protocols, topics::BeaconTopics};
use crate::req_resp::Codec;
use crate::{Behaviour, Bootnode, BuiltSwarm, PeerId, Wire, gossipsub_config};

/// How long gossipsub remembers a message id, so a duplicate arriving late is
/// dropped rather than re-forwarded.
///
/// The beacon p2p interface states this as `SLOTS_PER_EPOCH * SECONDS_PER_SLOT
/// * 2`, which is what is written here rather than the number it evaluates to,
/// so it stays correct if either factor moves.
pub fn seen_ttl(config: &Config) -> Duration {
    Duration::from_secs(preset::SLOTS_PER_EPOCH * config.seconds_per_slot * 2)
}

pub struct BeaconSwarmConfig {
    pub node_key: Vec<u8>,
    pub listening_socket: SocketAddr,
    pub fork_digest: ForkDigest,
    pub config: Config,
    pub genesis_time: u64,
    /// Parsed from the built-in list or from `--bootnodes`. Kept only so a
    /// record that does advertise `quic` can still be dialed statically; none
    /// of the published mainnet records does.
    pub bootnodes: Vec<Bootnode>,
}

/// Build the beacon swarm, subscribe to the seven topics, and dial any bootnode
/// that advertises a QUIC port.
pub fn build_beacon_swarm(
    config: BeaconSwarmConfig,
) -> Result<BuiltSwarm, libp2p::gossipsub::SubscriptionError> {
    let gossipsub = libp2p::gossipsub::Behaviour::new(
        libp2p::gossipsub::MessageAuthenticity::Anonymous,
        gossipsub_config(seen_ttl(&config.config)),
    )
    .expect("failed to initiate behaviour");

    let req_resp = request_response::Behaviour::new(protocols::registrations(), Default::default());

    let secret_key =
        secp256k1::SecretKey::try_from_bytes(config.node_key).expect("invalid node key");
    let identity = libp2p::identity::Keypair::from(secp256k1::Keypair::from(secret_key));

    // Lighthouse's identify protocol version. go-libp2p peers gate gossipsub
    // GRAFT on the identify exchange completing, so a peer that does not answer
    // is silently excluded from the mesh.
    let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
        "eth2/1.0.0".to_owned(),
        identity.public(),
    ));

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| Behaviour::new(identify, gossipsub, req_resp))
        .expect("failed to add behaviour to swarm")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    let local_peer_id = *swarm.local_peer_id();
    let mut bootnode_addrs = HashMap::new();
    for bootnode in config.bootnodes {
        let peer_id = PeerId::from_public_key(&bootnode.public_key);
        if peer_id == local_peer_id {
            continue;
        }
        let Some(quic_port) = bootnode.quic_port else {
            debug!(%peer_id, ip = %bootnode.ip, "Bootnode advertises no quic port, discv5 seed only");
            continue;
        };
        let addr = Multiaddr::empty()
            .with(bootnode.ip.into())
            .with(Protocol::Udp(quic_port))
            .with(Protocol::QuicV1)
            .with_p2p(peer_id)
            .expect("failed to add peer ID to multiaddr");
        bootnode_addrs.insert(peer_id, addr.clone());
        swarm.dial(addr).expect("failed to dial bootnode");
    }

    let listen_addr = Multiaddr::empty()
        .with(config.listening_socket.ip().into())
        .with(Protocol::Udp(config.listening_socket.port()))
        .with(Protocol::QuicV1);
    swarm
        .listen_on(listen_addr)
        .expect("failed to bind gossipsub listening address");

    let beacon_topics = BeaconTopics::new(config.fork_digest);
    for topic in &beacon_topics.topics {
        swarm.behaviour_mut().gossipsub.subscribe(topic)?;
        info!(topic = %topic, "Subscribed to beacon topic");
    }

    info!(
        socket = %config.listening_socket,
        fork_digest = %hex::encode(config.fork_digest),
        topics = beacon_topics.topics.len(),
        "Beacon P2P node started"
    );

    Ok(BuiltSwarm {
        local_peer_id,
        swarm,
        wire: Wire::Beacon(BeaconWire {
            fork_digest: config.fork_digest,
            topics: beacon_topics,
            config: config.config,
            genesis_time: config.genesis_time,
            metadata_seq_number: 0,
        }),
        bootnode_addrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seen_ttl_is_two_epochs() {
        // The design doc's parenthetical says 385s, which does not match its own
        // formula: 32 * 12 * 2 is 768. The formula is the one the beacon p2p
        // interface states, so it wins, and writing it out keeps it honest if
        // either factor ever moves.
        assert_eq!(seen_ttl(&Config::mainnet()), Duration::from_secs(768));
    }

    #[test]
    fn a_beacon_swarm_subscribes_to_seven_topics_and_dials_nothing() {
        // Port 0 asks the OS for a free port, so this cannot collide with a
        // running node or a sibling test.
        let built = build_beacon_swarm(BeaconSwarmConfig {
            node_key: vec![1u8; 32],
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            config: Config::mainnet(),
            genesis_time: 1_606_824_023,
            bootnodes: crate::parse_enrs(
                super::super::bootnodes::MAINNET_BOOTNODES
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
            ),
        })
        .expect("swarm builds");

        let wire = built.wire.beacon().expect("a beacon wire");
        assert_eq!(wire.topics.topics.len(), 7);
        assert_eq!(wire.fork_digest, [0x8c, 0x9f, 0x62, 0xfe]);
        assert!(
            built.bootnode_addrs.is_empty(),
            "no published mainnet bootnode advertises quic, so none is dialed"
        );
    }
}
```

The swarm test needs a tokio reactor for `with_tokio()`. `build_beacon_swarm`
itself only registers the listener, so mark the test `#[tokio::test]` and make
it `async fn`:

```rust
    #[tokio::test]
    async fn a_beacon_swarm_subscribes_to_seven_topics_and_dials_nothing() {
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p beacon::swarm -- --nocapture`
Expected: FAIL to compile, `cannot find function 'gossipsub_config' in the crate root`.

- [ ] **Step 3: Extract the shared gossipsub config**

In `crates/net/p2p/src/lib.rs`, add above `build_swarm`:

```rust
/// The gossipsub parameters both wires share.
///
/// `mesh_n` 8, low 6, high 12, the 700ms heartbeat, and the 6/3 history already
/// match the beacon spec, so `seen_ttl` is the only value that differs between
/// the two networks: lean's slot is 4s with a 3-slot justification lookback,
/// mainnet's epoch is 32 slots of 12s.
pub(crate) fn gossipsub_config(seen_ttl: Duration) -> libp2p::gossipsub::Config {
    libp2p::gossipsub::ConfigBuilder::default()
        // d
        .mesh_n(8)
        // d_low
        .mesh_n_low(6)
        // d_high
        .mesh_n_high(12)
        // d_lazy
        .gossip_lazy(6)
        .heartbeat_interval(Duration::from_millis(700))
        .fanout_ttl(Duration::from_secs(60))
        .history_length(6)
        .history_gossip(3)
        .duplicate_cache_time(seen_ttl)
        .validation_mode(ValidationMode::Anonymous)
        .message_id_fn(compute_message_id)
        // Taken from ream
        .max_transmit_size(MAX_COMPRESSED_PAYLOAD_SIZE)
        .max_messages_per_rpc(Some(500))
        .allow_self_origin(true)
        .idontwant_message_size_threshold(1000)
        .build()
        .expect("invalid gossipsub config")
}
```

Replace the inline builder at the top of `build_swarm` with a call, preserving
lean's own comment for its value:

```rust
    // seen_ttl_secs = seconds_per_slot * justification_lookback_slots * 2
    let gossipsub_config = gossipsub_config(Duration::from_secs(4 * 3 * 2));
```

Add a constructor to `Behaviour`, since `build_beacon_swarm` lives in another
module and the fields are private:

```rust
impl Behaviour {
    pub(crate) fn new(
        identify: libp2p::identify::Behaviour,
        gossipsub: libp2p::gossipsub::Behaviour,
        req_resp: request_response::Behaviour<Codec>,
    ) -> Self {
        Self {
            identify,
            gossipsub,
            req_resp,
        }
    }
}
```

and use it in `build_swarm` in place of the struct literal:

```rust
    let behavior = Behaviour::new(identify, gossipsub, req_resp);
```

Add to `crates/net/p2p/src/beacon/mod.rs`, in alphabetical position:

```rust
pub mod swarm;
```

- [ ] **Step 4: Add the beacon arms to `Request` and `ResponsePayload`**

In `crates/net/p2p/src/req_resp/messages.rs`, add the two enums and the two
variants:

```rust
use crate::beacon::messages::{BeaconMetaData, BeaconStatus, Goodbye, Ping};

/// A request on one of the beacon protocols.
#[derive(Debug, Clone)]
pub enum BeaconRequest {
    Status(BeaconStatus),
    Ping(Ping),
    /// The negotiated `metadata/N` protocol id.
    ///
    /// The request is empty on the wire, but the responder has to answer in the
    /// version the peer asked for, and `request_response::Event::Message` does
    /// not carry the protocol id. The codec does, so it records it here.
    MetaData(&'static str),
    Goodbye(Goodbye),
}

/// A response on one of the beacon protocols.
#[derive(Debug, Clone)]
pub enum BeaconResponse {
    Status(BeaconStatus),
    Pong(Ping),
    MetaData(BeaconMetaData),
}
```

Extend `Request`:

```rust
#[derive(Debug, Clone)]
pub enum Request {
    Status(Status),
    BlocksByRoot(BlocksByRootRequest),
    BlocksByRange(BlocksByRangeRequest),
    Beacon(BeaconRequest),
}
```

Extend `ResponsePayload`:

```rust
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ResponsePayload {
    Status(Status),
    Blocks(Vec<SignedBlock>),
    Beacon(BeaconResponse),
}
```

Re-export both from `crates/net/p2p/src/req_resp/mod.rs` by replacing the
existing `pub use messages::{...}` list. `ResponseCode` and `error_message` join
it because `messages` is private to `req_resp` and `crate::beacon::handler` is a
sibling module, so it cannot reach them by path:

```rust
pub use messages::{
    BLOCKS_BY_RANGE_PROTOCOL_V1, BLOCKS_BY_ROOT_PROTOCOL_V1, BeaconRequest, BeaconResponse,
    BlocksByRangeRequest, BlocksByRootRequest, MAX_REQUEST_BLOCKS, Request, RequestedBlockRoots,
    Response, ResponseCode, ResponsePayload, STATUS_PROTOCOL_V1, Status, error_message,
};
```

- [ ] **Step 5: Teach the codec the beacon protocols**

In `crates/net/p2p/src/req_resp/codec.rs`, replace `protocol_label` so it defers
to the beacon table:

```rust
fn protocol_label(protocol: &str) -> &'static str {
    match protocol {
        STATUS_PROTOCOL_V1 => "status",
        BLOCKS_BY_ROOT_PROTOCOL_V1 => "blocks_by_root",
        BLOCKS_BY_RANGE_PROTOCOL_V1 => "blocks_by_range",
        other => crate::beacon::protocols::label(other).unwrap_or("unknown"),
    }
}
```

Add these four helpers below `protocol_label`:

```rust
use crate::beacon::messages::{
    BeaconMetaData, BeaconStatus, Goodbye, MetaDataV1, MetaDataV2, MetaDataV3, Ping, StatusV1,
    StatusV2,
};
use crate::beacon::protocols;
use crate::req_resp::messages::{BeaconRequest, BeaconResponse};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Encode a `Status` for the negotiated protocol version.
///
/// A version mismatch is an error rather than a conversion: a v1 value written
/// on a v2 stream would be eight bytes short and the peer would read a
/// truncated container, which is worse than a refused write.
fn encode_beacon_status(protocol: &str, status: &BeaconStatus) -> io::Result<Vec<u8>> {
    match (protocol, status) {
        (protocols::STATUS_V1, BeaconStatus::V1(status)) => Ok(status.to_ssz()),
        (protocols::STATUS_V2, BeaconStatus::V2(status)) => Ok(status.to_ssz()),
        _ => Err(invalid(format!(
            "status version does not match protocol {protocol}"
        ))),
    }
}

fn decode_beacon_status(protocol: &str, payload: &[u8]) -> io::Result<BeaconStatus> {
    match protocol {
        protocols::STATUS_V1 => StatusV1::from_ssz_bytes(payload)
            .map(BeaconStatus::V1)
            .map_err(|err| invalid(format!("{err:?}"))),
        protocols::STATUS_V2 => StatusV2::from_ssz_bytes(payload)
            .map(BeaconStatus::V2)
            .map_err(|err| invalid(format!("{err:?}"))),
        _ => Err(invalid(format!("not a status protocol: {protocol}"))),
    }
}

fn encode_beacon_metadata(protocol: &str, metadata: &BeaconMetaData) -> io::Result<Vec<u8>> {
    match (protocol, metadata) {
        (protocols::METADATA_V1, BeaconMetaData::V1(value)) => Ok(value.to_ssz()),
        (protocols::METADATA_V2, BeaconMetaData::V2(value)) => Ok(value.to_ssz()),
        (protocols::METADATA_V3, BeaconMetaData::V3(value)) => Ok(value.to_ssz()),
        _ => Err(invalid(format!(
            "metadata version does not match protocol {protocol}"
        ))),
    }
}

fn decode_beacon_metadata(protocol: &str, payload: &[u8]) -> io::Result<BeaconMetaData> {
    match protocol {
        protocols::METADATA_V1 => MetaDataV1::from_ssz_bytes(payload)
            .map(BeaconMetaData::V1)
            .map_err(|err| invalid(format!("{err:?}"))),
        protocols::METADATA_V2 => MetaDataV2::from_ssz_bytes(payload)
            .map(BeaconMetaData::V2)
            .map_err(|err| invalid(format!("{err:?}"))),
        protocols::METADATA_V3 => MetaDataV3::from_ssz_bytes(payload)
            .map(BeaconMetaData::V3)
            .map_err(|err| invalid(format!("{err:?}"))),
        _ => Err(invalid(format!("not a metadata protocol: {protocol}"))),
    }
}
```

In `read_request`, add the beacon arms before the catch-all:

```rust
            protocols::STATUS_V1 | protocols::STATUS_V2 => Ok(Request::Beacon(
                BeaconRequest::Status(decode_beacon_status(protocol.as_ref(), &payload)?),
            )),
            protocols::PING_V1 => Ok(Request::Beacon(BeaconRequest::Ping(
                Ping::from_ssz_bytes(&payload).map_err(|err| invalid(format!("{err:?}")))?,
            ))),
            // Resolved to the `'static` constant so the variant can hold it.
            protocols::METADATA_V1 => Ok(Request::Beacon(BeaconRequest::MetaData(
                protocols::METADATA_V1,
            ))),
            protocols::METADATA_V2 => Ok(Request::Beacon(BeaconRequest::MetaData(
                protocols::METADATA_V2,
            ))),
            protocols::METADATA_V3 => Ok(Request::Beacon(BeaconRequest::MetaData(
                protocols::METADATA_V3,
            ))),
            protocols::GOODBYE_V1 => Ok(Request::Beacon(BeaconRequest::Goodbye(
                Goodbye::from_ssz_bytes(&payload).map_err(|err| invalid(format!("{err:?}")))?,
            ))),
```

In `write_request`, replace the `let encoded = match req { .. };` block:

```rust
        let encoded = match &req {
            Request::Status(status) => status.to_ssz(),
            Request::BlocksByRoot(request) => request.to_ssz(),
            Request::BlocksByRange(request) => request.to_ssz(),
            Request::Beacon(BeaconRequest::Status(status)) => {
                encode_beacon_status(protocol.as_ref(), status)?
            }
            Request::Beacon(BeaconRequest::Ping(ping)) => ping.to_ssz(),
            // The spec's MetaData request is empty, and `write_payload` of an
            // empty slice emits no bytes at all.
            Request::Beacon(BeaconRequest::MetaData(_)) => Vec::new(),
            Request::Beacon(BeaconRequest::Goodbye(goodbye)) => goodbye.to_ssz(),
        };
```

In `read_response`, add the beacon arms before the catch-all:

```rust
            protocols::STATUS_V1 | protocols::STATUS_V2 => {
                decode_beacon_single_chunk(io, protocol.as_ref(), label, |protocol, payload| {
                    decode_beacon_status(protocol, payload).map(BeaconResponse::Status)
                })
                .await
            }
            protocols::PING_V1 => {
                decode_beacon_single_chunk(io, protocol.as_ref(), label, |_, payload| {
                    Ping::from_ssz_bytes(payload)
                        .map(BeaconResponse::Pong)
                        .map_err(|err| invalid(format!("{err:?}")))
                })
                .await
            }
            protocols::METADATA_V1 | protocols::METADATA_V2 | protocols::METADATA_V3 => {
                decode_beacon_single_chunk(io, protocol.as_ref(), label, |protocol, payload| {
                    decode_beacon_metadata(protocol, payload).map(BeaconResponse::MetaData)
                })
                .await
            }
```

and add the reader those three share, beside `decode_status_response`:

```rust
/// Read a single-chunk beacon response: one result-code byte, then one payload.
///
/// Every beacon protocol this node registers answers with exactly one chunk, so
/// there is no EOF loop here; the multi-chunk shape arrives with the block
/// protocols.
async fn decode_beacon_single_chunk<T, F>(
    io: &mut T,
    protocol: &str,
    protocol_label: &str,
    decode: F,
) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
    F: FnOnce(&str, &[u8]) -> io::Result<BeaconResponse>,
{
    let mut result_byte = 0_u8;
    io.read_exact(std::slice::from_mut(&mut result_byte))
        .await?;
    let code = ResponseCode::from(result_byte);

    let decoded = decode_payload(io).await?;
    let payload = decoded.uncompressed;
    metrics::observe_reqresp_response_chunk_size(
        protocol_label,
        payload.len(),
        decoded.compressed_size,
    );

    if code != ResponseCode::SUCCESS {
        let message = ErrorMessage::from_ssz_bytes(&payload)
            .map_err(|err| invalid(format!("Invalid error message: {err:?}")))?;
        let error_str = String::from_utf8_lossy(&message).into_owned();
        trace!(?code, %error_str, "Received error response");
        return Ok(Response::error(code, message));
    }

    Ok(Response::success(ResponsePayload::Beacon(decode(
        protocol, &payload,
    )?)))
}
```

In `write_response`, add a third arm to the `match &payload` inside
`Response::Success`:

```rust
                    ResponsePayload::Beacon(response) => {
                        let encoded = match response {
                            BeaconResponse::Status(status) => {
                                encode_beacon_status(protocol.as_ref(), status)?
                            }
                            BeaconResponse::Pong(ping) => ping.to_ssz(),
                            BeaconResponse::MetaData(metadata) => {
                                encode_beacon_metadata(protocol.as_ref(), metadata)?
                            }
                        };
                        io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
                        let compressed_size = write_payload(io, &encoded).await?;
                        metrics::observe_reqresp_response_chunk_size(
                            label,
                            encoded.len(),
                            compressed_size,
                        );
                        Ok(())
                    }
```

Encoding before writing the SUCCESS byte matters for the same reason it does in
the `Blocks` arm: a refused encode must not leave a lone result code on the wire
with no payload behind it.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p req_resp::codec -- --nocapture`
Expected: PASS, all six new tests.

Run: `cargo test -p ethlambda-p2p beacon::swarm -- --nocapture`
Expected: PASS, both tests.

- [ ] **Step 7: Verify the lean suite**

Run: `make test`
Expected: PASS. The existing `req_resp::encoding` tests must be untouched: the
framing is shared and unchanged.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make fmt`
Expected: no diff.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -S -m "feat(p2p): build the beacon swarm and speak its req/resp protocols

One Codec serves both wires by dispatching on the protocol id it already
receives, so there is still one request_response behaviour and one swarm
adapter. The gossipsub parameters are shared too: seen_ttl is the only
value the two networks disagree about, and it is written as the spec's
formula rather than as the number it evaluates to.

Status and MetaData take their version from the negotiated protocol and
refuse a mismatch rather than converting. A v1 Status on a v2 stream is
eight bytes short, and a peer reading a truncated container is worse than
a write that failed."
```

---

## Task 10: The beacon handshake, responder, and gossip handler

**Files:**
- Create: `crates/net/p2p/src/beacon/handler.rs`
- Modify: `crates/net/p2p/src/beacon/mod.rs`
- Modify: `crates/net/p2p/src/lib.rs`
- Modify: `crates/net/p2p/src/req_resp/handlers.rs`
- Modify: `crates/net/p2p/src/metrics.rs`
- Test: `crates/net/p2p/src/beacon/handler.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/net/p2p/src/beacon/handler.rs`:

```rust
//! What `P2PServer` does with beacon traffic.
//!
//! Three things: it opens the `Status` handshake on connect, it answers the
//! handful of requests that keep a connection alive, and it decodes gossip.
//! It publishes nothing and serves no chain data, because nothing this node can
//! produce today would be signature-valid and nothing it holds is worth
//! serving.

use ethlambda_types::beacon::primitives::Root;
use libp2p::PeerId;
use libp2p::gossipsub::Event;
use libp2p::request_response::ResponseChannel;
use tracing::{debug, info, warn};

use super::messages::{
    AttnetsBits, BeaconMetaData, BeaconStatus, Goodbye, MetaDataV1, MetaDataV2, MetaDataV3, Ping,
    StatusV1, SyncnetsBits,
};
use super::{BeaconWire, constants, decode, protocols, topics};
use crate::gossipsub::decompress_message;
use crate::req_resp::{
    BeaconRequest, BeaconResponse, Request, Response, ResponseCode, ResponsePayload, error_message,
};
use crate::{P2PServer, metrics};

/// The `Status` this node advertises.
///
/// Every field but the fork digest is zero, which is the honest answer for a
/// node that holds no beacon chain. Lighthouse's relevance check explicitly
/// exempts a zero `finalized_root` from its finalized-root comparison, reading
/// it as "this peer is syncing" rather than as a conflicting chain, so a zero
/// Status keeps the connection instead of earning an `IrrelevantPeer`
/// disconnect. The anchor-and-follow work replaces this with the store-derived
/// Status.
pub fn build_status(wire: &BeaconWire) -> BeaconStatus {
    BeaconStatus::V1(StatusV1 {
        fork_digest: wire.fork_digest,
        finalized_root: Root::zero(),
        finalized_epoch: 0,
        head_root: Root::zero(),
        head_slot: 0,
    })
}

/// The `MetaData` this node advertises, in the version the protocol asked for.
///
/// `attnets` and `syncnets` are all-zero because this node subscribes to no
/// subnet, which is exactly what it serves. `custody_group_count` is
/// `CUSTODY_REQUIREMENT` rather than zero because peers may reject a lower
/// value outright; it is the widest gap between what this node advertises and
/// what it serves, and startup logs it.
pub fn build_metadata(wire: &BeaconWire, protocol: &str) -> Option<BeaconMetaData> {
    let seq_number = wire.metadata_seq_number;
    match protocol {
        protocols::METADATA_V1 => Some(BeaconMetaData::V1(MetaDataV1 {
            seq_number,
            attnets: AttnetsBits::default(),
        })),
        protocols::METADATA_V2 => Some(BeaconMetaData::V2(MetaDataV2 {
            seq_number,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
        })),
        protocols::METADATA_V3 => Some(BeaconMetaData::V3(MetaDataV3 {
            seq_number,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
            custody_group_count: constants::CUSTODY_REQUIREMENT,
        })),
        _ => None,
    }
}

/// Open the handshake on a newly established connection.
///
/// `status/1` rather than `status/2`: every mainnet client still answers v1, and
/// the probe that proved this path completed its handshake on it. If a client
/// ever drops v1, this is the single line that moves.
pub async fn send_status(server: &P2PServer, peer_id: PeerId, wire_status: BeaconStatus) {
    server
        .swarm_handle
        .send_request(
            peer_id,
            Request::Beacon(BeaconRequest::Status(wire_status)),
            libp2p::StreamProtocol::new(protocols::STATUS_V1),
        )
        .await;
}

/// Answer a beacon request, or drop the channel when the protocol expects no
/// answer.
pub async fn handle_beacon_request(
    server: &mut P2PServer,
    peer: PeerId,
    request: BeaconRequest,
    channel: ResponseChannel<Response>,
) {
    let Some(wire) = server.wire.beacon() else {
        warn!(%peer, "Beacon request arrived on a lean node; refusing");
        let response = Response::error(
            ResponseCode::INVALID_REQUEST,
            error_message("this node does not speak the beacon protocols"),
        );
        server.swarm_handle.send_response(channel, response);
        return;
    };

    let response = match request {
        BeaconRequest::Status(peer_status) => {
            if peer_status.fork_digest() != wire.fork_digest {
                // Not grounds for closing the stream: the peer told us who it
                // is and we answer honestly. Counting it is how a digest that
                // has moved under us becomes visible.
                warn!(
                    %peer,
                    peer_digest = %hex::encode(peer_status.fork_digest()),
                    our_digest = %hex::encode(wire.fork_digest),
                    "Peer is on another fork digest"
                );
                metrics::inc_beacon_status_digest_mismatch();
            } else {
                info!(
                    %peer,
                    peer_head_slot = peer_status.head_slot(),
                    peer_finalized_epoch = peer_status.finalized_epoch(),
                    "Beacon status received"
                );
            }
            Some(BeaconResponse::Status(build_status(wire)))
        }
        BeaconRequest::Ping(ping) => {
            debug!(%peer, peer_seq_number = ping.seq_number, "Ping received");
            Some(BeaconResponse::Pong(Ping {
                seq_number: wire.metadata_seq_number,
            }))
        }
        BeaconRequest::MetaData(protocol) => {
            build_metadata(wire, protocol).map(BeaconResponse::MetaData)
        }
        BeaconRequest::Goodbye(Goodbye { reason }) => {
            // No response: goodbye is one-way. Dropping the channel closes the
            // stream, which is what the peer is waiting for.
            info!(%peer, reason, "Peer said goodbye");
            return;
        }
    };

    let Some(response) = response else {
        warn!(%peer, "No response shape for beacon request");
        return;
    };
    server
        .swarm_handle
        .send_response(channel, Response::success(ResponsePayload::Beacon(response)));
}

/// Decode a gossip message and record what it was.
///
/// Nothing is forwarded to the chain actor yet: driving `on_block` and
/// `on_attestation` arrives with the anchor, since `on_block` rejects a block
/// whose parent is not in the store and nothing has put one there.
pub async fn handle_beacon_gossip_message(server: &mut P2PServer, event: Event) {
    let Event::Message { message, .. } = event else {
        unreachable!("we already matched on Message variant in handle_swarm_event");
    };
    let Some(wire) = server.wire.beacon() else {
        return;
    };

    let Some(kind) = topics::topic_kind(message.topic.as_str()) else {
        debug!(topic = %message.topic, "Gossip on an unparseable topic");
        return;
    };
    // `kind` borrows `message.topic`, and the metric labels need a 'static str,
    // so resolve it against the subscribed set once.
    let Some(label) = topics::SUBSCRIBED_TOPIC_KINDS
        .into_iter()
        .find(|subscribed| *subscribed == kind)
    else {
        debug!(topic = %message.topic, "Gossip on an unsubscribed topic");
        return;
    };

    let Ok(payload) = decompress_message(&message.data) else {
        metrics::inc_beacon_gossip(label, "decompress_failed");
        return;
    };

    match decode::decode_gossip(&wire.config, label, &payload) {
        Ok(decode::BeaconGossip::Block(block)) => {
            metrics::inc_beacon_gossip(label, "decoded");
            info!(
                slot = block.slot(),
                proposer = block.proposer_index(),
                fork = block.fork_name().as_str(),
                block_root = %ethlambda_types::ShortRoot(&block.message_hash_tree_root().0),
                bytes = payload.len(),
                "Beacon block decoded"
            );
        }
        Ok(other) => {
            metrics::inc_beacon_gossip(label, "decoded");
            debug!(kind = other.topic_kind(), bytes = payload.len(), "Beacon gossip decoded");
        }
        Err(err) => {
            metrics::inc_beacon_gossip(label, "decode_failed");
            debug!(kind = label, %err, bytes = payload.len(), "Beacon gossip decode failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::config::Config;

    fn wire() -> BeaconWire {
        BeaconWire {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            topics: topics::BeaconTopics::new([0x8c, 0x9f, 0x62, 0xfe]),
            config: Config::mainnet(),
            genesis_time: 1_606_824_023,
            metadata_seq_number: 0,
        }
    }

    #[test]
    fn the_advertised_status_carries_the_digest_and_nothing_else() {
        // Zero roots are the honest answer for a node with no chain, and
        // lighthouse exempts a zero finalized_root from its relevance check, so
        // this keeps the connection rather than earning a disconnect.
        let BeaconStatus::V1(status) = build_status(&wire()) else {
            panic!("v1 is what we send");
        };
        assert_eq!(status.fork_digest, [0x8c, 0x9f, 0x62, 0xfe]);
        assert_eq!(status.finalized_root, Root::zero());
        assert_eq!(status.head_root, Root::zero());
        assert_eq!(status.finalized_epoch, 0);
        assert_eq!(status.head_slot, 0);
    }

    #[test]
    fn metadata_matches_the_protocol_version_asked_for() {
        let wire = wire();
        assert!(matches!(
            build_metadata(&wire, protocols::METADATA_V1),
            Some(BeaconMetaData::V1(_))
        ));
        assert!(matches!(
            build_metadata(&wire, protocols::METADATA_V2),
            Some(BeaconMetaData::V2(_))
        ));
        let Some(BeaconMetaData::V3(v3)) = build_metadata(&wire, protocols::METADATA_V3) else {
            panic!("v3 requested");
        };
        assert_eq!(v3.custody_group_count, constants::CUSTODY_REQUIREMENT);
        assert!(build_metadata(&wire, protocols::PING_V1).is_none());
    }

    #[test]
    fn the_advertised_subnets_are_empty() {
        // What a node subscribing to no subnet actually serves. Claiming
        // otherwise would earn peer-score penalties for silence on subnets we
        // advertised.
        let Some(BeaconMetaData::V3(v3)) = build_metadata(&wire(), protocols::METADATA_V3) else {
            panic!("v3 requested");
        };
        assert_eq!(v3.attnets, AttnetsBits::default());
        assert_eq!(v3.syncnets, SyncnetsBits::default());
    }
}
```

Add to `crates/net/p2p/src/beacon/mod.rs`, in alphabetical position:

```rust
pub mod handler;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-p2p beacon::handler -- --nocapture`
Expected: FAIL to compile, `cannot find function 'inc_beacon_gossip' in module 'metrics'`.

- [ ] **Step 3: Add the two metrics**

Append to `crates/net/p2p/src/metrics.rs`:

```rust
static LEAN_BEACON_GOSSIP_MESSAGES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_beacon_gossip_messages_total",
        "Beacon gossip messages received, by topic and decode outcome",
        &["topic", "result"]
    )
    .unwrap()
});

static LEAN_BEACON_STATUS_DIGEST_MISMATCH_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "lean_beacon_status_digest_mismatch_total",
        "Beacon Status requests whose fork digest did not match ours"
    )
    .unwrap()
});

static LEAN_BEACON_FORK_DIGEST: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_beacon_fork_digest",
        "The fork digest this node computed at startup, as a label",
        &["digest"]
    )
    .unwrap()
});

/// Count one gossip message. `result` is `decoded`, `decode_failed`, or
/// `decompress_failed`.
pub fn inc_beacon_gossip(topic: &str, result: &str) {
    LEAN_BEACON_GOSSIP_MESSAGES_TOTAL
        .with_label_values(&[topic, result])
        .inc();
}

pub fn inc_beacon_status_digest_mismatch() {
    LEAN_BEACON_STATUS_DIGEST_MISMATCH_TOTAL.inc();
}

/// Publish the computed fork digest as a label, so a dashboard can tell at a
/// glance whether a node is stranded on a boundary it failed to cross.
pub fn set_beacon_fork_digest(digest: &str) {
    LEAN_BEACON_FORK_DIGEST.with_label_values(&[digest]).set(1);
}
```

The `lean_` prefix is kept even on the beacon wire: it is the repo-wide
convention and every dashboard keys on it.

- [ ] **Step 4: Dispatch gossip and connections on the wire**

In `crates/net/p2p/src/lib.rs`'s `handle_swarm_event`, replace the gossipsub arm:

```rust
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
            message @ libp2p::gossipsub::Event::Message { .. },
        )) => {
            if server.wire.beacon().is_some() {
                beacon::handler::handle_beacon_gossip_message(server, message).await;
            } else {
                gossipsub::handle_gossipsub_message(server, message).await;
            }
        }
```

In the `ConnectionEstablished` arm, replace the block that builds and sends the
lean status with a wire dispatch. The whole `if num_established.get() == 1 { .. }`
body becomes:

```rust
            if num_established.get() == 1 {
                server.connected_peers.insert(peer_id);
                let peer_count = server.connected_peers.len();
                metrics::notify_peer_connected(
                    server.resolve_node_name(Some(&peer_id)),
                    direction,
                    "success",
                );
                // Compute the beacon status and its log fields first, so no
                // borrow of `server.wire` is alive across the send.
                let beacon_status = server.wire.beacon().map(|wire| {
                    (
                        beacon::handler::build_status(wire),
                        hex::encode(wire.fork_digest),
                    )
                });
                match beacon_status {
                    Some((status, digest)) => {
                        info!(
                            %peer_id,
                            %direction,
                            peer_count,
                            fork_digest = %digest,
                            "Peer connected"
                        );
                        beacon::handler::send_status(server, peer_id, status).await;
                    }
                    None => {
                        let our_status = build_status(&server.store);
                        let our_finalized_slot = our_status.finalized.slot;
                        let our_head_slot = our_status.head.slot;
                        info!(
                            %peer_id,
                            %direction,
                            peer_count,
                            our_finalized_slot,
                            our_head_slot,
                            "Peer connected"
                        );
                        server
                            .swarm_handle
                            .send_request(
                                peer_id,
                                Request::Status(our_status),
                                libp2p::StreamProtocol::new(STATUS_PROTOCOL_V1),
                            )
                            .await;
                    }
                }
            } else {
```

`hex::encode` is called eagerly rather than inside the `info!`, because the
formatted digest has to outlive the borrow of `server.wire` for the same reason
the status does.

- [ ] **Step 5: Route beacon requests and responses**

`BeaconRequest::MetaData` already carries the negotiated protocol id (Task 9),
which is what lets the responder answer in the version the peer asked for:
`request_response::Event::Message` does not carry the protocol id, so the codec
records it on the request.

In `crates/net/p2p/src/req_resp/handlers.rs`, add the inbound arm to the
`match request` block:

```rust
                    Request::Beacon(request) => {
                        info!(kind = "beacon_request", peer_count, "P2P message received");
                        crate::beacon::handler::handle_beacon_request(
                            server, peer, request, channel,
                        )
                        .await;
                    }
```

and the outbound arm, inside `Response::Success { payload }`:

```rust
                        ResponsePayload::Beacon(response) => {
                            info!(kind = "beacon_response", peer_count, "P2P message received");
                            crate::beacon::handler::handle_beacon_response(server, peer, response);
                        }
```

Add that function to `crates/net/p2p/src/beacon/handler.rs`:

```rust
/// Record a beacon response. Nothing is driven off one yet.
pub fn handle_beacon_response(server: &mut P2PServer, peer: PeerId, response: BeaconResponse) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    match response {
        BeaconResponse::Status(status) => {
            if status.fork_digest() != wire.fork_digest {
                warn!(
                    %peer,
                    peer_digest = %hex::encode(status.fork_digest()),
                    our_digest = %hex::encode(wire.fork_digest),
                    "Handshake answered from another fork digest"
                );
                metrics::inc_beacon_status_digest_mismatch();
                return;
            }
            info!(
                %peer,
                peer_head_slot = status.head_slot(),
                peer_finalized_epoch = status.finalized_epoch(),
                "Beacon handshake complete"
            );
        }
        BeaconResponse::Pong(ping) => {
            debug!(%peer, peer_seq_number = ping.seq_number, "Pong received");
        }
        BeaconResponse::MetaData(_) => {
            debug!(%peer, "Peer metadata received");
        }
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-p2p beacon -- --nocapture`
Expected: PASS, every `beacon::*` test.

Run: `cargo test -p ethlambda-p2p req_resp -- --nocapture`
Expected: PASS.

- [ ] **Step 7: Verify the lean suite**

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make fmt`
Expected: no diff.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -S -m "feat(p2p): the beacon handshake, responder and gossip handler

Answers only what keeps a connection alive: a Status, a Pong, and a
MetaData in whichever version the peer negotiated. Goodbye is logged and
the channel dropped, because it is one-way.

The Status carries the computed digest and zeroes for everything else,
which is the honest answer for a node holding no chain. Lighthouse exempts
a zero finalized_root from its relevance check, so this reads as 'peer is
syncing' rather than as a conflicting chain; that is why the probe kept
its peers on the same shape.

Gossip is decoded, counted and logged. Forwarding to the chain actor waits
for the anchor: on_block rejects a block whose parent is not in the store,
and nothing has put one there."
```

---

## Task 11: `ethlambda beacon` startup

**Files:**
- Create: `bin/ethlambda/src/beacon.rs`
- Modify: `bin/ethlambda/src/main.rs`
- Test: `bin/ethlambda/src/beacon.rs`

Plan 2 added the `beacon` subcommand and its `--checkpoint-sync-url`. This task
fills in what it runs.

- [ ] **Step 1: Declare the module before it exists**

Add to `bin/ethlambda/src/main.rs`, beside the other module declarations:

```rust
mod beacon;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda beacon:: -- --nocapture`
Expected: FAIL to compile, `file not found for module 'beacon'`.

- [ ] **Step 3: Write the module and its tests**

Create `bin/ethlambda/src/beacon.rs` with the epoch helpers and their tests:

```rust
//! `ethlambda beacon`: startup for the mainnet follower.
//!
//! Every network parameter is derived rather than hardcoded. The order matters:
//! the fork digest depends on the epoch, which depends on genesis time, which
//! comes from the Beacon API, so the swarm cannot be built until that call has
//! returned.
//!
//! ```text
//! GET /eth/v1/beacon/genesis
//!   └─► genesis_validators_root, genesis_time
//!       └─► epoch = (now - genesis_time) / (seconds_per_slot * SLOTS_PER_EPOCH)
//!           └─► fork_digest = compute_fork_digest(Config::mainnet(), gvr, epoch)
//!               └─► gossip topics, ENR eth2 entry, discv5 admission
//! ```

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::fork_digest::{compute_fork_digest, next_fork_boundary};
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{Epoch, ForkDigest, Root};
use ethlambda_types::enr::{EnrForkId, FAR_FUTURE_EPOCH};
use eyre::WrapErr as _;
use serde::Deserialize;
use tracing::{info, warn};

/// The epoch containing wall-clock second `now`.
///
/// Before genesis this is 0 rather than an error: a node started early should
/// pick the genesis fork's topics and wait, not refuse to boot.
pub fn epoch_at(config: &Config, genesis_time: u64, now: u64) -> Epoch {
    now.saturating_sub(genesis_time) / (config.seconds_per_slot * preset::SLOTS_PER_EPOCH)
}

/// The wall-clock second `epoch` begins at.
pub fn time_at_epoch(config: &Config, genesis_time: u64, epoch: Epoch) -> u64 {
    genesis_time + epoch * config.seconds_per_slot * preset::SLOTS_PER_EPOCH
}

/// The `eth2` ENR entry for this chain at this epoch.
///
/// `next_fork_*` point at the next boundary that moves the digest, which
/// includes blob-parameter-only forks. Peers tolerate a difference here by
/// design: only `fork_digest` has to match.
pub fn enr_fork_id(config: &Config, genesis_validators_root: Root, epoch: Epoch) -> EnrForkId {
    let fork_digest = compute_fork_digest(config, genesis_validators_root, epoch);
    match next_fork_boundary(config, epoch) {
        Some(boundary) => EnrForkId {
            fork_digest,
            next_fork_version: config.fork_version(config.fork_at_epoch(boundary)),
            next_fork_epoch: boundary,
        },
        None => EnrForkId {
            fork_digest,
            next_fork_version: config.fork_version(config.fork_at_epoch(epoch)),
            next_fork_epoch: FAR_FUTURE_EPOCH,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet's genesis, 2020-12-01 12:00:23 UTC.
    const MAINNET_GENESIS_TIME: u64 = 1_606_824_023;

    fn mainnet_gvr() -> Root {
        Root::from_slice(
            &hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .expect("valid hex"),
        )
    }

    #[test]
    fn the_epoch_is_read_off_the_wall_clock() {
        let config = Config::mainnet();
        assert_eq!(epoch_at(&config, MAINNET_GENESIS_TIME, MAINNET_GENESIS_TIME), 0);
        // One epoch is SLOTS_PER_EPOCH slots of seconds_per_slot each.
        let one_epoch = config.seconds_per_slot * preset::SLOTS_PER_EPOCH;
        assert_eq!(
            epoch_at(&config, MAINNET_GENESIS_TIME, MAINNET_GENESIS_TIME + one_epoch),
            1
        );
        assert_eq!(
            epoch_at(&config, MAINNET_GENESIS_TIME, MAINNET_GENESIS_TIME + one_epoch - 1),
            0
        );
    }

    #[test]
    fn a_clock_before_genesis_reports_epoch_zero_rather_than_underflowing() {
        let config = Config::mainnet();
        assert_eq!(epoch_at(&config, MAINNET_GENESIS_TIME, 0), 0);
    }

    #[test]
    fn epoch_and_time_are_inverses() {
        let config = Config::mainnet();
        for epoch in [0u64, 1, 411_392, 419_072] {
            let at = time_at_epoch(&config, MAINNET_GENESIS_TIME, epoch);
            assert_eq!(epoch_at(&config, MAINNET_GENESIS_TIME, at), epoch);
        }
    }

    #[test]
    fn the_enr_fork_id_carries_the_computed_digest() {
        let config = Config::mainnet();
        let fork_id = enr_fork_id(&config, mainnet_gvr(), 419_072);
        assert_eq!(fork_id.fork_digest, [0x8c, 0x9f, 0x62, 0xfe]);
        // Nothing is scheduled past the last blob-schedule entry.
        assert_eq!(fork_id.next_fork_epoch, FAR_FUTURE_EPOCH);
        assert_eq!(fork_id.next_fork_version, config.fulu_fork_version);
    }

    #[test]
    fn a_pending_boundary_is_advertised() {
        let config = Config::mainnet();
        let fork_id = enr_fork_id(&config, mainnet_gvr(), 411_392);
        assert_eq!(fork_id.next_fork_epoch, 412_672);
        // A blob-parameter-only fork keeps fulu's version: it moves the digest
        // without introducing a new fork version, which is EIP-7892's point.
        assert_eq!(fork_id.next_fork_version, config.fulu_fork_version);
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda beacon:: -- --nocapture`
Expected: PASS, all five tests.

- [ ] **Step 5: Fetch the genesis metadata**

Append to `bin/ethlambda/src/beacon.rs`:

```rust
/// Path of the Beacon API's genesis endpoint, relative to the checkpoint URL.
const GENESIS_PATH: &str = "/eth/v1/beacon/genesis";

/// Timeout for the genesis fetch. The response is a few hundred bytes, so a
/// slow one means an unhealthy peer rather than a large body.
const GENESIS_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Deserialize)]
struct GenesisResponse {
    data: GenesisData,
}

#[derive(Debug, Deserialize)]
struct GenesisData {
    genesis_time: String,
    genesis_validators_root: String,
}

/// The two genesis fields the fork digest is derived from.
#[derive(Debug, Clone, Copy)]
pub struct Genesis {
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
}

/// Fetch `genesis_time` and `genesis_validators_root` from a Beacon API.
///
/// This is the whole of what startup needs from the network: the anchor state
/// itself belongs to the anchor-and-follow work, and must be checked against
/// these two values when it lands.
pub async fn fetch_genesis(base_url: &str) -> eyre::Result<Genesis> {
    let url = format!("{}{GENESIS_PATH}", base_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(GENESIS_TIMEOUT)
        .build()
        .wrap_err("failed to build the genesis HTTP client")?;
    let response: GenesisResponse = client
        .get(&url)
        .send()
        .await
        .wrap_err_with(|| format!("failed to GET {url}"))?
        .error_for_status()
        .wrap_err_with(|| format!("{url} returned an error status"))?
        .json()
        .await
        .wrap_err_with(|| format!("{url} did not return the expected JSON"))?;

    let genesis_time: u64 = response
        .data
        .genesis_time
        .parse()
        .wrap_err("genesis_time is not a number")?;
    let root_hex = response
        .data
        .genesis_validators_root
        .trim_start_matches("0x");
    let root_bytes = hex::decode(root_hex).wrap_err("genesis_validators_root is not hex")?;
    eyre::ensure!(
        root_bytes.len() == 32,
        "genesis_validators_root is {} bytes, not 32",
        root_bytes.len()
    );

    Ok(Genesis {
        genesis_time,
        genesis_validators_root: Root::from_slice(&root_bytes),
    })
}
```

Add to `bin/ethlambda/Cargo.toml` under `[dependencies]` if they are not already
there (`reqwest` and `serde` are, from checkpoint sync; `hex` may not be):

```toml
hex.workspace = true
```

- [ ] **Step 6: Write the run function**

Append to `bin/ethlambda/src/beacon.rs`:

```rust
/// Everything `run` needs, gathered from the `beacon` subcommand's flags.
pub struct BeaconRunConfig {
    pub checkpoint_sync_url: String,
    pub node_key: Vec<u8>,
    pub gossipsub_port: u16,
    pub discovery_port: u16,
    pub advertise_ip: Option<IpAddr>,
    /// `None` uses the built-in mainnet list.
    pub bootnode_enrs: Option<Vec<String>>,
}

/// Start the mainnet follower and return once the P2P actor is running.
pub async fn run(config: BeaconRunConfig) -> eyre::Result<ethlambda_p2p::P2P> {
    let chain = Config::mainnet();
    let genesis = fetch_genesis(&config.checkpoint_sync_url)
        .await
        .wrap_err("failed to fetch genesis metadata")?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the unix epoch")
        .as_secs();
    let epoch = epoch_at(&chain, genesis.genesis_time, now);
    let fork = chain.fork_at_epoch(epoch);
    let fork_id = enr_fork_id(&chain, genesis.genesis_validators_root, epoch);
    let digest_hex = hex::encode(fork_id.fork_digest);

    info!(
        genesis_time = genesis.genesis_time,
        genesis_validators_root = %format!("0x{}", hex::encode(genesis.genesis_validators_root.0)),
        epoch,
        fork = fork.as_str(),
        fork_digest = %digest_hex,
        "Derived the mainnet wire parameters"
    );
    ethlambda_p2p::metrics::set_beacon_fork_digest(&digest_hex);

    // The digest is computed once. Crossing a boundary while running strands
    // this node on topic names nobody publishes to, so say when that is.
    match next_fork_boundary(&chain, epoch) {
        Some(boundary) => info!(
            boundary_epoch = boundary,
            boundary_unix_time = time_at_epoch(&chain, genesis.genesis_time, boundary),
            "The fork digest changes at this boundary; restart the node to cross it"
        ),
        None => info!("No fork or blob-schedule boundary is scheduled"),
    }

    // Say plainly what is advertised but not served, so a running node never
    // implies more than it does.
    warn!(
        "Advertising cgc={} while custodying nothing, subscribing to no attestation, \
         sync committee or data column subnet, and publishing nothing",
        ethlambda_p2p::beacon::constants::CUSTODY_REQUIREMENT
    );

    let enrs = config
        .bootnode_enrs
        .unwrap_or_else(|| {
            ethlambda_p2p::beacon::bootnodes::MAINNET_BOOTNODES
                .iter()
                .map(|enr| enr.to_string())
                .collect()
        });
    let bootnodes = ethlambda_p2p::parse_enrs(enrs.clone());
    let discovery_bootnodes = ethlambda_p2p::parse_enrs(enrs);

    let listening_socket = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), config.gossipsub_port);
    let built = ethlambda_p2p::beacon::swarm::build_beacon_swarm(
        ethlambda_p2p::beacon::swarm::BeaconSwarmConfig {
            node_key: config.node_key.clone(),
            listening_socket,
            fork_digest: fork_id.fork_digest,
            config: chain,
            genesis_time: genesis.genesis_time,
            bootnodes,
        },
    )
    .map_err(|err| eyre::eyre!("{err}"))
    .wrap_err("failed to build the beacon swarm")?;

    let node_key = secp256k1::SecretKey::from_slice(&config.node_key)
        .wrap_err("node key is not a valid secp256k1 secret key")?;
    let discovery = ethlambda_p2p::discovery::spawn_discovery(
        ethlambda_p2p::discovery::DiscoverySpawnConfig {
            node_key,
            bind_ip: IpAddr::from([0, 0, 0, 0]),
            discovery_port: config.discovery_port,
            quic_port: config.gossipsub_port,
            // No attestation subnet is subscribed, so the bitfield is 64 bits
            // all unset: exactly what this node serves.
            subscription_subnets: Default::default(),
            attestation_committee_count: ethlambda_p2p::beacon::constants::ATTESTATION_SUBNET_COUNT,
            bootnodes: discovery_bootnodes,
            advertise_ip: config.advertise_ip,
            fork_id,
            custody_group_count: Some(ethlambda_p2p::beacon::constants::CUSTODY_REQUIREMENT),
        },
    )
    .await
    .map_err(|err| eyre::eyre!(err))
    .wrap_err("failed to start discv5 discovery")?;

    // An empty store. `P2PServer` holds one for the lean handlers; no beacon
    // path reads it until the anchor lands, at which point this becomes the
    // DB-backed store checkpoint sync produced.
    let store = ethlambda_storage::Store::from_anchor_state(
        Arc::new(ethlambda_storage::backend::in_memory::InMemoryBackend::new()),
        ethlambda_types::state::State::from_genesis(genesis.genesis_time, Vec::new()),
    );

    Ok(ethlambda_p2p::P2P::spawn(
        built,
        store,
        Default::default(),
        Some(discovery),
    ))
}
```

Confirm the in-memory backend's path with:

```bash
grep -rn "InMemoryBackend" crates/storage/src/lib.rs bin/ethlambda/src/ crates/blockchain/src/lib.rs | head -3
```

and use whichever path that reports; the module is `crates/storage/src/backend/in_memory.rs`
and may be re-exported at the crate root.

- [ ] **Step 7: Call it from the subcommand**

In `bin/ethlambda/src/main.rs`, fill in plan 2's `beacon` arm:

```rust
        Commands::Beacon(options) => {
            let node_key = read_hex_file_bytes(&options.node_key).wrap_err_with(|| {
                format!("failed to load node key from {}", options.node_key.display())
            })?;
            let bootnode_enrs = match options.bootnodes.as_ref() {
                Some(path) => Some(read_bootnode_strings(path)?),
                None => None,
            };
            let _p2p = beacon::run(beacon::BeaconRunConfig {
                checkpoint_sync_url: options.checkpoint_sync_url.clone(),
                node_key,
                gossipsub_port: options.gossipsub_port,
                // Defaults to gossipsub_port + 1 so the discv5 socket cannot
                // collide with QUIC out of the box.
                discovery_port: options.discovery.port,
                advertise_ip: options.discovery.advertise_ip,
                bootnode_enrs,
            })
            .await?;
            // Nothing to drive yet: the actor owns the swarm and the dial loop.
            std::future::pending::<()>().await;
            Ok(())
        }
```

`read_bootnode_strings` reads the ENR file as lines. If `main.rs` has no such
helper (today `read_bootnodes` returns parsed `Bootnode`s), add one beside it:

```rust
/// Read an ENR-per-line bootnode file, tolerating `- ` prefixes and `#`
/// comments so the same file works as YAML or as a plain list.
fn read_bootnode_strings(path: &std::path::Path) -> eyre::Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read bootnodes from {}", path.display()))?;
    Ok(contents
        .lines()
        .map(|line| line.trim().trim_start_matches("- ").trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect())
}
```

Plan 2 defines `BeaconOptions`. If its `--discovery.port` default is not
`gossipsub_port + 1`, set it there rather than compensating here: the design
makes that a per-subcommand default precisely so no resolution logic is needed.

- [ ] **Step 8: Verify it builds and the suites pass**

Run: `cargo build -p ethlambda --profile release-fast`
Expected: exit 0.

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make fmt`
Expected: no diff.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -S -m "feat(bin): ethlambda beacon derives its wire and joins mainnet

Nothing here is hardcoded. genesis_time and genesis_validators_root come
from the Beacon API, the epoch comes from the wall clock, the fork digest
comes from the schedule, and the topics, the eth2 ENR entry and discv5
admission all come from the digest. The anchor state itself is not fetched
yet; the two fields the digest needs are a few hundred bytes.

Startup logs the next boundary's epoch and wall-clock time, because the
digest is computed once and crossing one strands the node on topics nobody
publishes to. It also says plainly what is advertised but not served: a
cgc of 4 with nothing custodied, and no subnet of any family."
```

---

## Task 12: The live check, and the docs that describe it

**Files:**
- Create: `docs/beacon_wire.md`
- Modify: `docs/SUMMARY.md`
- Modify: `docs/discovery.md`

The success condition for this plan is a live public network, which no unit test
can assert. This task writes the procedure down so it is reproducible by someone
who did not implement it, and runs it.

- [ ] **Step 1: Generate a node key**

```bash
openssl rand -hex 32 > /tmp/beacon-node-key
```

Expected: a 64-character hex file. `--node-key` reads a hex string, not raw
bytes.

- [ ] **Step 2: Run the node against mainnet**

```bash
RUST_LOG=info,ethlambda_p2p=debug \
cargo run --profile release-fast -p ethlambda --bin ethlambda -- beacon \
  --checkpoint-sync-url https://beaconstate.info \
  --node-key /tmp/beacon-node-key \
  --gossipsub-port 9000 \
  --data-dir /tmp/ethlambda-beacon
```

Any public Beacon API works in place of `beaconstate.info`; the node reads two
fields from it. Leave it running for at least 120 seconds.

- [ ] **Step 3: Check the derived parameters, within 5 seconds of start**

Expected, in order:

```
Derived the mainnet wire parameters  genesis_time=1606824023 genesis_validators_root=0x4b363db9… epoch=… fork=fulu fork_digest=8c9f62fe
No fork or blob-schedule boundary is scheduled
Advertising cgc=4 while custodying nothing, …
Starting discv5 discovery  discovery_addr=0.0.0.0:9001 seeds=17 total_bootnodes=17
Local ENR  enr=enr:-…
Subscribed to beacon topic  topic=/eth2/8c9f62fe/beacon_block/ssz_snappy
… six more "Subscribed to beacon topic" lines …
Beacon P2P node started  socket=0.0.0.0:9000 fork_digest=8c9f62fe topics=7
```

`fork_digest` must match what a live crawl reports. If it does not, run
`cargo run -p ethlambda-p2p --example discv5_probe -- --network mainnet` and
compare against the plurality digest it reports; `seeds=17` proves the built-in
list parsed, and a lower number means a bootnode ENR was skipped with a warning.

- [ ] **Step 4: Check that peers connect, within 30 seconds**

Expected, repeatedly:

```
Dialing discovered peer  peer_id=… subnets=[]
Peer connected  peer_id=… direction=outbound peer_count=1 fork_digest=8c9f62fe
Beacon handshake complete  peer_id=… peer_head_slot=… peer_finalized_epoch=…
```

`peer_head_slot` should be within a few slots of
`(now - 1606824023) / 12`. A `Peer connected` with no `Beacon handshake
complete` behind it within a few seconds means the Status encoding is wrong; a
`Handshake answered from another fork digest` means the digest is.

`subnets=[]` on every candidate is expected: peers are ranked by uncovered
attestation subnets and this node covers none, so ranking is a no-op here.

- [ ] **Step 5: Check that a block decodes, within 30 seconds**

Expected, once per 12-second slot:

```
Beacon block decoded  slot=… proposer=… fork=fulu block_root=… bytes=…
```

This is the plan's success condition. `bytes` on mainnet is typically 100 KB to
250 KB. A `Beacon gossip decode failed` for `beacon_block` means the fork
selection or the slot offset is wrong; a stream of
`Beacon gossip decode failed` for `beacon_aggregate_and_proof` alone means the
electra boundary in `decode_gossip` is wrong and the block path is fine.

If nothing arrives at all, check the mesh:

```bash
curl -s localhost:5054/metrics | grep -E "lean_gossip_mesh_peers|lean_beacon_gossip"
```

Expected: at least one mesh peer, and
`lean_beacon_gossip_messages_total{topic="beacon_block",result="decoded"}` above
zero. Mesh peers at zero with connected peers above zero means the topic hash
disagrees, which is almost always the digest's hex formatting or
`compute_message_id`.

- [ ] **Step 6: Record the numbers**

Note, for the docs in Step 7: seconds to first peer, seconds to first decoded
block, peer count and mesh peer count at 120 seconds, and the observed fork
digest.

- [ ] **Step 7: Write the operator documentation**

Create `docs/beacon_wire.md` with exactly this content (the outer fence is four
backticks because the page itself contains fenced blocks):

````markdown
# The mainnet wire

`ethlambda beacon` follows the Ethereum Beacon Chain. This page describes what
it puts on the wire; `docs/discovery.md` covers the discv5 stack it shares with
lean.

## Running it

```bash
ethlambda beacon \
  --checkpoint-sync-url https://beaconstate.info \
  --node-key ./node-key \
  --gossipsub-port 9000
```

`--checkpoint-sync-url` is required. It is where `genesis_time` and
`genesis_validators_root` come from, and therefore where the fork digest comes
from. discv5 is forced on and needs no flag: no published mainnet bootnode
advertises a `quic` entry, so none is statically dialable and a crawl is the
only way to peer.

## The fork digest

Computed once at startup, never hardcoded:

```
epoch        = (now - genesis_time) / (SECONDS_PER_SLOT * SLOTS_PER_EPOCH)
fork_version = the mainnet schedule at epoch
base         = compute_fork_data_root(fork_version, genesis_validators_root)
digest       = base[..4]                                    if epoch <  FULU_FORK_EPOCH
             = xor(base, sha256(le64(bp.epoch) ++
                                le64(bp.max_blobs)))[..4]   if epoch >= FULU_FORK_EPOCH
```

`bp` is the latest blob-schedule entry at or before `epoch`, falling back to
`(ELECTRA_FORK_EPOCH, MAX_BLOBS_PER_BLOCK_ELECTRA)`. The fulu branch is
EIP-7892's, which is why mainnet's digest is `8c9f62fe` rather than fulu's bare
`82fae541`.

Startup logs the next boundary's epoch and wall-clock time. The digest is
computed once, so crossing one strands the node on topic names nobody publishes
to; restart it to pick up the new digest.

## Gossip

Seven topics, `/eth2/{digest}/{name}/ssz_snappy`:

| Topic | Decoded as |
| --- | --- |
| `beacon_block` | `SignedBeaconBlock`, fork chosen by the block's slot |
| `beacon_aggregate_and_proof` | `SignedAggregateAndProof`, phase0 or electra |
| `attester_slashing` | `AttesterSlashing`, phase0 or electra |
| `voluntary_exit` | `SignedVoluntaryExit` |
| `proposer_slashing` | `ProposerSlashing` |
| `bls_to_execution_change` | `SignedBLSToExecutionChange` |
| `sync_committee_contribution_and_proof` | `SignedContributionAndProof` |

No subnet family is subscribed: not `beacon_attestation_{0..63}`, not
`sync_committee_{0..3}`, not `data_column_sidecar_{0..127}`, not
`blob_sidecar_{subnet_id}`. That is 7 subscriptions rather than 203, and it
drops roughly 30k BLS verifications per epoch. Each family arrives with the work
that reads it.

Nothing is published. Nothing this node can produce today would be
signature-valid.

## Request/response

| Protocol | Direction |
| --- | --- |
| `status/1`, `status/2` | both |
| `ping/1` | both |
| `metadata/1`, `metadata/2`, `metadata/3` | both |
| `goodbye/1` | inbound; the reason code is logged and the stream closed |

The block and sidecar protocols are not registered, so a peer asking for one
gets a stream-negotiation refusal rather than an answer this node cannot back
up. That costs peer score, which is the accepted price of following before
serving.

The `Status` this node sends carries the computed fork digest and zeroes for
every checkpoint, which is the honest answer for a node holding no chain.
Lighthouse's relevance check exempts a zero `finalized_root`, so this reads as
"peer is syncing" rather than as a conflicting chain.

## The ENR

| Entry | Value |
| --- | --- |
| `eth2` | the computed `ENRForkID` |
| `attnets` | 64 bits, all unset |
| `cgc` | `CUSTODY_REQUIREMENT` |
| `quic` | `--gossipsub-port` |
| `udp` | `--discovery.port` |
| no `tcp` | ethlambda speaks QUIC only |

Two of these advertise less, or more, than they look like:

- `attnets` all-unset is exactly what a node subscribing to no attestation
  subnet serves. It costs only that subnet-gap-filling peers rank us lower.
- `cgc` advertises the custody requirement while this node custodies and serves
  nothing, because peers may reject a lower value outright. This is the widest
  gap between what is advertised and what is served, and startup warns about it.

The missing `tcp` entry means beacon clients cannot discover us: lighthouse's
discovery predicate requires `enr.tcp4().is_some() || enr.tcp6().is_some()` and
applies it as a query filter. We discover them, which is what a follower needs.

## Metrics

| Metric | Meaning |
| --- | --- |
| `lean_beacon_gossip_messages_total{topic,result}` | Gossip received, by topic and by `decoded` / `decode_failed` / `decompress_failed` |
| `lean_beacon_status_digest_mismatch_total` | Handshakes seen from another fork digest |
| `lean_beacon_fork_digest{digest}` | The digest computed at startup, as a label |

The `lean_` prefix is the repo-wide convention and applies here too.
````

Add to `docs/SUMMARY.md`, under `# Operations`, after the discovery entry:

```markdown
- [The mainnet wire](./beacon_wire.md)
```

In `docs/discovery.md`, replace the paragraph in "Proving the discovered peers
are real" that begins "That binary is a probe, not a second client mode.", and
the two bullets under it, with:

```markdown
That binary was a probe, and what it proved is now shipped:
[the mainnet wire](./beacon_wire.md) puts the same topic names, protocol ids and
`Status` handshake behind the `ethlambda beacon` subcommand. What the probe
shares with both is the layer underneath: discv5, ENR parsing and verification,
and the `ssz_snappy` framing.

Two details from it are worth keeping in mind:

- The probe learned the fork digest by plurality vote over discovered ENRs.
  `ethlambda beacon` computes it from the fork schedule instead, which is
  correct across a boundary rather than merely current. Bootnode records remain
  poor witnesses either way: mainnet's still advertise the phase0 digest, and
  three of them a pre-genesis one.
- Gossip message ids follow Altair's function, which inserts the topic length
  and topic bytes between the domain and the payload. Phase0's shorter form
  produces ids no peer agrees with, which breaks IWANT/IHAVE silently.
  `compute_message_id` in `crates/net/p2p/src/lib.rs` is already the Altair form
  and is shared by both wires.
```

- [ ] **Step 8: Verify the docs build**

Run: `make docs`
Expected: mdbook builds with no broken-link warnings.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -S -m "docs: describe the mainnet wire and how to check it live

The success condition for this work is a live public network, so the
procedure that checks it is written down rather than left in a shell
history: the exact command, what each log line should say, and what a
wrong digest, a wrong Status encoding and a wrong topic hash each look
like when they fail.

docs/discovery.md's probe section is retargeted: the probe proved the
path, and the path now ships."
```

---

## Done when

**Automated.** Every one of these is a command with a pass/fail answer.

- [ ] `make fmt` produces no diff
- [ ] `make lint` passes with no warnings
- [ ] `make test` passes
- [ ] `make test-beacon` passes both presets with plan 1's counts: mainnet 5705
      cases / 152 ignored, minimal 40009 / 3692
- [ ] `make docs` builds with no broken links
- [ ] `cargo test -p ethlambda-types fork_digest` reproduces all five mainnet
      digests, including `8c9f62fe`, `ad532ceb` and `b5303f2a` from
      `docs/discovery.md`
- [ ] `cargo test -p ethlambda-p2p beacon::topics` asserts the exact seven topic
      strings and that no subnet family is among them
- [ ] `cargo test -p ethlambda-p2p beacon::protocols` asserts the exact protocol
      id strings and that no block or sidecar protocol is registered
- [ ] `cargo test -p ethlambda-p2p beacon::messages` asserts the exact wire
      lengths of `Status` v1/v2 and `MetaData` v1/v2/v3
- [ ] `cargo test -p ethlambda-p2p beacon::bootnodes` parses all 17 records and
      confirms every one can seed discv5 and none is statically dialable
- [ ] `cargo test -p ethlambda-p2p beacon::decode` round-trips a block through
      `decode_gossip`, selects the right fork at all seven mainnet boundaries,
      and refuses sixteen lengths of junk on every topic without panicking
- [ ] `cargo test -p ethlambda-p2p req_resp::codec` round-trips every beacon
      request and response through the shared `ssz_snappy` framing
- [ ] `cargo test -p ethlambda-p2p beacon::swarm` builds a swarm with seven
      subscriptions and a 768-second `seen_ttl`
- [ ] `cargo test -p ethlambda beacon::` inverts epoch and wall-clock time and
      produces the mainnet `ENRForkID`
- [ ] A lean devnet runs unchanged: `make run-devnet`, blocks produced and
      finalized, with no subcommand added to any script

**Manual.** These need the public network and a human reading logs; the
procedure is Task 12, Steps 1 to 6.

- [ ] The node logs `fork_digest=8c9f62fe` (or whatever a concurrent
      `discv5_probe --network mainnet` run reports as the plurality) within 5
      seconds of start
- [ ] `Beacon P2P node started` reports `topics=7` and `seeds=17`
- [ ] At least one `Beacon handshake complete` within 30 seconds of start
- [ ] At least one `Beacon block decoded` within 30 seconds of start, with
      `fork=fulu` and a slot within a few of `(now - 1606824023) / 12`
- [ ] After 120 seconds, `lean_gossip_mesh_peers` is above zero and
      `lean_beacon_gossip_messages_total{topic="beacon_block",result="decoded"}`
      is at least 5

Then start plan 5, anchor and follow.
