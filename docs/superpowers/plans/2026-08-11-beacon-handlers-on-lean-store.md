# Beacon Handlers on the DB-backed `Store` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the four beacon fork-choice handlers off `ethlambda_beacon::fork_choice::Store`'s in-memory `HashMap`s and onto the DB-backed `ethlambda_storage::Store`, delete the in-memory store, and give `BlockChainServer` a single dispatch on the chain the data directory holds, with the lean path unchanged and all 150 mainnet `fork_choice` fixture cases still green.

**Architecture:** The cutover is made small by rehearsing it first. Tasks 2 to 7 grow `ethlambda_storage::Store` a beacon method surface (blocks, fork-tagged state snapshots, checkpoints, fork-choice scratch) with its own tests, while `fork_choice::Store` is untouched. Tasks 8 to 10 then make `fork_choice.rs` reach its *own* in-memory store through **exactly that same method surface**, one field group at a time, with the fixture suite green after each. Task 11 is the cutover proper: the field bodies are already gone, so it swaps the type, implements anchors-plus-replay behind the two functions the state reads now go through (`block_state`, `checkpoint_state`), and rebuilds the fixture runner's store construction. Task 12 adds the `BlockChainServer` match. The `make test-beacon` fixture counts are the gate on every task.

**Tech Stack:** Rust 1.97.1 (edition 2024), `libssz` / `libssz-derive` / `libssz-merkle` (patched to the `add-deref` rev), `lru`, `rocksdb`, `ethereum-types`, consensus-spec-tests v1.6.1 fixtures.

---

## Plan series

This is plan 3 of 5 for sub-projects A1 and A2 of
`docs/superpowers/specs/2026-08-10-mainnet-network-design.md`. Each plan ends
with a working, testable tree.

| # | Plan | Ends when |
|---|---|---|
| 1 | Beacon type unification (`2026-08-10-beacon-type-unification.md`, done) | Types live in `ethlambda-types`, `BeaconState::Lean` exists, every fixture suite green |
| 2 | CLI subcommands | `ethlambda lean` and `ethlambda beacon` parse, bare flags still resolve to `lean`, devnet unchanged |
| 3 | **Beacon handlers on the DB-backed `Store`, and the `BlockChainServer` variant dispatch** (this plan; spec §4, §5) | `fork_choice::Store` deleted, all 150 `fork_choice` fixture cases green against `ethlambda_storage::Store` |
| 4 | Mainnet wire | Node peers with mainnet, decodes a `beacon_block` within ~30s |
| 5 | Anchor and follow | Checkpoint sync, anchor-to-head range fetch, head tracks wall clock |

Plan 2 can land before or after this one: they touch disjoint files
(`bin/ethlambda/src/main.rs` and `cli.rs` versus `crates/storage`,
`crates/beacon`, `crates/blockchain`). Plans 4 and 5 both depend on this one:
they need the beacon `Store` and the dispatch to hang gossip and checkpoint sync
off.

---

## Where the spec and the code disagree

Three places. Each is resolved here in the code's favour, per the plan brief.

**1. `checkpoint_states` cannot be both "persisted" and inside a two-anchor disk
budget.** Spec §5 lists `checkpoint_states` under "Persisted", and then says
`States` "holds the latest finalized anchor and the one before it" for
"~700 MB steady state, two anchors". A persisted `checkpoint_states` would be a
third place full 350 MB states live. Resolution: checkpoint states are
**derived**, not stored. `checkpoint_state(store, checkpoint, config)` serves
them from the same anchors-plus-replay path as block states plus
`stf::process_slots`, cached in a small LRU. Nothing about the handlers' observable
behaviour changes, and the disk budget is the one the spec itself states.

**2. `get_state` cannot be one accessor for both chains.** Spec §5 says
`get_state` "returns `Result<Option<BeaconState>>` rather than the lean `State`,
which touches every caller in `blockchain` and `rpc`". That is unachievable
alongside the spec's own anchors-plus-replay decision: lean reconstructs a state
from `StateDiffs` *inside* `ethlambda-storage`, while beacon replays blocks
through `stf::state_transition`, which lives in `ethlambda-beacon` and cannot be
called from `ethlambda-storage` without a dependency cycle. The two have
different contracts, not one signature. Resolution: `get_state` stays lean-typed
and lean-only (its 11 callers in `blockchain` and `rpc` are untouched);
`ethlambda-storage` gains `beacon_state_snapshot` / `insert_beacon_state_snapshot`,
the raw fork-tagged `States` accessors, and `ethlambda-beacon` owns the replay on
top of them. The *storage format* break the spec asks for still happens in full:
`States` values gain the one-byte fork selector, and `db_version` gates startup.

**3. The beacon checkpoints cannot reuse `latest_justified()` / `latest_finalized()`.**
Spec §5's table maps them onto the existing lean accessors. Lean's `Checkpoint`
is `{ root: H256, slot: u64 }` in `ethlambda_types::checkpoint`; beacon's is
`{ epoch: Epoch, root: Root }` in `ethlambda_types::beacon::containers`. They are
different types over different fields. Resolution: four new `Metadata` keys and
four beacon-typed accessors. `time` and `genesis_time` *are* reused as the spec
says, since both are plain `u64` (with different units per chain, documented at
the accessor).

One further constraint the spec does not mention: `ethlambda-beacon` gaining a
dependency on `ethlambda-storage` pulls `rocksdb` into its build, so
`make test-beacon` compiles RocksDB once. Accepted rather than worked around with
a feature flag; it is a one-time build cost, and a `#[cfg]`-gated backend module
would buy nothing at the second preset run.

---

## File structure

| File | Responsibility |
|---|---|
| `crates/common/types/src/beacon/fork.rs` | **Modify.** `ForkName::selector` / `from_selector`: the one-byte on-disk tag |
| `crates/common/types/src/beacon/fork_choice.rs` | **Create.** `LatestMessage` and `PowBlock`, moved out of `ethlambda-beacon` so `ethlambda-storage` can hold them |
| `crates/common/types/src/beacon/mod.rs` | **Modify.** Add `pub mod fork_choice;` |
| `crates/storage/src/api/tables.rs` | **Modify.** Add `Table::BeaconForkChoice`; `ALL_TABLES` grows to 9 |
| `crates/storage/src/error.rs` | **Modify.** Add `DbVersionMismatch` and `WrongChain` |
| `crates/storage/src/store.rs` | **Modify.** `Chain`, `DB_VERSION`, the fork-selector state encoding, the three new `Store` fields |
| `crates/storage/src/beacon_store.rs` | **Create.** Every beacon method on `Store`: blocks, snapshots, caches, checkpoints, scratch, anchors |
| `crates/storage/src/lib.rs` | **Modify.** Add `mod beacon_store;` and re-export `Chain`, `BeaconBlockIndex`, `DB_VERSION` |
| `crates/storage/Cargo.toml` | **Modify.** Enable `libssz`'s `ethereum_types` feature (beacon `Root` is `ethereum_types::H256`) |
| `crates/beacon/src/fork_choice.rs` | **Modify.** The whole point: `Store` deleted, handlers take `ethlambda_storage::Store`, replay added |
| `crates/beacon/src/lib.rs` | **Modify.** The module doc's "depends on no other `ethlambda-*` crate" claim |
| `crates/beacon/Cargo.toml` | **Modify.** Add `ethlambda-storage` |
| `crates/beacon/tests/spec/fork_choice.rs` | **Modify.** Build the store on an `InMemoryBackend`; read the store through methods |
| `crates/blockchain/src/beacon_chain.rs` | **Create.** The beacon arm of each dispatch: `on_tick`, `on_block`, `on_attestation`, `head` |
| `crates/blockchain/src/lib.rs` | **Modify.** One `match self.store.chain()` at the top of each handler |
| `crates/blockchain/Cargo.toml` | **Modify.** Add `ethlambda-beacon` |
| `bin/ethlambda/src/main.rs` | **Modify.** Seed `BlockChainConfig::beacon_config` |
| `docs/beacon_stf.md` | **Modify.** The store is no longer in-memory |
| `docs/data_storage.md` | **Modify.** The fork selector, `db_version`, the ninth table, the beacon anchor rules |

---

## Task 1: Establish the baseline

**Files:** none modified.

This task has **no commit**. It exists so every later task has exact numbers to
compare against, and so a failure in Task 2 is known to be Task 2's.

- [ ] **Step 1: Confirm the fixture trees are present**

Run: `ls consensus-spec-tests/tests && ls leanSpec/fixtures`
Expected: `general`, `mainnet`, `minimal` under the first; a populated tree under
the second. If either is missing, run `make consensus-spec-tests` and
`make leanSpec/fixtures` (about 2.2 GB, several minutes).

- [ ] **Step 2: Record the beacon baseline**

Run: `make test-beacon`
Expected: PASS for both presets, with these fixture counts, which are what every
later task compares against:

```
mainnet   5705 fixture cases, 152 ignored
minimal  40009 fixture cases, 3692 ignored
```

`ethlambda-beacon`'s own lib-test count (195 mainnet, 196 minimal at the start of
this plan) **is allowed to move**: Tasks 8 to 11 rewrite `fork_choice.rs`'s unit
tests. The fixture counts are not allowed to move.

- [ ] **Step 3: Record the lean baseline**

Run: `make test`
Expected: PASS. This is the lean regression gate for every task below.

- [ ] **Step 4: Confirm the tree is clean**

Run: `make fmt && git diff --stat`
Expected: no diff.

Run: `make lint`
Expected: PASS with no warnings.

---

## Task 2: Give `ForkName` a stable one-byte selector

**Files:**
- Modify: `crates/common/types/src/beacon/fork.rs`
- Test: `crates/common/types/src/beacon/fork.rs`

The `States` table is about to hold both a lean `State` and a beacon
`BeaconState`, so its values need a tag. `self as u8` will not do: `ForkName`'s
variant order is load-bearing for the derived `Ord` (see plan 1), so a future
reorder would silently change what is already on disk.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/common/types/src/beacon/fork.rs`:

```rust
    #[test]
    fn every_fork_round_trips_through_its_selector() {
        for fork in ForkName::ALL {
            assert_eq!(ForkName::from_selector(fork.selector()), Some(fork));
        }
        // Lean is outside ALL but is exactly the value the tag exists to
        // distinguish, so it is checked separately rather than left out.
        assert_eq!(
            ForkName::from_selector(ForkName::Lean.selector()),
            Some(ForkName::Lean)
        );
    }

    #[test]
    fn selectors_are_pinned_to_their_on_disk_values() {
        // These bytes are a storage format: changing one makes every existing
        // database decode as the wrong fork. Asserted literally rather than
        // derived from the variant order, which the derived Ord already owns.
        assert_eq!(ForkName::Phase0.selector(), 0);
        assert_eq!(ForkName::Fulu.selector(), 6);
        // Lean sits at the top of the byte range so gloas and heze can keep
        // taking the next free value after fulu.
        assert_eq!(ForkName::Lean.selector(), 255);
        assert_eq!(ForkName::from_selector(7), None);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-types --profile release-fast selector -- --nocapture`
Expected: FAIL, `no function or associated item named 'selector' found for enum 'ForkName'`.

- [ ] **Step 3: Add the two functions**

Add to the `impl ForkName` block in `crates/common/types/src/beacon/fork.rs`:

```rust
    /// The one-byte tag this fork is stored under in a `States` value.
    ///
    /// Spelled out rather than `self as u8`. The variant order is already
    /// load-bearing for the derived [`Ord`] (see this enum's own doc), so
    /// deriving the on-disk tag from it too would mean a reorder made for the
    /// ordering's sake silently reinterpreted every state already written.
    ///
    /// [`ForkName::Lean`] takes 255 rather than 7 so that the beacon forks after
    /// fulu can keep taking the next free value as they land.
    pub const fn selector(self) -> u8 {
        match self {
            ForkName::Phase0 => 0,
            ForkName::Altair => 1,
            ForkName::Bellatrix => 2,
            ForkName::Capella => 3,
            ForkName::Deneb => 4,
            ForkName::Electra => 5,
            ForkName::Fulu => 6,
            ForkName::Lean => 255,
        }
    }

    /// The inverse of [`ForkName::selector`].
    ///
    /// `None` for a byte this build does not know, which means a corrupt or
    /// future-format database rather than anything a caller can recover from.
    pub const fn from_selector(byte: u8) -> Option<ForkName> {
        match byte {
            0 => Some(ForkName::Phase0),
            1 => Some(ForkName::Altair),
            2 => Some(ForkName::Bellatrix),
            3 => Some(ForkName::Capella),
            4 => Some(ForkName::Deneb),
            5 => Some(ForkName::Electra),
            6 => Some(ForkName::Fulu),
            255 => Some(ForkName::Lean),
            _ => None,
        }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-types --profile release-fast selector -- --nocapture`
Expected: PASS, both tests.

- [ ] **Step 5: Verify the suites**

Run: `make test`
Expected: PASS.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "feat(types): give ForkName a stable one-byte storage selector

The States table is about to hold a lean State and a beacon BeaconState
side by side, so its values need a tag. Spelled out rather than derived
from the variant order, which the derived Ord already owns: a reorder made
for the ordering's sake must not reinterpret states already on disk."
```

---

## Task 3: Tag `States` values, version the database, and record the chain

**Files:**
- Modify: `crates/storage/src/store.rs`
- Modify: `crates/storage/src/error.rs`
- Modify: `crates/storage/src/lib.rs`
- Modify: `crates/storage/Cargo.toml`
- Test: `crates/storage/src/store.rs`

The lean path is unchanged from the caller's side: `get_state` still returns
`State`. What changes is what a `States` value looks like on disk, and that a
data directory now says which chain it holds and which format version it is in.

`Root` (beacon) is `ethereum_types::H256`, so `libssz` needs its
`ethereum_types` feature in this crate from here on.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module at the bottom of `crates/storage/src/store.rs`:

```rust
    #[test]
    fn a_fresh_lean_store_records_its_chain_and_db_version() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend.clone(), State::from_genesis(7, vec![]));
        assert_eq!(store.chain(), Chain::Lean);

        let view = backend.begin_read().expect("read view");
        let version = view
            .get(Table::Metadata, KEY_DB_VERSION)
            .expect("get")
            .expect("db version written at bootstrap");
        assert_eq!(
            u64::from_ssz_bytes(&version).expect("valid version"),
            DB_VERSION
        );
    }

    #[test]
    fn states_values_carry_a_fork_selector() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend.clone(), State::from_genesis(7, vec![]));
        let anchor = store.head().expect("head root");

        let view = backend.begin_read().expect("read view");
        let value = view
            .get(Table::States, &anchor.to_ssz())
            .expect("get")
            .expect("anchor snapshot written at bootstrap");
        assert_eq!(value[0], ForkName::Lean.selector());
    }

    #[test]
    fn from_db_state_rejects_a_database_written_before_the_fork_selector() {
        let backend = Arc::new(InMemoryBackend::new());
        let _ = Store::from_anchor_state(backend.clone(), State::from_genesis(7, vec![]));

        // A pre-versioned database is exactly one with no version key, so
        // deleting it reproduces the format this build must refuse.
        let mut batch = backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::Metadata, vec![KEY_DB_VERSION.to_vec()])
            .expect("delete db version");
        batch.commit().expect("commit");

        let err = Store::from_db_state(backend, &genesis_config(7, &[]))
            .expect_err("a pre-versioned database must not be reused");
        assert!(matches!(
            err,
            Error::DbVersionMismatch {
                found: 0,
                expected: DB_VERSION
            }
        ));
    }

    #[test]
    fn from_db_state_refuses_a_beacon_data_directory() {
        let backend = Arc::new(InMemoryBackend::new());
        let _ = Store::from_anchor_state(backend.clone(), State::from_genesis(7, vec![]));

        // Rewrite only the chain byte: everything else is a valid lean chain,
        // so this pins the check to the chain tag rather than to some
        // side effect of a half-written directory.
        let mut batch = backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::Metadata,
                vec![(KEY_CHAIN.to_vec(), vec![Chain::Beacon.selector()])],
            )
            .expect("put chain");
        batch.commit().expect("commit");

        let err = Store::from_db_state(backend, &genesis_config(7, &[]))
            .expect_err("a beacon data directory must not be opened as lean");
        assert!(matches!(err, Error::WrongChain));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-storage --profile release-fast chain_and_db_version -- --nocapture`
Expected: FAIL, `cannot find value 'KEY_DB_VERSION' in this scope`.

- [ ] **Step 3: Enable the `ethereum_types` feature**

In `crates/storage/Cargo.toml`, replace the plain `libssz` line under
`[dependencies]`:

```toml
# `ethereum_types` because a beacon `Root` is an `ethereum_types::H256`, which
# `States` and the beacon block tables both key and encode.
libssz = { workspace = true, features = ["ethereum_types"] }
```

- [ ] **Step 4: Add the two error variants**

Add to the `Error` enum in `crates/storage/src/error.rs`:

```rust
    /// The data directory was written by a build with a different on-disk
    /// format. There is no migration: the `States` value layout changed, so
    /// every state already written would decode as the wrong shape.
    ///
    /// `found` is `0` for a directory written before versioning existed.
    #[error(
        "data directory has database version {found}, this build requires {expected}; \
         wipe the data directory and resync"
    )]
    DbVersionMismatch { found: u64, expected: u64 },
    /// The data directory holds the other chain. Opening it would write lean
    /// rows into a beacon chain's tables, or the reverse.
    #[error("data directory holds a beacon chain, not a lean chain; wipe it or use `ethlambda beacon`")]
    WrongChain,
```

- [ ] **Step 5: Add `Chain`, `DB_VERSION`, and the two metadata keys**

Add to `crates/storage/src/store.rs`, beside the existing metadata key
constants:

```rust
/// Key for the on-disk format version. Its value has type [`u64`] and it's SSZ-encoded.
const KEY_DB_VERSION: &[u8] = b"db_version";
/// Key for which chain this directory holds. Its value is a single
/// [`Chain::selector`] byte, not SSZ: it predates being able to decode
/// anything else in the directory.
const KEY_CHAIN: &[u8] = b"chain";

/// The on-disk format this build reads and writes.
///
/// Bumped whenever a table's key or value layout changes. `from_db_state`
/// refuses any other value rather than migrating: a lean devnet resyncs in
/// minutes, and a wrong guess about an old layout corrupts silently.
pub const DB_VERSION: u64 = 1;

/// The consensus protocol a data directory holds.
///
/// Written once at bootstrap and never rewritten, like `Metadata["config"]`. A
/// directory is one chain or the other for its whole life: the two use
/// different state shapes, different checkpoint types, and different clock
/// units, and nothing migrates between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Lean,
    Beacon,
}

impl Chain {
    /// The byte this chain is stored under. Spelled out for the same reason
    /// [`ForkName::selector`] is: it is a storage format, not a discriminant.
    pub const fn selector(self) -> u8 {
        match self {
            Chain::Lean => 0,
            Chain::Beacon => 1,
        }
    }

    /// The inverse of [`Chain::selector`].
    pub const fn from_selector(byte: u8) -> Option<Chain> {
        match byte {
            0 => Some(Chain::Lean),
            1 => Some(Chain::Beacon),
            _ => None,
        }
    }
}
```

Add the imports this needs at the top of the file:

```rust
use ethlambda_types::beacon::containers::BeaconState;
use ethlambda_types::beacon::fork::ForkName;
```

- [ ] **Step 6: Add the state value codec**

Add to `crates/storage/src/store.rs`, above `impl Store`:

```rust
/// Encodes a `States` value: the state's fork selector, then the variant's own
/// SSZ.
///
/// The tag is what lets one table hold both a lean `State` and a beacon
/// `BeaconState` without the reader having to already know which it is.
/// [`BeaconState::to_ssz`] panics on the `Lean` variant by design, so the lean
/// arm reaches through to the inner state rather than going via the enum.
pub(crate) fn encode_state_value(state: &BeaconState) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(state.fork_name().selector());
    match state {
        BeaconState::Lean(lean) => bytes.extend_from_slice(&lean.to_ssz()),
        beacon => bytes.extend_from_slice(&beacon.to_ssz()),
    }
    bytes
}

/// The inverse of [`encode_state_value`].
///
/// Panics on a value this build cannot tag-decode, matching every other read in
/// this file: `from_db_state` has already rejected a directory of the wrong
/// format version, so anything reaching here is corruption rather than an old
/// database.
pub(crate) fn decode_state_value(bytes: &[u8]) -> BeaconState {
    let (tag, ssz) = bytes.split_first().expect("state value is never empty");
    let fork = ForkName::from_selector(*tag).expect("state value carries a known fork selector");
    BeaconState::from_ssz(fork, ssz).expect("valid state")
}

/// [`decode_state_value`] for the lean reader, which has no beacon shape to do
/// anything with.
fn decode_lean_state_value(bytes: &[u8]) -> State {
    match decode_state_value(bytes) {
        BeaconState::Lean(state) => state,
        beacon => panic!(
            "lean read a {} state out of the States table; a data directory holds one chain",
            beacon.fork_name()
        ),
    }
}
```

- [ ] **Step 7: Route every `States` read and write through the codec**

Five sites in `crates/storage/src/store.rs`. Each is a one-line substitution:

| Site | Was | Becomes |
|---|---|---|
| `init_store`, the anchor snapshot | `anchor_state.to_ssz()` | `encode_state_value(&BeaconState::Lean(anchor_state.clone()))` |
| `get_state`, the snapshot fast path | `State::from_ssz_bytes(&bytes).expect("valid state")` | `decode_lean_state_value(&bytes)` |
| `reconstruct_state`, the walk's terminator | `State::from_ssz_bytes(&bytes).expect("valid state")` | `decode_lean_state_value(&bytes)` |
| `insert_state`, the anchor snapshot | `state.to_ssz()` | `encode_state_value(&BeaconState::Lean(state.clone()))` |
| `tests::insert_snapshot` | `state.to_ssz()` | `encode_state_value(&BeaconState::Lean(state.clone()))` |

`init_store` and `insert_state` both need the clone because the state is moved
on afterwards (into the `Self` it returns, and into `StateDiff::from_states`
respectively). In `insert_state` the clone replaces the existing
`is_anchor.then(|| state.to_ssz())`, so write it as:

```rust
        // Snapshot only at anchors; encode before `state` is consumed.
        let snapshot_bytes =
            is_anchor.then(|| encode_state_value(&BeaconState::Lean(state.clone())));
```

- [ ] **Step 8: Add the `chain` field and write both new keys at bootstrap**

Add the field to `struct Store`, beside `config`:

```rust
    /// Which chain this directory holds. Cached for the same reason [`Store::config`]
    /// is: written once at bootstrap, so a per-`Store` copy cannot go stale, and
    /// [`BlockChainServer`]'s dispatch reads it on every handler entry.
    pub(crate) chain: Chain,
```

Add the accessor to `impl Store`, beside `config`:

```rust
    /// Which consensus protocol this data directory holds.
    ///
    /// Infallible for the same reason [`Store::config`] is: fixed at bootstrap
    /// and cached, so this never reads the backend.
    pub fn chain(&self) -> Chain {
        self.chain
    }
```

Add the two entries to `init_store`'s `metadata_entries`, at the top of the
vector so a partially written directory still says what it is:

```rust
            let metadata_entries = vec![
                (KEY_DB_VERSION.to_vec(), DB_VERSION.to_ssz()),
                (KEY_CHAIN.to_vec(), vec![Chain::Lean.selector()]),
                (KEY_TIME.to_vec(), 0u64.to_ssz()),
```

Set `chain: Chain::Lean` in the `Self { .. }` `init_store` returns, and in
`from_db_state`'s and both test constructors' (`test_store`,
`test_store_with_backend`) struct literals.

- [ ] **Step 9: Check both keys in `from_db_state`**

Insert at the top of `from_db_state`'s existing `let persisted_config = { .. }`
block, immediately after `let view = backend.begin_read().expect("read view");`
and before the `KEY_CONFIG` read:

```rust
            // A directory with no config has never held a chain, so the version
            // check must come *after* that test, not before it: a fresh data
            // directory is `Ok(None)`, not a version mismatch.
            let Some(bytes) = view.get(Table::Metadata, KEY_CONFIG).expect("get config") else {
                return Ok(None);
            };
            let found = view
                .get(Table::Metadata, KEY_DB_VERSION)
                .expect("get db version")
                .map(|bytes| u64::from_ssz_bytes(&bytes).expect("valid db version"))
                .unwrap_or(0);
            if found != DB_VERSION {
                return Err(Error::DbVersionMismatch {
                    found,
                    expected: DB_VERSION,
                });
            }
            let chain = view
                .get(Table::Metadata, KEY_CHAIN)
                .expect("get chain")
                .and_then(|bytes| bytes.first().copied())
                .and_then(Chain::from_selector)
                .expect("a versioned directory always carries a chain tag");
            if chain != Chain::Lean {
                return Err(Error::WrongChain);
            }
```

and delete the `let Some(bytes) = view.get(Table::Metadata, KEY_CONFIG)` line
that was already there, since it moved up.

- [ ] **Step 10: Export the new names**

In `crates/storage/src/lib.rs`, extend the `store` re-export:

```rust
pub use store::{
    Chain, DB_VERSION, ForkCheckpoints, GetForkchoiceStoreError, MAX_RESUMABLE_DB_STATE_AGE, Store,
};
```

- [ ] **Step 11: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-storage --profile release-fast -- --nocapture`
Expected: PASS, including the four new tests and every existing storage test.

- [ ] **Step 12: Verify the suites**

Run: `make test`
Expected: PASS. Every existing lean test still runs against the new value
layout, which is the point: the format changed and no caller noticed.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 13: Commit**

```bash
git add -A
git commit -S -m "feat(storage): tag States values with their fork, and version the database

A States value now carries a one-byte fork selector ahead of its SSZ, so
one table can hold a lean State and a beacon BeaconState without the
reader having to already know which it is. That is a format break with no
migration, so a db_version key joins the genesis fingerprint and a
mismatch aborts startup, and a chain tag stops a lean build from opening
a beacon directory (and the reverse, once there is one)."
```

---

## Task 4: Move `LatestMessage` and `PowBlock` into `ethlambda-types`

**Files:**
- Create: `crates/common/types/src/beacon/fork_choice.rs`
- Modify: `crates/common/types/src/beacon/mod.rs`
- Modify: `crates/beacon/src/fork_choice.rs`
- Test: `crates/common/types/src/beacon/fork_choice.rs`

`ethlambda_storage::Store` is about to hold both, and `ethlambda-storage` cannot
depend on `ethlambda-beacon`: the dependency runs the other way. Same
move-then-re-export shape as plan 1.

- [ ] **Step 1: Write the failing test**

Create `crates/common/types/src/beacon/fork_choice.rs`:

```rust
//! The two fork-choice containers that are neither a block nor a state.
//!
//! They live here rather than in `ethlambda-beacon`'s `fork_choice` module
//! because the DB-backed `ethlambda_storage::Store` holds them, and
//! `ethlambda-storage` cannot depend on `ethlambda-beacon`: the dependency runs
//! the other way. `ethlambda_beacon::fork_choice` re-exports both at their old
//! paths, so every use site inside that crate is unchanged.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

use crate::beacon::primitives::{Epoch, Root, Uint256};

/// One validator's most recent attestation: the epoch it targeted, and the
/// block it attested to (the LMD GHOST vote).
///
/// `Copy`, matching the specification's `@dataclass(eq=True, frozen=True)`:
/// there is nothing here worth borrowing rather than copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestMessage {
    pub epoch: Epoch,
    pub root: Root,
}

/// The execution chain's own block header, as far as bellatrix's merge
/// transition check needs it: `specs/bellatrix/fork-choice.md`'s `PowBlock`.
///
/// The specification's own `get_pow_block(hash) -> Optional[PowBlock]` is
/// "implementation and context dependent": a real client would ask its
/// execution engine. The fork choice store's own record of these, populated by
/// the fixture suites' `on_merge_block` step, is what stands in for that.
///
/// Defined at the top level here, unlike in its former home: this module has no
/// `Result` alias of its own for the `SszDecode` derive's generated code to
/// collide with, so the nested module that used to shield it is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct PowBlock {
    pub block_hash: Root,
    pub parent_hash: Root,
    /// The total work behind `block_hash`, compared against
    /// [`crate::beacon::config::Config::terminal_total_difficulty`] to decide
    /// whether this is the one PoW block the merge transitioned at.
    pub total_difficulty: Uint256,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn a_pow_block_round_trips_through_ssz() {
        // The store persists these, so the derive has to survive the move out
        // of `ethlambda-beacon` intact.
        let block = PowBlock {
            block_hash: Root::repeat_byte(1),
            parent_hash: Root::repeat_byte(2),
            total_difficulty: Uint256::from(3u64),
        };
        let bytes = block.to_ssz();
        assert_eq!(
            PowBlock::from_ssz_bytes(&bytes).expect("valid pow block"),
            block
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-types --profile release-fast a_pow_block_round_trips -- --nocapture`
Expected: FAIL, `file not found for module 'fork_choice'` (the module is not
declared yet).

- [ ] **Step 3: Declare the module**

Add to `crates/common/types/src/beacon/mod.rs`, in alphabetical position among
the existing `pub mod` lines:

```rust
pub mod fork_choice;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p ethlambda-types --profile release-fast a_pow_block_round_trips -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Delete the originals and re-export**

In `crates/beacon/src/fork_choice.rs`, delete the `LatestMessage` struct and its
doc comment (the whole `// --- LatestMessage ---` section), and delete the
`mod pow_block { .. }` block together with its `pub use pow_block::PowBlock;`
line and the `// --- PowBlock ---` section's doc comment.

Add, beside the other `use` lines at the top of the file:

```rust
pub use ethlambda_types::beacon::fork_choice::{LatestMessage, PowBlock};
```

- [ ] **Step 6: Verify the suites**

Run: `make test-beacon`
Expected: PASS for both presets, with Task 1 Step 2's fixture counts. The
`fork_choice` suite exercises `PowBlock` directly through bellatrix's
`on_merge_block` step, so a broken derive shows up here.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -S -m "refactor(types): move LatestMessage and PowBlock into ethlambda-types

The DB-backed Store is about to hold both, and ethlambda-storage cannot
depend on ethlambda-beacon: the dependency runs the other way. Re-exported
at their old paths, so nothing inside ethlambda-beacon changes.

PowBlock loses the nested module it used to sit in: that existed only to
keep its SszDecode derive out of the scope of fork_choice.rs's own Result
alias, and the new module has no such alias."
```

---

## Task 5: Beacon block storage on `Store`

**Files:**
- Create: `crates/storage/src/beacon_store.rs`
- Modify: `crates/storage/src/store.rs`
- Modify: `crates/storage/src/lib.rs`
- Test: `crates/storage/src/beacon_store.rs`

Beacon blocks reuse the existing tables, per spec §5: the full signed block goes
in `BlockBodies`, a two-field walk record in `BlockHeaders`, and the parent link
in `LiveChain`, which is what gives the children scan and `get_ancestor` an index
without decoding a body.

`BlockRoots` is deliberately left unwritten on the beacon path: nothing serves
canonical-by-slot beacon queries until sub-project E, and an index nothing reads
is an invariant nothing checks.

**Every beacon accessor on `Store` is infallible**, matching how the lean
accessors already `expect` on backend I/O internally. This is what keeps
`fork_choice.rs` free of error conversion at 130 call sites.

- [ ] **Step 1: Write the failing tests**

Create `crates/storage/src/beacon_store.rs`:

```rust
//! Beacon Chain support on the DB-backed [`Store`].
//!
//! Split out of `store.rs` for size rather than for layering: these are `impl
//! Store` blocks like the ones there, over the same backend and the same tables.
//!
//! # What lives where
//!
//! | Fork choice needs | Table | Key | Value |
//! |---|---|---|---|
//! | the block itself, for the state transition | `BlockBodies` | root | fork selector, then `SignedBeaconBlock` SSZ |
//! | `slot` and `parent_root`, for tree walks | `BlockHeaders` | root | [`BeaconBlockEntry`] SSZ |
//! | the children of a root | `LiveChain` | slot ‖ root | parent root |
//! | a finalized anchor state | `States` | root | fork selector, then `BeaconState` SSZ |
//! | the unrealized justification of a block | `BeaconForkChoice` | root | beacon `Checkpoint` SSZ |
//!
//! `BlockRoots` is not written on this path. Nothing serves canonical-by-slot
//! beacon queries until sub-project E, and an index nothing reads is an
//! invariant nothing checks.
//!
//! # These accessors do not return `Result`
//!
//! Deliberately, and matching what `store.rs` already does: every lean accessor
//! there `expect`s on backend I/O internally and returns `Result` only for
//! conditions a caller can act on. `ethlambda_beacon::fork_choice` reaches these
//! from ~130 sites whose own error type lives in `ethlambda-types` and therefore
//! cannot carry a storage error, so returning one here would buy a
//! `.map_err(|err| Error::Storage(err.to_string()))` at each of them and nothing
//! else.

use std::collections::HashMap;

use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{Root, Slot};
use libssz::{SszDecode, SszEncode};
use libssz_derive::{SszDecode as SszDecodeDerive, SszEncode as SszEncodeDerive};

use crate::api::{StorageBackend, Table};
use crate::store::Store;

/// Every block in the beacon fork-choice window, as `root -> (slot, parent_root)`.
///
/// Built once per tree walk and passed down, rather than re-read per hop:
/// `get_weight` calls `get_ancestor` once per active validator, so a point
/// lookup per hop would multiply a scan the specification already writes as
/// naive by a backend round trip.
pub type BeaconBlockIndex = HashMap<Root, (Slot, Root)>;

/// What fork choice reads off a block without decoding its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncodeDerive, SszDecodeDerive)]
struct BeaconBlockEntry {
    slot: Slot,
    parent_root: Root,
}

/// A `BlockHeaders`/`BlockBodies`/`States` key: the block root's 32 bytes.
///
/// Raw bytes rather than `to_ssz()`, deliberately: a beacon `Root` and a lean
/// `H256` are different Rust types over the same 32 bytes, and writing the key
/// out this way makes it plain that the two layouts agree even though the two
/// chains never share a directory.
fn beacon_root_key(root: Root) -> Vec<u8> {
    root.0.to_vec()
}

/// A `LiveChain` key: slot big-endian, then the root, so lexicographic order is
/// slot order. Mirrors `store.rs`'s own `encode_slot_root_key`.
fn beacon_slot_root_key(slot: Slot, root: Root) -> Vec<u8> {
    let mut key = slot.to_be_bytes().to_vec();
    key.extend_from_slice(&root.0);
    key
}

/// The inverse of [`beacon_slot_root_key`].
fn decode_beacon_slot_root_key(bytes: &[u8]) -> (Slot, Root) {
    let slot = u64::from_be_bytes(bytes[..8].try_into().expect("valid slot bytes"));
    (slot, Root::from_slice(&bytes[8..]))
}

/// Encodes a `BlockBodies` value: the block's fork selector, then its SSZ.
fn encode_beacon_block_value(block: &SignedBeaconBlock) -> Vec<u8> {
    let mut bytes = vec![block.fork_name().selector()];
    bytes.extend_from_slice(&block.to_ssz());
    bytes
}

/// The inverse of [`encode_beacon_block_value`].
fn decode_beacon_block_value(bytes: &[u8]) -> SignedBeaconBlock {
    let (tag, ssz) = bytes.split_first().expect("block value is never empty");
    let fork = ForkName::from_selector(*tag).expect("block value carries a known fork selector");
    SignedBeaconBlock::from_ssz(fork, ssz).expect("valid signed beacon block")
}

impl Store {
    /// Records `block` under `root`, which must be the root of its unsigned
    /// message (`SignedBeaconBlock::message_hash_tree_root`).
    ///
    /// Writes all three rows in one batch: a half-written block would be visible
    /// to the children scan without being decodable.
    pub fn insert_beacon_block(&mut self, root: Root, block: &SignedBeaconBlock) {
        let entry = BeaconBlockEntry {
            slot: block.slot(),
            parent_root: block.parent_root(),
        };
        let key = beacon_root_key(root);

        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::BlockHeaders, vec![(key.clone(), entry.to_ssz())])
            .expect("put beacon block entry");
        batch
            .put_batch(
                Table::BlockBodies,
                vec![(key, encode_beacon_block_value(block))],
            )
            .expect("put beacon block");
        batch
            .put_batch(
                Table::LiveChain,
                vec![(
                    beacon_slot_root_key(entry.slot, root),
                    entry.parent_root.0.to_vec(),
                )],
            )
            .expect("put beacon live chain index");
        batch.commit().expect("commit");
    }

    /// The block stored under `root`, body and all.
    pub fn beacon_block(&self, root: Root) -> Option<SignedBeaconBlock> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockBodies, &beacon_root_key(root))
            .expect("get")
            .map(|bytes| decode_beacon_block_value(&bytes))
    }

    /// `root`'s slot and parent root, without decoding its body.
    pub fn beacon_block_entry(&self, root: Root) -> Option<(Slot, Root)> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockHeaders, &beacon_root_key(root))
            .expect("get")
            .map(|bytes| {
                let entry = BeaconBlockEntry::from_ssz_bytes(&bytes).expect("valid block entry");
                (entry.slot, entry.parent_root)
            })
    }

    /// Whether a block is stored under `root`.
    pub fn has_beacon_block(&self, root: Root) -> bool {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockHeaders, &beacon_root_key(root))
            .expect("get")
            .is_some()
    }

    /// Every stored block as `root -> (slot, parent_root)`. See
    /// [`BeaconBlockIndex`] for why a tree walk takes this rather than reading
    /// per hop.
    pub fn beacon_block_index(&self) -> BeaconBlockIndex {
        let view = self.backend.begin_read().expect("read view");
        view.prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(Result::ok)
            .map(|(key, value)| {
                let (slot, root) = decode_beacon_slot_root_key(&key);
                (root, (slot, Root::from_slice(&value)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_types::beacon::containers::phase0;
    use ethlambda_types::beacon::primitives::HashTreeRoot as _;

    use super::*;
    use crate::backend::InMemoryBackend;

    /// A signed block with an empty body and a zero signature. Phase0-shaped
    /// because nothing under test here reads a fork-specific field, matching
    /// the helper `fork_choice.rs`'s own unit tests use.
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

    /// An empty beacon store on an in-memory backend.
    fn beacon_store() -> Store {
        Store::init_beacon(Arc::new(InMemoryBackend::new()), 0)
    }

    #[test]
    fn a_beacon_block_round_trips_through_the_store() {
        let mut store = beacon_store();
        let signed = block(3, Root::repeat_byte(1));
        let root = signed.message_hash_tree_root();

        store.insert_beacon_block(root, &signed);

        assert!(store.has_beacon_block(root));
        assert_eq!(store.beacon_block(root), Some(signed));
        assert_eq!(
            store.beacon_block_entry(root),
            Some((3, Root::repeat_byte(1)))
        );
    }

    #[test]
    fn an_unknown_root_has_no_block() {
        let store = beacon_store();
        assert!(!store.has_beacon_block(Root::repeat_byte(9)));
        assert_eq!(store.beacon_block(Root::repeat_byte(9)), None);
        assert_eq!(store.beacon_block_entry(Root::repeat_byte(9)), None);
    }

    #[test]
    fn the_block_index_carries_every_parent_link() {
        let mut store = beacon_store();
        let genesis = block(0, Root::zero());
        let genesis_root = genesis.message_hash_tree_root();
        let child = block(1, genesis_root);
        let child_root = child.message_hash_tree_root();
        // A sibling at the same slot, so the index has to key on root rather
        // than on slot.
        let sibling = block(1, Root::repeat_byte(7));
        let sibling_root = sibling.message_hash_tree_root();

        store.insert_beacon_block(genesis_root, &genesis);
        store.insert_beacon_block(child_root, &child);
        store.insert_beacon_block(sibling_root, &sibling);

        let index = store.beacon_block_index();
        assert_eq!(index.len(), 3);
        assert_eq!(index[&genesis_root], (0, Root::zero()));
        assert_eq!(index[&child_root], (1, genesis_root));
        assert_eq!(index[&sibling_root], (1, Root::repeat_byte(7)));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-storage --profile release-fast beacon -- --nocapture`
Expected: FAIL, `file not found for module 'beacon_store'`.

- [ ] **Step 3: Declare the module and export the index type**

In `crates/storage/src/lib.rs`:

```rust
mod api;
pub mod backend;
mod beacon_store;
mod error;
mod state_diff;
mod store;

pub use api::{ALL_TABLES, StorageBackend, StorageReadView, StorageWriteBatch, Table};
pub use beacon_store::BeaconBlockIndex;
```

- [ ] **Step 4: Open the two fields `beacon_store.rs` needs**

In `crates/storage/src/store.rs`, change `struct Store`'s `backend` field from
private to `pub(crate)`:

```rust
pub struct Store {
    pub(crate) backend: Arc<dyn StorageBackend>,
```

- [ ] **Step 5: Add the metadata keys, the two beacon field types, and the two `Store` fields**

Add to `crates/storage/src/store.rs`, beside the other key constants:

```rust
/// Key for the beacon store's justified checkpoint. Its value has type
/// [`BeaconCheckpoint`] and it's SSZ-encoded. Separate from
/// [`KEY_LATEST_JUSTIFIED`] because the two chains' `Checkpoint` types carry
/// different fields: lean's is `{root, slot}`, beacon's is `{epoch, root}`.
pub(crate) const KEY_BEACON_JUSTIFIED: &[u8] = b"beacon_justified";
/// Key for the beacon store's finalized checkpoint. See [`KEY_BEACON_JUSTIFIED`].
pub(crate) const KEY_BEACON_FINALIZED: &[u8] = b"beacon_finalized";
/// Key for the beacon store's unrealized justified checkpoint.
pub(crate) const KEY_BEACON_UNREALIZED_JUSTIFIED: &[u8] = b"beacon_unrealized_justified";
/// Key for the beacon store's unrealized finalized checkpoint.
pub(crate) const KEY_BEACON_UNREALIZED_FINALIZED: &[u8] = b"beacon_unrealized_finalized";
/// Key for the roots of the finalized anchor states held in `States`, oldest
/// first, at most [`BEACON_ANCHORS_KEPT`]. Stored as concatenated 32-byte roots
/// rather than SSZ: it is read on every anchor promotion and the layout is one
/// line either way.
pub(crate) const KEY_BEACON_ANCHORS: &[u8] = b"beacon_anchors";
```

Change `KEY_TIME`'s declaration to `pub(crate) const KEY_TIME: &[u8] = b"time";`,
since `beacon_store.rs` reads the same key through its own accessor in Task 7.

Add the imports, aliasing the beacon types so neither can be confused with lean's:

```rust
use ethlambda_types::beacon::containers::Checkpoint as BeaconCheckpoint;
use ethlambda_types::beacon::fork_choice::{LatestMessage, PowBlock};
use ethlambda_types::beacon::primitives::Root as BeaconRoot;
```

Add the two field types and their capacities, above `struct Store`:

```rust
/// Beacon fork-choice state that is per-slot or per-epoch scratch rather than
/// chain history: nothing here survives a restart, and nothing here is worth the
/// write amplification of persisting.
///
/// `proposer_boost_root` resets every slot, `block_timeliness` is only read by
/// the same-slot reorg helpers, `equivocating_indices` is rebuilt by replaying
/// attester slashings on sync, `latest_messages` is rebuilt by the first epoch
/// of attestations, and `pow_blocks` stands in for a call to an execution client
/// that a restarted node would simply make again.
#[derive(Default)]
pub(crate) struct BeaconScratch {
    pub(crate) proposer_boost_root: BeaconRoot,
    pub(crate) block_timeliness: HashMap<BeaconRoot, bool>,
    pub(crate) equivocating_indices: HashSet<u64>,
    pub(crate) latest_messages: HashMap<u64, LatestMessage>,
    pub(crate) pow_blocks: HashMap<BeaconRoot, PowBlock>,
}

/// The beacon state caches.
///
/// A mainnet `BeaconState` is ~350 MB, so these are sized for the working set
/// the handlers need resident at once rather than for a hit rate: the latest
/// finalized anchor and the head's post-state, plus the justified checkpoint's
/// epoch-boundary state. Three entries, ~1 GB, which is the budget
/// `docs/superpowers/specs/2026-08-10-mainnet-network-design.md` §5 sets.
///
/// A miss is never an error: `ethlambda_beacon::fork_choice::block_state` and
/// `checkpoint_state` both derive the value by replaying from the nearest anchor.
/// That is what makes an aggressive capacity safe here, and it is why these are
/// caches rather than the store's record of anything.
pub(crate) struct BeaconCaches {
    pub(crate) states: LruCache<BeaconRoot, Arc<BeaconState>>,
    pub(crate) checkpoint_states: LruCache<(u64, BeaconRoot), Arc<BeaconState>>,
}

/// Block post-states held resident. See [`BeaconCaches`].
const BEACON_STATE_CACHE_CAPACITY: usize = 2;
/// Epoch-boundary states held resident. See [`BeaconCaches`].
const BEACON_CHECKPOINT_STATE_CACHE_CAPACITY: usize = 1;
/// Finalized anchor snapshots kept in `States`. The second is the margin that
/// lets a replay start below the newest one.
pub(crate) const BEACON_ANCHORS_KEPT: usize = 2;

impl BeaconCaches {
    pub(crate) fn new() -> Self {
        Self {
            states: LruCache::new(
                NonZeroUsize::new(BEACON_STATE_CACHE_CAPACITY).expect("capacity is non-zero"),
            ),
            checkpoint_states: LruCache::new(
                NonZeroUsize::new(BEACON_CHECKPOINT_STATE_CACHE_CAPACITY)
                    .expect("capacity is non-zero"),
            ),
        }
    }
}
```

Add the two fields to `struct Store`, beside the `chain` field Task 3 added:

```rust
    /// Beacon fork-choice scratch. Empty and untouched on a lean chain.
    pub(crate) beacon: Arc<Mutex<BeaconScratch>>,
    /// Beacon state caches. Empty and untouched on a lean chain.
    pub(crate) beacon_cache: Arc<Mutex<BeaconCaches>>,
```

and set both in `init_store`'s and `from_db_state`'s `Self { .. }` literals, and
in the two test constructors (`test_store`, `test_store_with_backend`):

```rust
            beacon: Arc::new(Mutex::new(BeaconScratch::default())),
            beacon_cache: Arc::new(Mutex::new(BeaconCaches::new())),
```

- [ ] **Step 6: Add the beacon bootstrap constructor**

Add to `impl Store` in `crates/storage/src/store.rs`, beside `from_anchor_state`:

```rust
    /// Initialize an empty beacon-chain store.
    ///
    /// Writes only what every later read assumes exists: the format version,
    /// the chain tag, the genesis time, a zero clock, and zeroed checkpoints.
    /// The anchor block and state are written by
    /// `ethlambda_beacon::fork_choice::get_forkchoice_store`, which is where the
    /// spec's own construction rules live and which needs beacon helpers this
    /// crate cannot call.
    pub fn init_beacon(backend: Arc<dyn StorageBackend>, genesis_time: u64) -> Self {
        let config = ChainConfig { genesis_time };
        let zero = BeaconCheckpoint::default();
        {
            let mut batch = backend.begin_write().expect("write batch");
            let metadata_entries = vec![
                (KEY_DB_VERSION.to_vec(), DB_VERSION.to_ssz()),
                (KEY_CHAIN.to_vec(), vec![Chain::Beacon.selector()]),
                (KEY_TIME.to_vec(), 0u64.to_ssz()),
                (KEY_CONFIG.to_vec(), config.to_ssz()),
                (KEY_BEACON_JUSTIFIED.to_vec(), zero.to_ssz()),
                (KEY_BEACON_FINALIZED.to_vec(), zero.to_ssz()),
                (KEY_BEACON_UNREALIZED_JUSTIFIED.to_vec(), zero.to_ssz()),
                (KEY_BEACON_UNREALIZED_FINALIZED.to_vec(), zero.to_ssz()),
                (KEY_BEACON_ANCHORS.to_vec(), Vec::new()),
            ];
            batch
                .put_batch(Table::Metadata, metadata_entries)
                .expect("put metadata");
            batch.commit().expect("commit");
        }

        info!(genesis_time, "Initialized beacon store");

        Self {
            backend,
            chain: Chain::Beacon,
            config,
            new_payloads: Arc::new(Mutex::new(PayloadBuffer::new(NEW_PAYLOAD_CAP))),
            known_payloads: Arc::new(Mutex::new(PayloadBuffer::new(AGGREGATED_PAYLOAD_CAP))),
            gossip_signatures: Arc::new(Mutex::new(GossipSignatureBuffer::new(
                GOSSIP_SIGNATURE_CAP,
            ))),
            state_cache: new_state_cache(),
            beacon: Arc::new(Mutex::new(BeaconScratch::default())),
            beacon_cache: Arc::new(Mutex::new(BeaconCaches::new())),
        }
    }
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-storage --profile release-fast beacon -- --nocapture`
Expected: PASS, all three new tests.

- [ ] **Step 8: Verify the suites**

Run: `make test`
Expected: PASS.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -S -m "feat(storage): store beacon blocks and open a beacon store

Beacon blocks reuse the existing tables, since a directory holds one chain:
the signed block in BlockBodies behind a fork selector, a two-field walk
record in BlockHeaders, and the parent link in LiveChain, which is what
gives get_ancestor and the children scan an index without decoding a body.

The accessors do not return Result. Every lean accessor here already
expects on backend I/O internally; fork choice reaches these from ~130
sites whose own error type lives in ethlambda-types and cannot carry a
storage error, so a Result would buy a map_err at each of them and nothing
else."
```

---

## Task 6: Beacon state snapshots, caches, and the two-anchor rule

**Files:**
- Modify: `crates/storage/src/beacon_store.rs`
- Modify: `crates/storage/src/store.rs`
- Test: `crates/storage/src/beacon_store.rs`

This is the memory design: `States` holds the latest finalized anchor and the one
before it, everything above finalization is a cache entry, and `LiveChain` is
pruned to the oldest retained anchor so the index the tree walks build stays
bounded by the unfinalized window.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/storage/src/beacon_store.rs`:

```rust
    /// A `BeaconState` whose shape is irrelevant to the test: these exercise
    /// the snapshot, cache, and anchor machinery, none of which reads a state
    /// field. `BeaconState::Lean` is the one variant this crate can build
    /// without `ethlambda-beacon`'s helpers, and `encode_state_value` handles
    /// it explicitly for exactly that reason.
    fn state(genesis_time: u64) -> BeaconState {
        BeaconState::Lean(ethlambda_types::state::State::from_genesis(
            genesis_time,
            Vec::new(),
        ))
    }

    #[test]
    fn a_state_snapshot_round_trips_through_the_states_table() {
        let mut store = beacon_store();
        let root = Root::repeat_byte(1);

        assert_eq!(store.beacon_state_snapshot(root), None);
        store.insert_beacon_state_snapshot(root, &state(42));
        assert_eq!(store.beacon_state_snapshot(root), Some(state(42)));
    }

    #[test]
    fn the_state_cache_is_shared_across_store_clones() {
        // `Store` is cloned into the RPC and P2P layers, so a cache that was
        // not shared would silently double the resident state count.
        let store = beacon_store();
        let clone = store.clone();
        let root = Root::repeat_byte(2);

        store.cache_beacon_state(root, Arc::new(state(42)));

        assert_eq!(
            clone.cached_beacon_state(root).map(|s| (*s).clone()),
            Some(state(42))
        );
    }

    #[test]
    fn promoting_a_third_anchor_drops_the_first() {
        let mut store = beacon_store();
        // Three blocks in a line, each keyed under its own root, so each anchor
        // has a real slot to prune against.
        let mut parent = Root::zero();
        let mut roots = Vec::new();
        for slot in 0..3u64 {
            let signed = block(slot, parent);
            let root = signed.message_hash_tree_root();
            store.insert_beacon_block(root, &signed);
            roots.push(root);
            parent = root;
        }

        for root in &roots {
            store.promote_beacon_anchor(*root, &state(42));
        }

        assert_eq!(store.beacon_anchors(), vec![roots[1], roots[2]]);
        assert_eq!(store.beacon_state_snapshot(roots[0]), None);
        assert_eq!(store.beacon_state_snapshot(roots[1]), Some(state(42)));
        assert_eq!(store.beacon_state_snapshot(roots[2]), Some(state(42)));
    }

    #[test]
    fn promoting_an_anchor_prunes_the_index_below_the_oldest_kept_one() {
        let mut store = beacon_store();
        let mut parent = Root::zero();
        let mut roots = Vec::new();
        for slot in 0..5u64 {
            let signed = block(slot, parent);
            let root = signed.message_hash_tree_root();
            store.insert_beacon_block(root, &signed);
            roots.push(root);
            parent = root;
        }

        // Anchors at slots 2 and 4: the oldest kept one is slot 2, so slots 0
        // and 1 leave the index and slots 2 to 4 stay.
        store.promote_beacon_anchor(roots[2], &state(42));
        store.promote_beacon_anchor(roots[4], &state(42));

        let index = store.beacon_block_index();
        assert_eq!(index.len(), 3);
        assert!(!index.contains_key(&roots[0]));
        assert!(!index.contains_key(&roots[1]));
        assert!(index.contains_key(&roots[2]));
        assert!(index.contains_key(&roots[4]));
    }
```

Add the import the tests need, to the `tests` module's `use` block:

```rust
    use ethlambda_types::beacon::containers::BeaconState;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-storage --profile release-fast anchor -- --nocapture`
Expected: FAIL, `no method named 'beacon_state_snapshot' found for struct 'Store'`.

- [ ] **Step 3: Add the snapshot and cache accessors**

Add to the `impl Store` block in `crates/storage/src/beacon_store.rs`:

```rust
    /// The full-state snapshot stored under `root`, if it is one of the
    /// finalized anchors.
    ///
    /// `None` for every state above finalization: those are not written at all.
    /// Reconstructing one is `ethlambda_beacon::fork_choice::block_state`'s job,
    /// since it needs `stf::state_transition`, which this crate cannot call.
    pub fn beacon_state_snapshot(&self, root: Root) -> Option<BeaconState> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::States, &beacon_root_key(root))
            .expect("get")
            .map(|bytes| decode_state_value(&bytes))
    }

    /// Writes `state` as the snapshot for `root`, without touching the anchor
    /// list. [`Store::promote_beacon_anchor`] is what a finalization advance
    /// should call; this is for the bootstrap anchor, which has no predecessor
    /// to prune against.
    pub fn insert_beacon_state_snapshot(&mut self, root: Root, state: &BeaconState) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::States,
                vec![(beacon_root_key(root), encode_state_value(state))],
            )
            .expect("put beacon state snapshot");
        batch.commit().expect("commit");
        self.push_beacon_anchor(root);
    }

    /// The memoized post-state for `root`, if it is still resident.
    ///
    /// A miss is not an error; see [`BeaconCaches`]. Returns an `Arc` rather
    /// than a clone because `get_weight` reads the justified checkpoint's state
    /// once per call and a mainnet state is ~350 MB.
    pub fn cached_beacon_state(&self, root: Root) -> Option<Arc<BeaconState>> {
        self.beacon_cache.lock().unwrap().states.get(&root).cloned()
    }

    /// Memoizes `state` as `root`'s post-state.
    ///
    /// Takes `&self`, not `&mut self`: `get_weight` and the rest of the
    /// read-only helpers derive on a miss and must be able to record the result.
    pub fn cache_beacon_state(&self, root: Root, state: Arc<BeaconState>) {
        self.beacon_cache.lock().unwrap().states.put(root, state);
    }

    /// The memoized state at `checkpoint`'s epoch boundary, if it is still
    /// resident. See [`Store::cached_beacon_state`].
    pub fn cached_checkpoint_state(&self, checkpoint: &Checkpoint) -> Option<Arc<BeaconState>> {
        self.beacon_cache
            .lock()
            .unwrap()
            .checkpoint_states
            .get(&(checkpoint.epoch, checkpoint.root))
            .cloned()
    }

    /// Memoizes `state` as the state at `checkpoint`'s epoch boundary.
    pub fn cache_checkpoint_state(&self, checkpoint: Checkpoint, state: Arc<BeaconState>) {
        self.beacon_cache
            .lock()
            .unwrap()
            .checkpoint_states
            .put((checkpoint.epoch, checkpoint.root), state);
    }
```

Add the imports:

```rust
use std::sync::Arc;

use ethlambda_types::beacon::containers::{BeaconState, Checkpoint};

use crate::store::{BEACON_ANCHORS_KEPT, decode_state_value, encode_state_value};
```

- [ ] **Step 4: Add the anchor list and promotion**

Add to the same `impl Store` block:

```rust
    /// The roots of the finalized anchor states held in `States`, oldest first.
    pub fn beacon_anchors(&self) -> Vec<Root> {
        let view = self.backend.begin_read().expect("read view");
        let bytes = view
            .get(Table::Metadata, KEY_BEACON_ANCHORS)
            .expect("get")
            .expect("a beacon store always has an anchor list");
        bytes.chunks_exact(32).map(Root::from_slice).collect()
    }

    /// Records `root` as the newest finalized anchor, writing `state` as its
    /// snapshot and dropping everything the two-anchor rule no longer keeps.
    ///
    /// Three things happen together, and they have to: the new snapshot is
    /// written, any anchor beyond [`BEACON_ANCHORS_KEPT`] has its snapshot
    /// deleted, and `LiveChain` is pruned below the oldest anchor still kept.
    ///
    /// That last bound is what makes the pruning safe rather than merely
    /// bounded. Fork choice never walks below its own finalized checkpoint, and
    /// the finalized checkpoint is at or after the newest anchor, which is at or
    /// after the oldest kept one. So every ancestry walk and every replay
    /// terminates inside the retained window by construction.
    pub fn promote_beacon_anchor(&mut self, root: Root, state: &BeaconState) {
        if self.beacon_anchors().last() == Some(&root) {
            return;
        }
        self.insert_beacon_state_snapshot(root, state);

        let anchors = self.beacon_anchors();
        let oldest = *anchors.first().expect("just pushed at least one anchor");
        let (prune_below, _parent_root) = self
            .beacon_block_entry(oldest)
            .expect("an anchor's own block is always stored");

        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_range(
                Table::LiveChain,
                &0u64.to_be_bytes(),
                &prune_below.to_be_bytes(),
            )
            .expect("prune beacon live chain index");
        batch.commit().expect("commit");
    }

    /// Appends `root` to the anchor list, deleting the snapshot of anything
    /// that falls out of [`BEACON_ANCHORS_KEPT`].
    fn push_beacon_anchor(&mut self, root: Root) {
        let mut anchors = self.beacon_anchors();
        if anchors.contains(&root) {
            return;
        }
        anchors.push(root);

        let mut dropped = Vec::new();
        while anchors.len() > BEACON_ANCHORS_KEPT {
            dropped.push(beacon_root_key(anchors.remove(0)));
        }

        let encoded: Vec<u8> = anchors.iter().flat_map(|root| root.0).collect();
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::Metadata, vec![(KEY_BEACON_ANCHORS.to_vec(), encoded)])
            .expect("put beacon anchors");
        batch
            .delete_batch(Table::States, dropped)
            .expect("delete superseded anchor snapshots");
        batch.commit().expect("commit");
    }
```

Add the import (`KEY_BEACON_ANCHORS` is already `pub(crate)` from Task 5 Step 5):

```rust
use crate::store::KEY_BEACON_ANCHORS;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-storage --profile release-fast -- --nocapture`
Expected: PASS, all four new tests plus every existing storage test.

- [ ] **Step 6: Verify the suites**

Run: `make test`
Expected: PASS.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -S -m "feat(storage): beacon state snapshots, caches, and the two-anchor rule

Beacon states cannot use lean's diff path: a StateDiff omits validators on
the documented assumption they never change, and a beacon registry changes
every epoch, so routing one through would corrupt every reconstruction
silently rather than failing.

So States holds the latest finalized anchor and the one before it, and
nothing else. A mainnet state is ~350 MB, so the caches hold three of them,
and a miss is a replay rather than an error. LiveChain is pruned to the
oldest kept anchor, which is safe by construction: fork choice never walks
below its own finalized checkpoint, and that is at or after both anchors."
```

---

## Task 7: Beacon checkpoints, scratch, and unrealized justifications

**Files:**
- Modify: `crates/storage/src/beacon_store.rs`
- Modify: `crates/storage/src/api/tables.rs`
- Test: `crates/storage/src/beacon_store.rs`

The rest of the method surface. One new table, for the one persisted map.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/storage/src/beacon_store.rs`:

```rust
    #[test]
    fn the_beacon_clock_and_checkpoints_round_trip() {
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 1_700);
        assert_eq!(store.beacon_genesis_time(), 1_700);
        assert_eq!(store.beacon_time(), 0);
        assert_eq!(store.beacon_justified_checkpoint(), Checkpoint::default());

        store.set_beacon_time(12);
        let justified = Checkpoint {
            epoch: 3,
            root: Root::repeat_byte(1),
        };
        let finalized = Checkpoint {
            epoch: 2,
            root: Root::repeat_byte(2),
        };
        store.set_beacon_justified_checkpoint(justified);
        store.set_beacon_finalized_checkpoint(finalized);
        store.set_beacon_unrealized_justified_checkpoint(justified);
        store.set_beacon_unrealized_finalized_checkpoint(finalized);

        assert_eq!(store.beacon_time(), 12);
        assert_eq!(store.beacon_justified_checkpoint(), justified);
        assert_eq!(store.beacon_finalized_checkpoint(), finalized);
        assert_eq!(store.beacon_unrealized_justified_checkpoint(), justified);
        assert_eq!(store.beacon_unrealized_finalized_checkpoint(), finalized);
    }

    #[test]
    fn fork_choice_scratch_round_trips_and_is_shared_across_clones() {
        let mut store = beacon_store();
        let clone = store.clone();
        let root = Root::repeat_byte(1);

        assert_eq!(store.proposer_boost_root(), Root::zero());
        assert_eq!(store.block_timeliness(root), None);
        assert!(!store.is_equivocating(7));
        assert_eq!(store.latest_message(7), None);

        store.set_proposer_boost_root(root);
        store.set_block_timeliness(root, true);
        store.insert_equivocating_index(7);
        store.set_latest_message(
            7,
            LatestMessage {
                epoch: 4,
                root: Root::repeat_byte(9),
            },
        );

        assert_eq!(clone.proposer_boost_root(), root);
        assert_eq!(clone.block_timeliness(root), Some(true));
        assert!(clone.is_equivocating(7));
        assert_eq!(
            clone.latest_message(7),
            Some(LatestMessage {
                epoch: 4,
                root: Root::repeat_byte(9)
            })
        );
    }

    #[test]
    fn a_pow_block_is_looked_up_by_its_own_hash() {
        let mut store = beacon_store();
        let pow = PowBlock {
            block_hash: Root::repeat_byte(1),
            parent_hash: Root::repeat_byte(2),
            total_difficulty: Uint256::from(9u64),
        };

        assert_eq!(store.beacon_pow_block(pow.block_hash), None);
        store.insert_beacon_pow_block(pow);
        assert_eq!(store.beacon_pow_block(pow.block_hash), Some(pow));
    }

    #[test]
    fn an_unrealized_justification_survives_a_store_reopen() {
        // Unlike the scratch above, this one is persisted: get_voting_source
        // reads it for every block from a prior epoch, and recomputing it means
        // replaying epoch processing per lookup.
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::init_beacon(backend.clone(), 0);
        let root = Root::repeat_byte(1);
        let checkpoint = Checkpoint {
            epoch: 5,
            root: Root::repeat_byte(2),
        };

        assert_eq!(store.unrealized_justification(root), None);
        store.set_unrealized_justification(root, checkpoint);

        let view = backend.begin_read().expect("read view");
        assert!(
            view.get(Table::BeaconForkChoice, &root.0)
                .expect("get")
                .is_some()
        );
        drop(view);
        assert_eq!(store.unrealized_justification(root), Some(checkpoint));
    }
```

Add to the `tests` module's imports:

```rust
    use ethlambda_types::beacon::fork_choice::{LatestMessage, PowBlock};
    use ethlambda_types::beacon::primitives::Uint256;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-storage --profile release-fast beacon_clock -- --nocapture`
Expected: FAIL, `no method named 'beacon_genesis_time' found for struct 'Store'`.

- [ ] **Step 3: Add the ninth table**

In `crates/storage/src/api/tables.rs`, add the variant, the `ALL_TABLES` entry
(the array length becomes 9), and the `name` arm:

```rust
    /// Beacon fork-choice records: block root -> unrealized justification
    /// (a beacon `Checkpoint`).
    ///
    /// The one fork-choice map that is worth persisting: `get_voting_source`
    /// reads it for every block from a prior epoch, and recomputing an entry
    /// means replaying epoch processing on a copy of that block's post-state.
    /// Empty on a lean chain.
    BeaconForkChoice,
```

```rust
pub const ALL_TABLES: [Table; 9] = [
    Table::BlockHeaders,
    Table::BlockBodies,
    Table::BlockProof,
    Table::BlockRoots,
    Table::States,
    Table::StateDiffs,
    Table::Metadata,
    Table::LiveChain,
    Table::BeaconForkChoice,
];
```

```rust
            Table::BeaconForkChoice => "beacon_fork_choice",
```

- [ ] **Step 4: Add the clock and checkpoint accessors**

Add to the `impl Store` block in `crates/storage/src/beacon_store.rs`:

```rust
    /// The beacon store's clock, as **Unix seconds**.
    ///
    /// Shares `Metadata["time"]` with the lean clock, which counts 800 ms
    /// intervals since genesis instead. That is safe precisely because a
    /// directory holds one chain: nothing ever reads the key through the other
    /// chain's accessor. The unit difference is why there are two accessors and
    /// not one.
    pub fn beacon_time(&self) -> u64 {
        self.beacon_metadata(KEY_TIME)
    }

    /// Sets [`Store::beacon_time`].
    pub fn set_beacon_time(&mut self, time: u64) {
        self.set_beacon_metadata(KEY_TIME, &time);
    }

    /// Genesis, as Unix seconds. Read off the anchor state at bootstrap.
    pub fn beacon_genesis_time(&self) -> u64 {
        self.config().genesis_time
    }

    /// The justified checkpoint fork choice is currently descending from.
    pub fn beacon_justified_checkpoint(&self) -> Checkpoint {
        self.beacon_metadata(KEY_BEACON_JUSTIFIED)
    }

    /// Sets [`Store::beacon_justified_checkpoint`]. No monotonicity check: the
    /// specification's own `update_checkpoints` owns that rule.
    pub fn set_beacon_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.set_beacon_metadata(KEY_BEACON_JUSTIFIED, &checkpoint);
    }

    /// The finalized checkpoint. Fork choice never descends below it.
    pub fn beacon_finalized_checkpoint(&self) -> Checkpoint {
        self.beacon_metadata(KEY_BEACON_FINALIZED)
    }

    /// Sets [`Store::beacon_finalized_checkpoint`].
    pub fn set_beacon_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.set_beacon_metadata(KEY_BEACON_FINALIZED, &checkpoint);
    }

    /// The highest justified checkpoint seen in any block's post-state, whether
    /// or not its own chain has an epoch boundary that reflects it yet.
    pub fn beacon_unrealized_justified_checkpoint(&self) -> Checkpoint {
        self.beacon_metadata(KEY_BEACON_UNREALIZED_JUSTIFIED)
    }

    /// Sets [`Store::beacon_unrealized_justified_checkpoint`].
    pub fn set_beacon_unrealized_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.set_beacon_metadata(KEY_BEACON_UNREALIZED_JUSTIFIED, &checkpoint);
    }

    /// The finalized counterpart to
    /// [`Store::beacon_unrealized_justified_checkpoint`].
    pub fn beacon_unrealized_finalized_checkpoint(&self) -> Checkpoint {
        self.beacon_metadata(KEY_BEACON_UNREALIZED_FINALIZED)
    }

    /// Sets [`Store::beacon_unrealized_finalized_checkpoint`].
    pub fn set_beacon_unrealized_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.set_beacon_metadata(KEY_BEACON_UNREALIZED_FINALIZED, &checkpoint);
    }

    /// Reads an SSZ metadata value that `init_beacon` guarantees exists.
    fn beacon_metadata<T: SszDecode>(&self, key: &[u8]) -> T {
        let view = self.backend.begin_read().expect("read view");
        let bytes = view
            .get(Table::Metadata, key)
            .expect("get")
            .expect("a beacon store writes every metadata key at bootstrap");
        T::from_ssz_bytes(&bytes).expect("valid encoding")
    }

    /// Writes an SSZ metadata value.
    fn set_beacon_metadata<T: SszEncode>(&self, key: &[u8], value: &T) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::Metadata, vec![(key.to_vec(), value.to_ssz())])
            .expect("put beacon metadata");
        batch.commit().expect("commit");
    }
```

Extend the `crate::store` import (every key is already `pub(crate)` from Task 5
Step 5):

```rust
use crate::store::{
    BEACON_ANCHORS_KEPT, KEY_BEACON_ANCHORS, KEY_BEACON_FINALIZED, KEY_BEACON_JUSTIFIED,
    KEY_BEACON_UNREALIZED_FINALIZED, KEY_BEACON_UNREALIZED_JUSTIFIED, KEY_TIME,
    decode_state_value, encode_state_value,
};
```

- [ ] **Step 5: Add the scratch and unrealized-justification accessors**

Add to the same `impl Store` block:

```rust
    /// The most recent timely, uncontested block seen this slot, or the zero
    /// root if none has arrived yet or a new slot has reset it.
    pub fn proposer_boost_root(&self) -> Root {
        self.beacon.lock().unwrap().proposer_boost_root
    }

    /// Sets [`Store::proposer_boost_root`].
    pub fn set_proposer_boost_root(&mut self, root: Root) {
        self.beacon.lock().unwrap().proposer_boost_root = root;
    }

    /// Whether `root`'s block arrived before the attestation deadline of the
    /// slot fork choice was in when it was imported.
    pub fn block_timeliness(&self, root: Root) -> Option<bool> {
        self.beacon.lock().unwrap().block_timeliness.get(&root).copied()
    }

    /// Sets [`Store::block_timeliness`].
    pub fn set_block_timeliness(&mut self, root: Root, timely: bool) {
        self.beacon
            .lock()
            .unwrap()
            .block_timeliness
            .insert(root, timely);
    }

    /// Whether `index` has been caught attesting to two conflicting things.
    pub fn is_equivocating(&self, index: u64) -> bool {
        self.beacon.lock().unwrap().equivocating_indices.contains(&index)
    }

    /// Records `index` as an equivocator. Never reversed: an equivocation is a
    /// fact about history, not a state that expires.
    pub fn insert_equivocating_index(&mut self, index: u64) {
        self.beacon.lock().unwrap().equivocating_indices.insert(index);
    }

    /// `index`'s most recent LMD GHOST vote.
    pub fn latest_message(&self, index: u64) -> Option<LatestMessage> {
        self.beacon.lock().unwrap().latest_messages.get(&index).copied()
    }

    /// Sets [`Store::latest_message`]. No monotonicity check: the
    /// specification's own `update_latest_messages` owns that rule.
    pub fn set_latest_message(&mut self, index: u64, message: LatestMessage) {
        self.beacon
            .lock()
            .unwrap()
            .latest_messages
            .insert(index, message);
    }

    /// The PoW block with this hash, if bellatrix's merge check has been told
    /// about it.
    pub fn beacon_pow_block(&self, hash: Root) -> Option<PowBlock> {
        self.beacon.lock().unwrap().pow_blocks.get(&hash).copied()
    }

    /// Records a PoW block for later lookup by its own hash.
    pub fn insert_beacon_pow_block(&mut self, block: PowBlock) {
        self.beacon
            .lock()
            .unwrap()
            .pow_blocks
            .insert(block.block_hash, block);
    }

    /// The unrealized justified checkpoint computed for `root`'s own post-state.
    pub fn unrealized_justification(&self, root: Root) -> Option<Checkpoint> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BeaconForkChoice, &beacon_root_key(root))
            .expect("get")
            .map(|bytes| Checkpoint::from_ssz_bytes(&bytes).expect("valid checkpoint"))
    }

    /// Sets [`Store::unrealized_justification`].
    pub fn set_unrealized_justification(&mut self, root: Root, checkpoint: Checkpoint) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::BeaconForkChoice,
                vec![(beacon_root_key(root), checkpoint.to_ssz())],
            )
            .expect("put unrealized justification");
        batch.commit().expect("commit");
    }
```

Add the imports:

```rust
use ethlambda_types::beacon::fork_choice::{LatestMessage, PowBlock};
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-storage --profile release-fast -- --nocapture`
Expected: PASS, all four new tests plus every existing storage test.

- [ ] **Step 7: Verify the suites**

Run: `make test`
Expected: PASS. `ALL_TABLES` grew, so the metrics loop in
`crates/blockchain/src/lib.rs` now reports a ninth table; nothing asserts on the
count.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -S -m "feat(storage): beacon checkpoints, fork-choice scratch, and unrealized justifications

The beacon checkpoints get their own metadata keys rather than reusing the
lean ones: the two Checkpoint types carry different fields, {root, slot}
against {epoch, root}. The clock does share a key, since both are a u64,
with the unit difference spelled out at each accessor.

One new table, for the one map worth persisting: get_voting_source reads
an unrealized justification for every block from a prior epoch, and
recomputing one means replaying epoch processing. The rest is per-slot or
per-epoch scratch a restarted node rebuilds in an epoch."
```

---

## Task 8: Route the fork choice store's scalars through methods

**Files:**
- Modify: `crates/beacon/src/fork_choice.rs`
- Modify: `crates/beacon/tests/spec/fork_choice.rs`

Tasks 8 to 10 are one refactor in three parts: `fork_choice.rs` stops touching
its own store's fields and starts calling the exact method names Tasks 5 to 7
put on `ethlambda_storage::Store`. The store stays in-memory throughout, so the
fixture suite gates each part, and Task 11 is left with a type swap rather than
a rewrite.

This part covers the scalars and checkpoints: 9 `store.time`, 4
`store.genesis_time`, 20 `store.justified_checkpoint`, 11
`store.finalized_checkpoint`, 3 each of the two unrealized checkpoints, and 8
`store.proposer_boost_root`.

- [ ] **Step 1: Make the fields private, so the compiler enumerates the work**

In `crates/beacon/src/fork_choice.rs`, drop `pub` from these seven fields of
`struct Store`:

```rust
    time: u64,
    genesis_time: u64,
    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    unrealized_justified_checkpoint: Checkpoint,
    unrealized_finalized_checkpoint: Checkpoint,
    proposer_boost_root: Root,
```

- [ ] **Step 2: Run the build to enumerate the failures**

Run: `cargo build -p ethlambda-beacon --profile release-fast --tests`
Expected: FAIL, one `field 'time' of struct 'Store' is private` (and the same
for the other six) per external use site. The fixture runner's `apply_checks`
accounts for four of them.

- [ ] **Step 3: Add the accessors**

Add to `impl Store` in `crates/beacon/src/fork_choice.rs`, keeping the doc
comments the fields carried:

```rust
    /// The current time, as Unix seconds. See the module documentation for how
    /// this relates to the millisecond deadlines the reorg helpers compute.
    pub fn beacon_time(&self) -> u64 {
        self.time
    }

    /// Sets [`Store::beacon_time`].
    pub fn set_beacon_time(&mut self, time: u64) {
        self.time = time;
    }

    /// Genesis, as Unix seconds.
    pub fn beacon_genesis_time(&self) -> u64 {
        self.genesis_time
    }

    /// The justified checkpoint fork choice is currently descending from.
    pub fn beacon_justified_checkpoint(&self) -> Checkpoint {
        self.justified_checkpoint
    }

    /// Sets [`Store::beacon_justified_checkpoint`]. No monotonicity check:
    /// [`update_checkpoints`] owns that rule.
    pub fn set_beacon_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.justified_checkpoint = checkpoint;
    }

    /// The finalized checkpoint. Fork choice never descends below it.
    pub fn beacon_finalized_checkpoint(&self) -> Checkpoint {
        self.finalized_checkpoint
    }

    /// Sets [`Store::beacon_finalized_checkpoint`].
    pub fn set_beacon_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.finalized_checkpoint = checkpoint;
    }

    /// The highest justified checkpoint observed in any block's post-state.
    pub fn beacon_unrealized_justified_checkpoint(&self) -> Checkpoint {
        self.unrealized_justified_checkpoint
    }

    /// Sets [`Store::beacon_unrealized_justified_checkpoint`].
    pub fn set_beacon_unrealized_justified_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.unrealized_justified_checkpoint = checkpoint;
    }

    /// The finalized counterpart to
    /// [`Store::beacon_unrealized_justified_checkpoint`].
    pub fn beacon_unrealized_finalized_checkpoint(&self) -> Checkpoint {
        self.unrealized_finalized_checkpoint
    }

    /// Sets [`Store::beacon_unrealized_finalized_checkpoint`].
    pub fn set_beacon_unrealized_finalized_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.unrealized_finalized_checkpoint = checkpoint;
    }

    /// The most recent timely, uncontested block seen this slot, or the zero
    /// root if none has arrived yet or a new slot has reset it.
    pub fn proposer_boost_root(&self) -> Root {
        self.proposer_boost_root
    }

    /// Sets [`Store::proposer_boost_root`].
    pub fn set_proposer_boost_root(&mut self, root: Root) {
        self.proposer_boost_root = root;
    }
```

- [ ] **Step 4: Rewrite every use site**

Apply this substitution table to `crates/beacon/src/fork_choice.rs` and
`crates/beacon/tests/spec/fork_choice.rs`. The compiler's error list from Step 2
is the checklist; every entry is a mechanical rename, and no expression's meaning
changes.

| Was | Becomes |
|---|---|
| `store.time` (read) | `store.beacon_time()` |
| `store.time = time;` | `store.set_beacon_time(time);` |
| `store.genesis_time` | `store.beacon_genesis_time()` |
| `store.justified_checkpoint` (read) | `store.beacon_justified_checkpoint()` |
| `store.justified_checkpoint = justified;` | `store.set_beacon_justified_checkpoint(justified);` |
| `store.finalized_checkpoint` (read) | `store.beacon_finalized_checkpoint()` |
| `store.finalized_checkpoint = finalized;` | `store.set_beacon_finalized_checkpoint(finalized);` |
| `store.unrealized_justified_checkpoint` (read) | `store.beacon_unrealized_justified_checkpoint()` |
| `store.unrealized_justified_checkpoint = x;` | `store.set_beacon_unrealized_justified_checkpoint(x);` |
| `store.unrealized_finalized_checkpoint` (read) | `store.beacon_unrealized_finalized_checkpoint()` |
| `store.unrealized_finalized_checkpoint = x;` | `store.set_beacon_unrealized_finalized_checkpoint(x);` |
| `store.proposer_boost_root` (read) | `store.proposer_boost_root()` |
| `store.proposer_boost_root = root;` | `store.set_proposer_boost_root(root);` |

Two sites need more than a rename, because they read and write in one statement:

`on_tick_per_slot`'s epoch pull-up passes two fields into a function that takes
`&mut store`, so the reads have to be bound first:

```rust
    if current_slot > previous_slot && compute_slots_since_epoch_start(current_slot) == 0 {
        let justified = store.beacon_unrealized_justified_checkpoint();
        let finalized = store.beacon_unrealized_finalized_checkpoint();
        update_checkpoints(store, justified, finalized);
    }
```

and `update_checkpoints` / `update_unrealized_checkpoints` themselves:

```rust
pub fn update_checkpoints(store: &mut Store, justified: Checkpoint, finalized: Checkpoint) {
    if justified.epoch > store.beacon_justified_checkpoint().epoch {
        store.set_beacon_justified_checkpoint(justified);
    }
    if finalized.epoch > store.beacon_finalized_checkpoint().epoch {
        store.set_beacon_finalized_checkpoint(finalized);
    }
}

pub fn update_unrealized_checkpoints(
    store: &mut Store,
    unrealized_justified: Checkpoint,
    unrealized_finalized: Checkpoint,
) {
    if unrealized_justified.epoch > store.beacon_unrealized_justified_checkpoint().epoch {
        store.set_beacon_unrealized_justified_checkpoint(unrealized_justified);
    }
    if unrealized_finalized.epoch > store.beacon_unrealized_finalized_checkpoint().epoch {
        store.set_beacon_unrealized_finalized_checkpoint(unrealized_finalized);
    }
}
```

In the file's own `mod tests`, `empty_store()` still constructs the struct
literally, which is allowed from inside the module. The two tests that assign
(`store.time = ...`, `store.justified_checkpoint = ...`) keep working for the same
reason; leave them as they are, so the private fields still have an in-module
exercise.

- [ ] **Step 5: Verify the suites**

Run: `make test-beacon`
Expected: PASS for both presets, with Task 1 Step 2's fixture counts.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -S -m "refactor(beacon): reach the fork choice store's scalars through methods

First of three parts that make fork_choice.rs stop touching its own
store's fields and start calling the method names the DB-backed Store
already answers to. The store is still the in-memory one, so the 150
fixture cases gate each part, and the cutover is left with a type swap
rather than a rewrite.

Making the fields private is what enumerates the work: the compiler lists
every site, including the four in the fixture runner's own checks."
```

---

## Task 9: Route blocks and the tree walks through an index

**Files:**
- Modify: `crates/beacon/src/fork_choice.rs`
- Modify: `crates/beacon/tests/spec/fork_choice.rs`
- Test: `crates/beacon/src/fork_choice.rs`

26 `store.blocks` and 2 `store.block_timeliness`. The interesting half is the
children scan: `filter_block_tree` scans the whole block map on every recursive
call, which on a DB-backed store would be a table scan per node. Both walks take
a prebuilt index instead, which is also what lets `get_ancestor` stop needing a
store at all.

- [ ] **Step 1: Write the failing tests**

Replace the two `get_ancestor` tests in `crates/beacon/src/fork_choice.rs`'s
`mod tests` with index-based ones. They assert the same behaviour against the
new signature:

```rust
    /// The block index `get_ancestor` and the tree walks take, built by hand.
    fn index(entries: &[(Root, Slot, Root)]) -> BeaconBlockIndex {
        entries
            .iter()
            .map(|&(root, slot, parent_root)| (root, (slot, parent_root)))
            .collect()
    }

    #[test]
    fn get_ancestor_walks_past_an_empty_slot_gap() {
        let genesis_root = Root::repeat_byte(1);
        let a_root = Root::repeat_byte(2);
        let b_root = Root::repeat_byte(3);
        // Slot 2 is empty: b's parent is a, two slots later.
        let index = index(&[
            (genesis_root, 0, Root::zero()),
            (a_root, 1, genesis_root),
            (b_root, 3, a_root),
        ]);

        // At b's own slot, b is its own ancestor.
        assert_eq!(get_ancestor(&index, b_root, 3).unwrap(), b_root);
        // Querying the empty slot, or a's own slot, must land on a rather than
        // on b, since b's slot is strictly after both.
        assert_eq!(get_ancestor(&index, b_root, 2).unwrap(), a_root);
        assert_eq!(get_ancestor(&index, b_root, 1).unwrap(), a_root);
        // Querying before a's slot must walk one hop further, to genesis.
        assert_eq!(get_ancestor(&index, b_root, 0).unwrap(), genesis_root);
    }

    #[test]
    fn get_ancestor_rejects_an_unknown_root() {
        // The specification's own KeyError-on-unknown-root is exactly the
        // "unhandled exception" case it calls invalid, so this must be an
        // error rather than a panic.
        let index = index(&[]);
        assert!(get_ancestor(&index, Root::repeat_byte(9), 0).is_err());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-beacon --profile release-fast --lib get_ancestor -- --nocapture`
Expected: FAIL, `cannot find type 'BeaconBlockIndex' in this scope`.

- [ ] **Step 3: Add the block accessors and take the index type**

In `crates/beacon/src/fork_choice.rs`, drop `pub` from `blocks` and
`block_timeliness`, add the index type alias, and add the accessors:

```rust
/// Re-exported so this module's signatures name the same type the DB-backed
/// store builds. See [`ethlambda_storage::BeaconBlockIndex`].
pub type BeaconBlockIndex = HashMap<Root, (Slot, Root)>;
```

```rust
    /// The block stored under `root`, body and all.
    pub fn beacon_block(&self, root: Root) -> Option<SignedBeaconBlock> {
        self.blocks.get(&root).cloned()
    }

    /// `root`'s slot and parent root, without decoding its body.
    pub fn beacon_block_entry(&self, root: Root) -> Option<(Slot, Root)> {
        self.blocks
            .get(&root)
            .map(|block| (block.slot(), block.parent_root()))
    }

    /// Whether a block is stored under `root`.
    pub fn has_beacon_block(&self, root: Root) -> bool {
        self.blocks.contains_key(&root)
    }

    /// Records `block` under `root`, the root of its unsigned message.
    pub fn insert_beacon_block(&mut self, root: Root, block: &SignedBeaconBlock) {
        self.blocks.insert(root, block.clone());
    }

    /// Every stored block as `root -> (slot, parent_root)`.
    ///
    /// Built once per tree walk and passed down, rather than re-read per hop:
    /// [`get_weight`] calls [`get_ancestor`] once per active validator, so a
    /// lookup per hop would multiply a scan the specification already writes as
    /// naive by a backend round trip.
    pub fn beacon_block_index(&self) -> BeaconBlockIndex {
        self.blocks
            .iter()
            .map(|(root, block)| (*root, (block.slot(), block.parent_root())))
            .collect()
    }

    /// Whether `root`'s block arrived before the attestation deadline of the
    /// slot fork choice was in when it was imported.
    pub fn block_timeliness(&self, root: Root) -> Option<bool> {
        self.block_timeliness.get(&root).copied()
    }

    /// Sets [`Store::block_timeliness`].
    pub fn set_block_timeliness(&mut self, root: Root, timely: bool) {
        self.block_timeliness.insert(root, timely);
    }
```

- [ ] **Step 4: Change the six signatures the index reaches**

```rust
pub fn get_ancestor(index: &BeaconBlockIndex, root: Root, slot: Slot) -> Result<Root> {
    let mut root = root;
    loop {
        let (block_slot, parent_root) = index
            .get(&root)
            .copied()
            .ok_or(Error::SpecAssert("root in store.blocks"))?;
        if block_slot > slot {
            root = parent_root;
        } else {
            return Ok(root);
        }
    }
}

pub fn get_checkpoint_block(index: &BeaconBlockIndex, root: Root, epoch: Epoch) -> Result<Root> {
    get_ancestor(index, root, compute_start_slot_at_epoch(epoch))
}
```

`filter_block_tree` and `get_filtered_block_tree` collect roots rather than
block references, since the index already carries everything the walk and
`get_head` read off a block:

```rust
pub fn filter_block_tree(
    store: &Store,
    index: &BeaconBlockIndex,
    block_root: Root,
    blocks: &mut HashSet<Root>,
    config: &Config,
) -> Result<bool> {
    // The specification indexes `store.blocks[block_root]` here, so an unknown
    // root is its own "unhandled exception" case rather than a childless leaf.
    // Kept explicit: without it a bad root would fall through to the leaf branch
    // and surface as some unrelated-looking error two calls later.
    verify(index.contains_key(&block_root), "block_root in store.blocks")?;

    let children: Vec<Root> = index
        .iter()
        .filter(|(_, (_, parent_root))| *parent_root == block_root)
        .map(|(root, _)| *root)
        .collect();

    // If any children branches contain expected finalized/justified
    // checkpoints, add to filtered block-tree and signal viability to parent.
    if !children.is_empty() {
        let mut any_viable = false;
        for child in children {
            if filter_block_tree(store, index, child, blocks, config)? {
                any_viable = true;
            }
        }
        if any_viable {
            blocks.insert(block_root);
            return Ok(true);
        }
        return Ok(false);
    }

    let current_epoch = get_current_store_epoch(store, config);
    let voting_source = get_voting_source(store, index, block_root, config)?;

    // The voting source should be either at the same height as the store's
    // justified checkpoint or not more than two epochs ago.
    let justified = store.beacon_justified_checkpoint();
    let correct_justified = justified.epoch == constants::GENESIS_EPOCH
        || voting_source.epoch == justified.epoch
        || voting_source.epoch.saturating_add(2) >= current_epoch;

    let finalized = store.beacon_finalized_checkpoint();
    let finalized_checkpoint_block = get_checkpoint_block(index, block_root, finalized.epoch)?;

    let correct_finalized = finalized.epoch == constants::GENESIS_EPOCH
        || finalized.root == finalized_checkpoint_block;

    // If expected finalized/justified, add to viable block-tree and signal
    // viability to parent.
    if correct_justified && correct_finalized {
        blocks.insert(block_root);
        return Ok(true);
    }

    Ok(false)
}

pub fn get_filtered_block_tree(
    store: &Store,
    index: &BeaconBlockIndex,
    config: &Config,
) -> Result<HashSet<Root>> {
    let base = store.beacon_justified_checkpoint().root;
    let mut blocks = HashSet::new();
    filter_block_tree(store, index, base, &mut blocks, config)?;
    Ok(blocks)
}

pub fn get_head(store: &Store, config: &Config) -> Result<Root> {
    let index = store.beacon_block_index();
    let blocks = get_filtered_block_tree(store, &index, config)?;
    let mut head = store.beacon_justified_checkpoint().root;
    loop {
        let children: Vec<Root> = blocks
            .iter()
            .copied()
            .filter(|root| index.get(root).is_some_and(|(_, parent)| *parent == head))
            .collect();
        if children.is_empty() {
            return Ok(head);
        }

        // Sort by latest attesting balance with ties broken lexicographically,
        // favoring the higher root: pairing the weight with the root itself as
        // the sort key gives exactly that, and `Root`'s derived `Ord` compares
        // its bytes in order, matching Python's default comparison of a
        // `bytes` root.
        let mut ranked = Vec::with_capacity(children.len());
        for root in children {
            ranked.push((get_weight(store, &index, root, config)?, root));
        }
        head = ranked
            .into_iter()
            .max()
            .expect("children is non-empty, checked above")
            .1;
    }
}
```

- [ ] **Step 5: Thread the index through the remaining callers**

`get_weight`, `get_voting_source`, `get_proposer_head`,
`should_override_forkchoice_update`, `is_head_weak`, `is_parent_strong`,
`validate_merge_block`, `compute_pulled_up_tip`, `validate_on_attestation`, and
`on_block` all read a block. Each gains an `index: &BeaconBlockIndex` parameter
immediately after `store`, except the four that are entry points and build one
themselves:

| Function | Index |
|---|---|
| `get_weight`, `get_voting_source`, `is_head_weak`, `is_parent_strong`, `filter_block_tree`, `get_filtered_block_tree`, `validate_merge_block`, `compute_pulled_up_tip` | takes `&BeaconBlockIndex` |
| `get_head`, `get_proposer_head`, `should_override_forkchoice_update`, `validate_on_attestation`, `on_block` | builds one with `store.beacon_block_index()` |

`on_block` builds one and passes it to both `get_checkpoint_block` and
`compute_pulled_up_tip`, so a block import scans `LiveChain` once rather than
twice. That scan is bounded by the unfinalized window, since anchor promotion
prunes the index behind finalization.

Inside each, replace `store.blocks.get(&root).ok_or(..)?.slot()` with

```rust
    let (block_slot, _parent_root) = index
        .get(&root)
        .copied()
        .ok_or(Error::SpecAssert("root in store.blocks"))?;
```

keeping each site's existing `SpecAssert` message verbatim, and replace
`store.blocks.contains_key(&target.root)` in `validate_on_attestation` with
`store.has_beacon_block(target.root)`.

`on_block`'s two block writes become:

```rust
    let block_slot = signed_block.slot();
    store.insert_beacon_block(block_root, &signed_block);
```

and its timeliness write becomes `store.set_block_timeliness(block_root, is_timely);`.
`is_head_late` becomes:

```rust
pub fn is_head_late(store: &Store, head_root: Root) -> Result<bool> {
    let timely = store
        .block_timeliness(head_root)
        .ok_or(Error::SpecAssert("head_root in store.block_timeliness"))?;
    Ok(!timely)
}
```

- [ ] **Step 6: Update the fixture runner's one block read**

In `crates/beacon/tests/spec/fork_choice.rs`, `check_head`:

```rust
    let actual_slot = store
        .beacon_block_entry(actual_root)
        .map(|(slot, _parent_root)| slot)
        .ok_or_else(|| {
            format!(
                "get_head returned 0x{}, which is not in store.blocks",
                hex::encode(actual_root.0)
            )
        })?;
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-beacon --profile release-fast --lib -- --nocapture`
Expected: PASS, including the two rewritten `get_ancestor` tests and
`get_head_breaks_equal_weight_ties_by_higher_root`.

- [ ] **Step 8: Verify the suites**

Run: `make test-beacon`
Expected: PASS for both presets, with Task 1 Step 2's fixture counts. This is the
first task that changes what the tree walks actually do, so a wrong index build
shows up as a wrong head here rather than as a compile error.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -S -m "refactor(beacon): walk the block tree through a prebuilt index

filter_block_tree scans the whole block map on every recursive call, and
get_weight calls get_ancestor once per active validator. Against a
DB-backed store that is a table scan per tree node and a point lookup per
hop, so both walks now take an index built once at the entry point.

get_ancestor stops taking a store at all, which is also what makes its two
unit tests a map literal rather than a whole store."
```

---

## Task 10: Route states, votes, and PoW blocks through methods

**Files:**
- Modify: `crates/beacon/src/fork_choice.rs`
- Test: `crates/beacon/src/fork_choice.rs`

The last field group, and the one that changes shape rather than just spelling.
19 `store.block_states`, 6 `store.checkpoint_states`, 3 `store.latest_messages`,
4 `store.equivocating_indices`, 3 `store.unrealized_justifications`, 2
`store.pow_blocks`.

Two things change beyond a rename:

- Every state read goes through `block_state` or `checkpoint_state`, free
  functions that return `Arc<BeaconState>`. That is what Task 11 replaces with
  replay: two function bodies rather than 25 call sites. The `Arc` is not an
  optimization detail, it is the memory budget: `get_weight` reads the justified
  checkpoint's state once per call, and a mainnet state is ~350 MB.
- `checkpoint_state` **derives on a miss** instead of erroring, so a cache
  eviction can never turn a valid call into a `SpecAssert`. That is the whole
  reason the caches can be sized in single digits.

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `crates/beacon/src/fork_choice.rs`:

```rust
    #[test]
    fn a_checkpoint_state_is_derived_when_it_is_not_cached() {
        // The caches are sized for resident memory, not for a hit rate, so an
        // eviction must be invisible: every caller derives on a miss. A store
        // with a block state and no checkpoint state at all is exactly the
        // post-eviction shape.
        let config = Config::active();
        let mut store = empty_store();
        let block_root = Root::repeat_byte(1);
        let checkpoint = Checkpoint {
            epoch: 0,
            root: block_root,
        };

        store.insert_beacon_block(block_root, &block(0, Root::zero()));
        let state = crate::helpers::test_state::with_validators(1);
        store.cache_beacon_state(block_root, Arc::new(state));

        assert!(!store.has_checkpoint_state(&checkpoint));
        let derived = checkpoint_state(&store, checkpoint, &config)
            .expect("a checkpoint state is derivable from its block's post-state");
        assert_eq!(derived.slot(), 0);
        assert!(store.has_checkpoint_state(&checkpoint));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-beacon --profile release-fast --lib a_checkpoint_state_is_derived -- --nocapture`
Expected: FAIL, `cannot find function 'checkpoint_state' in this scope`.

- [ ] **Step 3: Change the two state maps to hold `Arc`, and add the accessors**

In `crates/beacon/src/fork_choice.rs`, change the field types and drop `pub`
from the five remaining fields. The two state maps go behind a `Mutex`, which is
what the DB-backed store's caches already are, and for the same reason:
`checkpoint_state` derives on a miss and has to record the result from a `&Store`
caller.

```rust
    blocks: HashMap<Root, SignedBeaconBlock>,
    block_states: Mutex<HashMap<Root, Arc<BeaconState>>>,
    block_timeliness: HashMap<Root, bool>,
    checkpoint_states: Mutex<HashMap<(Epoch, Root), Arc<BeaconState>>>,
    latest_messages: HashMap<ValidatorIndex, LatestMessage>,
    unrealized_justifications: HashMap<Root, Checkpoint>,
    equivocating_indices: HashSet<ValidatorIndex>,
    pow_blocks: HashMap<Root, PowBlock>,
```

Replace the existing `checkpoint_state` / `has_checkpoint_state` /
`insert_checkpoint_state` methods, and add the rest, so the whole set matches the
DB-backed store's names:

```rust
    /// The memoized post-state for `root`, if it is still resident.
    ///
    /// A miss is not an error: [`block_state`] derives the value. Returns an
    /// `Arc` because a mainnet state is ~350 MB and [`get_weight`] reads one per
    /// call.
    pub fn cached_beacon_state(&self, root: Root) -> Option<Arc<BeaconState>> {
        self.block_states.lock().unwrap().get(&root).cloned()
    }

    /// Memoizes `state` as `root`'s post-state.
    ///
    /// Takes `&self`, not `&mut self`: the read-only helpers derive on a miss
    /// and must be able to record the result, which is why the map is behind a
    /// mutex rather than being a plain field.
    pub fn cache_beacon_state(&self, root: Root, state: Arc<BeaconState>) {
        self.block_states.lock().unwrap().insert(root, state);
    }

    /// The memoized state at `checkpoint`'s epoch boundary, if it is still
    /// resident. See [`Store::cached_beacon_state`].
    pub fn cached_checkpoint_state(&self, checkpoint: &Checkpoint) -> Option<Arc<BeaconState>> {
        self.checkpoint_states
            .lock()
            .unwrap()
            .get(&(checkpoint.epoch, checkpoint.root))
            .cloned()
    }

    /// Memoizes `state` as the state at `checkpoint`'s epoch boundary.
    pub fn cache_checkpoint_state(&self, checkpoint: Checkpoint, state: Arc<BeaconState>) {
        self.checkpoint_states
            .lock()
            .unwrap()
            .insert((checkpoint.epoch, checkpoint.root), state);
    }

    /// Whether [`Store::cached_checkpoint_state`] would return `Some`.
    pub fn has_checkpoint_state(&self, checkpoint: &Checkpoint) -> bool {
        self.cached_checkpoint_state(checkpoint).is_some()
    }

    /// Whether `index` has been caught attesting to two conflicting things.
    pub fn is_equivocating(&self, index: ValidatorIndex) -> bool {
        self.equivocating_indices.contains(&index)
    }

    /// Records `index` as an equivocator.
    pub fn insert_equivocating_index(&mut self, index: ValidatorIndex) {
        self.equivocating_indices.insert(index);
    }

    /// `index`'s most recent LMD GHOST vote.
    pub fn latest_message(&self, index: ValidatorIndex) -> Option<LatestMessage> {
        self.latest_messages.get(&index).copied()
    }

    /// Sets [`Store::latest_message`]. No monotonicity check:
    /// [`update_latest_messages`] owns that rule.
    pub fn set_latest_message(&mut self, index: ValidatorIndex, message: LatestMessage) {
        self.latest_messages.insert(index, message);
    }

    /// The unrealized justified checkpoint computed for `root`'s own post-state.
    pub fn unrealized_justification(&self, root: Root) -> Option<Checkpoint> {
        self.unrealized_justifications.get(&root).copied()
    }

    /// Sets [`Store::unrealized_justification`].
    pub fn set_unrealized_justification(&mut self, root: Root, checkpoint: Checkpoint) {
        self.unrealized_justifications.insert(root, checkpoint);
    }

    /// The PoW block with this hash, if bellatrix's merge check has been told
    /// about it.
    pub fn beacon_pow_block(&self, hash: Root) -> Option<PowBlock> {
        self.pow_blocks.get(&hash).copied()
    }

    /// Records a PoW block for later lookup by its own hash.
    pub fn insert_beacon_pow_block(&mut self, block: PowBlock) {
        self.pow_blocks.insert(block.block_hash, block);
    }
```

Add the import the two `Mutex` fields need, extending the existing `use std::`
line:

```rust
use std::sync::{Arc, Mutex};
```

Drop `#[derive(Debug)]` from `Store` and fold the reason into the doc paragraph
that already explains why it is not `Clone`:

```rust
/// Does not implement `Debug` or `Clone`. `block_states` and
/// `checkpoint_states` each hold a full [`BeaconState`] per entry, and the store
/// keeps one for every block still within the unfinalized window, so either
/// would silently touch an unbounded amount of state on every call.
```

- [ ] **Step 4: Add `block_state` and `checkpoint_state`**

Add to `crates/beacon/src/fork_choice.rs`, above the handlers:

```rust
/// The post-state of the block at `root`.
///
/// The single place every state read goes through, so that the DB-backed store's
/// anchors-plus-replay reconstruction has exactly one body to live in rather
/// than being spread over every call site. On the in-memory store this is the
/// cache lookup it always was.
pub fn block_state(store: &Store, root: Root, _config: &Config) -> Result<Arc<BeaconState>> {
    store
        .cached_beacon_state(root)
        .ok_or(Error::SpecAssert("block_root in store.block_states"))
}

/// The state at `checkpoint`'s epoch boundary.
///
/// Derives it when it is not cached, rather than erroring. The caches are sized
/// for resident memory rather than for a hit rate (a mainnet state is ~350 MB),
/// so an eviction has to be invisible: a `SpecAssert` here would turn a memory
/// decision into a consensus one.
pub fn checkpoint_state(
    store: &Store,
    checkpoint: Checkpoint,
    config: &Config,
) -> Result<Arc<BeaconState>> {
    if let Some(state) = store.cached_checkpoint_state(&checkpoint) {
        return Ok(state);
    }

    // A clone, matching the specification's own `copy(store.block_states[...])`:
    // `process_slots` advances this copy toward the checkpoint's epoch boundary
    // in place, and the block's own post-state must be left as the block
    // produced it.
    let mut base_state = (*block_state(store, checkpoint.root, config)?).clone();
    let target_slot = compute_start_slot_at_epoch(checkpoint.epoch);
    if base_state.slot() < target_slot {
        stf::process_slots(&mut base_state, target_slot, config)?;
    }

    let state = Arc::new(base_state);
    store.cache_checkpoint_state(checkpoint, Arc::clone(&state));
    Ok(state)
}
```

and reduce `store_target_checkpoint_state` to the thin wrapper the specification
names, since the caching moved:

```rust
/// The specification's `store_target_checkpoint_state`. Caching is
/// [`checkpoint_state`]'s job now, so this exists only to keep `on_attestation`
/// reading like the specification's own version.
pub fn store_target_checkpoint_state(
    store: &mut Store,
    target: Checkpoint,
    config: &Config,
) -> Result<()> {
    checkpoint_state(store, target, config)?;
    Ok(())
}
```

- [ ] **Step 5: Rewrite every remaining use site**

| Was | Becomes |
|---|---|
| `store.checkpoint_state(&cp).ok_or(Error::SpecAssert(..))?` | `&*checkpoint_state(store, cp, config)?` |
| `store.block_states.get(&root).ok_or(Error::SpecAssert(m))?` | `&*block_state(store, root, config)?` |
| `store.block_states.get(&root)...clone()` | `(*block_state(store, root, config)?).clone()` |
| `store.block_states.contains_key(&root)` | `store.cached_beacon_state(root).is_some()` |
| `store.block_states.insert(root, state)` | `store.cache_beacon_state(root, Arc::new(state))` |
| `store.insert_checkpoint_state(cp, state)` | `store.cache_checkpoint_state(cp, Arc::new(state))` |
| `store.equivocating_indices.contains(&index)` | `store.is_equivocating(index)` |
| `store.equivocating_indices.insert(index)` | `store.insert_equivocating_index(index)` |
| `store.latest_messages.get(&index)` | `store.latest_message(index)` |
| `store.latest_messages.insert(index, message)` | `store.set_latest_message(index, message)` |
| `store.unrealized_justifications.get(&root).copied()` | `store.unrealized_justification(root)` |
| `store.unrealized_justifications.insert(root, cp)` | `store.set_unrealized_justification(root, cp)` |
| `store.pow_blocks.get(&hash).copied()` | `store.beacon_pow_block(hash)` |
| `store.pow_blocks.insert(b.block_hash, b)` | `store.insert_beacon_pow_block(b)` |

Two consequences worth naming, because they change signatures rather than
spelling:

`get_proposer_score`, `get_weight`, `is_head_weak`, and `is_parent_strong` all
read the justified checkpoint's state, so each now derives it:

```rust
pub fn get_proposer_score(store: &Store, config: &Config) -> Result<Gwei> {
    let justified_state = checkpoint_state(store, store.beacon_justified_checkpoint(), config)?;
    let committee_weight = get_total_active_balance(&justified_state)? / preset::SLOTS_PER_EPOCH;
    Ok(committee_weight.saturating_mul(config.proposer_score_boost) / 100)
}
```

and `on_block`'s post-state insert has to hand the `Arc` over before reading the
checkpoints back off it:

```rust
    let state = Arc::new(state);
    store.insert_beacon_block(block_root, &signed_block);
    store.cache_beacon_state(block_root, Arc::clone(&state));
```

after which the `(current_justified, finalized)` block below it reads
`state.current_justified_checkpoint()` and `state.finalized_checkpoint()`
directly, and the temporary re-read out of `block_states` goes away.

`on_attester_slashing` reads `store.block_states[justified.root]`, which is now
`block_state(store, store.beacon_justified_checkpoint().root, config)?`. That
gives it a `config` parameter it did not have:

```rust
pub fn on_attester_slashing(
    store: &mut Store,
    attester_slashing: &AttesterSlashing,
    config: &Config,
) -> Result<()> {
```

Update its two callers in `crates/beacon/tests/spec/fork_choice.rs`
(`apply_block`'s replay loop and `apply_execution_step`'s
`attester_slashing` arm) to pass `config`.

- [ ] **Step 6: Fix `empty_store` and the remaining unit tests**

`empty_store()` constructs the struct literally, so the two `Mutex` fields and
the `Arc` values need spelling out:

```rust
    fn empty_store() -> Store {
        Store {
            time: 0,
            genesis_time: 0,
            justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            unrealized_justified_checkpoint: Checkpoint::default(),
            unrealized_finalized_checkpoint: Checkpoint::default(),
            proposer_boost_root: Root::zero(),
            equivocating_indices: HashSet::new(),
            blocks: HashMap::new(),
            block_states: Mutex::new(HashMap::new()),
            block_timeliness: HashMap::new(),
            checkpoint_states: Mutex::new(HashMap::new()),
            latest_messages: HashMap::new(),
            unrealized_justifications: HashMap::new(),
            pow_blocks: HashMap::new(),
        }
    }
```

`get_head_breaks_equal_weight_ties_by_higher_root` and
`get_voting_source_pulls_up_a_prior_epoch_blocks_vote` insert states, so their
`store.block_states.insert(root, state)` becomes
`store.cache_beacon_state(root, Arc::new(state))` and their
`store.insert_checkpoint_state(cp, state)` becomes
`store.cache_checkpoint_state(cp, Arc::new(state))`.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-beacon --profile release-fast --lib -- --nocapture`
Expected: PASS, including the new derivation test.

- [ ] **Step 8: Verify the suites**

Run: `make test-beacon`
Expected: PASS for both presets, with Task 1 Step 2's fixture counts.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -S -m "refactor(beacon): read every fork choice state through two functions

block_state and checkpoint_state are where the DB-backed store's
anchors-plus-replay reconstruction is going to live, so every one of the 25
state reads goes through them now, while they are still cache lookups.

They return Arc, which is the memory budget rather than a detail:
get_weight reads the justified checkpoint's state once per call and a
mainnet state is ~350 MB. And checkpoint_state derives on a miss instead
of erroring, so a cache sized for resident memory can never turn an
eviction into a consensus failure."
```

---

## Task 11: The cutover

**Files:**
- Modify: `crates/beacon/src/fork_choice.rs`
- Modify: `crates/beacon/Cargo.toml`
- Modify: `crates/beacon/tests/spec/fork_choice.rs`
- Modify: `crates/beacon/src/lib.rs`

The one task that cannot be split. Tasks 8 to 10 removed every reason it would
have to be: `fork_choice.rs` already calls the exact method names
`ethlambda_storage::Store` answers to, so what is left is deleting the in-memory
struct, pointing the module at the other type, writing the two reconstruction
bodies, and changing how the fixture runner builds its store. The 150 fixture
cases gate all of it at once, which is the point: nothing here can be verified
except by running them.

- [ ] **Step 1: Add the dependency**

Add to `crates/beacon/Cargo.toml` under `[dependencies]`:

```toml
# The fork choice store. This ends the crate's isolation from the rest of the
# workspace, deliberately: a mainnet BeaconState is ~350 MB and cannot live in
# a HashMap. `ethlambda-storage` depends on `ethlambda-types` and nothing else
# of ours, so there is no cycle; the cost is that this crate's build now
# includes RocksDB.
ethlambda-storage.workspace = true
```

- [ ] **Step 2: Delete the in-memory store and point at the other one**

In `crates/beacon/src/fork_choice.rs`, delete the whole `pub struct Store { .. }`
declaration and the `impl Store { .. }` block Tasks 8 to 10 built up, and the
`pub type BeaconBlockIndex` alias. Replace them with:

```rust
pub use ethlambda_storage::{BeaconBlockIndex, Store};
```

Every `&Store` and `&mut Store` in the file now names the DB-backed store, and
every method call in the file already exists on it.

- [ ] **Step 3: Rebuild `get_forkchoice_store`**

Replace the body of `get_forkchoice_store` so it takes a backend and writes
through the store, keeping both of the specification's checks and both of the
comments explaining them:

```rust
pub fn get_forkchoice_store(
    backend: Arc<dyn StorageBackend>,
    anchor_state: BeaconState,
    anchor_block: SignedBeaconBlock,
    config: &Config,
) -> Result<Store> {
    // The specification's `BeaconState` and `BeaconBlock` are already one
    // fork's own types, so a mismatch between them cannot even be expressed
    // there; here both are enums, so this crate has to enforce the invariant
    // by hand, the same way `stf::state_transition` does for every later
    // block.
    verify(
        anchor_block.fork_name() == anchor_state.fork_name(),
        "anchor_block's fork matches anchor_state's",
    )?;
    verify(
        anchor_block.state_root() == anchor_state.hash_tree_root(),
        "anchor_block.state_root == hash_tree_root(anchor_state)",
    )?;

    let anchor_root = anchor_block.message_hash_tree_root();
    let anchor_epoch = get_current_epoch(&anchor_state);
    let justified_checkpoint = Checkpoint {
        epoch: anchor_epoch,
        root: anchor_root,
    };
    // The specification gives finality the same starting value as
    // justification: a trusted anchor is finalized by fiat, not by having
    // actually gone through the FFG rules.
    let finalized_checkpoint = justified_checkpoint;

    // `SECONDS_PER_SLOT * anchor_state.slot` is arithmetic over values that
    // ultimately come from an externally supplied anchor, so this fails
    // loudly on overflow rather than silently wrapping the store's clock.
    let time = config
        .seconds_per_slot
        .checked_mul(anchor_state.slot())
        .and_then(|slot_seconds| slot_seconds.checked_add(anchor_state.genesis_time()))
        .ok_or(Error::ArithmeticOverflow(
            "anchor_state.genesis_time + SECONDS_PER_SLOT * anchor_state.slot",
        ))?;

    let mut store = Store::init_beacon(backend, anchor_state.genesis_time());
    store.set_beacon_time(time);
    store.set_beacon_justified_checkpoint(justified_checkpoint);
    store.set_beacon_finalized_checkpoint(finalized_checkpoint);
    store.set_beacon_unrealized_justified_checkpoint(justified_checkpoint);
    store.set_beacon_unrealized_finalized_checkpoint(finalized_checkpoint);
    store.set_unrealized_justification(anchor_root, justified_checkpoint);
    store.insert_beacon_block(anchor_root, &anchor_block);

    // The anchor is the base of every replay: it is the one state that is
    // written to disk rather than reconstructed, and every later state is
    // reachable from it by replaying blocks forward.
    store.insert_beacon_state_snapshot(anchor_root, &anchor_state);
    let anchor_state = Arc::new(anchor_state);
    store.cache_beacon_state(anchor_root, Arc::clone(&anchor_state));
    store.cache_checkpoint_state(justified_checkpoint, anchor_state);

    Ok(store)
}
```

Add the two imports it needs:

```rust
use std::sync::Arc;

use ethlambda_storage::StorageBackend;
```

- [ ] **Step 4: Implement replay behind `block_state`**

Replace `block_state`'s body:

```rust
/// The post-state of the block at `root`.
///
/// The single place every state read goes through, which is what lets the whole
/// reconstruction live in one function.
///
/// Three tiers, cheapest first:
///
/// 1. the cache, which holds the working set (see `ethlambda-storage`'s own
///    `BeaconCaches`);
/// 2. a `States` snapshot, which exists only for the finalized anchors;
/// 3. replay: walk parent links back to the first root either tier answers for,
///    then apply each block forward.
///
/// Termination is by construction, not by a bound. The bootstrap anchor always
/// has a snapshot, [`on_block`] rejects any block that does not descend from the
/// finalized checkpoint, and `Store::promote_beacon_anchor` never prunes below
/// the older of the two anchors it keeps. So the walk always meets a snapshot
/// before it runs out of blocks; running out is the same "unknown root" fault
/// the specification calls invalid, and is reported as such.
///
/// Replay passes `validate_result = false`. The proposer signature and the
/// committed state root were both checked when the block was first imported, and
/// re-checking the state root means a `hash_tree_root` of a ~350 MB state per
/// block replayed.
pub fn block_state(store: &Store, root: Root, config: &Config) -> Result<Arc<BeaconState>> {
    if let Some(state) = store.cached_beacon_state(root) {
        return Ok(state);
    }
    if let Some(state) = store.beacon_state_snapshot(root) {
        let state = Arc::new(state);
        store.cache_beacon_state(root, Arc::clone(&state));
        return Ok(state);
    }

    // Walk back to the nearest state we have, collecting the blocks to replay.
    let mut replay: Vec<SignedBeaconBlock> = Vec::new();
    let mut cursor = root;
    let mut state = loop {
        let block = store
            .beacon_block(cursor)
            .ok_or(Error::SpecAssert("block_root in store.block_states"))?;
        let parent_root = block.parent_root();
        replay.push(block);

        if let Some(state) = store.cached_beacon_state(parent_root) {
            break (*state).clone();
        }
        if let Some(state) = store.beacon_state_snapshot(parent_root) {
            break state;
        }
        cursor = parent_root;
    };

    // `replay` runs target -> anchor child; reverse to anchor child -> target.
    replay.reverse();
    for block in &replay {
        stf::state_transition(&mut state, block, false, config, &stf::ExecutionEngine::valid())?;
    }

    let state = Arc::new(state);
    store.cache_beacon_state(root, Arc::clone(&state));
    Ok(state)
}
```

- [ ] **Step 5: Promote a finalized anchor when finalization advances**

Add, above the handlers:

```rust
/// Writes the state at the finalized checkpoint to disk, if finalization has
/// moved since the last time this ran.
///
/// This is the only thing that ever writes a `States` row after bootstrap, and
/// it is what keeps replay's walk short: without it, every reconstruction would
/// run all the way back to the genesis anchor. `Store::promote_beacon_anchor`
/// keeps the newest two and prunes the block index below the older one.
///
/// Called from the two handlers that can advance finalization, which are also
/// the two that have a `config` to materialize the state with.
fn promote_finalized_anchor(store: &mut Store, config: &Config) -> Result<()> {
    let finalized = store.beacon_finalized_checkpoint();
    if store.beacon_anchors().last() == Some(&finalized.root) {
        return Ok(());
    }
    // A finalized checkpoint whose block has not been imported is the genesis
    // checkpoint before any block: there is nothing to snapshot.
    if !store.has_beacon_block(finalized.root) {
        return Ok(());
    }
    let state = block_state(store, finalized.root, config)?;
    store.promote_beacon_anchor(finalized.root, &state);
    Ok(())
}
```

Call it as the last statement of `on_block`, replacing the bare `Ok(())`:

```rust
    // Eagerly compute unrealized justification and finality.
    compute_pulled_up_tip(store, block_root, config)?;

    promote_finalized_anchor(store, config)
```

and at the end of `on_tick`, whose epoch pull-up is the other way finalization
advances:

```rust
pub fn on_tick(store: &mut Store, time: u64, config: &Config) {
    let tick_slot = time.saturating_sub(store.beacon_genesis_time()) / config.seconds_per_slot;
    while get_current_slot(store, config) < tick_slot {
        let next_slot = get_current_slot(store, config).saturating_add(1);
        let previous_time = store
            .beacon_genesis_time()
            .saturating_add(next_slot.saturating_mul(config.seconds_per_slot));
        on_tick_per_slot(store, previous_time, config);
    }
    on_tick_per_slot(store, time, config);

    // `on_tick` has no `Result` in the specification and none here, so an
    // anchor that cannot be materialized is logged rather than returned: the
    // next block import calls this again, and a store that has genuinely lost
    // its history fails loudly at the next `block_state` instead.
    let _ = promote_finalized_anchor(store, config)
        .inspect_err(|err| tracing::warn!(?err, "could not promote the finalized anchor"));
}
```

- [ ] **Step 6: Rebuild the fixture runner's store construction**

In `crates/beacon/tests/spec/fork_choice.rs`, `run_case`:

```rust
    let backend = Arc::new(InMemoryBackend::new());
    let mut store = fork_choice::get_forkchoice_store(backend, anchor_state, anchor_block, config)
        .map_err(|err| format!("get_forkchoice_store: {err:?}"))?;
```

and add the import:

```rust
use ethlambda_storage::backend::InMemoryBackend;
```

`apply_checks` needs no change: Task 8 already moved its five store reads onto
the accessors, and `check_head`'s block read moved in Task 9. That is the whole
point of having rehearsed: the runner reads the new type through names it is
already using.

- [ ] **Step 7: Move the unit tests onto the DB-backed store**

`empty_store()` becomes a real store on an in-memory backend, which is the last
struct literal to go:

```rust
    /// A store with no blocks and every checkpoint at its default (genesis)
    /// value, on a throwaway in-memory backend. Tests fill in only what the
    /// function under test actually reads.
    fn empty_store() -> Store {
        Store::init_beacon(Arc::new(ethlambda_storage::backend::InMemoryBackend::new()), 0)
    }
```

The four tests that use it keep their bodies verbatim: Task 8 moved their
checkpoint and clock assignments onto setters, Task 9 moved their block inserts
onto `insert_beacon_block`, and Task 10 moved their state inserts onto
`cache_beacon_state` and `cache_checkpoint_state`. Every one of those names is
already the DB-backed store's.

Add one test for the tier only this task introduces, the fall-through from an
empty cache to a `States` snapshot. It writes the snapshot directly rather than
going through `get_forkchoice_store`, so it does not need to synthesize an anchor
block whose `state_root` and `body_root` both agree with `test_state`'s header:

```rust
    #[test]
    fn a_state_falls_through_the_cache_to_its_snapshot() {
        // Only the anchors are written, so an empty cache has to find one and
        // repopulate itself rather than reporting the state missing.
        let config = Config::active();
        let mut store = empty_store();
        let root = Root::repeat_byte(1);
        let expected = crate::helpers::test_state::with_validators(1);

        store.insert_beacon_state_snapshot(root, &expected);
        assert!(store.cached_beacon_state(root).is_none());

        let served = block_state(&store, root, &config).expect("the snapshot serves the read");
        assert_eq!(served.hash_tree_root(), expected.hash_tree_root());
        assert!(
            store.cached_beacon_state(root).is_some(),
            "a snapshot read must repopulate the cache, or every later read replays"
        );
    }
```

The replay tier itself has no unit test here, deliberately: exercising it needs a
signed block whose proposer, RANDAO reveal, and committed state root all satisfy
`stf::state_transition`, which is what a fixture case already is. All 150
`fork_choice` cases run through `block_state` on every step, and any case with
more than one block past its anchor exercises replay directly.

- [ ] **Step 8: Update the crate's own module documentation**

In `crates/beacon/src/lib.rs`, the module doc still claims total isolation, which
plan 1 already made half false and this task makes wholly false. Replace:

```rust
//! This crate is unrelated to the Lean consensus protocol the rest of this
//! repository implements. The two share no types and no code beyond the SSZ
//! crates, so nothing here depends on another `ethlambda-*` crate, and nothing
//! else in the workspace depends on this crate.
```

with:

```rust
//! This crate implements no part of the Lean consensus protocol the rest of this
//! repository implements, but it no longer stands apart from it. Its containers
//! live in `ethlambda-types` (see `ForkName::Lean` and `BeaconState::Lean` for
//! why), and its fork choice store *is* `ethlambda_storage::Store`, because a
//! mainnet `BeaconState` is ~350 MB and cannot live in a `HashMap`. What stays
//! here is Beacon Chain *behavior*: `helpers`, `stf`, `genesis`, `upgrade`,
//! `fork_choice`, `bls`, `kzg`, and `hash`.
```

- [ ] **Step 9: Run the suites**

Run: `make test-beacon`
Expected: PASS for both presets, with Task 1 Step 2's fixture counts **exactly**:
mainnet 5705 cases / 152 ignored, minimal 40009 / 3692. This is the task's whole
verification. `ethlambda-beacon`'s lib-test count will have moved from Task 1's
195/196, since Tasks 9 to 11 rewrote its unit tests; that is expected and the
fixture counts are not.

If a case fails, the likely causes in order are: replay reaching a root with no
snapshot (a `SpecAssert("block_root in store.block_states")` from `block_state`),
an anchor promoted before its block was imported, or the `LiveChain` prune in
`promote_beacon_anchor` cutting above what a `get_checkpoint_block` walk needs.

Run: `make test`
Expected: PASS. `ethlambda-blockchain` does not depend on `ethlambda-beacon`
yet, so the lean side is untouched; this run confirms the new
`ethlambda-storage` API broke nothing it already had.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -S -m "feat(beacon): put the fork choice handlers on the DB-backed Store

The in-memory Store is gone. A mainnet BeaconState is ~350 MB and the
store held one per block in the unfinalized window, so it could never have
run against mainnet.

What replaces it is anchors plus replay, not lean's diff path: a StateDiff
omits validators on the documented assumption they never change, and a
beacon registry changes every epoch. So States holds the latest finalized
anchor and the one before it, and everything above finalization is
reconstructed by replaying blocks forward. Termination is by construction:
on_block rejects anything not descending from the finalized checkpoint,
and anchor promotion never prunes below the older of the two it keeps.

The fixture runners move in the same commit, so all 150 fork_choice cases
gate the change itself rather than being adapted to it afterwards."
```

---

## Task 12: `BlockChainServer` dispatches on the chain

**Files:**
- Create: `crates/blockchain/src/beacon_chain.rs`
- Modify: `crates/blockchain/src/lib.rs`
- Modify: `crates/blockchain/Cargo.toml`
- Modify: `bin/ethlambda/src/main.rs`
- Test: `crates/blockchain/src/beacon_chain.rs`

One `match` at the top of each handler, and nothing shared below it. The beacon
arms of `on_block` and `on_attestation` have no caller until plan 4 wires beacon
gossip to the actor; they are `pub`, tested, and reachable, which is the point of
landing them now.

The match is on `Store::chain()` rather than on a freshly read state's
`fork_name()`, for one reason: reading a ~350 MB head state on every tick to
learn something that is fixed for the directory's whole life is not a dispatch,
it is a page fault. `chain()` is the same fact, cached from `Metadata["chain"]`
the way `config()` already is, and it is written from the anchor state's own
variant at bootstrap.

- [ ] **Step 1: Write the failing tests**

Create `crates/blockchain/src/beacon_chain.rs`:

```rust
//! The beacon arm of each [`crate::BlockChainServer`] handler.
//!
//! Nothing here is shared with `crate::store`, by decision: lean's fork-choice
//! weight is one vote per validator over an unfiltered tree, beacon's is summed
//! effective balances with proposer boost and equivocation exclusion over an
//! FFG-filtered tree, and only the descent loop itself coincides.
//!
//! `on_block` and `on_attestation` have no caller until plan 4 hands decoded
//! beacon objects to the actor. They are here, and tested, because the dispatch
//! they sit behind is what makes `BeaconState::Lean`'s `unreachable!()` arms
//! sound: the boundary has to exist before anything crosses it.

use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::{SignedBeaconBlock, phase0};
use ethlambda_beacon::error::Result;
use ethlambda_beacon::fork_choice::{self, Attestation, AttesterSlashing, DataAvailability};
use ethlambda_beacon::primitives::Root;
use ethlambda_storage::Store;

/// Advances the store's clock to `timestamp_ms`.
///
/// The beacon clock is Unix **seconds**, so this is where the actor's
/// millisecond tick is truncated. That is not a loss of resolution the handler
/// cares about: `fork_choice`'s only sub-slot comparisons recompute
/// milliseconds from this value on demand (see its module documentation).
pub fn on_tick(store: &mut Store, timestamp_ms: u64, config: &Config) {
    fork_choice::on_tick(store, timestamp_ms / 1000, config);
}

/// Imports `block`, then replays every attestation and attester slashing its
/// body carries, matching what the reference test generator's `add_block` does.
///
/// `DataAvailability::NotRequired` unconditionally: no column subnet is
/// subscribed, so no sampling evidence exists to pass. Sub-project D is what
/// makes post-fulu data availability enforceable; until then this is logged once
/// at startup rather than silently implied.
pub fn on_block(store: &mut Store, block: SignedBeaconBlock, config: &Config) -> Result<()> {
    let (attestations, slashings) = block_operations(&block);
    fork_choice::on_block(store, block, config, &DataAvailability::NotRequired)?;

    for attestation in &attestations {
        fork_choice::on_attestation(store, attestation, true, config)?;
    }
    for slashing in &slashings {
        fork_choice::on_attester_slashing(store, slashing, config)?;
    }
    Ok(())
}

/// Applies a gossiped aggregate's attestation to fork choice.
pub fn on_attestation(store: &mut Store, attestation: &Attestation, config: &Config) -> Result<()> {
    fork_choice::on_attestation(store, attestation, false, config)
}

/// Records every validator common to both halves of `slashing` as equivocating.
pub fn on_attester_slashing(
    store: &mut Store,
    slashing: &AttesterSlashing,
    config: &Config,
) -> Result<()> {
    fork_choice::on_attester_slashing(store, slashing, config)
}

/// The LMD GHOST head.
pub fn head(store: &Store, config: &Config) -> Result<Root> {
    fork_choice::get_head(store, config)
}

/// The attestations and attester slashings carried in `block`'s body, in the
/// fork-generic shapes the handlers take.
fn block_operations(block: &SignedBeaconBlock) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    match block {
        SignedBeaconBlock::Electra(block) | SignedBeaconBlock::Fulu(block) => (
            block
                .message
                .body
                .attestations
                .iter()
                .cloned()
                .map(Attestation::Electra)
                .collect(),
            block
                .message
                .body
                .attester_slashings
                .iter()
                .cloned()
                .map(AttesterSlashing::Electra)
                .collect(),
        ),
        SignedBeaconBlock::Phase0(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Altair(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Bellatrix(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Capella(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Deneb(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
    }
}

/// Phase0 through deneb share one attestation and slashing shape, so their five
/// arms above share one body.
///
/// Takes iterators rather than the lists themselves: each fork's body names its
/// own `SszList` bound, so a parameter typed on the list would need one generic
/// per bound, and `.iter()` erases exactly that difference.
fn phase0_operations<'a>(
    attestations: impl Iterator<Item = &'a phase0::Attestation>,
    slashings: impl Iterator<Item = &'a phase0::AttesterSlashing>,
) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    (
        attestations.cloned().map(Attestation::Phase0).collect(),
        slashings.cloned().map(AttesterSlashing::Phase0).collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_beacon::containers::Checkpoint;
    use ethlambda_storage::backend::InMemoryBackend;

    use super::*;

    #[test]
    fn the_beacon_tick_advances_the_store_in_seconds() {
        // The actor's clock is milliseconds and the beacon store's is seconds,
        // so this pins the one conversion the dispatch is responsible for.
        let config = Config::active();
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);

        on_tick(&mut store, 3 * config.seconds_per_slot * 1000, &config);

        assert_eq!(store.beacon_time(), 3 * config.seconds_per_slot);
    }

    #[test]
    fn the_beacon_tick_resets_the_proposer_boost_at_a_slot_boundary() {
        let config = Config::active();
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);
        store.set_proposer_boost_root(Root::repeat_byte(1));

        on_tick(&mut store, config.seconds_per_slot * 1000, &config);

        assert_eq!(store.proposer_boost_root(), Root::zero());
    }

    #[test]
    fn the_beacon_tick_pulls_up_justification_at_an_epoch_boundary() {
        use ethlambda_beacon::preset;

        let config = Config::active();
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);
        let unrealized = Checkpoint {
            epoch: 1,
            root: Root::repeat_byte(5),
        };
        store.set_beacon_unrealized_justified_checkpoint(unrealized);

        let epoch_start_seconds = preset::SLOTS_PER_EPOCH * config.seconds_per_slot;
        on_tick(&mut store, epoch_start_seconds * 1000, &config);

        assert_eq!(store.beacon_justified_checkpoint(), unrealized);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-blockchain --profile release-fast beacon_tick -- --nocapture`
Expected: FAIL, `failed to resolve: use of unresolved module or unlinked crate 'ethlambda_beacon'`.

- [ ] **Step 3: Add the dependency and declare the module**

Add to `crates/blockchain/Cargo.toml` under `[dependencies]`:

```toml
# The beacon arm of each handler's dispatch. Pulls the Beacon Chain state
# transition, BLS, and KZG into this crate's build.
ethlambda-beacon.workspace = true
```

Add to `crates/blockchain/src/lib.rs`, among the module declarations:

```rust
pub mod beacon_chain;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-blockchain --profile release-fast beacon_tick -- --nocapture`
Expected: PASS, all three tests.

- [ ] **Step 5: Carry the beacon config on the server**

Add to `BlockChainConfig` in `crates/blockchain/src/lib.rs`:

```rust
    /// The Beacon Chain fork schedule and timing, read only when
    /// [`ethlambda_storage::Store::chain`] is [`Chain::Beacon`]. The lean wiring
    /// passes `Config::mainnet()` and never reads it.
    pub beacon_config: ethlambda_types::beacon::config::Config,
```

Add the matching field to `BlockChainServer`, destructure it in
`BlockChain::spawn`'s `let BlockChainConfig { .. }`, and set it in the
`BlockChainServer { .. }` literal.

In `bin/ethlambda/src/main.rs`, add it to the `BlockChainConfig` literal that
builds the lean node:

```rust
        // Unread on a lean chain: the dispatch never reaches the beacon arm.
        // `ethlambda beacon` (plan 5) is what supplies a config that matters.
        beacon_config: ethlambda_types::beacon::config::Config::mainnet(),
```

Named through `ethlambda-types` rather than `ethlambda-beacon` deliberately: it
is the same type after plan 1's move, and the binary already depends on
`ethlambda-types`, so this adds no dependency to it.

- [ ] **Step 6: Add the dispatch to each handler**

In `crates/blockchain/src/lib.rs`, rename the existing
`BlockChainServer::on_tick` to `lean_on_tick`, leaving its body untouched, and
add:

```rust
    /// The one dispatch point for the tick handler.
    ///
    /// Nothing beacon-typed may be read above this `match`, and nothing lean-
    /// typed below its `Lean` arm: this is the boundary that makes
    /// `BeaconState::Lean`'s `unreachable!()` arms sound.
    async fn on_tick(&mut self, timestamp_ms: u64, ctx: &Context<Self>) {
        match self.store.chain() {
            Chain::Lean => self.lean_on_tick(timestamp_ms, ctx).await,
            Chain::Beacon => {
                beacon_chain::on_tick(&mut self.store, timestamp_ms, &self.beacon_config)
            }
        }
    }
```

Rename `BlockChainServer::on_block` to `lean_on_block` and add:

```rust
    /// The one dispatch point for block import. See [`Self::on_tick`].
    fn on_block(&mut self, signed_block: SignedBlock) {
        match self.store.chain() {
            Chain::Lean => self.lean_on_block(signed_block),
            // A lean gossip block cannot reach a beacon chain: plan 4 is what
            // gives the P2P layer beacon message variants, and until then this
            // arm exists to keep the lean import from running on a beacon store
            // rather than to handle traffic.
            Chain::Beacon => warn!("dropping a lean block on a beacon chain"),
        }
    }
```

Apply the same shape to the `NewAttestation` and `NewAggregatedAttestation`
handlers, whose bodies move to `lean_on_attestation` and
`lean_on_aggregated_attestation`, with the `Chain::Beacon` arm dropping and
warning for the same reason.

Add the import:

```rust
use ethlambda_storage::{ALL_TABLES, Chain, Store};
```

- [ ] **Step 7: Verify the suites**

Run: `make test`
Expected: PASS. Every existing lean test now runs through the `Chain::Lean` arm,
so a mis-wired dispatch fails the whole lean suite rather than one assertion:
that is the coverage the dispatch itself gets, since constructing a
`BlockChainServer` in a unit test would mean standing up a key manager, an event
bus, and two controllers to observe one `match`.

Run: `make test-beacon`
Expected: PASS for both presets, with Task 1 Step 2's fixture counts.

Run: `make fmt && make lint`
Expected: no diff, no warnings.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -S -m "feat(blockchain): dispatch each handler on the chain the directory holds

One match at the top of each handler and nothing shared below it. The head
descent is deliberately not extracted: lean weighs one vote per validator
over an unfiltered tree, beacon sums effective balances with proposer boost
and equivocation exclusion over an FFG-filtered tree, and only the descent
loop coincides.

The match reads Store::chain() rather than a freshly read state's
fork_name(): that is the same fact, cached from Metadata the way config()
already is, and reading a ~350 MB head state per tick to learn something
fixed for the directory's whole life is a page fault, not a dispatch.

on_block and on_attestation's beacon arms have no caller until plan 4
wires beacon gossip. They land now because the boundary has to exist
before anything crosses it."
```

---

## Task 13: Update the documentation the change invalidates

**Files:**
- Modify: `docs/beacon_stf.md`
- Modify: `docs/data_storage.md`

Both documents assert things that are now false, and both are read as contracts.

- [ ] **Step 1: Correct `docs/beacon_stf.md`'s store description**

The `## Layout` table's `fork_choice` row reads "The LMD GHOST store". Replace it
with:

```markdown
| `fork_choice` | LMD GHOST, over `ethlambda_storage::Store` |
```

Add, in the section that describes the store, replacing whatever claims it is
in-memory:

```markdown
The fork choice store is `ethlambda_storage::Store`, the same DB-backed store the
lean side uses. It was an in-memory `HashMap` per field until
`docs/superpowers/plans/2026-08-11-beacon-handlers-on-lean-store.md`; a mainnet
`BeaconState` is ~350 MB and the store held one per block in the unfinalized
window, so that shape could never have run against mainnet.

Beacon states do not use lean's `StateDiff` path. A diff omits `validators` on
the documented assumption that they never change, and a beacon registry changes
every epoch, so routing one through would corrupt every reconstruction silently
rather than failing. Instead:

- `States` holds the latest finalized anchor and the one before it, each behind
  a one-byte fork selector.
- Everything above finalization is reconstructed by `fork_choice::block_state`,
  which replays blocks forward from the nearest anchor with
  `validate_result = false`.
- Two small LRUs hold the working set: the head's post-state and the anchor, plus
  the justified checkpoint's epoch-boundary state. A miss is a replay, never an
  error, which is what lets them be that small.
```

- [ ] **Step 2: Correct `docs/data_storage.md`**

Add a section covering what changed, and update the table count from eight to
nine wherever it appears:

```markdown
## Two chains, one storage layer

A data directory holds one chain for its whole life. `Metadata["chain"]` says
which, `Metadata["db_version"]` says which on-disk format it is in, and
`from_db_state` refuses anything that does not match on either count: there is no
migration, because the `States` value layout changed and a lean devnet resyncs in
minutes.

`States` values now begin with a one-byte `ForkName::selector`, so one table can
hold a lean `State` and a beacon `BeaconState` without the reader having to
already know which it is.

On a beacon chain the tables carry different things:

| Table | Beacon contents |
|---|---|
| `BlockHeaders` | block root -> `(slot, parent_root)`, the two fields the tree walks read |
| `BlockBodies` | block root -> fork selector, then `SignedBeaconBlock` SSZ |
| `LiveChain` | slot ‖ root -> parent root: the children index |
| `States` | the latest two finalized anchors only |
| `StateDiffs` | unused; beacon states replay rather than diff |
| `BlockRoots`, `BlockProof` | unused |
| `BeaconForkChoice` | block root -> unrealized justification |

`BeaconForkChoice` is the ninth table and is empty on a lean chain, as are the
beacon fields on `Store` itself.
```

- [ ] **Step 3: Verify the documentation builds**

Run: `make docs`
Expected: mdbook builds with no broken-link warnings.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -S -m "docs: record that the beacon fork choice store is the DB-backed one

Both documents asserted things that are now false, and both are read as
contracts: beacon_stf.md said the store was in-memory, and data_storage.md
described eight tables holding only lean rows."
```

---

## Done when

- [ ] `make test-beacon` passes both presets with Task 1 Step 2's fixture counts, unchanged: mainnet 5705 cases / 152 ignored, minimal 40009 / 3692
- [ ] `make test` passes
- [ ] `make lint` passes with no warnings
- [ ] `make fmt` produces no diff
- [ ] `make docs` builds with no broken-link warnings
- [ ] `grep -n 'pub struct Store' crates/beacon/src/fork_choice.rs` finds nothing: the in-memory store is gone
- [ ] `grep -rn 'store\.blocks\.\|store\.block_states\.\|store\.checkpoint_states\.\|store\.latest_messages\.\|store\.pow_blocks\.\|store\.equivocating_indices\.' crates/beacon/src/fork_choice.rs` finds nothing: every field access goes through a method (the trailing dot keeps this off the `"root in store.blocks"` assertion strings, which stay as the specification writes them)
- [ ] `crates/beacon/tests/spec/fork_choice.rs` builds its store with `ethlambda_storage::backend::InMemoryBackend`
- [ ] `BlockChainServer::on_tick`, `on_block`, and the two attestation handlers each open with one `match self.store.chain()`, with no beacon-typed read above it
- [ ] A lean devnet runs unchanged: `make run-devnet`, blocks produced and finalized, on a fresh data directory (the format break makes an existing one refuse to open, by design)

Then start plan 4, mainnet wire.
