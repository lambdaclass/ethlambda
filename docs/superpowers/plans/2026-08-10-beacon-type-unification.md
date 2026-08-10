# Beacon Type Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge `feat/beacon-chain-stf`, move its container and configuration types into `ethlambda-types` under a `beacon` namespace, and add the `Lean` variant to `ForkName` and `BeaconState`, so a single `BlockChainServer` can later dispatch on the state variant.

**Architecture:** Every step is a mechanical move followed by a re-export. `crates/beacon/src/lib.rs` keeps a module path for each moved module (`pub use ethlambda_types::beacon::primitives;`), so all ~35k lines of `crate::primitives::X` inside the beacon crate keep compiling untouched. The tree is green after every task, and the beacon fixture suites gate every one of them.

**Tech Stack:** Rust 1.97.1 (edition 2024), `libssz` / `libssz-derive` / `libssz-merkle`, `ethereum-types`, consensus-spec-tests v1.6.1 fixtures.

---

## Plan series

This is plan 1 of 5 for sub-projects A1 and A2 of
`docs/superpowers/specs/2026-08-10-mainnet-network-design.md`. Each plan ends
with a working, testable tree.

| # | Plan | Ends when |
|---|---|---|
| 1 | **Beacon type unification** (this plan) | Types live in `ethlambda-types`, `BeaconState::Lean` exists, every fixture suite green |
| 2 | CLI subcommands | `ethlambda lean` and `ethlambda beacon` parse, bare flags still resolve to `lean`, devnet unchanged |
| 3 | Beacon handlers on the DB-backed `Store`, and the `BlockChainServer` variant dispatch (spec §4, §5) | `fork_choice::Store` deleted, all 150 `fork_choice` fixture cases green against `ethlambda_storage::Store` |
| 4 | Mainnet wire | Node peers with mainnet, decodes a `beacon_block` within ~30s |
| 5 | Anchor and follow | Checkpoint sync, anchor-to-head range fetch, head tracks wall clock |

Do not start plan 2 until this one is complete: every later plan depends on
where these types live.

---

## File structure

| File | Responsibility |
|---|---|
| `crates/common/types/src/beacon/mod.rs` | **Create.** Namespace root for the moved beacon types |
| `crates/common/types/src/beacon/primitives.rs` | **Move** from `crates/beacon/src/primitives.rs`. Scalar aliases, `Root`, fixed-length byte strings |
| `crates/common/types/src/beacon/constants.rs` | **Move** from `crates/beacon/src/constants.rs`. Values the spec fixes outright |
| `crates/common/types/src/beacon/preset.rs` | **Move** from `crates/beacon/src/preset.rs`. Compile-time container bounds |
| `crates/common/types/src/beacon/fork.rs` | **Move** from `crates/beacon/src/fork.rs`. `ForkName`, gains `Lean` |
| `crates/common/types/src/beacon/config.rs` | **Move** from `crates/beacon/src/config.rs`. Fork schedule, blob schedule |
| `crates/common/types/src/beacon/containers/` | **Move** from `crates/beacon/src/containers/`. `BeaconState` gains `Lean` |
| `crates/common/types/src/lib.rs` | **Modify.** Add `pub mod beacon;` |
| `crates/common/types/src/state.rs` | **Modify.** Lean `State` gains `PartialEq` |
| `crates/common/types/Cargo.toml` | **Modify.** Add `ethereum-types`, `sha2`, and the `ethereum_types` features on `libssz` / `libssz-merkle` |
| `crates/beacon/src/lib.rs` | **Modify.** Each `pub mod X` becomes `pub use ethlambda_types::beacon::X` |
| `crates/beacon/Cargo.toml` | **Modify.** Add `ethlambda-types`; drop deps that left with the moved modules |
| `Cargo.toml` | **Modify.** Add `ethereum-types` and `sha2` to `[workspace.dependencies]` |
| `docs/beacon_stf.md` | **Modify.** Record that the crate now depends on `ethlambda-types` |

### The one edit every moved file needs

Inside `ethlambda-beacon`, `crate::constants` means the beacon constants. Inside
`ethlambda-types` it means **lean's** `constants`, which is a different module
that already exists. The same trap applies to `crate::primitives`. So every
moved file has its own-crate paths rewritten from `crate::` to `crate::beacon::`
as part of its move:

```bash
# Run inside the moved file's directory, on the moved files only.
sed -i '' 's/crate::/crate::beacon::/g' <moved files>
```

Which files this applies to, counted on `feat/beacon-chain-stf`:

| Module | `crate::` occurrences | Rewrite needed |
|---|---|---|
| `primitives.rs` | 0 | No |
| `fork.rs` | 0 | No |
| `constants.rs` | 8 | Yes |
| `preset.rs` | 4 | Yes |
| `config.rs` | 4 | Yes |
| `containers/` (9 files) | 29 | Yes |

Most are intra-doc links in `///` comments. Those still matter: `make docs` and
`cargo doc` both fail on a broken intra-doc link, and a stale link would point at
lean's module.

---

## Task 1: Merge the beacon branch and establish a green baseline

**Files:**
- Modify: `Cargo.toml`
- Modify: `Makefile`

- [ ] **Step 1: Merge**

```bash
git merge feat/beacon-chain-stf --no-edit
```

Expect conflicts in `Cargo.toml`. Both branches add to `members` and to
`[workspace.dependencies]`. Resolve to the **union**: keep `crates/beacon` in
`members`, keep `ethlambda-beacon = { path = "crates/beacon" }` in
`[workspace.dependencies]`, and keep both branches' trailing comments about the
local path overrides marked DO NOT COMMIT.

- [ ] **Step 2: Verify the workspace resolves**

Run: `cargo metadata --format-version 1 > /dev/null`
Expected: exit 0, no output.

If this fails with an unresolved `ethrex-p2p`, `ethrex-rlp`, or `ethrex-common`
path, the local ethrex checkout named in `crates/net/p2p/Cargo.toml` is missing.
That path dependency is a known DO NOT COMMIT override on the discv5 branch, not
something this plan changes.

- [ ] **Step 3: Download the beacon fixtures**

Run: `make consensus-spec-tests`
Expected: three tarballs (`general`, `minimal`, `mainnet`) downloaded and
extracted under `consensus-spec-tests/tests/`. About 2.2 GB, several minutes.

- [ ] **Step 4: Record the baseline**

Run: `make test-beacon`
Expected: PASS for both presets. Record the case counts from the output; they are
what every later task compares against.

```
mainnet   5705 fixture cases, 152 ignored, 244 lib tests
minimal  40009 fixture cases, 3692 ignored, 245 lib tests
```

- [ ] **Step 5: Verify lean is untouched**

Run: `make test`
Expected: PASS. This excludes `ethlambda-beacon` by design, so it is the lean
regression gate for every task below.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml
git commit -m "merge: bring the beacon chain state transition onto the mainnet branch"
```

---

## Task 2: Move `primitives` into `ethlambda_types::beacon`

**Files:**
- Create: `crates/common/types/src/beacon/mod.rs`
- Move: `crates/beacon/src/primitives.rs` to `crates/common/types/src/beacon/primitives.rs`
- Modify: `crates/common/types/src/lib.rs`
- Modify: `crates/common/types/Cargo.toml`
- Modify: `crates/beacon/src/lib.rs`
- Modify: `crates/beacon/Cargo.toml`
- Modify: `Cargo.toml`
- Test: `crates/common/types/src/beacon/mod.rs`

`primitives.rs` imports only `core::fmt`, `libssz_derive`, and `ethereum_types`,
so it moves with no edits to its body.

- [ ] **Step 1: Write the failing test**

Create `crates/common/types/src/beacon/mod.rs` with the test that proves the
namespace exists and does not collide with lean's own `primitives`:

```rust
//! Beacon Chain types, namespaced away from the lean types alongside them.
//!
//! `ethlambda-types` already has `primitives`, `constants`, and `checkpoint`
//! modules of its own, and lean's `Checkpoint` is a different type from
//! beacon's by the same name. Everything moved out of `ethlambda-beacon` lives
//! under this module so both sets can coexist.

pub mod primitives;

#[cfg(test)]
mod tests {
    #[test]
    fn beacon_and_lean_roots_are_distinct_types() {
        let beacon: super::primitives::Root = super::primitives::Root::zero();
        let lean = crate::primitives::H256::ZERO;
        assert_eq!(beacon.0, lean.0);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-types beacon_and_lean_roots -- --nocapture`
Expected: FAIL, `file not found for module 'primitives'`.

- [ ] **Step 3: Move the file and wire the module in**

```bash
git mv crates/beacon/src/primitives.rs crates/common/types/src/beacon/primitives.rs
```

Add to `crates/common/types/src/lib.rs`, keeping the existing modules in
alphabetical position:

```rust
pub mod beacon;
```

Add to `[workspace.dependencies]` in the root `Cargo.toml`:

```toml
# Matches the version ethrex uses, and the version libssz's `ethereum_types`
# feature is built against.
ethereum-types = "0.15.1"

# `asm` selects the CPU's SHA-256 instructions where it has them. Merkleization
# is almost entirely SHA-256 compressions, so this is not a micro-optimization.
sha2 = { version = "0.10.9", features = ["asm"] }
```

Add to `crates/common/types/Cargo.toml` under `[dependencies]`, replacing the
two existing plain `libssz` lines:

```toml
libssz = { workspace = true, features = ["ethereum_types"] }
libssz-merkle = { workspace = true, features = ["ethereum_types"] }
ethereum-types.workspace = true
```

- [ ] **Step 4: Re-export from the beacon crate**

In `crates/beacon/src/lib.rs`, replace `pub mod primitives;` with:

```rust
pub use ethlambda_types::beacon::primitives;
```

Add to `crates/beacon/Cargo.toml` under `[dependencies]`:

```toml
ethlambda-types.workspace = true
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p ethlambda-types beacon_and_lean_roots -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Verify nothing else moved**

Run: `make test-beacon`
Expected: PASS, with the exact case counts recorded in Task 1 Step 4.

Run: `make test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(types): move beacon primitives into ethlambda-types

The beacon containers have to live beside lean's State for BeaconState to
gain a Lean variant. Moving them one module at a time, each behind a
re-export from ethlambda-beacon, keeps every intermediate commit green:
the crate's own 35k lines still say crate::primitives and still compile."
```

---

## Task 3: Move `constants`

**Files:**
- Move: `crates/beacon/src/constants.rs` to `crates/common/types/src/beacon/constants.rs`
- Modify: `crates/common/types/src/beacon/mod.rs`
- Modify: `crates/beacon/src/lib.rs`
- Test: `crates/common/types/src/beacon/mod.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/common/types/src/beacon/mod.rs`:

```rust
    #[test]
    fn beacon_constants_are_reachable_beside_lean_constants() {
        // Both crates define a `constants` module; the namespace keeps them
        // apart. `FAR_FUTURE_EPOCH` is the sentinel every unscheduled fork
        // epoch carries.
        assert_eq!(super::constants::FAR_FUTURE_EPOCH, u64::MAX);
        assert_eq!(crate::constants::FORK_DIGEST, "12345678");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-types beacon_constants_are_reachable -- --nocapture`
Expected: FAIL, `could not find 'constants' in the module`.

- [ ] **Step 3: Move the file and wire the module in**

```bash
git mv crates/beacon/src/constants.rs crates/common/types/src/beacon/constants.rs
sed -i '' 's/crate::/crate::beacon::/g' crates/common/types/src/beacon/constants.rs
```

The `sed` rewrites the 8 `crate::` references, all intra-doc links. Without it
they resolve to lean's `constants` module and `cargo doc` fails.

Add to `crates/common/types/src/beacon/mod.rs`, above `pub mod primitives;`:

```rust
pub mod constants;
```

In `crates/beacon/src/lib.rs`, replace `pub mod constants;` with:

```rust
pub use ethlambda_types::beacon::constants;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p ethlambda-types beacon_constants_are_reachable -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Verify the suites**

Run: `make test-beacon`
Expected: PASS, same case counts as Task 1 Step 4.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(types): move beacon constants into ethlambda-types"
```

---

## Task 4: Move `preset`

**Files:**
- Move: `crates/beacon/src/preset.rs` to `crates/common/types/src/beacon/preset.rs`
- Modify: `crates/common/types/src/beacon/mod.rs`
- Modify: `crates/common/types/Cargo.toml`
- Modify: `crates/beacon/Cargo.toml`
- Modify: `crates/beacon/src/lib.rs`
- Test: `crates/common/types/src/beacon/mod.rs`

`preset` is feature-gated: `preset-minimal` switches every constant. That feature
has to exist on `ethlambda-types` now, and `ethlambda-beacon`'s own
`preset-minimal` forwards to it, so `make test-beacon`'s second run still selects
the minimal preset.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/common/types/src/beacon/mod.rs`:

```rust
    #[test]
    fn preset_slots_per_epoch_matches_the_selected_preset() {
        #[cfg(not(feature = "preset-minimal"))]
        assert_eq!(super::preset::SLOTS_PER_EPOCH, 32);
        #[cfg(feature = "preset-minimal")]
        assert_eq!(super::preset::SLOTS_PER_EPOCH, 8);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-types preset_slots_per_epoch -- --nocapture`
Expected: FAIL, `could not find 'preset' in the module`.

- [ ] **Step 3: Move the file and forward the feature**

```bash
git mv crates/beacon/src/preset.rs crates/common/types/src/beacon/preset.rs
sed -i '' 's/crate::/crate::beacon::/g' crates/common/types/src/beacon/preset.rs
```

The `sed` matters here beyond the doc links: `preset.rs:365` and `preset.rs:494`
read `crate::constants::BYTES_PER_FIELD_ELEMENT` in real code, which would
resolve to lean's `constants` and fail to compile.

Add to `crates/common/types/src/beacon/mod.rs`:

```rust
pub mod preset;
```

Add to `crates/common/types/Cargo.toml`, above `[dependencies]`:

```toml
[features]
# Compile the beacon containers against the minimal preset instead of mainnet.
#
# Container shapes are compile-time constants (SSZ list and vector bounds), so
# the preset cannot be selected at runtime. Mainnet is the implicit default.
# `ethlambda-beacon`'s feature of the same name forwards to this one.
preset-minimal = []
```

Change `crates/beacon/Cargo.toml`'s feature to forward:

```toml
[features]
preset-minimal = ["ethlambda-types/preset-minimal"]
```

In `crates/beacon/src/lib.rs`, replace `pub mod preset;` with:

```rust
pub use ethlambda_types::beacon::preset;
```

- [ ] **Step 4: Run the test to verify it passes, under both presets**

Run: `cargo test -p ethlambda-types preset_slots_per_epoch -- --nocapture`
Expected: PASS.

Run: `cargo test -p ethlambda-types --features preset-minimal preset_slots_per_epoch -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Verify the suites**

Run: `make test-beacon`
Expected: PASS for both presets, same case counts as Task 1 Step 4. A minimal run
reporting mainnet's 5705 cases means the feature is not forwarding.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(types): move the beacon preset into ethlambda-types

The preset fixes SSZ container bounds at compile time, so it has to be a
Cargo feature on whichever crate defines the containers. ethlambda-beacon
keeps a preset-minimal feature that forwards, so the two-preset test
target is unchanged."
```

---

## Task 5: Move `fork`

**Files:**
- Move: `crates/beacon/src/fork.rs` to `crates/common/types/src/beacon/fork.rs`
- Modify: `crates/common/types/src/beacon/mod.rs`
- Modify: `crates/beacon/src/lib.rs`
- Test: `crates/common/types/src/beacon/fork.rs`

`fork.rs` carries its own test module, which moves with it and must keep passing
untouched.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/common/types/src/beacon/mod.rs`:

```rust
    #[test]
    fn fork_ordering_is_reachable_from_the_namespace() {
        use super::fork::ForkName;
        assert!(ForkName::Fulu > ForkName::Phase0);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-types fork_ordering_is_reachable -- --nocapture`
Expected: FAIL, `could not find 'fork' in the module`.

- [ ] **Step 3: Move the file**

```bash
git mv crates/beacon/src/fork.rs crates/common/types/src/beacon/fork.rs
```

Add to `crates/common/types/src/beacon/mod.rs`:

```rust
pub mod fork;
```

In `crates/beacon/src/lib.rs`, replace `pub mod fork;` with:

```rust
pub use ethlambda_types::beacon::fork;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-types fork -- --nocapture`
Expected: PASS, including the three tests that moved with the file:
`ordering_follows_fork_order`, `parse_round_trips_every_fork`,
`neighbours_terminate_at_the_ends`.

- [ ] **Step 5: Verify the suites**

Run: `make test-beacon`
Expected: PASS, same case counts as Task 1 Step 4.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(types): move ForkName into ethlambda-types"
```

---

## Task 6: Move `config`

**Files:**
- Move: `crates/beacon/src/config.rs` to `crates/common/types/src/beacon/config.rs`
- Modify: `crates/common/types/src/beacon/mod.rs`
- Modify: `crates/beacon/src/lib.rs`
- Test: `crates/common/types/src/beacon/mod.rs`

`config.rs` reads `crate::constants`, `crate::fork::ForkName`, and
`crate::primitives`. All three moved in Tasks 3 to 5, but inside
`ethlambda-types` those paths now resolve to lean's own `constants` and
`primitives` modules, so they have to be rewritten. `crate::constants::FAR_FUTURE_EPOCH`
would otherwise silently look for a lean constant that does not exist.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/common/types/src/beacon/mod.rs`:

```rust
    #[test]
    fn mainnet_config_carries_the_fulu_schedule() {
        let config = super::config::Config::mainnet();
        assert_eq!(config.fulu_fork_version, [0x06, 0x00, 0x00, 0x00]);
        assert_eq!(config.fulu_fork_epoch, 411_392);
        // The two blob-parameter-only forks, which perturb the fork digest.
        assert_eq!(config.blob_schedule.len(), 2);
        assert_eq!(config.blob_schedule[0].epoch, 412_672);
        assert_eq!(config.blob_schedule[0].max_blobs_per_block, 15);
        assert_eq!(config.blob_schedule[1].epoch, 419_072);
        assert_eq!(config.blob_schedule[1].max_blobs_per_block, 21);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-types mainnet_config_carries -- --nocapture`
Expected: FAIL, `could not find 'config' in the module`.

- [ ] **Step 3: Move the file**

```bash
git mv crates/beacon/src/config.rs crates/common/types/src/beacon/config.rs
sed -i '' 's/crate::/crate::beacon::/g' crates/common/types/src/beacon/config.rs
```

Add to `crates/common/types/src/beacon/mod.rs`:

```rust
pub mod config;
```

In `crates/beacon/src/lib.rs`, replace `pub mod config;` with:

```rust
pub use ethlambda_types::beacon::config;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p ethlambda-types mainnet_config_carries -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Verify the suites**

Run: `make test-beacon`
Expected: PASS, same case counts as Task 1 Step 4.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(types): move the beacon Config into ethlambda-types"
```

---

## Task 7: Move `containers`

**Files:**
- Move: `crates/beacon/src/containers/` to `crates/common/types/src/beacon/containers/`
- Modify: `crates/common/types/src/beacon/mod.rs`
- Modify: `crates/beacon/src/lib.rs`
- Modify: `crates/beacon/Cargo.toml`
- Modify: `crates/common/types/Cargo.toml`
- Test: `crates/common/types/src/beacon/mod.rs`

The containers derive their SSZ codecs and merkleization, so `libssz-merkle` and
`sha2` follow them across. `containers/mod.rs` also reads `crate::error`, which
stays in `ethlambda-beacon`, so that one import has to change.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/common/types/src/beacon/mod.rs`:

No fork's `BeaconState` derives `Default`, and `helpers::test_state` stays in
`ethlambda-beacon`, so this test asserts the path resolves without constructing
a state:

```rust
    #[test]
    fn the_beacon_containers_are_reachable_from_the_namespace() {
        use super::containers::{BeaconState, phase0};

        // A type-level assertion: naming the variant constructor as a function
        // proves both the enum and the per-fork struct resolve, with nothing to
        // construct. No fork's BeaconState derives Default.
        let _: fn(phase0::BeaconState) -> BeaconState = BeaconState::Phase0;
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-types the_beacon_containers_are_reachable -- --nocapture`
Expected: FAIL, `could not find 'containers' in the module`.

- [ ] **Step 3: Move the directory**

```bash
git mv crates/beacon/src/containers crates/common/types/src/beacon/containers
sed -i '' 's/crate::/crate::beacon::/g' crates/common/types/src/beacon/containers/*.rs
```

That rewrites 29 references across the 9 files. The `error` module has not moved
yet, so `crate::beacon::error` is briefly wrong; Step 4 moves it and makes the
path correct. Do not try to build between Step 3 and Step 4.

Add to `crates/common/types/src/beacon/mod.rs`:

```rust
pub mod containers;
```

Add to `crates/common/types/Cargo.toml` under `[dependencies]`:

```toml
sha2.workspace = true
```

In `crates/beacon/src/lib.rs`, replace `pub mod containers;` with:

```rust
pub use ethlambda_types::beacon::containers;
```

- [ ] **Step 4: Move the error type the containers need**

`containers/mod.rs` opens with `use crate::error::{Error, Result};`, and
`Error::UnsupportedForFork` is returned by the fork-gated accessors. The error
type is used by `stf`, `helpers`, and `fork_choice` too, so it moves rather than
being duplicated.

```bash
git mv crates/beacon/src/error.rs crates/common/types/src/beacon/error.rs
```

Add to `crates/common/types/src/beacon/mod.rs`:

```rust
pub mod error;
```

The Step 3 `sed` already rewrote `crate::error` to `crate::beacon::error` in the
container files, which is the correct path once `error.rs` sits at
`crates/common/types/src/beacon/error.rs`. Nothing further to edit there.

In `crates/beacon/src/lib.rs`, add alongside the other re-exports:

```rust
pub use ethlambda_types::beacon::error;
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p ethlambda-types the_beacon_containers_are_reachable -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Verify the suites**

Run: `make test-beacon`
Expected: PASS for both presets, same case counts as Task 1 Step 4. This is the
task most likely to move a count: `ssz_static` covers every container, so a
mis-moved derive shows up here rather than at compile time.

Run: `make test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(types): move the beacon containers into ethlambda-types

This is the move the Lean variant needs: BeaconState now lives in the
same crate as lean's State, so the variant can name it directly rather
than inverting the dependency between the two crates."
```

---

## Task 8: Give lean's `State` `PartialEq`

**Files:**
- Modify: `crates/common/types/src/state.rs:15`
- Test: `crates/common/types/src/state.rs`

`BeaconState` derives `Debug, Clone, PartialEq`. A `Lean(State)` variant needs
`State` to derive all three; it has the first two.

- [ ] **Step 1: Write the failing test**

Add to the test module at the bottom of `crates/common/types/src/state.rs`, or
create one if the file has none:

`State` has no `Default`; `State::from_genesis(genesis_time, validators)` at
`crates/common/types/src/state.rs:90` is its constructor, and an empty validator
list is valid input.

```rust
#[cfg(test)]
mod partial_eq_tests {
    use super::*;

    #[test]
    fn a_state_equals_its_own_clone() {
        let state = State::from_genesis(0, Vec::new());
        assert_eq!(state, state.clone());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ethlambda-types a_state_equals_its_own_clone -- --nocapture`
Expected: FAIL, `binary operation '==' cannot be applied to type 'State'`.

- [ ] **Step 3: Add the derive**

At `crates/common/types/src/state.rs:15`, change:

```rust
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
```

to:

```rust
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode, HashTreeRoot)]
```

If the compiler reports a field whose type lacks `PartialEq`, add the derive to
that type too, working outward until it resolves. `State`'s fields are
`ChainConfig`, `BlockHeader`, two `Checkpoint`s, and four SSZ collections, so
expect at most a handful. Do not add `Eq`: nothing needs the stronger claim.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p ethlambda-types a_state_equals_its_own_clone -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Verify the suites**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(types): derive PartialEq on the lean State

BeaconState derives PartialEq, so the Lean variant added next needs it."
```

---

## Task 9: Add `ForkName::Lean`

**Files:**
- Modify: `crates/common/types/src/beacon/fork.rs`
- Test: `crates/common/types/src/beacon/fork.rs`

`Lean` is declared last, so the derived `Ord` sorts it after every beacon fork,
and it is deliberately **absent** from `ForkName::ALL`. `ALL` is what `parse`,
`previous`, `next`, and the fixture harness search, so keeping `Lean` out of it
means no fixture case can ever be lean and `upgrade` can never traverse into it,
while the ordering still reads the way the state-transition gates need.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/common/types/src/beacon/fork.rs`:

```rust
    #[test]
    fn lean_sorts_after_every_beacon_fork() {
        // "Lean is the next fork": every `fork >= ForkName::X` gate in the
        // state transition reads as true for a lean state.
        for fork in ForkName::ALL {
            assert!(ForkName::Lean > fork, "Lean must outrank {fork}");
        }
    }

    #[test]
    fn lean_is_not_a_beacon_fork() {
        // ALL drives `parse`, `previous`, `next`, and the fixture harness's
        // test-list construction. Lean is outside all four.
        assert!(!ForkName::ALL.contains(&ForkName::Lean));
        assert_eq!(ForkName::parse("lean"), None);
        assert_eq!(ForkName::Lean.next(), None);
        assert_eq!(ForkName::Lean.previous(), None);
    }

    #[test]
    fn fulu_is_still_the_last_beacon_fork() {
        // Guards the reason Lean is kept out of ALL: adding it there would make
        // this None into Some(Lean) and let `upgrade` walk off the end.
        assert_eq!(ForkName::Fulu.next(), None);
    }

    #[test]
    fn lean_has_a_name() {
        assert_eq!(ForkName::Lean.as_str(), "lean");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-types lean_sorts_after -- --nocapture`
Expected: FAIL, `no variant named 'Lean' found for enum 'ForkName'`.

- [ ] **Step 3: Add the variant**

In `crates/common/types/src/beacon/fork.rs`, add `Lean` as the last variant and
document why it sits outside `ALL`:

```rust
/// A named fork of the Beacon Chain, ordered oldest to newest, followed by
/// Lean.
///
/// The variant order is the fork order, so the derived [`Ord`] is the comparison
/// the state transition uses to gate behavior: `fork >= ForkName::Altair` reads
/// as "altair or later".
///
/// [`ForkName::Lean`] is last so that every such gate reads as true for a lean
/// state, and is deliberately absent from [`ForkName::ALL`]: lean is not a point
/// on the Beacon Chain's fork timeline, has no spec fixtures, and must never be
/// a target of [`crate::beacon::upgrade`]-style traversal. See
/// [`ForkName::ALL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
    /// The Lean consensus protocol, which this repository implements alongside
    /// the Beacon Chain. Not a Beacon Chain fork, and not in [`ForkName::ALL`].
    Lean,
}
```

Then extend the doc on `ALL` and add the `as_str` arm. `ALL` itself does not
change:

```rust
    /// Every *Beacon Chain* fork this crate implements, in order.
    ///
    /// [`ForkName::Lean`] is not here: it is not a Beacon Chain fork. Because
    /// `parse`, `previous`, `next`, and the spec-fixture harness all search this
    /// array, its absence is what makes `parse("lean")` return `None`, keeps
    /// `Fulu.next()` at `None`, and stops any fixture directory from resolving
    /// to a lean case.
    pub const ALL: [ForkName; 7] = [
```

In `as_str`, which matches variants directly rather than through `ALL`:

```rust
            ForkName::Fulu => "fulu",
            ForkName::Lean => "lean",
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-types fork -- --nocapture`
Expected: PASS, all four new tests plus the three that moved in Task 5.

- [ ] **Step 5: Verify the suites**

Run: `make test-beacon`
Expected: PASS for both presets, same case counts as Task 1 Step 4. A changed
ignored-count means `Lean` leaked into the fixture walk.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(types): add ForkName::Lean, outside ForkName::ALL

Declared last so the derived Ord puts it after every beacon fork, which
is what 'fork >= ForkName::X' gating in the state transition reads.

Kept out of ALL because ALL is what parse, previous, next and the fixture
harness search: absence there is what makes parse(\"lean\") None, keeps
Fulu.next() None so upgrade cannot walk off the end, and stops a fixture
directory from ever resolving to a lean case."
```

---

## Task 10: Add `BeaconState::Lean`

**Files:**
- Modify: `crates/common/types/src/beacon/containers/mod.rs`
- Test: `crates/common/types/src/beacon/containers/mod.rs`

The `Lean` arm of every fork-dispatching accessor is `unreachable!()`, per the
spec: a lean state must never reach a beacon accessor, because the single `match`
at the top of each `BlockChainServer` handler dispatches first. Each message
names the dispatcher that should have caught it, so a violation is diagnosable
from the panic alone.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/common/types/src/beacon/containers/mod.rs`:

```rust
    #[test]
    fn a_lean_state_reports_the_lean_fork() {
        let state = BeaconState::Lean(crate::state::State::from_genesis(0, Vec::new()));
        assert_eq!(state.fork_name(), ForkName::Lean);
    }

    #[test]
    #[should_panic(expected = "lean state reached a beacon accessor")]
    fn a_lean_state_panics_in_a_beacon_accessor() {
        // The guarantee is structural, not type-level: BeaconState::Lean is
        // constructible anywhere, so this pins the failure mode to a named
        // panic rather than a silent wrong answer.
        let state = BeaconState::Lean(crate::state::State::from_genesis(0, Vec::new()));
        let _ = state.slot();
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p ethlambda-types a_lean_state -- --nocapture`
Expected: FAIL, `no variant named 'Lean' found for enum 'BeaconState'`.

- [ ] **Step 3: Add the variant**

In `crates/common/types/src/beacon/containers/mod.rs`, add the variant last:

```rust
/// The beacon state, in whichever fork's shape it currently has, plus the lean
/// state.
///
/// [`BeaconState::Lean`] is not a Beacon Chain shape. It is here so that one
/// `BlockChainServer` can dispatch on a single state type; every accessor below
/// treats it as unreachable, and the enforced boundary is the single `match` at
/// the top of each handler.
#[derive(Debug, Clone, PartialEq)]
pub enum BeaconState {
    Phase0(phase0::BeaconState),
    Altair(altair::BeaconState),
    Bellatrix(bellatrix::BeaconState),
    Capella(capella::BeaconState),
    Deneb(deneb::BeaconState),
    Electra(electra::BeaconState),
    Fulu(fulu::BeaconState),
    Lean(crate::state::State),
}
```

- [ ] **Step 4: Add the `fork_name` arm and let the compiler find the rest**

```rust
            BeaconState::Fulu(_) => ForkName::Fulu,
            BeaconState::Lean(_) => ForkName::Lean,
```

Run: `cargo build -p ethlambda-types`
Expected: FAIL, one `non-exhaustive patterns: 'BeaconState::Lean(_)' not covered`
error per remaining `match`. There are 103 `BeaconState::` matches in this file,
though most are inside already-exhaustive `_ =>` arms and will not error.

For each error, add a `Lean` arm naming the accessor:

```rust
            BeaconState::Lean(_) => unreachable!(
                "lean state reached a beacon accessor (slot); \
                 BlockChainServer must dispatch on fork_name() before this point"
            ),
```

Use the accessor's own name in the parenthesis each time, so a panic in
production says which one was called.

- [ ] **Step 5: Handle `from_ssz`**

`BeaconState::from_ssz(fork, bytes)` matches on `ForkName`, not on the state, so
adding a variant does not break it, but `ForkName::Lean` is now a reachable
input. Add an arm that decodes the lean state, since it is a real SSZ container
and the alternative is a panic on a legitimate call:

```rust
            ForkName::Lean => Ok(BeaconState::Lean(crate::state::State::from_ssz_bytes(
                bytes,
            )?)),
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p ethlambda-types a_lean_state -- --nocapture`
Expected: PASS, both tests.

- [ ] **Step 7: Verify the suites**

Run: `make test-beacon`
Expected: PASS for both presets, same case counts as Task 1 Step 4. No fixture
constructs a `Lean` state, so no `unreachable!` should fire; one that does means
an accessor is reached through a path the dispatch boundary does not cover.

Run: `make test`
Expected: PASS.

Run: `make lint`
Expected: PASS with no warnings.

Run: `make fmt`
Expected: no diff.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(types): add BeaconState::Lean

One BlockChainServer dispatches on the state variant, so the two chains
need one state type. Beacon accessors treat the variant as unreachable
and say so by name: the guarantee is the single match at the top of each
handler, not the type system, so the failure mode is a named panic rather
than a silent wrong answer."
```

---

## Task 11: Update the crate documentation

**Files:**
- Modify: `docs/beacon_stf.md`

`docs/beacon_stf.md` states that the crate "depends on no other `ethlambda-*`
crate, and nothing else in the workspace depends on it". Both halves are now
false, and the doc is the crate's own contract.

- [ ] **Step 1: Update the isolation claim**

Replace the paragraph reading:

```markdown
This is not the Lean consensus protocol the rest of this repository implements.
The two share no types and no code beyond the SSZ crates: the crate depends on no
other `ethlambda-*` crate, and nothing else in the workspace depends on it.
```

with:

```markdown
This is not the Lean consensus protocol the rest of this repository implements.
The two share no *logic*, but they now share a crate: the containers, primitives,
presets, constants, fork names, and configuration live in `ethlambda-types` under
its `beacon` module, so `BeaconState` can carry a `Lean` variant and one
`BlockChainServer` can dispatch on it. This crate keeps the parts that are
Beacon Chain behavior rather than Beacon Chain data: `helpers`, `stf`, `genesis`,
`upgrade`, `fork_choice`, `bls`, `kzg`, and `hash`. It re-exports each moved
module at its old path, so code inside the crate still says `crate::primitives`.

`ForkName::Lean` sits outside `ForkName::ALL`, which is what keeps it out of the
fixture harness, out of `parse`, and out of `upgrade`'s traversal. See
`ForkName::ALL`'s own documentation.
```

- [ ] **Step 2: Update the layout table**

In the `## Layout` table, replace the rows for the moved modules with a note
above the table:

```markdown
`preset`, `config`, `constants`, `fork`, `primitives`, `containers`, and `error`
moved to `ethlambda-types::beacon` and are re-exported here at their old paths.
```

and delete those seven rows, leaving `bls`, `kzg`, `helpers`, `stf`, `genesis`,
`upgrade`, and `fork_choice`.

- [ ] **Step 3: Verify the docs build**

Run: `make docs`
Expected: mdbook builds with no broken-link warnings.

- [ ] **Step 4: Commit**

```bash
git add docs/beacon_stf.md
git commit -m "docs(beacon): record that the containers moved to ethlambda-types

The crate's stated isolation was load-bearing documentation, and both
halves of it are now false: it depends on ethlambda-types, and the types
it defines are used by the lean side."
```

---

## Done when

- [ ] `make test-beacon` passes both presets with the counts from Task 1 Step 4
- [ ] `make test` passes
- [ ] `make lint` passes with no warnings
- [ ] `make fmt` produces no diff
- [ ] `ethlambda_types::beacon::containers::BeaconState::Lean` exists and reports `ForkName::Lean`
- [ ] `ForkName::parse("lean")` returns `None` and `ForkName::Fulu.next()` returns `None`
- [ ] A lean devnet runs unchanged: `make run-devnet`, blocks produced and finalized

Then start plan 2, CLI subcommands.
