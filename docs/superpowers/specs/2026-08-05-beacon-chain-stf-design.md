# Beacon Chain state transition and Store: design

**Date:** 2026-08-05
**Status:** approved, implementation staged

## Goal

A new crate implementing the Ethereum **Beacon Chain** consensus specification
(`ethereum/consensus-specs`), phase0 through fulu inclusive: the state
transition function, the fork choice Store, and the supporting containers,
helpers, and cryptography. Correctness is defined by the released spec test
fixtures, and cross-checked against Lighthouse by differential fuzzing.

This is unrelated to the Lean consensus protocol the rest of this repository
implements. The two share no types and no code beyond the SSZ crates. The new
crate depends on no other `ethlambda-*` crate, and nothing in the existing tree
depends on it.

## Scope

| In scope | Out of scope |
|----------|--------------|
| phase0, altair, bellatrix, capella, deneb, electra, fulu | gloas and later (present in v1.6.1, not requested) |
| State transition: slots, blocks, operations, epoch processing | Networking, gossip validation, the beacon API |
| Fork choice Store: `on_tick`, `on_block`, `on_attestation`, `on_attester_slashing`, `get_head` | Validator duties, block production, the builder flow |
| BLS (blst), KZG including the fulu cell/column proofs (c-kzg) | Light client suites |
| Fork upgrades (`upgrade_to_*`) and genesis initialization | Historical state storage, database backends |

## Reference material

| What | Where | Pinned at |
|------|-------|-----------|
| Specification text (the implementation source of truth) | `ethereum/consensus-specs` | `v1.6.1` |
| Presets and configs | `presets/{mainnet,minimal}/*.yaml`, `configs/*.yaml` | `v1.6.1` |
| Test fixtures | `consensus-specs` release assets `general`/`minimal`/`mainnet` | `v1.6.1` |
| Differential reference, and a second opinion when spec text is ambiguous | `sigp/lighthouse` (`types`, `state_processing`, `fork_choice`) | `v8.2.1` |

Fixtures are pinned deliberately. This repository's Lean fixtures track a
rolling `latest`, which has produced surprise CI failures when upstream adds a
rule; a version-pinned Beacon fixture tree fails only when we change something.

## Architecture

```
crates/beacon/
  Cargo.toml           features: preset-mainnet (default) | preset-minimal
  src/
    lib.rs             module graph, crate documentation
    preset.rs          compile-time constants, cfg-selected per preset
    config.rs          runtime configuration: fork epochs and versions
    fork.rs            ForkName, ordered Phase0 < Altair < ... < Fulu
    primitives.rs      Slot, Epoch, Gwei, Root, Version, Domain, ParticipationFlags
    hash.rs            sha256 helpers
    bls.rs             blst wrapper
    kzg.rs             c-kzg wrapper plus the two Fiat-Shamir challenge functions
    containers/
      mod.rs           the BeaconState / BeaconBlock / BeaconBlockBody enums
      phase0.rs ... fulu.rs    per-fork container structs
      shared.rs        fork-invariant containers
    helpers/           accessors, predicates, math, committees, shuffling
    stf/
      mod.rs           state_transition, process_slots
      block.rs         block header, randao, eth1 data, execution payload, withdrawals, sync aggregate
      operations.rs    attestations, slashings, deposits, exits, execution requests
      epoch.rs         justification, rewards, registry, slashings, and the rest of process_epoch
      upgrade.rs       upgrade_to_altair ... upgrade_to_fulu
      genesis.rs       initialize_beacon_state_from_eth1, is_valid_genesis_state
    fork_choice/
      store.rs         Store and its handlers
      head.rs          get_head, LMD-GHOST weights, filter_block_tree
  tests/
    spec_tests.rs      single integration binary
    spec/              one module per fixture runner, one owner per file
fuzz/                  separate crate, excluded from the workspace
```

### Fork representation

Each fork gets its own container structs, deriving SSZ encode, decode, and
`hash_tree_root`. An enum wraps them:

```rust
pub enum BeaconState {
    Phase0(phase0::BeaconState),
    Altair(altair::BeaconState),
    // ... through Fulu
}
```

Deriving the SSZ traits per fork is the point of this choice. Container
serialization and merkleization is the highest-risk code in the project, and the
per-fork field lists are not a growing tail:

- `previous_epoch_attestations` and `current_epoch_attestations` exist only in
  phase0. From altair on they are absent from both the encoding and the merkle
  tree, replaced in position by `previous_epoch_participation` and
  `current_epoch_participation`, which have a different type.
- `latest_execution_payload_header` keeps its name but is a different container
  in bellatrix, capella, deneb, electra, and fulu.
- The field count crosses a power of two at electra, so the state's merkle tree
  is 5 levels deep through deneb and 6 from electra on. The same logical field
  has a different generalized index in different forks.

| Fork | State fields | HTR leaves | Depth |
|------|--------------|------------|-------|
| phase0 | 21 | 32 | 5 |
| altair | 24 | 32 | 5 |
| bellatrix | 25 | 32 | 5 |
| capella, deneb | 28 | 32 | 5 |
| electra | 37 | 64 | 6 |
| fulu | 38 | 64 | 6 |

Hand-written codecs would have to reproduce all of that. Derived ones get it
from the struct definition, which is checked field-by-field against the spec
text and then verified by the `ssz_static` fixtures.

The enum's own SSZ is a match that delegates to the active variant. Decoding
needs the fork from context, so the entry point is
`BeaconState::from_ssz(fork, bytes)` rather than a `SszDecode` impl.

### Avoiding a sevenfold state transition

The cost of per-fork structs is that a naive implementation duplicates every
function seven times. Two mechanisms prevent that:

1. **Accessors for fork-invariant fields.** About 20 of the state's fields exist
   unchanged in every fork. One local `macro_rules!` in `containers/mod.rs`
   generates the read and write accessor pair for each, from a single list. That
   list doubles as the crate's statement of which fields are fork-invariant.

   The macro has two rules, `copy` and `reference`, because returning `&u64` for
   a slot would make the state transition noisier than returning it by value.
   Write accessors are named explicitly (`slot`, `slot_mut`) rather than derived
   from the field name, since `macro_rules!` cannot concatenate identifiers on
   stable Rust.

   There is one other macro in the crate, for the fixed-length byte strings in
   `primitives.rs`, and no procedural macros beyond the SSZ derives.

2. **Matching only where the spec diverges.** State transition functions take
   `&mut BeaconState` and use accessors. A function matches on the fork only
   where the specification itself changes behavior, and the match arms then
   mirror the spec's own diff, which makes them reviewable against it.

Functions that are inherently fork-specific, such as `process_sync_aggregate`
(altair and later) or `process_consolidation_request` (electra and later),
return an error for forks that do not have them.

### Presets

Container sizes differ between presets, and `libssz` needs them as compile-time
constants. Stable Rust cannot take a const-generic argument from a trait's
associated const, so the preset cannot be a type parameter. Instead, features
select a constant module:

```rust
#[cfg(feature = "preset-minimal")]
pub use minimal::*;
#[cfg(not(feature = "preset-minimal"))]
pub use mainnet::*;
```

There is only a `preset-minimal` feature, with mainnet as the implicit default.
A `preset-mainnet` feature would need to be mutually exclusive with it, and
mutually exclusive features are awkward under Cargo's feature unification:
`--features preset-minimal` would silently keep mainnet unless the caller also
passed `--no-default-features`. Constants feed const-generic bounds directly:
`SszVector<Root, { preset::SLOTS_PER_HISTORICAL_ROOT }>`, where the braces are
required because the argument is a path rather than a bare identifier. The test
target runs the suite twice, once per preset, and each run walks only its own
fixture tree.

The spec's split between preset (compile-time, affects container shape) and
config (runtime, affects fork scheduling) is preserved: fork epochs live in
`Config`, so the `transition` suite can set a custom fork epoch per case.

### Fork choice

`Store` is a plain struct of maps, constructed by `get_forkchoice_store`, with
`on_tick`, `on_block`, `on_attestation`, and `on_attester_slashing` handlers
plus `get_head`. Proposer boost and the equivocating-indices set are fields on
`Store`, matching the spec.

## Testing

### Fixture runners

`make consensus-spec-tests` downloads and extracts the three release tarballs
into a gitignored directory, with the version pinned in the Makefile. All three
unpack to `tests/<name>/...`, so they extract into one directory and land side by
side:

```text
consensus-spec-tests/tests/<config>/<fork>/<runner>/<handler>/<suite>/<case>/
```

Cases are `.ssz_snappy` (raw snappy, not framed) plus `meta.yaml` where a suite
needs it. `ssz_static` cases also carry `roots.yaml`, holding the expected
`hash_tree_root`, and `value.yaml`. The runners use `serialized.ssz_snappy` and
`roots.yaml`; nothing needs `value.yaml`, which is what spares the containers
from needing serde implementations.

| Runner | Gate for |
|--------|----------|
| `bls`, `kzg` | Stage 1, cryptography |
| `ssz_static` | Every fork's containers |
| `shuffling` | Committee helpers |
| `operations` | Per-operation processing |
| `epoch_processing` | Individual epoch sub-functions |
| `sanity`, `random`, `finality`, `rewards` | Whole blocks and slots end to end |
| `fork_choice` | Store |
| `genesis` | Genesis initialization |
| `transition`, `fork` | Fork upgrades |

`ssz_generic` exercises the SSZ library rather than our containers, so it is a
stretch goal, not a gate.

### Differential fuzzing

A `fuzz/` crate outside the workspace, so Lighthouse's dependency tree never
enters our lockfile. Targets take raw bytes, decode with both implementations,
run both state transitions, and compare:

- agreement on accept versus reject, and
- the post-state `hash_tree_root` when both accept.

Rejection *reasons* are not compared, because the two error taxonomies do not
correspond. The corpus is seeded from fixture pre-states and blocks, which gives
libFuzzer valid, structurally deep starting points to mutate. Targets:
`ssz_state_roundtrip`, `block_processing`, `epoch_processing`.

## Staging

Each stage is at least one commit, and lands only when its fixture gate is
green. Work fans out to parallel agents by file ownership: one agent per file,
never a shared file.

`Status` records where the work actually got to, since the gate column turned out
to be wrong in one place.

| # | Stage | Fixture gate | Status |
|---|-------|--------------|--------|
| 1 | Scaffold: preset, config, fork, primitives, hash, bls, kzg | `general/bls`, `general/kzg` | done |
| 2 | Fixture harness: download, loader, runner skeleton | harness self-tests | done |
| 3 | phase0 containers, the enum, accessors | `ssz_static` phase0 | done |
| 4 | Helpers: accessors, predicates, math, committees, shuffling | `shuffling` | done |
| 5 | phase0 blocks and operations | `operations` phase0 | done |
| 6 | phase0 epoch processing | `epoch_processing`, `finality`, `sanity`, `random`, `rewards` | done, plus `genesis` |
| 7 | phase0 fork choice | ~~`fork_choice` phase0~~ | **written, not gated** |
| 8 | altair: sync committees, participation flags, inactivity | altair suites | containers and `fork` only |
| 9 | bellatrix: execution payload, merge transition | bellatrix suites |
| 10 | capella: withdrawals, BLS-to-execution changes | capella suites |
| 11 | deneb: blob commitments | deneb suites |
| 12 | electra: max EB, deposit and withdrawal requests, consolidations, committee bits | electra suites |
| 13 | fulu: proposer lookahead, blob schedule | fulu suites |
| 14 | Differential fuzzing | corpus replay |
| 15 | Documentation | mdbook builds |

Stages 3 and 4 must complete before the state transition fan-out, because
everything downstream depends on those types and helpers.

### The stage 7 gate does not exist

This plan assumed a phase0 `fork_choice` suite. There is none: the release ships
`fork_choice` from altair onward, because the suite's cases are built from states
that only later forks have. So stage 7's code is written but cannot be verified
until stage 8's state transition lands, and stage 7 should have been sequenced
after it. Anything relying on the store before then is relying on unit tests.

### Genesis was missing from the plan

`initialize_beacon_state_from_eth1` and the `genesis` suite appear in no stage
above. They were folded into stage 6. The suite ships only under `minimal`, so
the mainnet build has no genesis coverage at all.

## Dependencies

Chosen to match ethrex where ethrex has made the choice.

| Crate | Version | Purpose |
|-------|---------|---------|
| `libssz`, `libssz-derive`, `libssz-merkle`, `libssz-types` | workspace | SSZ, already used by this repository |
| `blst` | 0.3.16 | BLS12-381 signatures |
| `c-kzg` | 2.1.8, `eip-7594` + `ethereum_kzg_settings` | KZG, including fulu cell proofs |
| `sha2` | 0.10.9 | Hashing |
| `snap` | 1.1.1 | Fixture decompression |
| `num-bigint` | 0.4.6 | Reduction mod r in the Fiat-Shamir challenges |
| `serde`, `serde_yaml_ng`, `hex`, `thiserror`, `tracing`, `rayon` | workspace | Existing workspace versions |

`c-kzg` does not export `compute_challenge` or the cell-proof batch challenge,
both of which have their own fixture handlers, so `kzg.rs` implements those two
directly from the spec. That is what `num-bigint` is for: both reduce a SHA-256
digest modulo the BLS field order.

The KZG suites are all `kzg-mainnet` and the trusted setup is not
preset-dependent, so the embedded mainnet setup is correct under both presets.

## Deliberate simplifications

Each is documented where it is implemented.

- `verify_and_notify_new_payload` returns the fixture's `execution_valid`. There
  is no execution client.
- `is_data_available` trusts blobs and columns supplied by the fixture. Sampling
  is a networking concern.
- Light client suites are skipped, as light client objects are out of scope.
- Rejection reasons are not compared during differential fuzzing, only the
  accept-or-reject decision and the resulting state root.
