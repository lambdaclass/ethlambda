# Beacon Chain state transition

`crates/beacon` (`ethlambda-beacon`) implements the Ethereum **Beacon Chain**
consensus specification, [`ethereum/consensus-specs`][specs], phase0 through
fulu.

This is not the Lean consensus protocol the rest of this repository implements.
The two share no types and no code beyond the SSZ crates: the crate depends on no
other `ethlambda-*` crate, and nothing else in the workspace depends on it.

Correctness is defined by the released spec test fixtures, pinned in the
`Makefile`.

## Running the tests

```bash
make consensus-spec-tests   # download the fixture tarballs (about 2.2 GB)
make test-beacon            # build and test once per preset
```

`make test` deliberately excludes this crate, so the Lean workflow keeps working
without the fixture download.

## Layout

| Module | Holds |
|--------|-------|
| `preset` | Compile-time constants, mainnet or minimal |
| `config` | Runtime configuration: fork schedule, churn limits, blob schedule |
| `constants` | Values the spec fixes outright: domain types, flag weights, sentinels |
| `fork` | `ForkName`, ordered oldest to newest |
| `primitives` | Scalar aliases, `Root`, and the fixed-length byte strings |
| `bls` | BLS12-381 via `blst` |
| `kzg` | KZG via `c-kzg`, plus the two challenge functions c-kzg does not export |
| `containers` | The `BeaconState` enum, fork-invariant containers, per-fork containers |
| `helpers` | The spec's helper functions |
| `stf` | The state transition: slots, blocks, operations, epoch processing |
| `genesis` | Building a genesis state from Eth1 deposits |
| `upgrade` | Fork upgrades between per-fork state shapes |
| `fork_choice` | The LMD GHOST store |

## Three kinds of parameter

The specification distinguishes constants, presets, and configuration, and so
does this crate, because they have genuinely different lifetimes.

**Presets** (`preset`) set container sizes, so they must be compile-time
constants: `SszVector<Root, { preset::SLOTS_PER_HISTORICAL_ROOT }>`. The preset
therefore cannot be a runtime value or a type parameter. Stable Rust cannot take a
const-generic argument from a trait's associated const, so the preset is selected
by Cargo feature: mainnet by default, minimal with `preset-minimal`. The test
target builds the crate twice and each run walks only its own fixture tree.

**Configuration** (`config`) is runtime, because the `transition` fixture suite
moves a fork's activation epoch per test case. That is the concrete reason fork
scheduling is not a preset.

**Constants** (`constants`) are fixed by the specification and vary by neither.

## How forks are represented

Containers that change between forks are defined once per fork as plain structs
that derive their SSZ encoding, decoding, and merkleization, and an enum wraps
them:

```rust
pub enum BeaconState {
    Phase0(phase0::BeaconState),
    // one variant per fork that changes the state's shape
}
```

Deriving the SSZ traits is the whole reason for that shape. Container
serialization and merkleization is the highest-risk code in the crate, and the
per-fork field lists are not a growing tail:

- `previous_epoch_attestations` and `current_epoch_attestations` exist **only** in
  phase0. From altair on they are absent from both the encoding and the merkle
  tree, replaced in position by `previous_epoch_participation` and
  `current_epoch_participation`, which have a different type.
- `latest_execution_payload_header` keeps its name from bellatrix on but is a
  different container in bellatrix, capella, deneb, electra, and fulu.
- The field count crosses a power of two at electra, so the state's merkle tree is
  five levels deep through deneb and six from electra on. The same logical field
  has a different generalized index in different forks.

| Fork | State fields | HTR leaves | Depth |
|------|--------------|------------|-------|
| phase0 | 21 | 32 | 5 |
| altair | 24 | 32 | 5 |
| bellatrix | 25 | 32 | 5 |
| capella, deneb | 28 | 32 | 5 |
| electra | 37 | 64 | 6 |
| fulu | 38 | 64 | 6 |

A single container with fork-conditional serialization would have to reproduce all
of that by hand. Derived codecs get it from the struct definition, which is
checked field by field against the spec text and then verified by `ssz_static`.

Since SSZ carries no type tag, the fork cannot be recovered from the bytes, so
decoding takes it from context: `BeaconState::from_ssz(fork, bytes)`.

### Not duplicating the state transition seven times

The cost of per-fork structs is that a naive implementation would copy every
function once per fork. Two things prevent that:

1. **Accessors for the fork-invariant fields.** About twenty of the state's fields
   are identical in every fork. One `macro_rules!` in `containers/mod.rs`
   generates their read and write accessors from a single list, and that list
   doubles as the crate's statement of which fields are fork-invariant: a fork
   that changes one moves it out of the list and gains an explicit match at each
   use site.

2. **Matching only where the spec diverges.** Functions take the enum and use
   accessors, matching on the fork only where the specification itself changes
   behavior, so a match arm can be reviewed against the spec's own diff.

## Macros and traits

Two `macro_rules!` in the whole crate, both local, both replacing boilerplate that
would otherwise run to hundreds of near-identical lines: the fixed-length byte
strings in `primitives`, and the state accessors in `containers`. No procedural
macros beyond the SSZ derives, and no trait abstracting over BLS or KZG backends.

## Cryptography

`bls` wraps `blst`, and `kzg` wraps `c-kzg` with the `eip-7594` cell and column
functions fulu needs, both matching the versions ethrex uses.

Two details worth knowing:

- Every BLS function re-validates its inputs on each call rather than trusting a
  wrapper validated once. `BlsPubkey` is deliberately unvalidated on construction,
  because deposit processing has to be able to hold a key that never validates, so
  nothing upstream guarantees a key is a subgroup-correct point.
- `compute_challenge` and `compute_verify_cell_kzg_proof_batch_challenge` are
  implemented directly from the spec rather than called, because c-kzg keeps them
  as private steps of its own proof routines yet both have their own fixture
  handlers.

## Fixture suites

`consensus-spec-tests/tests/<config>/<fork>/<runner>/<handler>/<suite>/<case>/`,
where `<config>` is `general` for the configuration-independent suites and the
preset name otherwise. Container files are `.ssz_snappy`: SSZ compressed with
*raw* snappy, not the framed format.

Runners discover their cases from disk rather than listing them, so a fixture
release that adds cases needs no code change. Two properties are deliberate: a
suite that matches no case **fails** rather than reporting green, and a container
or fork pair with no implementation yet is counted and printed rather than passed
over silently, so the output never implies more coverage than exists.

`value.yaml` goes unread in `ssz_static`. Using it would need a serde
implementation for every container and would pin down nothing that the serialized
bytes and expected root do not already.

## Status

Phase0 is complete and green against every phase0 fixture suite the release
ships. Altair has its containers and its fork upgrade; its state transition is
not written yet. Bellatrix through fulu have nothing beyond the preset and
configuration values.

Case counts below are per preset, `minimal` first:

| Suite | State |
|-------|-------|
| `general/bls` | green, 20 cases |
| `general/kzg` | green, 344 cases across all 12 handlers |
| `ssz_static` | green, 25,215 / 1,025 cases |
| `shuffling` | green, 300 cases |
| `operations` | green, 119 / 118 phase0 cases |
| `epoch_processing` | green, 56 / 52 phase0 cases |
| `sanity/blocks` | green, 45 / 40 phase0 cases |
| `sanity/slots` | green, 7 phase0 cases |
| `finality` | green, 5 phase0 cases |
| `random` | green, 16 phase0 cases |
| `rewards` | green, 49 phase0 cases |
| `genesis` | green, 10 cases (minimal only: the release ships no mainnet genesis fixtures) |
| `fork` | altair only |
| `fork_choice` | **implemented but not gated**, see below |
| `transition` | not implemented |

The fork-invariant containers are verified against every fork's `ssz_static`
cases, and phase0's attestation containers through deneb, since electra is where
the aggregation bits widen from one committee to a slot's worth. The state and
block containers exist for phase0 and altair; the sync committee containers are
checked from altair onward, since they do not change shape again.

### The fork choice store is not fixture-verified

`fork_choice.rs` implements the whole of `specs/phase0/fork-choice.md`, but the
release ships **no phase0 `fork_choice` suite**: it starts at altair. So the store
is covered only by unit tests until altair's state transition lands, and should be
treated as unverified against the specification's own cases. This is the largest
piece of the crate carrying that caveat.

### A note on earlier case counts

Counts reported before the runners landed were too high by roughly sevenfold.
`collect_all_handlers` walked the fork directories and then delegated to
`collect`, which walks them again, so every case was emitted once per fork
shipping that runner. The cases were always being *run*; they were counted many
times over. Both collectors now share one suite walk.

## Deliberate simplifications

- Light client containers and suites are out of scope.
- `ssz_generic` exercises the SSZ library rather than this crate's containers, so
  it is not a gate.
- The state transition mutates in place, as the specification does, so a state
  passed to `state_transition` is left partly modified when a block turns out to
  be invalid. Callers that need the pre-state clone it first, which is what the
  fixture runners do.

## What the fixture format asserts by omission

A case with a `post` state must succeed and land exactly on it. A case *without*
one must be **rejected**. The second half is what keeps the suites honest: an
implementation that accepted everything would otherwise pass every case that
ships a post-state. That rule lives in one place, `check_transition`, and every
state-comparing runner goes through it.

Two consequences worth knowing:

- Roughly a quarter of the phase0 `operations` cases are rejection cases, so the
  invalid path gets as much coverage as the valid one.
- The `rewards` suite is the exception to state comparison: it compares the five
  per-component delta vectors directly. That is sharper, because the components
  are summed into balances, so a sign error in one component and a compensating
  error in another would produce correct balances from incorrect deltas.

## Where the specification's Python does more than it appears to

Two places where a faithful-looking transcription is wrong, both found by the
fixtures rather than by reading:

- `get_matching_target_attestations` evaluates `get_block_root` **inside** a list
  comprehension, so it never runs when there are no attestations. That call has
  its own range assertion, which fails for the epoch a state sits at the start of.
  Hoisting it out of the loop rejects states the specification accepts.
- `get_attesting_indices` returns an unordered set, and `get_indexed_attestation`
  sorts it. A committee is a *shuffled* slice of the registry, so filtering it in
  position order yields attesters in shuffle order, which is almost never
  ascending. `is_valid_indexed_attestation` requires sorted indices, so skipping
  the sort rejects every valid attestation.

Both are cases where the Python reads as if order or evaluation point does not
matter, and both change the result.

[specs]: https://github.com/ethereum/consensus-specs
