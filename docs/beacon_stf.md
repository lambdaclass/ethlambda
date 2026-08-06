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

| Suite | State |
|-------|-------|
| `general/bls` | green, 20 cases |
| `general/kzg` | green, 344 cases across all 12 handlers |
| `ssz_static` | green: 5,505 cases (mainnet), 135,423 (minimal) |
| `shuffling` | green, 300 cases |
| `operations`, `epoch_processing`, `sanity`, `finality`, `random`, `rewards`, `fork_choice`, `genesis`, `transition` | not yet implemented |

The fork-invariant containers are verified against every fork's `ssz_static`
cases, and phase0's attestation containers through deneb, since electra is where
the aggregation bits widen from one committee to a slot's worth. Fork-specific
state and block containers are implemented for phase0 only so far.

## Deliberate simplifications

- Light client containers and suites are out of scope.
- `ssz_generic` exercises the SSZ library rather than this crate's containers, so
  it is not a gate.

[specs]: https://github.com/ethereum/consensus-specs
