# Beacon Chain state transition

`crates/beacon` (`ethlambda-beacon`) implements the Ethereum **Beacon Chain**
consensus specification, [`ethereum/consensus-specs`][specs], phase0 through
fulu.

This is not the Lean consensus protocol the rest of this repository implements.
The two share no *logic*, but they now share a crate: the containers, primitives,
presets, constants, fork names, error type, and configuration live in
`ethlambda-types` under its `beacon` module, so `BeaconState` can carry a `Lean`
variant and one `BlockChainServer` can dispatch on it. This crate keeps the parts
that are Beacon Chain behavior rather than Beacon Chain data: `helpers`, `stf`,
`genesis`, `upgrade`, `fork_choice`, `bls`, `kzg`, and `hash`. It re-exports each
moved module at its old path, so code inside the crate still says
`crate::primitives`.

`ForkName::Lean` sits outside `ForkName::ALL`, which is what keeps it out of the
fixture harness, out of `parse`, and out of `upgrade`'s traversal. See
`ForkName::ALL`'s own documentation.

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

`preset`, `config`, `constants`, `fork`, `primitives`, `containers`, and `error`
moved to `ethlambda_types::beacon` and are re-exported here at their old paths.

| Module | Holds |
|--------|-------|
| `bls` | BLS12-381 via `blst` |
| `kzg` | KZG via `c-kzg`, plus the two challenge functions c-kzg does not export |
| `helpers` | The spec's helper functions |
| `stf` | The state transition: slots, blocks, operations, epoch processing |
| `genesis` | Building a genesis state from Eth1 deposits |
| `upgrade` | Fork upgrades between per-fork state shapes |
| `fork_choice` | LMD GHOST, over `ethlambda_storage::Store` |

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

## Retuning a value without redefining a function

The specification expresses a retuned constant as a fresh name per fork
(`MIN_SLASHING_PENALTY_QUOTIENT`, then `..._ALTAIR`, then `..._BELLATRIX`) and
redefines the function that reads it, so each fork carries its own copy of
that function differing in one identifier. `preset::retuned`
(`crates/beacon/src/preset.rs`) selects the value by fork instead, in four
functions, so `slash_validator` and its neighbors stay a single copy each
rather than one per fork.

This is the one place in the crate where a preset value is chosen at runtime.
It is sound because none of these values bound a container: they are divisors
and multipliers in balance arithmetic, not container shape.

The minimal preset is **not** a uniformly scaled mainnet: it overrides only
*phase0's* retuned values and inherits every later fork's from mainnet
unchanged. So a value can move one way across a fork boundary under mainnet
and the other way under minimal: `INACTIVITY_PENALTY_QUOTIENT` falls from
phase0 to altair under mainnet and rises under minimal. A test asserting that
slashing gets uniformly harsher across the forks holds under mainnet and is
false under minimal, so `preset::retuned`'s own tests pin the fork-to-constant
mapping directly, which holds under both presets, rather than any numeric
relationship, which does not.

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
- `latest_execution_payload_header` keeps its name from bellatrix on, but is a
  different container only in bellatrix, capella, and deneb; electra and fulu
  reuse deneb's shape unchanged.
- The field count crosses a power of two at electra, so the state's merkle tree is
  five levels deep through deneb and six from electra on. The same logical field
  has a different generalized index in different forks.
- `SignedBeaconBlock::Fulu` wraps `electra::SignedBeaconBlock` rather than a
  `fulu` type of its own, since fulu changes no field of a block. It still
  needs to be its own variant: fulu changes how a block is *processed*, since
  the blob commitment limit becomes epoch-dependent, so code that dispatches
  on fork still has to tell a fulu block from an electra one even though both
  carry the identical payload.

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

### No block-body enum

`BeaconState` and `SignedBeaconBlock` are the only enums; there is no
`BeaconBlockBody` enum or a body trait. Such a type would have to grow a
method or match arm per fork-specific field or operation list, which defeats
the point of dispatching once: a caller of `body.attester_slashings()` would
still have to know which fork it is dealing with to make sense of what comes
back, since electra's attester slashings are not phase0's. What actually lets
one function serve every fork is narrower and cheaper: `process_block_header`,
`process_randao`, and `process_eth1_data` each take the handful of fields they
read directly, rather than a whole body, so validating a header does not care
whether the body it came from also carries a sync aggregate or an execution
payload. A shared step earns its genericity by needing less, not by being
handed a bigger abstraction to see through. See `stf/mod.rs`'s module doc for
the full reasoning.

### Crossing a fork boundary

`process_slots` performs the fork-boundary state upgrade itself, inside its
slot loop, at the first slot of the activation epoch, looping again in case a
single configuration activates two forks at the same epoch. `state_transition`
checks the block's fork against the state's own only *after* calling
`process_slots`, not before: a block at the first slot of an activation epoch
is legitimately post-fork shaped while the state arriving there is still
pre-fork, which is exactly what a fork transition consists of. Checking first
would reject every legitimate fork-boundary block and make crossing a fork
impossible.

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

## Performance

The mainnet spec suite went from 1576s to about 106s. Two causes:

1. `sha2`'s `asm` feature selects the CPU's SHA-256 instructions. Without it,
   `sha2` compiles the portable scalar backend on aarch64 regardless of what
   the CPU supports, and merkleization is almost entirely SHA-256
   compressions, so a spec fixture case running two whole-state
   merkleizations feels the difference more than anything else does.
2. Every fixture case is its own test, so the harness runs them concurrently at
   one case per work item. That is finer-grained than a suite-per-test layout
   could balance, where the slowest suite alone set the wall clock.

CPU time and wall clock separate the two cleanly, since running work in
parallel cannot reduce the total CPU time it takes:

| Measure | Before | After | Factor |
| --- | --- | --- | --- |
| CPU time | 3041s | 928s | 3.3x, the hardware SHA-256 |
| Wall clock | 1576s | 106s | 14.9x, both causes together |

So parallelism accounts for the remaining 4.9x, taking the run from two of
eleven cores busy to about eight. The 3.3x understates the hashing change,
because the later run does strictly more work: `transition` went from failing
immediately to running every case.

## One test per fixture case

The suites were once one test apiece, each looping over its own cases and
aggregating outcomes. That made every failure a failure of the whole suite: the
name in the output was the suite's, and a single bad case marked thousands of
passing ones as part of one failed test.

A fixture case is not known until the fixture tree is walked, and `#[test]`
needs its tests at compile time, so the spec binary supplies its own harness
(`harness = false`, with `libtest_mimic`) and builds its test list at run time.
Each case is then named, counted, filtered, and attributed on its own, and
`--test-threads`, `--ignored`, `--list`, and substring filters all keep working.
A filter selects a whole suite as readily as one case, since a test's name is
its runner followed by `Case::id`:

```text
operations/electra/attester_slashing/pyspec_tests/basic_double
```

Two things that arrangement has to be careful about:

- A case whose fork this crate does not implement becomes an **ignored** test
  rather than a missing one. The harness counts and names ignored tests, which
  says more than the tally the old aggregate printed.
- A suite that matches no case at all would otherwise contribute no tests, and a
  run of nothing passes. The aggregate used to assert it had matched something;
  that check survives as one `<runner>/matched_fixture_cases` test per suite, so
  a stale runner or handler name still fails loudly.

## Status

All seven forks, phase0 through fulu, have containers, fork upgrades, state
transitions, and epoch processing. Every fixture case passes on both presets:

| Preset | Fixture cases | Ignored | Lib tests |
|--------|---------------|---------|-----------|
| mainnet | 5705, all green | 152 | 244 |
| minimal | 40009, all green | 3692 | 245 |

Minimal runs more cases because the release ships more fixtures for it, and it
runs two runners mainnet does not: `genesis`'s `initialization` and `validity`.
The release ships no mainnet `genesis` fixtures, so that whole runner is gated
behind the `preset-minimal` feature (`tests/spec/genesis.rs`).

Nothing is ignored for being unimplemented. Every ignored case is one of two
deliberate exclusions:

- `LightClient*` containers under `ssz_static`, 5 container types across altair
  through fulu. The light-client sync protocol is a different layer from the
  state transition and fork choice, and is not in this crate's scope.
- The `gloas` and `eip7805` fixture trees, one ignored entry each. See
  "Accounting for every fork directory" below.

## Accounting for every fork directory

`collect` identifies a fork by parsing the directory name into a `ForkName`, and
a name that does not parse is skipped. That skip is silent in a way the
`HIGHEST_IMPLEMENTED_FORK` gate is not: the cases never become tests, so they are
not counted as ignored either, and nothing in the output says they exist.

The release does ship two such trees. `gloas` is the fork after fulu, and
`eip7805` is not a fork in the sequence at all, being one of the per-EIP trees
generated against a variant of some fork's rules. Between them they hold 1898
mainnet and 17539 minimal cases, all of which were previously dropped without a
trace, which is the opposite of what this harness promises.

So `UNMODELED_FORKS` names them, each reports as one ignored test, and
`fixture_forks/every_directory_is_accounted_for` fails if the tree holds a fork
directory that is neither parseable nor listed. A release that adds a fork now
forces a decision instead of quietly widening the gap.

| Suite | Covers |
|-------|--------|
| `general/bls` | Cryptography, fork- and preset-independent |
| `general/kzg` | Cryptography, fork- and preset-independent |
| `ssz_static` | Every fork's containers |
| `shuffling` | Committee helpers |
| `operations`, `epoch_processing` | Every fork's operation and epoch sub-function |
| `sanity/blocks`, `sanity/slots`, `finality`, `random`, `rewards` | Whole blocks and slots, end to end |
| `fork`, `transition` | Fork upgrades, standalone and mid-chain |
| `genesis` | Genesis initialization (minimal only, see above) |
| `fork_choice` | The `Store`; see below |

### Fork choice is fixture-verified

150 mainnet `fork_choice` cases pass, covering bellatrix's `on_merge_block`/
terminal-PoW validation, `should_override_forkchoice_update`, deneb's blob
data availability, and fulu's column data availability.

### Where the fork choice store lives

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

That last point is a rule, not an optimization: any check that asks whether a
state is *cached* turns an eviction into a consensus decision. `on_block`'s
"parent must be known" test therefore reads the block index
(`Store::has_beacon_block`) rather than the state cache, and `checkpoint_state`
derives on a miss rather than returning an error.

The release still ships no phase0 `fork_choice` suite: the earliest is
altair's, built from altair-shaped states even though altair changes nothing
about fork choice itself (`Store` accepts a block from any fork this crate
implements; see `fork_choice.rs`'s own module doc). Landing altair's state
transition is what let this suite start running at all.

### A note on earlier case counts

Counts reported before the runners landed were too high by roughly sevenfold.
`collect_all_handlers` walked the fork directories and then delegated to
`collect`, which walks them again, so every case was emitted once per fork
shipping that runner. The cases were always being *run*; they were counted many
times over. Both collectors now share one suite walk.

## A recurring bug: projecting when an accessor was needed

Reach for a concrete per-fork projection, such as `altair_state(state)`, only
when the return type must be that fork's own. Reach through a `BeaconState`
accessor when the fields involved are shared. The trap is that a projection
like `altair_state(state)` matches only `BeaconState::Altair`, so it compiles
cleanly, passes the fork that introduced the field, and returns
`UnsupportedForFork` for every later fork that shares the exact same field
through a different variant.

This caused five separate bugs during implementation:

- Capella's withdrawal sweep, projected to capella's own state.
- Deneb reusing that same sweep, still projected to capella's state.
- Altair's participation fields, projected to altair's state, so every one of
  the five later forks that also carries participation failed.
- Deneb's `process_attestation`, projected to deneb's state.
- `slash_validator` calling phase0's `initiate_validator_exit` at electra,
  which also left electra's EIP-7251 churn cursor unadvanced, mispricing every
  later exit processed in the same epoch.

## Deliberate simplifications

- Light client containers and suites are out of scope.
- `ssz_generic` exercises the SSZ library rather than this crate's containers, so
  it is not a gate.
- The state transition mutates in place, as the specification does, so a state
  passed to `state_transition` is left partly modified when a block turns out to
  be invalid. Callers that need the pre-state clone it first, which is what the
  fixture runners do.
- `ExecutionEngine` (`stf::mod`) stands in for a real execution client: just
  `execution_valid: bool`, read straight from a fixture's `execution.yaml`
  rather than a payload actually validated.

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
