# Beacon Chain state transition

The `beacon` module of `ethlambda-state-transition`
(`crates/blockchain/state_transition/src/beacon/`) implements the Ethereum
**Beacon Chain** consensus specification,
[`ethereum/consensus-specs`][specs], phase0 through gloas.

This is not the Lean consensus protocol the rest of the crate implements. The two
sit in one crate for the reason their types sit in one crate: a caller
dispatching on a state's fork can then reach either chain's rules without the two
living in separate dependency trees. They share nothing else. Nothing above
`beacon` in this crate reads anything inside it, and nothing inside it reads
lean's own modules.

The containers, presets, configuration and primitives this module transitions are
in `ethlambda-types`, under its own `beacon` namespace, because
`ethlambda-storage` and the networking crates need those types and must not
depend on `blst` and `c-kzg`. What lives here is the behavior: the state
transition, the fork choice store, the helpers, and the two cryptography modules.

`blst`, `c-kzg` and `num-bigint` are therefore on the lean binary's dependency
path, since `ethlambda-blockchain`, `ethlambda-rpc` and `ethlambda-test-fixtures`
all depend on this crate. The module is not feature-gated; that is the accepted
cost of holding both chains' rules in one place.

The types are re-exported at the paths they had when they were defined here, so
`crate::beacon::containers`, `crate::beacon::preset` and `crate::beacon::config`
still resolve, and
`ethlambda_state_transition::beacon::containers::X` and
`ethlambda_types::beacon::containers::X`
are one type by one name. Two definitions travel in the other direction, for the
same reason they moved: `fork_choice` re-exports `LatestMessage` and `PowBlock`,
which `ethlambda-storage` persists, and `helpers::misc` re-exports
`compute_fork_data_root`, which the networking crate's fork digest is built on.

One consequence reaches every match in the module. `ethlambda-types` gives
`BeaconState` and `ForkName` a `Lean` variant, so that one state type can carry
either chain, and every match on either needs an arm for it. No lean value can
reach this module: a fixture case's fork is parsed from a directory name and
`ForkName::ALL` has no lean entry, and a beacon block or a deposit set produces a
beacon state. So those arms panic and name themselves, through
`lean_state_unreachable`/`lean_fork_unreachable` (`src/beacon/lean_boundary.rs`) and
`lean_is_not_a_fixture_fork` in the spec tests, rather than widening signatures to
a `Result` no correct caller could ever see. They are named arms rather than a
catch-all `_`, so a real fork added to the enum still breaks every match that has
to grow an arm for it.

Correctness is defined by the released spec test fixtures, pinned in the
`Makefile`.

## Running the tests

```bash
make consensus-spec-tests   # download the fixture tarballs (mainnet and minimal)
make cryptography-specs     # download the BLS/KZG test vectors
make test-beacon            # build and test once per preset
```

`make test-beacon` is the two per-preset targets, `test-beacon-mainnet` and
`test-beacon-minimal`, run one after the other. Either can be run on its own,
which is what CI does: the presets get a job each, so the two build and run
concurrently instead of end to end.

A run reads its own preset's tree and opens nothing else.
`CONSENSUS_SPEC_TESTS_CONFIGS` narrows the download to that, and CI sets it.
Locally the default fetches both, so both presets can be run without
re-downloading. The BLS and KZG vectors are a separate, preset-independent
download: consensus-specs shipped them itself, under a `general` config,
through v1.7.0-alpha.12, but v1.7.0-alpha.13 (consensus-specs #5398) moved them
to `ethereum/cryptography-specs`, which `make cryptography-specs` fetches into
its own `cryptography-specs/` tree.

The download is stamped with the release it came from and the configs it holds
(`consensus-spec-tests/.version-<version>-<configs>`), so changing either wipes
the tree and fetches afresh. Without the version in that name a bump would be a
silent no-op: the extracted directories already exist, so `make` would consider
them current and both presets would report green against the old fixtures.
Without the configs, a narrowed download would mark a tree missing one preset as
complete, and that preset's next run would fail on a missing directory rather
than fetching what it needs. The wipe matters as much as the re-download, since
the tarballs unpack side by side into one directory, and layering a new release
over an old one would keep cases the new one deleted.

`make test` covers the whole workspace, in two halves, and still needs no
fixture download. The halves are all that `test-node`'s `--exclude` flags do;
nothing is dropped to keep the beacon suite out. Two gates keep it that way,
both tied to the `beacon-spec-tests` feature that `make test-beacon` turns on:

- The `beacon_spec_tests` target declares `required-features =
  ["beacon-spec-tests"]`, so `cargo test` skips building it entirely.
- The BLS and KZG fixture vectors are unit tests inside the module, which no
  target gate reaches, so each carries
  `#[cfg_attr(not(feature = "beacon-spec-tests"), ignore = ...)]`. They report as
  ignored rather than disappearing, which is why `make test-beacon` also passes
  `--lib`: 15 tests would otherwise never run.

Neither gate touches the module itself, which always compiles. What they stand
for is the fixture tree, not the code.

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
| `lean_boundary` | The two `#[track_caller]` panics for the `Lean` arm of the shared enums |

The first five come from `ethlambda_types::beacon` and are re-exported by
`beacon/mod.rs`; the rest are defined here.

## Three kinds of parameter

The specification distinguishes constants, presets, and configuration, and so
does this module, because they have genuinely different lifetimes.

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
(`crates/common/types/src/beacon/preset.rs`, reached here as `crate::preset`)
selects the value by fork instead, in four functions, so `slash_validator` and its neighbors stay a single copy each
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
  reuse deneb's shape unchanged, and gloas drops it for a block hash and the
  latest bid.
- The field count crosses a power of two at electra, so the state's merkle tree is
  five levels deep through deneb and six from electra on. The same logical field
  has a different generalized index in different forks. Gloas's state is a
  progressive container (EIP-7495), whose tree has no fixed depth at all.
- `SignedBeaconBlock::Fulu` wraps `electra::SignedBeaconBlock` rather than a
  `fulu` type of its own, since fulu changes no field of a block. It still
  needs to be its own variant: fulu changes how a block is *processed*, since
  the blob commitment limit becomes epoch-dependent, so code that dispatches
  on fork still has to tell a fulu block from an electra one even though both
  carry the identical payload. Gloas is a different case: its block body
  changes (a bid in place of a payload, payload attestations, the parent's
  execution requests), so `SignedBeaconBlock::Gloas` has a type of its own.

| Fork | State fields | HTR leaves | Depth |
|------|--------------|------------|-------|
| phase0 | 21 | 32 | 5 |
| altair | 24 | 32 | 5 |
| bellatrix | 25 | 32 | 5 |
| capella, deneb | 28 | 32 | 5 |
| electra | 37 | 64 | 6 |
| fulu | 38 | 64 | 6 |
| gloas | 46 | progressive | none |

A single container with fork-conditional serialization would have to reproduce all
of that by hand. Derived codecs get it from the struct definition, which is
checked field by field against the spec text and then verified by `ssz_static`.

Since SSZ carries no type tag, the fork cannot be recovered from the bytes, so
decoding takes it from context: `BeaconState::from_ssz(fork, bytes)`.

### Not duplicating the state transition once per fork

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

## Registry and balances

`validators` and `balances` hold one entry per validator, about 2.4M on
mainnet, so they dominate both the cost of a state root and the memory of every
cached state. They are `ethlambda_ssz_tree::List`s rather than `SszList`s (from
gloas on, `ethlambda_ssz_tree::ProgressiveList`s, described in the Gloas section
below): persistent Merkle trees in the shape of the SSZ one, modeled on the
`milhouse` lists lighthouse keeps its state in.

- **Nodes cache their hash, and states share nodes.** A state derived from
  another shares every subtree the block did not touch through `Arc`, and its
  root rehashes only the touched paths. A state decoded from storage is rebased
  onto a cached relative, so it shares memory with it too.
- **Leaves and inner nodes are page-sized.** A leaf holds a contiguous run of
  elements (32 validators, 512 balances), and an inner node up to 512 child
  pointers standing for nine binary levels at once. A lookup therefore crosses
  a handful of nodes rather than one per level of the registry's depth, and
  iteration walks each leaf as a slice. A composite leaf also keeps each
  element's root once hashed, and a rebuilt leaf carries over the roots of the
  elements it did not change, so one changed validator costs one validator
  hash plus a fold of the cached roots.
- **Writes are buffered.** `get_mut`, `IndexMut` and `push` record the new
  value; `BeaconState::apply_pending_mutations` folds everything buffered into
  the trees in one pass. The state transition calls it at the top of
  `process_slot`, after `process_block`, and at the end of `process_slots` (epoch
  processing runs after the loop's last `process_slot`). A root taken with
  writes pending is still correct but computed on a throwaway copy, and the
  store flushes a state before caching it, since a shared `Arc` cannot be
  flushed later.

The access pattern matters. `state.validator(i)` and `state.balance(i)` are tree
descents, cheap next to a hash but far from an array index, and they add up
when a helper calls them once per validator:
`get_total_active_balance` builds the active-index `Vec` and then reads every
index back, and runs several times per block (once per attestation through
`get_base_reward_per_increment`, once per execution request through the churn
limits). In the 2026-09-28 import profile, those per-index reads and the
repeated whole-registry scans were the largest cost left after hashing. A loop
over the registry should walk `iter_validators()`, zipped with
`iter_balances()` where it needs both. The total active balance is the obvious
candidate for computing once per epoch rather than per call, once it is shown
that no block operation changes it mid-epoch.

Epoch steps 1-3 (justification, inactivity updates, rewards) follow that rule
through `helpers::participation`. One walk of `iter_validators()`, zipped with
the flat participation slices, produces each validator's flags, its effective
balance and the balance totals (an `EpochSummary`); the three steps then run
over flat data and write back only the balances that changed. The summary lives
for those three steps only, since registry updates change what it read. The
per-block pulled-up tip needs just the totals, which `ParticipationTotals`
computes without allocating. The fixtures still call each step alone, so the
public step functions stay and each builds what it needs. The
specification-shaped implementation is kept in `participation_reference` and
`stf::epoch::altair_reference` for tests and debug builds: the driver runs it on
a clone for registries of up to 4096 validators and asserts the outcomes agree.
The leak flag is read once per step rather than once per validator, which fails
some states the specification accepts; see
[Spec Deviations](spec_deviations.md#the-inactivity-leak-check-runs-once-per-epoch-step-not-once-per-validator).

Electra and fulu go further (`stf::epoch::single_pass`): steps 2-9 (inactivity,
rewards, registry updates, slashings, pending deposits, effective-balance
updates) run in one loop over the registry, each validator on a local copy, with
the changes written back afterwards. What depends on more than one validator is
handled outside the loop: the exit-churn cursor is advanced locally in index
order, the pending-deposit queue is planned before the loop (top-ups of existing
validators inside it, deposits that create validators after it), and pending
consolidations run after it, with the effective-balance update of every
validator they name deferred until they are done. The genesis epoch and states
whose registry-sized lists differ in length fall back to the step-by-step path.
The debug oracle runs the specification-shaped steps on a clone and asserts the
two full states hash equal.

## Gloas

Five of gloas's EIPs shape this module: ePBS (EIP-7732), progressive lists and
containers (EIP-7688), proposer selection that skips slashed validators
(EIP-8045), increased exit and consolidation churn (EIP-8061), and builder
deposits and exits (EIP-8282). EIP-7843 and EIP-7928 only add payload fields
(`slot_number`, which `verify_execution_payload_envelope` checks, and
`block_access_list`). It is the one fork whose containers change shape
wholesale, so its code sits beside the pre-gloas code rather than inside it: `stf/gloas.rs` and
`stf/epoch/gloas.rs` (transition), `helpers/gloas.rs` (helpers), the gloas
section of `fork_choice.rs` (fork choice), and `containers/gloas.rs` in
`ethlambda-types`. Every gloas case that is not ignored passes on both presets.

The live follower follows gloas (`ForkName::Gloas.is_followed()`): the chain
actor imports gloas blocks and their payload envelopes, a gloas checkpoint
anchor is accepted (it starts EMPTY, with no payload known), and the clock
passing the fork epoch no longer forces the sync status to syncing. Fork choice
records the head node's payload status next to the head root
(`Store::head_payload_status`, in memory, recomputed by the first head
computation after a restart), which the envelope by-range server reads to
withhold the head's envelope while the head is the EMPTY node. The node is
still only a follower: the validator-client endpoints refuse a gloas epoch.

### The envelope pipeline in the chain actor

Order of arrival is not order of validity: an envelope can beat its block, a
block can name a parent payload that has not arrived, and the columns an
envelope's commitments need can lag both. `beacon_envelope.rs` holds each case
in a queue with its own bound, and `beacon_columns.rs` bounds the parked
sidecars of the same fork.

| Queue | Holds | Released when |
|---|---|---|
| `awaiting_import` | an envelope whose block is stored but has no post-state (pending on a parent, held for columns or for its parent's payload), checked against the stored block's bid | the block imports; evicted with the block when it is discarded and at finality; bounded by the stored blocks, not by arrival slot |
| `awaiting_block` | an envelope whose block is not stored at all | the block imports; evicted after `ENVELOPE_AWAITING_BLOCK_TTL_SLOTS`, capped per slot and per root |
| `awaiting_columns` | a consensus-checked envelope whose bid has commitments and whose sampled columns are not all stored | the last column is stored |
| `awaiting_engine` | a consensus-valid envelope the execution client gave no answer for | the per-slot redrive gets an answer (see [beacon_engine.md](./beacon_engine.md#gloas)) |
| `blocks_awaiting_parent_payload` | a block whose parent is FULL with a payload not yet verified, capped per parent | that parent's envelope verifies |

Data availability moves with the payload: a gloas block's commitments are in its
bid, so the columns gate the envelope that reveals the payload, not the block's
own import. A held block's parent envelope is requested through
`FetchRequest.needs_envelope` the moment the block is held, whatever its source:
`BlockSource::Sync` also marks by-root answers and pending children a cascade
released, so no range batch can be assumed to bring the envelope, and p2p dedups
in-flight roots. The tick re-asks once a slot for every parent still missing
one, which is only what recovers a fetch that gave up; catch-up does not wait
for it.

The two envelope-before-block queues differ in who has vouched for the root.
A range batch's envelopes arrive when all but its first block are stored and
unimported, so a stored block's own bid is the authority: an envelope matching
it (`envelope_matches_bid`) goes to `awaiting_import` outside the per-slot cap,
and one contradicting it is dropped. Only a root with no stored block, which
nobody has authenticated, is held under the per-slot cap and the TTL.
Everything is swept at finality, except the finalized block's own envelope.

Fork-choice events are timed at their arrival: the store clock is advanced to
the moment an envelope, block or payload vote reached the node before its
handler runs, because the tick fires once per slot and the timeliness deadlines
would otherwise be judged at the slot's start. Payload votes already verified
in p2p are applied without a second signature check
(`apply_verified_payload_attestation`). The PTC vote vectors are not persisted
and are reseeded empty on resume; see [data_storage.md](./data_storage.md).

### The deferred payload

A gloas block has no execution payload. Its body commits to a builder's bid
(`process_execution_payload_bid`), and the builder reveals the payload later in
a `SignedExecutionPayloadEnvelope`. The payload is applied by the *next*
block: `process_parent_execution_payload` compares that block's bid against the
parent's committed one to tell whether the parent was full or empty, and for a
full parent `apply_parent_execution_payload` runs the execution-layer requests
carried in `parent_execution_requests` and settles the builder's payment. An
empty parent must carry no requests.

`verify_execution_payload_envelope` is the checking half that used to sit in
`process_execution_payload`, and it mutates nothing: fork choice calls it on a
stored state when an envelope arrives, and only the next block changes state.
Block processing therefore takes no `ExecutionEngine`, and `process_withdrawals`
takes no payload, since the expected withdrawals are a function of the state
alone.

Execution-layer requests moved with the payload. Deposit, withdrawal and
consolidation requests, and the two builder requests, are reached only through
`apply_parent_execution_payload`; gloas's `process_operations` no longer calls
the first three. Their behavior did not change, so
`apply_parent_execution_payload` calls the fulu and electra processors instead
of keeping copies.

### Progressive lists and the registry

EIP-7688 makes most lists in the gloas state and body unbounded, merkleized as a
chain of growing subtrees (EIP-7916), and makes the big containers progressive
(EIP-7495); a progressive container has no fixed depth. The other progressive
lists are libssz's `ProgressiveList`. The registry is the exception:
`validators` and `balances` stay tree-backed, through
`ethlambda_ssz_tree::ProgressiveList`, which has the same persistent nodes,
update buffer and rebase as the bounded `List` and the same method set, so a
gloas state shares subtrees with its parent the way earlier ones do.

The registry therefore has two list types across the forks, and an accessor
cannot return either one. The whole-registry accessors were replaced by
element-level ones on `BeaconState`: `validator_count`, `validator`,
`validator_mut`, `balance`, `balance_mut`, `push_validator`, `iter_validators`,
`iter_balances` and `validators_root`. Each dispatches once and hands back an
element, a count or an iterator. Only the few that need the list itself
(`iter_validators`, `iter_balances`, rebasing onto a cached state, pointer
equality) match on the private `Registry` enum.

### One function for both list types

The spec modifies a small part of what gloas touches, and the rest is electra's
text run against a differently typed list. Copying it would fork every fix, so
the shared functions take narrow views instead:

| View | Reaches |
|------|---------|
| `PendingQueueFields` | The deposit balance cursor and the three pending queues, on electra, fulu and gloas |
| `ChurnCursorsMut` | The four exit and consolidation churn cursors, on the same three forks |
| `gloas_state`, `gloas_state_ref` | Gloas's own concrete state, for fields only gloas has |

Both list types deref to a slice of the same element type, so a view can expose
slices and element-level methods and let electra's `process_withdrawal_request`,
`process_consolidation_request`, exit and slashing paths serve a gloas state
unchanged. The churn limit is the one input that differs: electra's cursor
functions read gloas's own limits on a gloas state, which is a fork dispatch
inside them rather than a second copy. A function gets a gloas copy only where
the spec marks it modified. The rule for choosing between the views and a
projection is the one in "A recurring bug" below: project only when the return
type must be gloas's own.

### Fork choice

Gloas gives each block two branches to weigh: *empty*, where no payload was
revealed or attested as timely and available, and *full*, where the builder's
payload was. A gloas fork-choice node is therefore `(root, PayloadStatus)`
with `Empty`, `Full` and `Pending`, where every earlier fork's node is a bare
root. Nodes are derived on demand from the block tree, each block's bid and the
set of verified payloads (`get_node_children` builds them), not stored, which
mirrors the spec's `Store`.

`ForkRules` (`PreGloas` or `Gloas`) is the other new dimension. It is derived
from an exhaustive match on a fork or a container, and it is what
`validate_on_attestation` and `update_latest_messages` read, since gloas turns
`data.index` into the payload flag and orders votes by slot instead of target
epoch. A vote's rules follow its own container, not the clock.

One head computation serves every fork: `get_head_node` builds a weight table
for the node tree in one bottom-up pass and descends over it. The current
slot's fork selects the two rules that differ: from `GLOAS_FORK_EPOCH` on,
blocks carry the payload dimension their bids give them and the proposer boost
is gated by `should_apply_proposer_boost`; before it, every block is a single
full node and the boost applies whenever it is set. A block's fork and parent
payload status are recorded at import (`BlockPayloadLink`), so the walk decodes
no block in the ordinary case; the two exceptions are in
[spec_deviations.md](spec_deviations.md). `compute_head` and the spec-literal
`gloas_get_head` are kept as the references it is tested against; the cost
argument is in the same page. The spec never describes a tree that
crosses the boundary, so that page also records the rule this module chose.
Two new handlers, `on_execution_payload_envelope` and
`on_payload_attestation_message`, join the spec's list of ways to change the
store.

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
where `<config>` is the preset name. Container files are `.ssz_snappy`: SSZ
compressed with *raw* snappy, not the framed format. The BLS and KZG vectors
live in a separate tree, `cryptography-specs/tests/<kind>/<handler>/<case>/`,
flatter still: no fork and no suite level, since neither is preset- or
fork-dependent.

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

- A case whose fork this module does not implement becomes an **ignored** test
  rather than a missing one. The harness counts and names ignored tests, which
  says more than the tally the old aggregate printed.
- A suite that matches no case at all would otherwise contribute no tests, and a
  run of nothing passes. The aggregate used to assert it had matched something;
  that check survives as one `<runner>/matched_fixture_cases` test per suite, so
  a stale runner or handler name still fails loudly.

## Status

All eight forks, phase0 through gloas, have containers, fork upgrades, state
transitions, and epoch processing. At the pinned fixture release every case
that is not ignored passes on both presets:

| Preset | Fixture cases passed | Ignored | Lib tests |
|--------|----------------------|---------|-----------|
| mainnet | 7175 | 1285 | 433 passed, 1 ignored |
| minimal | 49261 | 5403 | 434 passed, 1 ignored |

The lib counts are with `beacon-spec-tests` on, and include lean's own unit
tests, since the two chains share one lib target. The one ignored lib test is
a timing measurement, not a fixture.

Minimal runs more cases because the release ships more fixtures for it, and it
runs two runners mainnet does not: `genesis`'s `initialization` and `validity`.
The release ships no mainnet `genesis` fixtures, so that whole runner is gated
behind the `preset-minimal` feature (`tests/beacon_spec/genesis.rs`).

The gossip validation vectors this crate's `gossip.rs` runner covers come from
the same tree as every other suite. The node validates four topics under fulu's
rules; every other case is ignored by name rather than left unmatched.

Nothing is ignored for being unimplemented in the state transition or fork
choice: `HIGHEST_IMPLEMENTED_FORK` is gloas, and every gloas case that is not
ignored runs. The ignored cases are deliberate exclusions:

- `LightClient*` containers under `ssz_static`, 5 container types across altair
  through gloas. The light-client sync protocol is a different layer from the
  state transition and fork choice, and is not in this module's scope.
- `networking/gossip_*` cases outside what the node validates: every fork's
  cases for topics it has no validator for (`IGNORED_HANDLERS`), non-fulu cases
  of the aggregate and attestation topics (block and data column validate fulu
  and gloas), and the vectors in `SKIPPED`, which assume a bad-block cache.
- The `heze` fixture tree, one ignored entry. See "Accounting for every fork
  directory" below.

## Accounting for every fork directory

`collect` identifies a fork by parsing the directory name into a `ForkName`, and
a name that does not parse is skipped. That skip is silent in a way the
`HIGHEST_IMPLEMENTED_FORK` gate is not: the cases never become tests, so they are
not counted as ignored either, and nothing in the output says they exist.

`gloas` does not take this silent path: `ForkName::parse("gloas")` succeeds, so
its cases become ordinary tests, individually named and run. `heze`, the one
fork after gloas, is still unparseable and would be silently skipped without
this section's own accounting.

So `UNMODELED_FORKS` names `heze` alone, it reports as one ignored test, and
`fixture_forks/every_directory_is_accounted_for` fails if the tree holds a fork
directory that is neither parseable nor listed. A release that adds a fork
forces a decision instead of quietly widening the gap.

| Suite | Covers |
|-------|--------|
| `bls` (`cryptography-specs`) | Cryptography, fork- and preset-independent |
| `kzg` (`cryptography-specs`) | Cryptography, fork- and preset-independent |
| `ssz_static` | Every fork's containers |
| `shuffling` | Committee helpers |
| `operations`, `epoch_processing` | Every fork's operation and epoch sub-function |
| `sanity/blocks`, `sanity/slots`, `finality`, `random`, `rewards` | Whole blocks and slots, end to end |
| `fork`, `transition` | Fork upgrades, standalone and mid-chain |
| `genesis` | Genesis initialization (minimal only, see above) |
| `fork_choice` | The `Store`; see below |

### Fork choice is fixture-verified

205 mainnet `fork_choice` cases pass, covering bellatrix's `on_merge_block`/
terminal-PoW validation, the `v1.7.0` proposer-boost dependent-root gate and
`get_proposer_head`'s proposer-equivocation branch, deneb's blob data
availability, fulu's column data availability, and gloas's payload-aware
suites: `get_head`, `get_parent_payload_status`, `on_block`, `on_attestation`,
`on_execution_payload_envelope`, `on_payload_attestation_message`,
`payload_data_availability`, `payload_timeliness` and `ex_ante`. Gloas
accounts for 54 of the 205.

The release still ships no phase0 `fork_choice` suite: the earliest is
altair's, built from altair-shaped states even though altair changes nothing
about fork choice itself (`Store` accepts a block from any fork this module
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
- Altair's participation fields, projected to altair's state, so every later
  fork that also carries participation failed.
- Deneb's `process_attestation`, projected to deneb's state.
- `slash_validator` calling phase0's `initiate_validator_exit` at electra,
  which also left electra's EIP-7251 churn cursor unadvanced, mispricing every
  later exit processed in the same epoch.

## Deliberate simplifications

- Light client containers and suites are out of scope.
- `ssz_generic` exercises the SSZ library rather than the beacon containers, so
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
