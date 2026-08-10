# Differential fuzzing against lighthouse

This crate differentially fuzzes `ethlambda-beacon` against
[sigp/lighthouse](https://github.com/sigp/lighthouse)'s consensus crates:
the same bytes are decoded and processed by both implementations, and a
target fails when they disagree. It is a normal `cargo-fuzz` crate, detached
from the repository's workspace (see "Why this crate is detached" below), so
it is built and run with `cargo fuzz`, not `cargo build`/`cargo test`.

## Feasibility

lighthouse's consensus crates (`types`, `state_processing`, and everything
they pull in) are not published to crates.io; sigp publishes only the
`lighthouse` binary itself, plus a handful of standalone libraries (`ssz`,
`tree_hash`, `superstruct`, `milhouse`) that used to live in the monorepo and
were later split out. `types` and `state_processing` were not among those, so
the only way to depend on them is a git dependency pointing at the
`sigp/lighthouse` repository directly, naming the package inside it:

```toml
types = { git = "https://github.com/sigp/lighthouse", tag = "v8.2.1", package = "types" }
state_processing = { git = "https://github.com/sigp/lighthouse", tag = "v8.2.1", package = "state_processing" }
```

### Why `v8.2.1`, and why a tag at all

Pinned to a tag rather than `main` so that a disagreement found today and one
found next month are compared against the same lighthouse behavior; `main`
moves, and a branch dependency would silently change what "disagreement"
means between runs without anyone noticing. `v8.2.1` is lighthouse's latest
non-prerelease tag as of when this was written (`git ls-remote --tags`,
newest by version, excluding `-rc.*`/`-beta.*`/`-exp` tags). Nothing about
the choice is more specific than "the newest stable tag available"; there is
no reason to prefer an older one, and every fork this repository implements
(phase0 through fulu) is long since stable in lighthouse's history at this
tag, which already carries support for `gloas`, a fork past even fulu.

### Whether it actually resolves and compiles

Both were verified directly, not assumed:

- `cargo fetch` against a scratch crate depending on just `types` and
  `state_processing` at this tag resolved cleanly (321 packages, all locked
  to versions compatible with this repository's pinned Rust 1.97.1), and
  `cargo build` on that scratch crate compiled both crates and linked a
  working binary. Neither crate is marked `publish = false`, but that only
  gates `cargo publish`; it has no bearing on git dependencies.
- lighthouse has no `rust-toolchain.toml` and its CI tests against "latest
  stable", not a pinned nightly. Its MSRV, read from `lighthouse`'s own
  `rust-version` field in `Cargo.toml` (what its `check-msrv` CI job actually
  checks against), is `1.88.0`, comfortably under this repository's `1.97.1`.
  Both repositories also target edition 2024. There is no toolchain conflict.
- `types`' and `state_processing`'s own `[dependencies]` need nothing exotic:
  the default `bls` backend is `blst` (the same crate `ethlambda-beacon`
  already depends on directly), so no portable-mode or alternate-backend
  feature is needed to build on this machine. Their `[dev-dependencies]`
  (`beacon_chain`, a large chunk of the rest of the monorepo) never get built
  here, since a git dependency's dev-dependencies are only compiled for that
  dependency's own tests, not by anything depending on it as a library.
- Running `cargo metadata` against this crate's actual `Cargo.toml` (not the
  scratch crate) confirms `types` and `state_processing` resolve from
  `git+https://github.com/sigp/lighthouse?tag=v8.2.1#b263df596671a2bd42bf1034e1cdc8188ba8a9b0`,
  and the most recent `cargo check --workspace --examples` from this
  directory compiled `ethlambda-beacon`, both lighthouse crates, and all
  three fuzz targets with zero errors (see "Current build status" below for
  the fuller, less settled story of getting there).

### Preset: a Cargo feature versus a type parameter

`ethlambda-beacon` selects a preset at compile time with the
`preset-minimal` feature, because its container bounds are compile-time SSZ
constants (`libssz_types::SszList<T, N>`'s `N`). lighthouse selects one with
a generic type parameter instead (`MainnetEthSpec` or `MinimalEthSpec`,
both implementing its `EthSpec` trait), because its bounds are `typenum`
constants; both types can live in the same binary at once, so lighthouse
never needed a feature to choose between them. There is nothing to enable on
lighthouse's side to match this crate's feature, only a type to name for a
given build. `src/lib.rs`'s `LhSpec` type alias is `cfg`-gated on the same
`preset-minimal` feature (forwarded to `ethlambda-beacon/preset-minimal` in
this crate's own `Cargo.toml`), so exactly one preset pair is ever compiled
into a given fuzz binary, and `SLOTS_PER_EPOCH` was checked to actually agree
between the two implementations, on both presets, rather than assumed.

### Fork selection: `ChainSpec` versus `Config`

Both crates schedule forks at runtime rather than compile time (this
repository's own `crates/beacon/src/config.rs` explains why: the `transition`
fixture suite needs to move a fork's activation epoch per test case).
lighthouse's `ForkName::make_genesis_spec` builds a `ChainSpec` where a named
fork (and everything before it) is active from genesis and everything after
it is unscheduled, the same shape `Config::with_fork_epoch` produces starting
from `Config::minimal()`. Two things worth knowing before touching either:

- lighthouse names phase0 `ForkName::Base`, not `Phase0`; every later fork
  shares its name with this crate's `ForkName`. `to_lighthouse_fork` in
  `src/lib.rs` is the explicit mapping.
- `Config::mainnet()` is *not* "every fork unscheduled": it carries the real
  historical mainnet fork schedule (altair at its real activation epoch, and
  so on), while `Config::minimal()` defaults every fork after phase0 to
  unscheduled, since `minimal` is a fixture base rather than a network. Since
  the only fork these targets exercise today is phase0 (see
  `IMPLEMENTED_FORKS` below), and phase0 is active from genesis in both
  configurations either way, `lighthouse_spec()` and `our_config()` in
  `src/lib.rs` use `ChainSpec::mainnet()`/`ChainSpec::minimal()` and
  `Config::mainnet()`/`Config::minimal()` unmodified, the same way this
  repository's own `crates/beacon/tests/spec/sanity.rs` runs its fixtures
  against `Config::active()` with no override. A fork added to
  `IMPLEMENTED_FORKS` later whose *real* mainnet activation epoch a
  fixture-sized state could actually reach (altair's cannot: its mainnet
  `altair_fork_epoch` is far beyond anything a fixture or a fuzz-mutated
  state's slot could plausibly represent) would need
  `make_genesis_spec`/`with_fork_epoch` instead.

### Feasibility verdict

Feasible, and not just in principle: as of the most recent check (see
"Current build status" below), this crate, `ethlambda-beacon`, and both
lighthouse crates all compile together, all three fuzz targets included.
Getting there needed one addition this task did not anticipate, covered next
("A wrinkle this task did not anticipate"), but nothing encountered here was
an irreconcilable conflict.

## Why this crate is detached

`crates/beacon/fuzz/Cargo.toml` declares its own empty `[workspace]` table,
which makes Cargo treat it as its own workspace root regardless of where it
sits in the directory tree, rather than being swept into the repository
root's workspace. This is the ordinary arrangement for a `cargo-fuzz` crate
(`libfuzzer-sys` and a large git dependency have no business in the main
workspace's `Cargo.lock`), and it was the only option available here besides:
the root `Cargo.toml`'s `exclude` list would work too, but editing the root
`Cargo.toml` was off limits for this task, since other agents are actively
changing `crates/beacon/src` at the same time.

This was checked, not assumed: `cargo metadata` run from this directory
reports its own `workspace_root` as `crates/beacon/fuzz` with exactly one
workspace member (`ethlambda-beacon-fuzz`), and building or checking it never
touches the root `Cargo.lock` or `Cargo.toml` (verified by hashing both
before and after). One consequence of detachment worth knowing: this crate
does not inherit the root workspace's `[patch]` section, which is exactly
what the next section is about.

## A wrinkle this task did not anticipate

`ethlambda-beacon` needs mutable `SszList`/`SszVector` access
(`DerefMut`/`IndexMut`) that the published `libssz-types` 0.2.2 does not
provide; the repository root's `Cargo.toml` currently carries a local,
explicitly `DO NOT COMMIT`, machine-specific `[patch.crates-io]` override
pointing at a local `libssz` checkout to work around this until a fixed
version is released. A `[patch]` section applies only within the workspace
that declares it. Since this crate is deliberately its own workspace (see
above), it does not inherit that patch, and **`ethlambda-beacon` will not
compile from this crate at all without adding the same override here**,
independently of anything to do with lighthouse or the fuzz targets
themselves. This was confirmed directly: `cargo check --workspace` from this
directory against a plain crates.io `libssz-types` fails with thirteen
`DerefMut`/`IndexMut`-not-implemented errors scattered across
`ethlambda-beacon`'s own source, none of them related to fuzzing.

This is not this crate's problem to fix (the fix is a released `libssz-types`,
tracked wherever the root override's removal is tracked), but it is a real,
if temporary, cost of the detachment this task asked for: a workspace-level
fix does not automatically reach a deliberately-detached crate, so the two
copies have to be kept in sync by hand until the real fix lands. To build
this crate locally today, add the same block (adjusted to wherever your own
`libssz` checkout lives) to this crate's `Cargo.toml`:

```toml
[patch.crates-io]
libssz = { path = "/path/to/libssz/crates/ssz" }
libssz-derive = { path = "/path/to/libssz/crates/ssz-derive" }
libssz-merkle = { path = "/path/to/libssz/crates/ssz-merkle" }
libssz-types = { path = "/path/to/libssz/crates/ssz-types" }
```

It is not checked in here, for the same reason the root's copy is not: it
names an absolute path that only exists on one machine.

## Current build status

`crates/beacon/src` was being edited concurrently by other agents for the
entire time this crate was written, so "does it build" was not a single
fact to check once; it was checked repeatedly, and the answer changed each
time for reasons that had nothing to do with this crate. In order:

- **Verified**: the lighthouse git dependency resolves and its crates
  actually compile, both in isolation (a scratch crate depending on nothing
  else) and as part of this crate's own dependency graph.
- **Verified**: this crate's `Cargo.toml` is well formed and properly
  detached from the workspace (`cargo metadata`, hashes on the root
  `Cargo.lock`/`Cargo.toml` before and after).
- An early check (with the local libssz patch above added) found
  `epoch_processing` and `ssz_roundtrip` compiling cleanly, and
  `state_transition` failing with exactly one error, `E0308`, on the line
  calling `stf::state_transition(&mut our_state, &our_block, true,
  &our_config)`: the function still expected
  `&containers::phase0::SignedBeaconBlock`, and this target passes
  `&containers::SignedBeaconBlock`, the enum this task described as landing.
  `containers::SignedBeaconBlock` itself, with `from_ssz`, `to_ssz`, and
  `fork_name`, had already landed by that point; only
  `stf::state_transition`'s own parameter type had not caught up yet.
- A check minutes later found `ethlambda-beacon` itself failing to compile
  for unrelated reasons (a call site out of step with `process_operations`'
  signature, a missing `hash_tree_root` trait import), evidence of the
  refactor moving underneath rather than a defect in this crate.
- **The most recent check, `cargo check --workspace --examples` with the
  local libssz patch added, finished clean: zero errors.** All three
  `[[bin]]` targets and the `seed_corpus` example compiled, including
  `state_transition`; `stf::state_transition` had by then been updated to
  take `&containers::SignedBeaconBlock`, matching this target exactly.
  `ethlambda-beacon` itself built with a handful of unrelated warnings
  (unused imports and dead code in `upgrade.rs`, left over from in-progress
  work there), no errors.
- **Not attempted**: a `cargo fuzz build`/`cargo fuzz run` under `cargo-fuzz`
  itself. `cargo-fuzz` is not installed in this environment (a nightly Rust
  toolchain is, which it also needs); nothing here required installing it,
  since dependency resolution and compilation can both be checked with plain
  `cargo check`/`cargo metadata` against the `[[bin]]` targets directly.
  `cargo install cargo-fuzz` followed by the run commands below is the
  remaining step to exercise the sanitizer-instrumented build this crate is
  meant for, and, on the evidence above, there is a good chance it already
  works; re-run `cargo check` first if it does not, since the surrounding
  crate has kept moving.

None of this means the crate is guaranteed to build at any *particular*
moment someone reads this. It means the specific gap this task asked about
(the block enum) has closed, and the only remaining reason a build might
fail today is the local libssz patch above, or whatever
`crates/beacon/src` happens to look like when you check.

## Running the targets

```sh
cargo install cargo-fuzz   # once

# mainnet (the default preset)
cargo fuzz run ssz_roundtrip corpus/ssz_roundtrip/mainnet      # cheapest; see below
cargo fuzz run epoch_processing corpus/epoch_processing/mainnet
cargo fuzz run state_transition corpus/state_transition/mainnet

# minimal
cargo fuzz run ssz_roundtrip --features preset-minimal corpus/ssz_roundtrip/minimal
```

The trailing path is the corpus directory to seed and grow from; without it,
`cargo fuzz run` defaults to `corpus/<target>` directly, which after
`seed_corpus.sh` holds a `mainnet` and a `minimal` subdirectory rather than
files, so it needs to be named explicitly. Add `--features preset-minimal`
to compare the `minimal` preset instead of the default `mainnet` one, and
match it with the `minimal` corpus subdirectory; never point a `minimal`
build at the `mainnet` corpus or the reverse (see "Known false-positive
shapes" below for why that pairing matters, not just which preset you meant
to run).

### Which target to run first

`ssz_roundtrip` touches only SSZ decode, `hash_tree_root`, and re-encode: no
signature verification, no committee computation, no reward arithmetic. It
is the cheapest target to execute per input, which means libFuzzer gets more
executions per second out of it, and it covers the one layer every other
target also depends on, so a bug here would otherwise show up confusingly in
both of the others at once. Run it on its own first; a clean run of it is
what makes the other two targets' results trustworthy rather than suspect.

## Corpus

Random bytes almost never decode as a valid SSZ container, let alone one
whose fields describe a state a block can actually apply to, so an unseeded
run of any of these targets tests close to nothing: libFuzzer would spend
almost all of its time on inputs that die at the first `from_ssz` call.
Seed the corpus from the real fixtures instead:

```sh
./seed_corpus.sh                    # seeds all three targets' corpora
./seed_corpus.sh ssz_roundtrip       # seeds just one
```

This wraps `cargo run --example seed_corpus --release`, a plain Rust program
(no `cargo-fuzz` or nightly toolchain needed to run it), which walks
`consensus-spec-tests/tests/<mainnet,minimal>/phase0/sanity/blocks/*/*/` (the
same fixture tree `crates/beacon/tests/spec/sanity.rs` runs against; requires
`make consensus-spec-tests` to have been run from the repository root first)
and writes `corpus/<target>/<preset>/<case>` files: one subdirectory per
preset, never mixed, matching "Running the targets" above.

### Byte layout

Each fixture's `pre.ssz_snappy` and `blocks_0.ssz_snappy` are raw-snappy
compressed; the seeding script decompresses both once, up front, rather than
writing the compressed bytes into the corpus. A single mutated bit in a
snappy stream almost always just fails decompression rather than reaching
the decode logic either implementation actually needs exercised, so seeding
with compressed bytes would waste the same time an unseeded run wastes, just
one layer further in.

What each target's corpus entries actually contain (see `src/lib.rs`'s
`split_one`/`split_two` for the reading side, and `examples/seed_corpus.rs`'s
`frame_one`/`frame_two` for the writing side):

- `epoch_processing`, `ssz_roundtrip`: `[fork: 1 byte][state: remaining bytes]`.
- `state_transition`: `[fork: 1 byte][state length: 4 bytes, little-endian][state: that many bytes][block: remaining bytes]`.

The fork byte is taken modulo the length of `ForkName::ALL`, every fork this
repository implements at all, not modulo the length of `IMPLEMENTED_FORKS`,
the (much shorter, today just phase0) list this comparison can actually run.
A mutator is free to walk that byte through every value; each target checks
`IMPLEMENTED_FORKS` itself and discards anything outside it before either
implementation sees the input, which is why growing `IMPLEMENTED_FORKS` (as
`ethlambda_beacon` grows a state transition for more forks) needs no change
anywhere else, corpus included.

## What a disagreement means

Each target discards an input where either implementation fails to *decode*
it (for `state_transition` and `epoch_processing`; `ssz_roundtrip` treats a
decode disagreement as itself the finding, see its own doc comment for why)
and where both implementations reject a well-formed input for whatever
reason. A test failure means one of:

- **`state_transition`**: one implementation accepted the block and the
  other rejected it, or both accepted it and their post-states'
  `hash_tree_root`s differ.
- **`epoch_processing`**: one implementation's epoch transition succeeded and
  the other's failed, or both succeeded and the resulting `hash_tree_root`s
  differ.
- **`ssz_roundtrip`**: one implementation decoded the input as a valid state
  and the other did not, or both decoded it but computed different
  `hash_tree_root`s, or both agree on the root but re-encode it to different
  bytes.

In every case, *disagreement on the reason* is designed out, not a finding:
the two crates do not share an error type, and nothing here compares error
messages or variants, only the accept/reject boolean and, when both accept,
the resulting root or bytes.

### Known false-positive shapes

- **Differing rejection reasons.** Already excluded by construction (see
  above); mentioned here because it is the single most common way a
  differential fuzzer against two independently-written implementations
  produces noise, and it is worth remembering while reading a target's source
  rather than only when reading its output.
- **Differing preset.** A `mainnet`-built binary fed a `minimal`-shaped
  corpus entry (or the reverse) will almost always just fail to decode on
  both sides and get discarded, not reported; the risk worth designing
  against is the opposite direction, a `mainnet`-sized input coincidentally
  also satisfying `minimal`'s smaller container bounds well enough to decode
  as *something*, at which point the two implementations are no longer even
  answering the same question. `seed_corpus.sh` writes each preset's cases
  into its own `corpus/<target>/<preset>/` subdirectory for exactly this
  reason (see `write_seed`'s doc comment in `examples/seed_corpus.rs`); do
  not manually copy files, saved crash artifacts included, from one preset's
  subdirectory into a run built for the other.
- **Differing fork schedule.** Covered under "Fork selection" above:
  `Config::mainnet()` carries the real fork history while
  `Config::minimal()` does not, and getting that backwards for a fork this
  crate does not yet implement would make a fixture-sized state cross a fork
  boundary on one side of the comparison and not the other. Not reachable
  today, since `IMPLEMENTED_FORKS` is only phase0, but the exact thing to
  re-check when extending it.
- **The libssz-types patch.** Not a fuzzing false positive as such, but a
  build-time trap: forgetting to add the local patch (see above) makes
  `ethlambda-beacon` itself fail to compile, in a way that has nothing to do
  with these targets and can look like this crate is broken when it is not.
