# Property Testing (ephyra)

ethlambda checks some of its code against reference models with
[ephyra](https://github.com/datadog-labs/ephyra), a property-based testing
library from Datadog. A property states what must hold for every input; ephyra
generates inputs, and when one breaks the property it shrinks it to a minimal
counterexample and prints a line that replays exactly that case.

ephyra is a workspace dev-dependency (`ephyra = "0.0.1"`), so the properties
are ordinary tests: `make test` and `cargo test` run them with a default budget
of 10,000 passing inputs each, unless a property sets its own.

`ssz-tree` and `storage` also have older proptest suites
(`crates/common/ssz-tree/tests/model.rs`, `beacon_state_delta.rs`,
`proto_array.rs`). New properties use ephyra.

## What is covered

| Property file | Code under test | Oracle |
|---|---|---|
| `crates/net/p2p/src/req_resp/encoding_properties.rs` | req/resp length prefix (`encode_varint`/`decode_varint`) and snappy framing (`write_payload`/`decode_payload`) | round trip; a protobuf varint model in `u128`; on corrupted streams, no panic and nothing accepted beyond its declared length or `MAX_PAYLOAD_SIZE` |
| `crates/blockchain/state_transition/tests/justification_properties.rs` | `slot_is_justifiable_after`, `justified_slots_ops` | leanSpec's `Slot.is_justifiable_after` rule for rule; the relative-indexed bitlist against a set of absolute slots over random extend / justify / finalize sequences |
| `crates/common/types/tests/u256_properties.rs` | beacon `U256`'s hand-written `Ord`, decimal `Display`/`from_dec_str`, JSON | the value as two `u128` halves; `u128`'s own formatting where the value fits |

The p2p properties live inside the crate (`#[cfg(test)]` module) because the
codec is `pub(crate)`. The others are integration tests over public APIs.

## Running

```bash
# One file, the default budget.
cargo test --profile release-fast -p ethlambda-p2p --lib encoding_properties
cargo test --profile release-fast -p ethlambda-state-transition --test justification_properties
cargo test --profile release-fast -p ethlambda-types --test u256_properties
```

Every setting can be changed from the environment, without touching the code:

| Variable | Effect |
|---|---|
| `EPHYRA_BUDGET_MS=60000` | stop each property after a minute |
| `EPHYRA_TESTS=N` | require N passing inputs (overrides `tests = ...` in the attribute) |
| `EPHYRA_SEED=N` | a different, reproducible search |
| `EPHYRA_FAILURES=N` | keep going until N distinct failures instead of stopping at the first |
| `EPHYRA_REPLAY=seed:iteration` | rerun the one input a failure report printed |
| `EPHYRA_REGRESSIONS=0` | don't replay or record remembered failures |

A longer hunt is the default run with a time budget and a few seeds:

```bash
for seed in 1 2 3; do
  EPHYRA_SEED=$seed EPHYRA_BUDGET_MS=60000 EPHYRA_TESTS=100000000 EPHYRA_FAILURES=5 \
    cargo test --profile release-fast -p ethlambda-state-transition --test justification_properties
done
```

`release-fast` keeps `overflow-checks` off (it matches `release`), so an
arithmetic overflow wraps instead of panicking. For code without leanVM
signature work on the path, a `--profile dev` run turns them on and can surface
an overflow as a panic first.

## Reading a failure

```text
ephyra: FAILED, property panicked: assertion `left == right` failed: varint [80, 80, 80, 80, 10] read as 0
  counterexample: [128, 128, 128, 128, 16]
  original:       [161, 196, 128, 198, 163, 127, 160, 189, 228] (size 3, iteration 8)
  reproduce: EPHYRA_REPLAY=887486680178929998:8
  remembered in .ephyra/regressions/req_resp_encoding_properties_a_varint_is_refused_or_read_as_the_value_it_encodes.jsonl
```

The failure is saved under the crate's `.ephyra/regressions/` and replayed
first on every later run, so it keeps failing until fixed. Those files are
committed, the way proptest's `*.proptest-regressions` are; everything else in
`.ephyra/` is ignored. Delete the entry once the bug is fixed and a plain
`#[test]` pins the counterexample.

## Writing a property

- **Take the expected behaviour from the spec, not from the code.** A model is
  worth having only if it is written independently: leanSpec, the
  consensus-specs, the protobuf varint definition. Name the source in the
  property's doc comment.
- **Generate valid inputs by construction**, and bias them toward the
  boundaries where bugs sit (varint widths, the 128-bit halves of a `U256`,
  squares and pronics one off). `gens::frequency` mixes a uniform draw with the
  edges.
- **For state, generate sequences of steps** and check the model after every
  step, as `the_justified_window_matches_a_set_of_absolute_slots` does.
- **Keep shrinking intact**: `gens::vec`, `gens::int`, tuples, `dependent` and
  `#[derive(ephyra::Arbitrary)]` shrink; a bare closure generator and `.map`
  do not shrink what they produce.
- **Give each check its own `assert!`**: ephyra tells failures apart by the
  line that panicked.
- **When a property fails**, replay it, put the counterexample in a plain
  `#[test]` that fails on the unmodified code, and only then fix. If the
  failure is real but out of reach (a distance no chain can reach, say),
  exclude exactly that range with a comment saying what was found and why it
  doesn't matter; don't weaken the property otherwise.

The ephyra docs written for this workflow are its
[STARTUP.md](https://github.com/datadog-labs/ephyra/blob/main/STARTUP.md) and
[API.md](https://github.com/datadog-labs/ephyra/blob/main/API.md).

## Findings

| Found by | What | Status |
|---|---|---|
| `a_varint_is_refused_or_read_as_the_value_it_encodes` | `decode_varint` dropped the bits of a 5-byte length prefix above bit 31: `80 80 80 80 10` declares 2^32 bytes and `decode_payload` read it as an empty payload, so a prefix over `MAX_PAYLOAD_SIZE` passed the size check. Pinned by `a_length_prefix_wider_than_u32_is_refused` in `encoding.rs`. | fixed: `decode_varint` accumulates in a `u64`, reads at most 5 bytes and refuses a value past `u32::MAX` |
| `justifiability_matches_the_spec` | Above `delta = u64::MAX / 4`, `slot_is_justifiable_after`'s pronic test overflows and answers false where leanSpec says true. 2^62 slots past finalization, unreachable. | excluded (`REACHABLE_DELTA`) |
