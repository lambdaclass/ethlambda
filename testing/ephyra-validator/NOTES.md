# Ephyra validator testing notes

Target revision: `92a11a46858d681daa6a7a997eb166ac476ea89b`.

## Properties and sources

1. **Model safety:** a signature accepted for a key must not conflict with any previously accepted or imported signature for that key. Conflict means distinct blocks in one slot, distinct attestations at one target, or a strict surround in either direction. Source: [consensus validator slashing rules](https://ethereum.github.io/consensus-specs/specs/phase0/validator/), `slashing_protection/mod.rs` module docs and existing rule tests. A refusal of a model-safe signature is counted, not failed, as permitted by [EIP-3076's minimal strategy](https://eips.ethereum.org/EIPS/eip-3076).
2. **Persistence:** reopening a file-backed record must preserve every refusal. Source: `SlashingProtection::open` and `check_and_record_*` docs; existing `a_reopened_record_remembers_what_was_signed` test.
3. **Round trip:** export followed by import into an empty record must preserve every refusal for exported keys. Source: EIP-3076 conditions and `SlashingProtection::export` / `import` docs; existing export tests.
4. **Untrusted interchange:** `stage` and `import` must not panic on arbitrary text; a rejected import must leave the record unchanged. Source: `stage` / `import` docs and existing malformed interchange tests.
5. **Fail closed:** when a durable write fails, nothing is signed. Source: module's order of operations, `commit` docs and existing `a_failed_write_refuses_and_changes_nothing` test. This is run only if write failure can be injected without changing the target.

The EIP-3076 vector test is `crates/validator/tests/interchange_vectors.rs`; it uses the minimal-strategy `should_succeed` expectation.

## `chain_check` pivot properties and sources

After two slashing-protection rounds with no new failure and flat coverage, the pivot tests derive these claims from `crates/validator/src/chain_check.rs` module and function docs, checked against its existing tests before writing generators:

1. **Ordered merge:** when `current` and every node schedule have fork epochs in order, `merge_schedule` keeps its output in order. It must not move a fork already active under `current`, and it must not unschedule a fork `current` already scheduled. Source: `forks_in_order` and `merge_schedule` docs, especially the whole-result order check.
2. **Response order:** for compatible reports with identical duty offsets, permuting the nodes cannot change the merged configuration or change descriptions. The docs say node answer order does not alter list order; differing duty offsets are intentionally read from the first listed node, so this property holds their offsets equal. Source: `merge_schedule` and `Served` docs.
3. **Chain boundary:** differences in forks that are future under both schedules are compatible; when a fork has become active under either schedule, its epoch and version must match. Source: `first_chain_difference` docs and its future/active tests.
4. **Follow result:** `follow_schedule` returns `None` exactly when `merge_schedule` leaves the configuration unchanged; otherwise it returns the merged configuration. Source: `follow_schedule` docs.

## Focused continuation

After the original two flat rounds, a requested follow-up targeted two gaps:

1. **Malformed durable records:** after a block is durably recorded, each of ten corruptions (invalid UTF-8, empty or truncated bytes, wrong version, duplicate key, unknown or missing field, impossible vote, invalid pubkey, overflowing slot) must make each of `open`, `open_locked`, and `open_offline` fail without rewriting the corrupt bytes. Restoring the original bytes must restore the recorded refusal and permit a later block. Source: `slashing_protection/file.rs` “Reading fails closed” docs and the three opening methods' docs. The 10 × 3 matrix is also run exhaustively at slot 5 before the generated cases. A missing directory must make `lock` and `open` fail without creating it.
2. **Different duty offsets:** when nodes serve different offsets, all ten merged offsets must come from the first listed node, even if that node has no say in the forks. Reordering reports may change those offsets, but must leave every other configuration field and the number of fork disagreements unchanged; `follow_schedule` must return that merge. Source: `Served` and `merge_schedule` docs, plus the existing `the_duty_offsets_follow_the_first_node` test. Node positions retain their say when reordered.

## Remaining-gap continuation

The next request was to cover the three gaps named after the focused continuation:

1. **Unordered current schedule:** when the client's Fulu epoch is after its Gloas epoch but a node with a say serves an ordered future pair, the merge must adopt that ordered pair rather than freeze the bad current schedule. Source: `merge_schedule`'s whole-result order check and its comment that an initially unordered schedule must not freeze every fork. Generated cases vary both epoch pairs and versions.
2. **Response-time fork boundary:** with a local Beacon API server that delays `spec`, a fork reported before its epoch must be adopted, while the same fork reported at its epoch must be refused. The epoch changes only as the server sends the delayed response, exposing an implementation that reads the epoch before the answer. Source: `check_once` docs and the existing `the_epoch_is_read_once_the_node_has_answered` test.
3. **Fast answer beside a slow node:** a fast node that was the only one with a say at startup can schedule a future fork before a slow node's answer moves the epoch across the boundary. The final schedule must retain that fork. Source: `check_once` docs and the existing `a_hung_node_does_not_hold_back_another_nodes_answer` test. The generated cases vary both delays and the fork version.
4. **Post-rename directory-flush failure:** a macOS-only, test-owned dynamic library makes both directory `F_FULLFSYNC` and fallback `fsync` fail after a marker is enabled, while file flush and rename still succeed. For both block and attestation writes, the API must return `Error::Unflushed`, refuse signing, advance its in-memory watermark to match the renamed file, and preserve the refusal across reopen. Source: `slashing_protection/file.rs` durable-write docs, `secure_fs::sync_directory`, and `SlashingProtection::commit` / `check_and_record_*` docs. The injector is built and loaded in a child test process; no target code was changed.

## Runs and coverage

Tested revision: `92a11a46858d681daa6a7a997eb166ac476ea89b`; ephyra is pinned to crates.io `=0.0.1` in this crate's own lockfile. The checkout requests Rust 1.97.1, which was unavailable locally, so commands used installed stable Rust 1.99.1. All coverage builds used `-C instrument-coverage`, `RUST_TEST_THREADS=1`, and the module-specific `EPHYRA_COVERAGE_FILTER`.

| Property | Ephyra cases | Highest filtered coverage |
| --- | ---: | --- |
| Model safety | 2,460 traces | 64/84 functions, 116/173 counters in `slashing_protection` |
| Persistence | 2,160 traces | 67/84 functions, 121/173 counters |
| Export/import round trip | 2,160 traces | 67/84 functions, 121/173 counters |
| Untrusted interchange | 2,560 texts | 50/84 functions, 75/173 counters |
| Fail closed before rename | 13 measured invocations; 26 injected failing writes, plus two full-suite reruns | Plain test; outside Ephyra's per-property coverage |
| Malformed durable record | 1,100 generated cases plus 120 exhaustive matrix checks | 39/84 functions, 68/173 counters in `slashing_protection` |
| Fail closed after rename | 2 successful child invocations; 4 injected failing directory flushes | Plain macOS test; outside Ephyra's per-property coverage |
| Ordered schedule merge | 5,100 cases | 23/27 functions, 46/71 counters in `chain_check` |
| Response-order independence | 5,100 cases | 23/27 functions, 46/71 counters |
| Future/active chain difference | 5,100 cases | 4/27 functions, 16/71 counters |
| `follow_schedule` result | 5,100 cases | 24/27 functions, 49/71 counters |
| Different duty offsets | 3,600 cases | 24/27 functions, 48/71 counters in `chain_check` |
| Repair unordered current schedule | 2,000 cases | 12/27 functions, 24/71 counters in `chain_check` |
| Delayed answer at fork boundary | 320 cases | 19/37 functions, 47/87 counters in `chain_check` |
| Fast answer beside slow node | 320 cases | 19/37 functions, 44/87 counters in `chain_check` |

Slashing counts include a 20-case smoke run, a 100-case expanded run, four 200-case rounds (seeds 41701–41704), a 20-case and 200-case run after making the round-trip oracle independent of `export`, a 20-case run after adding direct combined `absorb`, and four final 200-case rounds (seeds 41710–41713). Model safety alone had one extra 100-case generator round. The final model-safety property also verifies documented `register`, `import`, and `absorb` counts and that accepted registrations exist. The last two final 200-case rounds had no new failures or coverage growth. The text generator's maximum was 50/84 functions and 75/173 counters; its last two rounds did not exceed that. Chain counts include a 100-case baseline and four 1,000-case rounds (seeds 61102–61105). After the warning-mode check raised `follow_schedule` coverage by one counter, its last two rounds were flat. Thus the original suite stopped before the three-hour limit.

The focused continuation ran durable-record seeds 71201 (100), 71203 (200), and 71204 (200), then 300 more cases in each of two full isolated-crate runs. The 30-case exhaustive matrix ran with each of the latter four invocations. The two final seeded rounds were flat at 39/84 functions and 68/173 counters, with no failure. Differing-offset seeds 71202 (100) and 71205–71209 (500 each) were followed by 500 more cases in each full run. The last two rounds after strengthening the whole-config assertion were flat at 24/27 functions and 48/71 counters, with no failure.

The remaining-gap continuation ran unordered seeds 91301, 91304 and 91305 at 500 cases each, plus 500 in the final full suite. The last two seeded rounds were flat at 12/27 functions and 24/71 counters. Delayed-boundary seed 91302 ran 20 cases, seeds 91306 and 91307 ran 100 each, and the final suite ran 100; the last two seeded rounds were flat at 19/37 functions and 47/87 counters. Fast/slow seed 91303 ran 20 cases, seeds 91308 and 91309 ran 100 each, and the final suite ran 100; the last two successful seeded rounds were flat at 19/37 functions and 44/87 counters. The different function/counter denominators for `check_once` reflect its generic code instantiated with `HttpBeaconNode` in the timing test binary. All reported rounds passed. The final isolated-crate suite passed 7 chain, 3 timing, and 10 slashing tests; Ephyra's CLI-only generator tests were ignored there. `ephyra check` passed all eight generators over 10,000 cases each, and their shrinkers passed the integration checks. The durable generator's 360 distinct inputs exactly match its finite 12 slots × 10 corruptions × 3 openers.

The focused tests reached `file::read`'s pre-parse I/O error through invalid UTF-8; the plain missing-directory test reached `file::lock`'s directory-open I/O error. The macOS injector reached the post-rename `Error::Unflushed` path for both signing methods, outside Ephyra's per-property grid. Ephyra's filtered grids still leave the export serialization error mapping, other rare write-error mappings, and generated tracing/Serde callbacks unreached in the generated properties. The unordered-current branch and `check_once` response-timing paths are now exercised. The individual chain grids still omit target functions that a particular property does not call; their totals are not a combined module coverage figure.

The validator library suite passed 804 tests (2 ignored) during the original work. After downloading the project's pinned v5.3.0 interchange archive and verifying its SHA-256 from `Makefile`, the disabled EIP-3076 vector test passed all 38 fixture cases. Neither validator code nor existing tests changed in the continuations, so the validator suite was not rerun.

## Over-refusal counts

These count only generated attempts by registered keys with valid message shapes that the consensus-rule model deemed safe, but the record refused. Unregistered keys and impossible source/target pairs are excluded. A byte-identical re-sign or an out-of-order but non-slashable message can be in this count; EIP-3076's minimal strategy permits it.

| Final-generator 200-case seed | Blocks | Attestations |
| --- | ---: | ---: |
| 41710 | 113 | 176 |
| 41711 | 116 | 190 |
| 41712 | 126 | 175 |
| 41713 | 103 | 184 |
| **Total, final 800 cases** | **458** | **725** |

Across the original 2,060 measured model-safety cases, including earlier generator versions, the counts were 1,057 block and 1,904 attestation over-refusals. Two later full-suite reruns added 400 safety traces, but their per-run counters were captured by the test harness and are not included in those totals. The final 800 seeded cases accepted 1,067 block and 1,284 attestation attempts. These are attempt counts, including each key in a batch, not unique messages.

## Failures and verdicts

No validator property failed in any round; there is no generated counterexample to shrink or retain as a plain failing regression test. Review found a **test bug** in an early round-trip oracle: it probed the original through its own export, which could have hidden a faulty export. The final oracle adds bounds parsed independently from the durable record, and its reruns passed. The permission-based failure injector worked on this host: both block and attestation writes returned outer errors, the file-backed export stayed unchanged, and both operations succeeded after permissions were restored.

Three continuation setup failures had **test bug** verdicts, not target-code verdicts: the first C injector crashed its child before a test ran because its libc forwarding recursed; the injector now forwards unrelated calls through direct system calls, and the plain `post_rename_directory_flush_failure` test passes. The local Beacon API server once panicked on an accepted socket returning `WouldBlock`; it now switches accepted sockets to blocking mode and tolerates cancelled connections, and seed 91309 passed on rerun. Ephyra's CLI initially found that two integration files both named a predicate `valid_case`; the timing predicate and generator now have unique names, and all eight CLI generator checks pass. None of these setup failures had a generated target input to shrink.

## Reproduction and next tests

From `testing/ephyra-validator/`, set `RUSTUP_TOOLCHAIN=stable RUST_TEST_THREADS=1` and run `cargo test --tests` for the complete isolated suite. Run `cargo test --test properties post_rename_directory_flush_failure -- --nocapture` for the plain macOS injector, or `cargo test --test check_once_timing -- --nocapture` with `EPHYRA_COVERAGE_FILTER=ethlambda_validator::chain_check` for the timing cases. `EPHYRA_SEED` selects the seeds above; `EPHYRA_TESTS` sets each property's case count. `./.tools/bin/ephyra check` was used for the final generator check; `.tools/` is ignored and can be reinstalled with `cargo install ephyra-cli --version '=0.0.1' --locked --root .tools`.

All three gaps named before this continuation were exercised. A future test could replay interrupted writes across an actual crash-capable filesystem and process restart; the current injector verifies the API's handling of a failed directory flush within a live process. The export serialization error mapping appears unreachable with the current bounded record types, while remaining tracing callbacks have no separate safety assertion.
