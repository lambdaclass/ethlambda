# Review guide: in-process ethrex, scoped down

What to look at, what to be suspicious of, and what is still unfinished.

**Branch:** `feat/ethrex-inprocess` — one commit (`134dcb4`) off `origin/main` (`b4a8f78`).
**Not pushed yet.** Nothing is force-pushed and PR #530 is untouched pending your call (§7).

---

## 1. What this is

Run the execution layer **in-process**: ethrex linked in as a library, driven by
direct function calls. One binary, no Engine API, no JSON-RPC, no JWT.

Per your scoping call, all out-of-process machinery was removed. That work still
exists as PR #367, so nothing is lost — this branch simply stops overlapping it.

| | Previous PR #530 | This branch |
|---|---|---|
| Commits | 12 (3 merges of main, plus #367 absorbed) | **1**, off current main |
| Files changed | ~80 | **43** |
| Engine-API code | ~790 lines (JWT, JSON-RPC client, wire test) | **0** |
| EL interface | `ExecutionEngine` trait, Engine-API methods, `PayloadId`, payload cache, wire types | **3 direct methods** |
| CLI | `--execution-mode` + 3 external flags | **`--el-genesis`** |

Diff: 43 files, +3444 / −779.

## 2. Suggested reading order

Reviewing in this order means each file makes sense before you reach its callers.

1. `crates/net/ethrex-engine/src/lib.rs` — **the whole EL surface**, three methods.
   Read this first; everything else is wiring.
2. `crates/net/ethrex-engine/src/conversion.rs` — the payload ⇄ block mapping. The
   only genuinely fiddly code; check the field table in the guide against it.
3. `crates/blockchain/src/el_integration.rs` — the four actor hooks and the
   never-stall-consensus policy.
4. `crates/blockchain/src/lib.rs` — where those hooks attach to the tick loop
   (interval 0 head update, interval 4 build, gossip import).
5. `bin/ethlambda/src/main.rs` — engine construction and the **genesis seeding**
   (§4, decision 3).
6. `crates/blockchain/state_transition/src/execution_payload.rs` and the type
   changes — the consensus-side schema (§5).
7. Everything else is test literals, docs and tooling.

## 3. The claim most worth challenging

**Some code that arrived via #367 stays, and it is not Engine-API code.**

| Kept | Why it is required in-process |
|---|---|
| `ExecutionPayloadV3` in `BlockBody` | The proposer embeds the payload so **peers execute it in their own embedded EL**. Without it, no peer can replicate execution. |
| `process_execution_payload` (STF) | Validates the payload's parent hash and slot timestamp on import. |
| `latest_execution_payload_header` in `State` / `StateDiff` | Reconstructed states must keep the EL block-hash chain, or the parent-hash check breaks after a diff replay. |
| `State::from_genesis_with_el_hash` | Seeds the consensus genesis with the EL genesis hash. |

If you disagree that these belong here, that is the conversation to have — it is
the one place where "only in-process changes" is a judgement call rather than a
mechanical deletion.

## 4. Decisions to scrutinise

Each is reversible; the cost of reversing is noted.

**1. Direct API instead of the `ExecutionEngine` trait.** (your D1=B)
`build_payload` / `execute_payload` / `set_head`. This deleted `PayloadId`, the
`Mutex<HashMap<[u8;8], _>>` payload cache, and the build-then-fetch two-step —
all artefacts of the Engine API being stateless and networked.
*Reversing:* reintroduce the trait, which #367 already contains.

**2. No fee-recipient configuration.** ← *the one I am least sure about*
#367 read `suggested_fee_recipient` from `validator-config.yaml`; main has no such
plumbing. Rather than re-add config parsing for something the integration does not
need, the EL is handed the zero address with a comment. Lean has no fee market or
block rewards, so nothing is being directed anywhere.
*Reversing:* ~20 lines — a config field, a hex parser, and one more `BlockChainConfig` field.

**3. The EL genesis hash is derived, not configured.**
The engine bootstraps from `--el-genesis`, so its startup head *is* the EL genesis
block; `main.rs` reads it back and seeds the consensus anchor. The external path
needed a flag because the EL was a separate process.
*Why it matters:* forgetting this seed fails **silently** — consensus looks healthy
while the EL sits frozen at genesis and every proposal falls back to a synthetic
payload. Worth confirming you find the derivation trustworthy.

**4. `execute_payload` is synchronous.**
`Blockchain::add_block` is a sync ethrex call, so the gossip-import path no longer
awaits. Simpler, but it does mean EL execution happens on the actor thread.
*Consider:* whether block execution time on the actor is acceptable, or whether it
should move off-thread later.

**5. Single ethrex revision across the workspace.**
`crates/net/p2p` was pinned to an older ethrex for ENR parsing; it now follows the
workspace revision, which required porting `parse_enrs` to v15's typed
`NodeRecord`. This touches a crate unrelated to the feature.
*Why it is not optional:* `ethrex-crypto` bundles a C SHA3 with non-namespaced
symbols, so two ethrex versions multiply-define them under GNU `ld`. macOS `ld64`
tolerates it — it only fails in the Linux release build.

**6. In-memory EL store.** EL state resets on restart. Fine for a PoC; persistence
is an `ethrex-storage` feature away and pairs with EL-aware checkpoint sync.

**7. Mock-EL test seam dropped.** (your D4) No trait means nothing to mock; the
engine tests drive a real embedded ethrex instead.

## 5. Consensus-path changes to check carefully

These touch the tick loop, so they deserve more attention than the rest:

- **Interval 4** — `build_execution_payload` runs inline, immediately before the
  block is assembled. Failure returns `None` and `build_block` falls back to
  `synthetic_payload`.
- **Interval 0** — `notify_execution_layer` updates the EL head, spawned
  fire-and-forget.
- **Gossip import** — `import_gossiped_block` executes the payload *before* the
  store sees the block. A rejection drops the block; anything else proceeds.
- **Own block** — after building, we execute our own payload, because nobody
  gossips it back to us and the EL head would otherwise never advance.

The invariant throughout: **the execution layer never stalls consensus.** Only an
explicit rejection of a received payload drops a block; every other failure logs
and continues.

## 6. Verification status

| Check | Status |
|---|---|
| `cargo build --workspace` | ✅ clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ clean |
| `cargo fmt --all --check` | ✅ clean |
| Tests (blockchain, state-transition, engine, bin, p2p) | ✅ **299 passed, 0 failed** |
| Engine roundtrip + beacon-root rejection tests | ✅ pass |
| 3-node devnet **with** the embedded EL | ✅ finalized at slot 40 |
| 3-node devnet **without** the EL (control) | ✅ finalized at slot 41 |

The EL-enabled run matches the consensus-only control, so the execution layer
costs nothing in liveness. All three nodes agreed on the same finalized root, and
each executed exactly 43 payloads — lockstep.

### 6.1 Bug found by the devnet and fixed: `parent_hash mismatch`

Worth reading, because it is the one real defect the scope-down introduced and no
unit test could have caught it — it only appears with **multiple independent
execution layers**.

**Symptom.** With the EL enabled the chain never finalized: 22 `parent_hash
mismatch` errors, peer imports halved (13 vs 30), no aggregation coverage, no
finality. Silent from the proposer's side — zero EL rejections, zero warnings.
The block simply did not stick anywhere.

**Cause.** The state transition requires

```
payload.parent_hash == state.latest_execution_payload_header.block_hash
```

— the parent the *consensus chain* expects. `build_payload` instead derived the
parent from `store.get_latest_canonical_block_hash()`, this node's *own* EL head.
With three independent ELs those drift apart, so a proposer's payload named the
wrong parent and every node's STF rejected the block.

#367 did not have this bug: its build-mode `forkchoiceUpdated` pointed the EL at
`el_hash_at(store.head())` before building. Collapsing that two-step into one call
dropped the step that set the parent.

**Fix.** `build_payload` takes `parent_el_hash` explicitly; `el_integration` passes
`el_hash_at(head_root)` — the consensus head's payload hash — and the engine
re-points the EL at that block before building. safe/finalized are deliberately
left unset there: pinning them would forbid a later build on an earlier block.

**Regression test.** `builds_on_the_requested_parent_not_the_el_head` advances the
EL two blocks, then asks for a payload extending block 1 and asserts the payload
names *that* parent. It fails against the old code.

**Method note.** The first hypothesis — that `import_gossiped_block` was dropping
blocks on EL rejection — was wrong, and the logs disproved it (zero rejections)
before any code was changed.

## 7. Open questions for you

1. **Publishing.** Force-push this onto `feat/ethrex-inprocess-poc` (keeps PR #530
   and its discussion) or push `feat/ethrex-inprocess` as a new PR and close #530?
   Force-push rewrites the remote branch, so it needs your say-so.
2. **Decision 2** — fee-recipient config: leave dropped, or restore it?
3. **Decision 4** — EL execution on the actor thread: acceptable for now?
4. Anything in §3 you think should not be in this PR.

## 8. Known remaining work

- The two published artifacts still describe the trait / two-mode design and need
  updating once the code settles.
- `docs/plans/scope-down-to-inprocess.md` (the proposal) and this file can both be
  dropped from the PR if you would rather not carry planning docs.
- Prague / `ExecutionPayloadV4` support is out of scope; the EL genesis must be
  Cancun.
