# PoC: In-process ethrex integration (ethrex as a crate)

## Goal

Prove that ethlambda can drive an **in-process** ethrex execution layer — ethrex
linked as a library crate, no separate binary, no JSON-RPC/JWT hop — and run the
**full slot loop** against it in a devnet: build a payload on proposal, execute
imported payloads, advance both chains slot-by-slot.

This is the counterpart to PR #367, which integrates ethrex **out-of-process**
over the Engine API. This PoC reuses #367's abstractions wholesale and adds a
second implementation of the same seam.

## Decisions (confirmed)

- **Base branch:** off `engine-api-integration` (#367). Reuse the `ExecutionEngine`
  trait, `ExecutionPayloadV3` types, STF `process_execution_payload`, and the
  interval-4/interval-0 slot wiring as-is.
- **ethrex dependency:** pinned **git** dependency on `lambdaclass/ethrex`
  (`rev = <de9b249ba or later>`). Local checkout at `/Users/pablodeymonnaz/Lambda/ethrex`
  is used only to study the API during development.
- **Success criteria:** in-process engine wired into the live slot loop and
  validated in a running devnet (not just a unit test).

## The seam (already exists on #367)

`ExecutionEngine` (`crates/net/ethrex-client/src/client.rs:181`) — three async methods:

```rust
async fn forkchoice_updated_v3(&self, state, Option<PayloadAttributesV3>) -> ForkChoiceUpdatedResponse;
async fn get_payload(&self, PayloadId) -> ExecutionPayloadV3;
async fn new_payload(&self, &ExecutionPayloadV3, parent_beacon_block_root: H256) -> PayloadStatus;
```

The actor holds `Option<Arc<dyn ExecutionEngine>>` and calls it at:
- interval 4: `request_payload_id_for_next_slot` → `forkchoice_updated_v3(_, Some(attrs))`
- interval 0: `take_prepared_payload` → `get_payload`, then `new_payload` (self-import)
- on gossiped block: `validate_payload_with_el` → `new_payload`
- each tick: `notify_execution_layer` → `forkchoice_updated_v3(_, None)`

**Nothing in `crates/blockchain` changes.** The PoC only provides a new impl of the
trait and wires it up in `main.rs`.

## ethrex library API (verified against local checkout @ de9b249ba)

| Need | ethrex API |
|---|---|
| Bootstrap EL state | `Store::new_from_genesis(path, EngineType::{InMemory,RocksDB}, genesis)` (`storage/store.rs:1824`) |
| Construct engine | `Blockchain::new(store, BlockchainOptions)` / `default_with_store(store)` (`blockchain/blockchain.rs:372`) |
| FCU (head/safe/finalized) | `apply_fork_choice(&store, head, safe, finalized)` (`blockchain/fork_choice.rs:39`) |
| Payload id | `BuildPayloadArgs { .. }.id()` (`blockchain/payload.rs:108`) |
| Start build | `create_payload(&args, &store)` → `Block` (`blockchain/payload.rs:130`) |
| Finish build | `Blockchain::build_payload(block)` → `PayloadBuildResult` (sync, `payload.rs:469`) |
| Import/execute | `Blockchain::add_block(&self, block) -> Result<(), ChainError>` (`blockchain.rs:1976`) |
| Payload ↔ Block | `ExecutionPayload::{from_block, into_block}` (`rpc/types/payload.rs:110,162`) |

## Work breakdown

### Phase 0 — Cargo integration & de-risk ✅ DONE
1. ✅ Added `ethrex-common`/`ethrex-storage`/`ethrex-blockchain` as pinned git deps
   (`rev = de9b249baa8451290b06021c17756ccdd4031da4`) in `[workspace.dependencies]`.
2. ✅ New crate `crates/net/ethrex-engine` (`ethlambda-ethrex-engine`) links all three.
3. ✅ `cargo generate-lockfile` — 823 packages resolved to Rust 1.92.0-compatible
   versions, **zero unification conflicts** (tokio, ethereum-types, etc. all unified).
4. ✅ `cargo build -p ethlambda-ethrex-engine` — clean compile of ethrex-common,
   ethrex-levm, ethrex-storage, ethrex-vm, ethrex-blockchain + our crate. 0 errors.

**Result: dependency risk fully retired. ethrex embeds as an unmodified git dep.**
Phase 0 is self-contained (only links ethrex; uses no #367 code), so it lands as a
standalone PR off `main` on branch `feat/ethrex-inprocess-poc`. Phase 1 onward re-stacks
on `engine-api-integration` (#367) to reuse its `ExecutionEngine` trait + payload types.

### Phase 1 — New crate `crates/net/ethrex-engine` (in-process impl)

**Status:** the #367-independent core landed on `feat/ethrex-inprocess-poc` (PR #530):
`EthrexEngine` bootstraps an in-memory ethrex store from an EL genesis and exposes
`build_block` / `import_block` / `set_forkchoice` / `head_hash` / `head_number` over
ethrex-native types, proven by the `roundtrip` integration test (genesis → build →
execute → fork-choice → head advances to block 1). Deferred to the #367 re-stack:
the ethlambda `ExecutionPayloadV3` ⇄ ethrex `Block` conversion, the `ExecutionEngine`
trait impl, and the payload-id (`get_payload`) cache path.

1. `EthrexEngine { blockchain: Arc<Blockchain>, store: Store }`.
2. Constructor: build a `Store` from the EL genesis (`genesis-el.json`), wrap in
   `Blockchain`. In-memory store for the PoC (simplest); rocksdb path optional later.
3. Implement `ExecutionEngine`:
   - `forkchoice_updated_v3(state, None)` → `apply_fork_choice`, map result → `ForkChoiceUpdatedResponse` (payload_id = None).
   - `forkchoice_updated_v3(state, Some(attrs))` → `apply_fork_choice`, build `BuildPayloadArgs` from attrs, compute `id()`, `create_payload`, stash `(id → Block)` in an internal map; return the id.
   - `get_payload(id)` → look up the stashed block, `build_payload`, convert result `Block` → ethlambda `ExecutionPayloadV3`.
   - `new_payload(payload, pbbr)` → ethlambda `ExecutionPayloadV3` → ethrex `Block` (`into_block`), `add_block`, map `Ok`→VALID / `Err`→INVALID → `PayloadStatus`.
4. **Type-conversion module** (the bulk of the code): ethlambda ⇄ ethrex for
   `ExecutionPayloadV3`, `ForkChoiceState`, `PayloadAttributesV3`, `PayloadStatus`.
   Both sides mirror `execution-apis` field-for-field, so it's mechanical but must be exact.

### Phase 2 — CLI wiring (`bin/ethlambda/src/main.rs`)
1. `build_execution_client` currently returns the JSON-RPC `EngineClient`. Add a
   mode selector: `--execution-mode {external,inprocess}` (default `external` to
   preserve #367 behavior), plus `--el-genesis <path>` for the in-process store.
2. In `inprocess` mode, construct `EthrexEngine` and return it as `Arc<dyn ExecutionEngine>`.

### Phase 3 — Devnet validation
1. Extend/adapt `scripts/engine-api-demo/` (or the devnet-runner skill) to launch
   ethlambda with `--execution-mode inprocess`; no separate ethrex process.
2. Confirm slot-by-slot advancement: proposal builds a real payload, import
   executes it, EL head tracks the Lean head. Capture logs as the PoC evidence.

### Phase 4 — Tests & docs
1. Reuse the `MockEngine` pattern for unit coverage of the conversion functions.
2. One integration test: genesis → build payload → new_payload roundtrip in-process.
3. Update this plan's status; short section in `docs/rpc.md` or a new `docs/`
   note describing the two execution modes.

## Embeddability audit (done — no ethrex fork needed)

Audited the local checkout @ `de9b249ba`. **ethrex needs no modification** to be used
as a git dependency, provided we depend on the three core library crates and
reimplement the payload↔block conversion ourselves.

- **Crates to depend on:** `ethrex-storage`, `ethrex-blockchain`, `ethrex-common`.
  All three pull **none** of axum/tower/hyper/clap/libp2p/revm.
- **Dependency-conflict risk is low.** ethrex uses its own EVM (`levm`, no `revm`),
  its own devp2p (no `libp2p` — zero conflict with our libp2p fork), and does **not**
  use `ethereum_ssz` (it uses an optional LambdaClass `libssz` fork behind `eip-8025`).
  Conversions happen at the type boundary, so no SSZ compatibility is required.
  Remaining semver checks only: `tokio 1.41.1`, `ethereum-types 0.15.1`.
- **The one trap:** `ExecutionPayload::{into_block,from_block}` live in `ethrex-rpc`,
  which unconditionally drags in the full axum/reqwest server + `ethrex-p2p` and has
  no slimming feature. **Do not depend on `ethrex-rpc`.** Those functions are pure
  ~30-line field mapping over public `ethrex-common` types (`Block`/`BlockHeader`/
  `BlockBody`, all fields `pub`; public `compute_transactions_root` /
  `compute_withdrawals_root` / `DEFAULT_OMMERS_HASH`). Reimplement the mapping in our
  crate against `ethrex-common`.
- **Bootstrap glue** in `cmd/ethrex/initializers.rs` is thin wrappers; every primitive
  (`Store::new_from_genesis`/`add_initial_state`, `Blockchain::new`, `Genesis` parsing)
  is public in the library crates. Replicate ~5 lines; don't depend on the `ethrex` binary.

Call-site notes (not modifications): `Store::new_from_genesis` takes a genesis **file
path `&str`**, not a `Genesis`; `create_payload` takes a third `extra_data: Bytes` arg;
`apply_fork_choice` is **async**; `add_block`/`build_payload` take `Block` **by value**;
enable the `rocksdb` feature on `ethrex-storage` only if persistence is wanted (in-memory
by default).

## Risks / open questions

1. **Version co-existence (low, was flagged highest).** Confirm `tokio 1.41.1` and
   `ethereum-types 0.15.1` unify with ethlambda's versions. Structural conflicts
   (revm/libp2p/ssz) are ruled out by the audit above. Still worth a Phase-0
   compile gate; consider feature-gating ethrex so the default build stays lean.
2. **Sync vs async build.** `build_payload` is sync; the trait is async. For the
   PoC, building lazily inside `get_payload` (sync call in async fn) is fine.
   `initiate_payload_build` + async `get_payload(id)` is the closer mirror if
   build latency matters.
4. **Genesis alignment.** EL genesis must be post-Prague (Cancun/Prague fork
   config) so V3/V4 payload shapes round-trip. Reuse `scripts/engine-api-demo/genesis-el.json`.
5. **Store lifetime & determinism.** In-memory store resets on restart (fine for
   PoC). Checkpoint/restart behavior is out of scope.

## Out of scope (PoC)

- Persisted (rocksdb) EL store, checkpoint sync of EL state.
- Amsterdam/BAL (V5) payloads — stays on the V4/pre-Amsterdam path like #367.
- Removing the out-of-process path — both coexist behind `--execution-mode`.
- fork_digest bump / peering changes.
