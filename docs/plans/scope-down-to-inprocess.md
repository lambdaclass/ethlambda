# Plan: scope PR #530 down to the in-process ethrex integration

**Goal.** PR #530 should contain only what is needed to run ethrex **embedded as a
crate**. All Engine-API / out-of-process machinery comes out. That work already
lives in PR #367, so nothing is lost — #530 stops superseding it and becomes a
focused, reviewable change.

Status: proposal. Nothing has been changed yet.

---

## 1. What the in-process path actually needs

Working backwards from "a node runs ethrex in-process and its peers can validate
what it produced", these pieces are **load-bearing** and must stay even though
some arrived via #367:

| Piece | Where | Why it is required |
|---|---|---|
| `ExecutionPayloadV3` type | `crates/common/types/src/execution_payload.rs` | The proposer embeds the payload in the Lean block body so **peers can execute it in their own embedded EL**. Consensus schema, not transport. |
| Payload in `BlockBody`, header in `State` | `types/src/{block,state}.rs` | Same reason; plus the parent-hash chain the STF checks. |
| `process_execution_payload` | `state_transition/src/execution_payload.rs` | Validates payload parent hash + slot timestamp during the STF. |
| `latest_execution_payload_header` in `StateDiff` | `storage/src/state_diff.rs` | Reconstructed states must keep the EL block-hash chain. |
| `State::from_genesis_with_el_hash` | `types/src/el_genesis.rs` | Seeds the consensus genesis with the EL genesis hash. Without it the EL never starts building. |
| EL hooks on the actor | `blockchain/src/el_integration.rs` | Build at interval 4, execute on import, per-slot head update. |
| `EthrexEngine` + conversion | `crates/net/ethrex-engine/` | The integration itself. |

**Everything else from #367 is Engine-API-only and comes out.**

## 2. What comes out

| Item | Lines / size | Notes |
|---|---|---|
| `crates/net/ethrex-client/src/auth.rs` | 140 | JWT HS256 minting — meaningless in-process |
| `crates/net/ethrex-client/src/client.rs` | 284 | `EngineClient` JSON-RPC over reqwest |
| `crates/net/ethrex-client/tests/wire_smoke.rs` | 115 | JSON-RPC wire test against a mock TCP server |
| `crates/net/ethrex-client/src/{error,types,lib}.rs` | 254 | See decision **D1** — partly relocated, not all deleted |
| `--execution-endpoint`, `--execution-jwt-secret`, `--execution-genesis-block-hash` | cli.rs | External-mode flags |
| `--execution-mode` enum | cli.rs | Only one mode remains (see **D2**) |
| `build_execution_client()`, capability handshake, `ETHLAMBDA_ENGINE_CAPABILITIES` | main.rs | External wiring |
| `scripts/engine-api-demo/` | 4 files | #367 demo (external ethrex process) |
| `docs/plans/engine-api-integration.md`, `docs/plans/lean-execution-payload-schema.md` | 2 files | #367 planning docs |
| `reqwest`, `jsonwebtoken` deps | Cargo.toml | Only used by the JSON-RPC client |

## 3. Decisions to make

### D1 — What replaces the `ExecutionEngine` trait? **(the important one)**

The trait and its Engine-API-shaped wire types live in the crate we are deleting.
With the external implementation gone there is exactly **one** implementation left,
and the repo's own convention is to avoid single-implementation traits.

**Option A — keep the trait and wire types.** Move `ExecutionEngine`,
`ForkChoiceState`, `PayloadAttributesV3`, `PayloadStatus`, `PayloadId`,
`ForkChoiceUpdatedResponse`, `EngineClientError` into `ethrex-engine` (or a small
shared crate); delete only the JSON-RPC client, JWT and CLI.
*Smaller diff; re-adding an external mode later is trivial. Keeps an abstraction
with one implementor and a payload-id cache that exists only because the Engine
API is stateless.*

**Option B — collapse to a direct in-process API. (recommended)** Drop the trait
and the wire types. `EthrexEngine` exposes what the actor actually needs:

```rust
impl EthrexEngine {
    /// Build the payload for `slot` on top of the current head.
    pub async fn build_payload(&self, slot, timestamp, fee_recipient, beacon_root)
        -> Result<ExecutionPayloadV3, EngineError>;
    /// Execute and import a payload; Ok(()) means the EL accepted it.
    pub async fn execute_payload(&self, payload: &ExecutionPayloadV3, parent_root: H256)
        -> Result<(), EngineError>;
    /// Point the EL at head / safe / finalized.
    pub async fn set_head(&self, head: H256, safe: H256, finalized: H256)
        -> Result<(), EngineError>;
}
```

*This deletes `PayloadId`, the `Mutex<HashMap<[u8;8], ExecutionPayloadV3>>` payload
cache, the `ForkChoiceUpdatedResponse`/`PayloadStatus` round-trip, and the whole
build-then-fetch two-step — all of which exist only because the Engine API is a
stateless request/response protocol. The actor holds
`Option<Arc<EthrexEngine>>` instead of `Option<Arc<dyn ExecutionEngine>>`.*
*Cost: if an external mode returns, the abstraction has to be reintroduced — but
#367 already has it, so it would come back with that PR.*

### D2 — Does `--execution-mode` survive?

With one mode, the flag is redundant. Proposal: **remove it**; the EL is enabled
by passing `--el-genesis <path>` and disabled by omitting it. One flag, no
invalid combinations.
*(Alternative: keep `--execution-mode inprocess` as the explicit opt-in. Say the
word if you prefer an explicit switch.)*

### D3 — Branch strategy

**Option A — removal commits on the current branch (recommended).** Add commits
that delete the Engine-API code. The **diff against main**, which is what
reviewers read, ends up exactly right. History shows add-then-remove, which a
squash-merge flattens.

**Option B — fresh branch off main, re-apply only the in-process work.** Clean
history and clean diff, at the cost of redoing the merge with a fast-moving main
(14 commits in the last two hours) and losing this branch's commit trail.

### D4 — Keep the mock-EL test seam?

`ExecutionEngine` also let tests substitute a mock EL. Under Option B there is no
trait to mock. The `ethrex-engine` integration tests already drive a real embedded
ethrex, which is arguably better coverage. Flagging it so the loss is deliberate.

## 4. Execution steps (assumes D1=B, D2=remove, D3=A)

1. **Move the payload types out of the doomed crate.** `ExecutionPayloadV3` and
   friends already live in `ethlambda-types`; confirm nothing else in
   `ethrex-client` is load-bearing.
2. **Rewrite `EthrexEngine`'s public API** to the three methods above; delete the
   payload-id cache and the `ExecutionEngine` impl. Update
   `crates/net/ethrex-engine/tests/roundtrip.rs` to the new API.
3. **Rewrite `el_integration.rs`** against the new API: `build_execution_payload`
   becomes one call; `validate_payload_with_el` calls `execute_payload`;
   `notify_execution_layer` calls `set_head`. Keep the permissive posture — an EL
   error logs and never stalls consensus.
4. **Change the actor's field** to `Option<Arc<EthrexEngine>>` (`lib.rs`,
   `BlockChainConfig`).
5. **Strip the CLI**: delete the four external flags and `ExecutionMode`; keep
   `--el-genesis`; `build_inprocess_engine` becomes the only constructor.
6. **Delete** `crates/net/ethrex-client/` entirely, its workspace member entry and
   dependency lines, plus `reqwest`/`jsonwebtoken` if nothing else uses them.
7. **Delete** `scripts/engine-api-demo/` and the two #367 plan docs.
8. **Update the docs** — `docs/ethrex-inprocess-integration.md` currently frames
   everything as "second implementation of the trait"; rewrite sections 1, 2, 4
   and the design-decisions table around the direct API. Same for the two
   published artifacts.
9. **Verify**: `cargo build --workspace`, `clippy -D warnings`, `fmt`, the
   workspace tests, and `scripts/inprocess-devnet/run.sh --nodes 3 --slots 32
   --trace` end-to-end.
10. **Update the PR description** to say #530 is in-process only and #367 remains
    the Engine-API PR.

## 5. Expected outcome

- ~800 lines of Engine-API client code and 6 files of #367 artifacts removed.
- The actor holds a concrete engine; no single-implementor trait, no payload-id
  cache, no wire types, no JWT, no reqwest.
- `--el-genesis` is the whole EL surface.
- #530 and #367 stop overlapping: one embeds ethrex, the other speaks Engine API.

## 6. Risks

- **The STF payload schema stays.** It arrived with #367 but is required for
  in-process too. Reviewers who equate "payload in the block body" with "the
  Engine-API PR" may flag it; the justification is in §1.
- **Re-merging main.** main is moving fast; the sooner this lands the fewer
  re-merges. Sequencing the removal as one focused pass keeps that window short.
- **Rewriting `el_integration.rs`** touches the consensus tick path. Covered by
  the workspace tests plus a devnet run, which is how the current behaviour was
  validated.
