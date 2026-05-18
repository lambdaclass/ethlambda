# Engine API integration: ethlambda ↔ ethrex

> Plan owner: pablo
> Created: 2026-05-13
> Status: draft, awaiting scope confirmation

## Goal

Integrate ethlambda (Lean consensus client) with ethrex (Ethereum execution
client) over the standard Engine API: JWT-authenticated JSON-RPC on a separate
"auth" port, with `engine_*` methods driving execution-layer fork choice,
payload validation, and payload building.

## Starting state

**ethlambda** (this repo):
- Pure consensus, no execution layer awareness.
- `BlockBody` carries `attestations` only — no `execution_payload` field
  (`crates/common/types/src/block.rs`).
- `State` carries justification/finalization data but no
  `latest_execution_payload_header`.
- No JWT / JSON-RPC client crate.
- Slot duration: 4s, tick intervals 0-4 per slot.

**ethrex** ([lambdaclass/ethrex](https://github.com/lambdaclass/ethrex)):
- Full mainline Engine API on an auth RPC port: V1-V5 of `engine_newPayload`,
  V1-V4 of `engine_forkchoiceUpdated`, V1-V5 of `engine_getPayload`, plus
  `engine_exchangeCapabilities` and `engine_getClientVersionV1`.
- JWT HS256 bearer auth (`crates/networking/rpc/authentication.rs`).
- Reference Engine *client* (used when ethrex acts as a rollup sequencer)
  in `crates/networking/rpc/clients/auth/mod.rs` — direct template for our
  new client crate.
- `PayloadAttributesV4` already includes `slot_number: u64`, friendly to
  Lean's slot-driven model.

**leanSpec**: no execution payload definition. Lean Ethereum consensus does
not currently mandate an EL. This means integration is *additive* — we choose
when to carry/validate payloads.

## Scope options (the question that needs answering)

Three plausible interpretations of "integrate":

| Option | What it means | Effort | Spec dependency |
|---|---|---|---|
| **A. Spike** | ethlambda speaks JWT+JSON-RPC to ethrex. On each tick, fires `engine_forkchoiceUpdated` with the current head/finality hashes (initially dummy `H256::zero()`). Validates JWT plumbing end-to-end. No block-schema changes. | ~1 day | none |
| **B. Scaffold** | Spike + typed Rust wrappers for all four engine methods, CLI flags, capability handshake on startup, observability. Block schema unchanged. Still no real payload flow because blocks have no payload. | ~3-5 days | none |
| **C. Full merge** | Add `execution_payload(_header)` to Lean `BlockBody` + `State`, propagate through STF (call `engine_newPayload` on import, `engine_getPayload` on proposal), require ethrex for consensus validity. | weeks | requires leanSpec proposal — not yet drafted |

**Recommendation**: do **A → B → wait for spec**. Option C should not be
attempted ahead of a leanSpec change; doing so forks ethlambda from the other
six Lean clients.

## Architecture (B target)

### New crate: `crates/net/ethrex-client`

```
crates/net/ethrex-client/
├── Cargo.toml          # reqwest (rustls-tls), serde, jsonwebtoken, bytes, eyre/thiserror
└── src/
    ├── lib.rs          # public EngineClient API
    ├── auth.rs         # JWT HS256 generation (iat-based, 60s expiry per spec)
    ├── transport.rs    # reqwest + bearer + JSON-RPC envelope
    ├── methods.rs      # engine_exchangeCapabilities / fcu / newPayload / getPayload wrappers
    └── types/          # PayloadStatus, ForkChoiceState, ExecutionPayload, PayloadAttributes(V3,V4)
        └── ...         # ported from ethrex's rpc/types/ — minimal subset, ours own
```

Why a separate crate (not in `crates/net/rpc`): rpc crate today serves the
*beacon* HTTP API and the metrics server. Engine API is conceptually a
*client* to a different process, so it belongs in its own crate to keep
dependencies clean (rpc doesn't need `jsonwebtoken`; ethrex-client doesn't
need axum).

### Types

We re-derive the mainline Engine API types locally (not depend on
`ethrex_rpc`) — ethrex is a sibling project, not an upstream library. We mirror
field names exactly so JSON wire format is identical.

Minimal V1 subset to start:
- `ForkChoiceState { head_block_hash, safe_block_hash, finalized_block_hash }`
- `PayloadAttributesV3` (Cancun) and `PayloadAttributesV4` (Prague, with
  `slot_number`) — both supported, picked per ethrex's capabilities.
- `ExecutionPayload` (with optional V3/V4 fields)
- `PayloadStatus { status, latest_valid_hash, validation_error }`

### CLI flags (`bin/ethlambda`)

| Flag | Default | Purpose |
|---|---|---|
| `--execution-endpoint` | (unset; integration disabled if missing) | URL of ethrex auth RPC, e.g. `http://127.0.0.1:8551` |
| `--execution-jwt-secret` | (unset) | Path to JWT hex secret file (same format ethrex/lighthouse/etc. use) |
| `--execution-fee-recipient` | (unset) | 20-byte hex; required only when proposing |

Behavior:
- Both unset → integration **disabled**, ethlambda runs as before.
- Both set → instantiate `EngineClient`, run capability handshake on startup
  (log mismatches as warnings, not errors), pass client to `BlockChain` actor.
- Capability handshake also fetches `engine_getClientVersionV1` and logs
  ethrex name/version for support diagnostics.

### Blockchain actor hookup (Option B level)

In `crates/blockchain/src/lib.rs`:
- On each `Tick`, if integration is enabled and tick interval is 0 (block
  proposal time): call `engine_forkchoiceUpdated` with our current
  `(head, safe, finalized)` hashes mapped onto dummy execution-block hashes
  (e.g., `H256::zero()` or `keccak256(beacon_root)` — TBD).
- On block import: log only, no payload flow.

This is deliberately a no-op for ethrex (the FCU it receives points at hashes
it doesn't know about → it returns `SYNCING`). The point is to exercise the
*wire* end-to-end so the real schema work (Option C) can land without surprises.

### Observability

Three new metrics (`ethrex_engine_*` to disambiguate from internal ethlambda
metrics; falls under "Custom Metrics" in `docs/metrics.md`):

- `lean_ethrex_engine_request_duration_seconds{method}` — histogram
- `lean_ethrex_engine_request_total{method, status}` — counter (`status` ∈ `ok`, `rpc_error`, `transport_error`)
- `lean_ethrex_engine_last_payload_status{}` — int gauge (0=unknown, 1=valid, 2=invalid, 3=syncing, 4=accepted)

## Milestones

### M1 — Plan locked + scope decided (TODAY)
Resolve A/B/C with user. Plan stays in `docs/plans/`.

### M2 — `ethrex-client` crate skeleton (1-2 days, parallelizable)
- New crate compiles in workspace, exports `EngineClient` with all four
  methods returning `eyre::Result<_>`, JWT auth implemented and unit-tested
  (fixed `iat`, deterministic token).
- Stub integration test against `mockito` (no real ethrex).

### M3 — Wire into `bin/ethlambda` (1 day)
- CLI flags added, client constructed at startup, capability handshake logged.
- Disabled by default; `make test` unchanged.

### M4 — FCU on tick (½ day)
- Blockchain actor fires `engine_forkchoiceUpdated` on interval 0 of every
  slot when client is configured. Use dummy hashes initially.
- Add metrics. Document expected `SYNCING` response.

### M5 — End-to-end test against real ethrex (1 day)
- Devnet config wiring ethlambda → local ethrex; verify ethrex logs receive
  the FCU and respond. No consensus block changes yet.

### M6 — Real payload flow (Option C, in scope as of 2026-05-18)

#### Scope decisions locked

- **Branch/PR**: extend the existing `engine-api-integration` branch (PR #367) rather than open a new one.
- **Schema**: mirror canonical Ethereum `ExecutionPayloadV3` (Cancun) verbatim — every field, exact JSON wire shape. We do not invent a Lean-specific minimal payload.
- **Upstream coordination**: lead unilaterally. Implement in ethlambda first, propose the schema to leanSpec as a follow-up.

#### Cost note (read before phase 1)

M6 is ~5–10× the size of PR #367's Option B scaffold. It touches three core schema types (`BlockBody`, `State`, `ExecutionPayloadHeader`), six functional sites (`process_block`, `build_block`, `on_block`, `notify_execution_layer`, `fcu` call site, capability handshake), every spec fixture (forkchoice / STF / signature SSZ inputs), and the gossipsub `fork_digest` (peering with other Lean clients breaks the moment this lands).

Estimated diff added to PR #367: **~+1600 / −200** on top of the current ~+1300, taking the PR to **~+3000 / −230 net** — at the upper bound of single-PR reviewability. If at any phase boundary this is judged too large to review as one unit, the natural split is `Phase 1–2` (schema additions, no behavior change) on PR #367 and `Phase 3–7` (EL wiring + fixture bump) on a follow-up PR. Decision deferred to end of Phase 2.

#### Phase 1 — Promote `ExecutionPayloadV3` into the canonical types crate

`ExecutionPayloadV3`, `ExecutionPayloadHeader`, `Withdrawal`, and the hex serde helpers live in `crates/net/ethrex-client/src/types.rs`. The block schema needs them, so the types crate (foundational) can't depend on the client crate. Move:

- New module `crates/common/types/src/execution_payload.rs` carrying the moved types.
- Add `Default`, `SszEncode`, `SszDecode`, `HashTreeRoot` derives — the existing ethrex-client copy only has serde.
- `crates/net/ethrex-client/src/lib.rs` re-exports from `ethlambda_types` so its public API is unchanged.

No behavior change. Net: +1 module, ~+250/−50.

#### Phase 2 — Embed payload in block schema

- `BlockBody { attestations }` → `BlockBody { attestations, execution_payload: ExecutionPayloadV3 }`.
- `State` gains `latest_execution_payload_header: ExecutionPayloadHeader`.
- `State::from_genesis(...)` seeds the header with parent_hash/state_root/block_hash all-zero, `block_number = 0`, `timestamp = GENESIS_TIME`. (Open question on genesis convention — see below.)
- `process_block` (state_transition) adds `process_execution_payload(state, block)` before `process_attestations`, mirroring the Capella spec line you pointed at:
  - `assert payload.parent_hash == state.latest_execution_payload_header.block_hash`
  - `assert payload.timestamp == GENESIS_TIME + slot * SLOT_DURATION`
  - Cache the new header onto `state.latest_execution_payload_header`.

Files: `crates/common/types/src/{block,state,execution_payload}.rs`, `crates/blockchain/state_transition/src/lib.rs`. ~+400/−20.

#### Phase 3 — `engine_newPayloadV3` on block import

In `crates/blockchain/src/store.rs::on_block` (line 412), after structural / signature gates pass and before fork-choice insertion, call `client.new_payload_v3(body.execution_payload)` when the client is configured:

- `INVALID` → reject with `StoreError::ExecutionPayloadInvalid`.
- `SYNCING` / `ACCEPTED` → log + accept (CL outpaces EL, EL will catch up).
- `VALID` → log + accept.

`on_block_without_verification` (the fork-choice-test seam) does NOT call the EL — preserves existing test isolation. ~+150/−10.

#### Phase 4 — `engine_getPayloadV3` on block proposal

Block-build flow today (store.rs:1043 `build_block`) constructs `BlockBody { attestations }` synchronously. Adding the payload requires a pre-arranged `payload_id`:

- At interval 4 of slot N-1, if we're the proposer for slot N: fire `engine_forkchoiceUpdatedV3` with `Some(PayloadAttributesV3 { timestamp: GENESIS_TIME + N*4, prev_randao: 0, suggested_fee_recipient, withdrawals: [], parent_beacon_block_root: 0 })`. EL returns a `payload_id`. Stash on the `BlockChain` actor.
- At interval 0 of slot N (proposal time), call `client.get_payload_v3(payload_id)` → parse into `ExecutionPayloadV3` → pass into `build_block` to embed in `BlockBody`.
- No client configured: synthesize a zero payload (parent_hash = prev header's block_hash, timestamp = slot-mapped, txs/withdrawals empty). Keeps non-EL-paired nodes producing parseable blocks.

Files: `crates/blockchain/src/{lib,store}.rs`. ~+250/−10.

#### Phase 5 — Replace `H256::ZERO` in `notify_execution_layer`

The whole conversation that started this expansion. Once blocks carry payloads, the function reads `block.body.execution_payload.block_hash` for head/safe/finalized off the store. Genesis special case stays zero. Drop the "placeholder" doc comment. ~+50/−30.

#### Phase 6 — Fork digest bump

New `BlockBody` SSZ root → gossipsub topic hashes change → ethlambda peering with the existing devnet4 set breaks the moment this is deployed. Pick a new 4-byte sentinel (e.g. `0xdeadbeef`) and coordinate via the leanSpec issue. ENR records unchanged. ~+30/−10.

#### Phase 7 — Fixtures, tests, and the leanSpec issue

What landed:

- Spec-fixture skip gates (`FIXTURES_AWAIT_M6_REGEN: bool = true`) at the top of `tests/forkchoice_spectests.rs`, `tests/signature_spectests.rs`, `tests/stf_spectests.rs`, and the BlockBody/Block/State/SignedBlock arms of `tests/ssz_spectests.rs`. Phase 2c. To clear: flip the bool and run `make leanSpec/fixtures` after upstream regenerates.
- `process_execution_payload_*` unit tests (4 cases) in `crates/blockchain/state_transition/src/lib.rs`. Phase 2d.
- `build_block_embeds_provided_execution_payload` unit test in `crates/blockchain/src/store.rs`. Phase 7 (this commit) — proves the proposer threads the EL-fetched payload into `BlockBody` verbatim instead of synthesizing.
- `docs/plans/lean-execution-payload-schema.md` — draft of the leanSpec issue. Cross-link when filing upstream.

Deferred (need an `EngineClient` trait abstraction to mock cleanly):

- `on_block_rejects_when_el_says_invalid` — would exercise `Handler<NewBlock>`'s INVALID-verdict drop path. Currently testable end-to-end only via a real TCP-mocked EL (cf. `tests/wire_smoke.rs`), which the sandbox blocks; out of scope until we trait-abstract.
- `notify_execution_layer_sends_real_hashes_after_first_block` — same blocker, plus the function spawns its FCU call so capturing the wire bytes wants a recording mock.

~+500/−100 originally estimated; actual ~+150/−5 because the EL-mocked tests are deferred.

#### Risks

1. **Wire incompatibility with other Lean clients** until they adopt the same schema. ethlambda runs in isolation for the gap.
2. **Spec-fixture regeneration burden** if the leanSpec issue lands with a different field ordering/naming than what we shipped.
3. **Genesis EL hash convention.** ethrex's `engine_newPayloadV3` re-derives `block_hash` from the rest of the payload. An all-zero genesis `block_hash` will fail re-derivation on the first non-genesis block. Mitigation: compute the real keccak-over-fields block_hash even for the synthetic genesis payload, OR pin a real ethrex-blessed genesis EL block and use its hash.
4. **Slot duration mismatch.** Lean = 4s, Ethereum mainnet = 12s. `compute_time_at_slot` is local to our chain so timestamps are consistent within ethlambda↔ethrex pairing, but if we ever bridge to a mainnet-derived EL state it'll be visible.

## Open questions

1. **Genesis EL hash mapping**: zero, or a real ethrex-blessed genesis-block header? Recomputing block_hash from zero-fields would let us stay all-zero, but ethrex may reject as a degenerate block.
2. **Multi-EL support** (Lighthouse/Lodestar style): out of scope. Single EL endpoint only.
3. **JWT secret format**: file vs. inline hex. ethrex/lighthouse/teku all accept a file containing `0x`-prefixed hex; we follow the same convention. ✓ already in PR #367.
4. **Slot → timestamp mapping**: ethlambda has `GENESIS_TIME` + slot duration = 4s. Lean slot 0 timestamp = `GENESIS_TIME`. ethrex `PayloadAttributesV4` wants Unix `timestamp` + `slot_number`. Both available.
5. **Capability handshake update**: today we advertise V3 only. Should the new payload work bump to V4 (Prague + `slot_number` in PayloadAttributesV4)? V3 covers the goal; V4 is a Phase-N option.

## References

- ethrex Engine API: <https://github.com/lambdaclass/ethrex/tree/main/crates/networking/rpc/engine>
- ethrex auth client (template): <https://github.com/lambdaclass/ethrex/blob/main/crates/networking/rpc/clients/auth/mod.rs>
- ethrex JWT auth: <https://github.com/lambdaclass/ethrex/blob/main/crates/networking/rpc/authentication.rs>
- Engine API spec: <https://github.com/ethereum/execution-apis/tree/main/src/engine>
- Capability list (mainline): `engine_*V1..V5` — see `engine/mod.rs:CAPABILITIES`
